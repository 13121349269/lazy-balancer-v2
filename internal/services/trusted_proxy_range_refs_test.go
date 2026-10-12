package services

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// 受信代理网段引用 IP 地址列表（trusted_proxy_range_refs，2026-10-12）：
// 渲染静态展开 = 内联 CIDR ∪ 引用名单条目。展开形状四断言：内联在前、
// 引用按 refs 出现顺序追加、跨来源按规范前缀去重、裸 IP 补 /32（v4）。
func TestTrustedProxyRender_expandsReferencedLists(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database, "lb_tpr", "tpr.example.test", 8080)
	res, err := database.Exec(`INSERT INTO security_ip_lists (name, category, entries) VALUES ('CDN 回源', 'CDN 节点', '[{"value":"198.51.100.0/24","remark":""},{"value":"192.0.2.7","remark":"与内联重复"},{"value":"203.0.113.99","remark":""}]')`)
	if err != nil {
		t.Fatal(err)
	}
	listID, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`UPDATE global_config SET trusted_proxy_enabled=1, trusted_proxy_ranges='["203.0.113.0/24","192.0.2.7"]', trusted_proxy_range_refs=? WHERE id=1`,
		"["+jsonInt(listID)+"]"); err != nil {
		t.Fatal(err)
	}

	// When
	generated := generateCaddyConfigFromStore(database)
	if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generation failed: %s", message)
	}

	// Then
	apps := generated["apps"].(map[string]interface{})
	httpApp := apps["http"].(map[string]interface{})
	servers := httpApp["servers"].(map[string]interface{})
	if len(servers) == 0 {
		t.Fatal("no servers rendered")
	}
	want := []string{"203.0.113.0/24", "192.0.2.7/32", "198.51.100.0/24", "203.0.113.99/32"}
	for name, serverVal := range servers {
		srv, ok := serverVal.(map[string]interface{})
		if !ok {
			continue
		}
		tp, ok := srv["trusted_proxies"].(map[string]interface{})
		if !ok {
			t.Fatalf("server %s missing trusted_proxies", name)
		}
		got, _ := tp["ranges"].([]string)
		if !equalStringSlices(got, want) {
			t.Fatalf("server %s ranges=%v, want %v (内联在前/引用追加/去重/裸 IP 补 /32)", name, got, want)
		}
	}
}

// 名单不存在（悬空引用，仅见于带外改库/导入）→ 该名单贡献零条目，渲染
// 照常成功（保存侧校验与删除守卫保证常规路径不产生悬空引用）。
func TestTrustedProxyRender_missingRefListContributesZero(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database, "lb_tpm", "tpm.example.test", 8080)
	if _, err := database.Exec(`UPDATE global_config SET trusted_proxy_enabled=1, trusted_proxy_ranges='["203.0.113.0/24"]', trusted_proxy_range_refs='[424242]' WHERE id=1`); err != nil {
		t.Fatal(err)
	}

	// When
	generated := generateCaddyConfigFromStore(database)
	if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generation failed: %s", message)
	}

	// Then：ranges 仅内联
	apps := generated["apps"].(map[string]interface{})
	httpApp := apps["http"].(map[string]interface{})
	servers := httpApp["servers"].(map[string]interface{})
	for name, serverVal := range servers {
		srv, ok := serverVal.(map[string]interface{})
		if !ok {
			continue
		}
		tp, ok := srv["trusted_proxies"].(map[string]interface{})
		if !ok {
			t.Fatalf("server %s missing trusted_proxies", name)
		}
		got, _ := tp["ranges"].([]string)
		if !equalStringSlices(got, []string{"203.0.113.0/24"}) {
			t.Fatalf("server %s ranges=%v, want [203.0.113.0/24]", name, got)
		}
	}
}

// 重载联动门（威胁库门同款 fail-safe）：IP 名单内容变化时若被
// trusted_proxy_range_refs 引用 → 触发配置重载（true）；未引用 → false；
// refs JSON 解析失败按被引用处理（宁可多一次重载，不欠渲染收敛）。
func TestTrustedListsReferencedByTrustedProxy_gate(t *testing.T) {
	overrideWafDirForTest(t)
	newClusterTestService(t)
	// Given：一条自定义名单（id 自增——内置威胁三源已占低位 id，读回真实 id）
	res, err := db.DB.Exec(`INSERT INTO security_ip_lists (name, entries) VALUES ('cdn-src', '[]')`)
	if err != nil {
		t.Fatal(err)
	}
	listID, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`UPDATE global_config SET trusted_proxy_range_refs=? WHERE id=1`, "["+jsonInt(listID)+"]"); err != nil {
		t.Fatal(err)
	}
	if !trustedListsReferencedByTrustedProxy([]int{int(listID)}) {
		t.Fatal("refs 含目标 id 时应为 true")
	}
	if trustedListsReferencedByTrustedProxy([]int{424242}) {
		t.Fatal("refs 不含目标 id 时应为 false")
	}

	// 畸形 refs（带外改库形态）→ 按被引用处理（fail-closed）
	if _, err := db.DB.Exec(`UPDATE global_config SET trusted_proxy_range_refs='not-json' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if !trustedListsReferencedByTrustedProxy([]int{424242}) {
		t.Fatal("refs JSON 解析失败须按可能被引用处理（true）——与威胁库门口径一致")
	}
}

// 集群快照携带 refs（主端装载恒携带）+ 从端 apply 落库。
func TestLoadSnapshotGlobalSettings_carriesTrustedProxyRangeRefs(t *testing.T) {
	service, database := newClusterTestService(t)
	if _, err := database.Exec(`UPDATE global_config SET trusted_proxy_range_refs='[7,9]' WHERE id=1`); err != nil {
		t.Fatal(err)
	}

	var snapshot models.ClusterSnapshot
	if err := service.loadSnapshotGlobalSettings(context.Background(), database, &snapshot); err != nil {
		t.Fatalf("load snapshot settings: %v", err)
	}
	if snapshot.BasicSettings.TrustedProxyRangeRefs != "[7,9]" {
		t.Fatalf("trusted_proxy_range_refs=%q, want [7,9]", snapshot.BasicSettings.TrustedProxyRangeRefs)
	}
	wire, err := json.Marshal(snapshot.BasicSettings)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(wire), `"trusted_proxy_range_refs":"[7,9]"`) {
		t.Fatalf("wire basic_settings=%s, must carry trusted_proxy_range_refs", wire)
	}
}

func TestUpdateSnapshotSettings_trustedProxyRangeRefsApplied(t *testing.T) {
	_, database := newClusterTestService(t)
	ctx := context.Background()
	caddyConfig := "{}"

	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := updateSnapshotSettings(ctx, tx, models.ClusterSnapshot{
		CaddyConfig: &caddyConfig,
		BasicSettings: models.ClusterBasicSettings{
			JWTExpireMinutes:      20,
			TrustedProxyRangeRefs: "[11]",
		},
	}); err != nil {
		t.Fatalf("apply settings: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	var got string
	if err := database.QueryRow(`SELECT COALESCE(trusted_proxy_range_refs,'[]') FROM global_config WHERE id=1`).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != "[11]" {
		t.Fatalf("applied trusted_proxy_range_refs=%q, want [11]", got)
	}
}

func equalStringSlices(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
