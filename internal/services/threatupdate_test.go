package services

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"lazy-balancer-v2/internal/taskengine"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

func overrideWafDirForTest(t *testing.T) {
	t.Helper()
	restoreWaf := OverrideThreatWafDirForTest(t.TempDir())
	t.Cleanup(restoreWaf)
}

// 威胁情报库名单化（v2.3.2 重构）测试基座：三源指向 httptest 桩；
// 内容与行状态分离——条目写 security_ip_lists 的 system=1 内置名单行，
// 状态/计数/版本写 security_threat_sources。
func setupThreatTest(t *testing.T, bodies map[string][]string, failSources map[string]bool, rawBodies map[string]string) {
	t.Helper()
	ResetThreatUpdateManagerForTest()
	for _, name := range []string{"ustc", "firehol_l1", "et_compromised"} {
		name := name
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if failSources[name] {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "text/plain")
			if raw, ok := rawBodies[name]; ok {
				_, _ = w.Write([]byte(raw))
				return
			}
			list := bodies[name]
			if list == nil {
				list = []string{"203.0.113.1", "10.9.0.0/24"} // 缺省合法两条目
			}
			_, _ = w.Write([]byte(strings.Join(list, "\n") + "\n"))
		}))
		t.Cleanup(server.Close)
		if _, err := db.DB.Exec(`UPDATE security_threat_sources SET url=? WHERE name=?`, server.URL, name); err != nil {
			t.Fatal(err)
		}
	}
}

func readThreatRow(t *testing.T, name string) (status, version, message string, count, failures int) {
	t.Helper()
	if err := db.DB.QueryRow(`SELECT update_status, version, message, entry_count, consecutive_failures FROM security_threat_sources WHERE name=?`, name).
		Scan(&status, &version, &message, &count, &failures); err != nil {
		t.Fatal(err)
	}
	return
}

// 读内置名单条目值集合（内容写面断言入口）。
func readThreatListEntries(t *testing.T, source string) []string {
	t.Helper()
	name := db.ThreatListNameBySource(source)
	if name == "" {
		t.Fatalf("未登记的源: %s", source)
	}
	var system int
	if err := db.DB.QueryRow(`SELECT system FROM security_ip_lists WHERE name=?`, name).Scan(&system); err != nil {
		t.Fatalf("内置名单缺失 %q: %v", name, err)
	}
	if system != 1 {
		t.Fatalf("名单 %q system=%d, want 1", name, system)
	}
	// RDB: 系统列表条目从 .iplist 文件读取（不存在=未更新,返回空）
	raw, ferr := os.ReadFile(filepath.Join(wafDir, "threat-"+source+".iplist"))
	if ferr != nil {
		if os.IsNotExist(ferr) {
			return nil // 禁用/未更新源无文件——等价旧 DB entries 空
		}
		t.Fatalf("读 .iplist %s: %v", source, ferr)
	}
	var out []string
	for _, line := range strings.Split(string(raw), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out
}

// 单任务按 id 升序执行全部启用源；条目聚合后写入内置名单行；
// 行状态 success、entry_count=解析条数、version=成功日期。
func TestThreatUpdate_runsEnabledSourcesInOrder(t *testing.T) {
	overrideWafDirForTest(t)
	newClusterTestService(t)
	var mu sync.Mutex
	var order []string
	setupThreatTest(t, nil, nil, nil)
	for _, name := range []string{"ustc", "firehol_l1", "et_compromised"} {
		name := name
		var url string
		if err := db.DB.QueryRow(`SELECT url FROM security_threat_sources WHERE name=?`, name).Scan(&url); err != nil {
			t.Fatal(err)
		}
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			mu.Lock()
			order = append(order, name)
			mu.Unlock()
			_, _ = w.Write([]byte("203.0.113.1\n10.9.0.0/24\n"))
		}))
		t.Cleanup(server.Close)
		if _, err := db.DB.Exec(`UPDATE security_threat_sources SET url=? WHERE name=?`, server.URL, name); err != nil {
			t.Fatal(err)
		}
	}

	if err := GetThreatUpdateManager().RunUpdate("manual", nil); err != nil {
		t.Fatalf("run update: %v", err)
	}

	wantOrder := []string{"ustc", "firehol_l1", "et_compromised"}
	if fmt.Sprint(order) != fmt.Sprint(wantOrder) {
		t.Fatalf("执行顺序=%v, want %v", order, wantOrder)
	}
	today := time.Now().UTC().Format("2006.01.02")
	for _, name := range wantOrder {
		entries := readThreatListEntries(t, name)
		if len(entries) != 2 || entries[0] != "10.9.0.0/24" || entries[1] != "203.0.113.1/32" {
			t.Fatalf("源 %s 名单=%v, want 聚合排序 [10.9.0.0/24 203.0.113.1/32]", name, entries)
		}
		status, version, _, count, failures := readThreatRow(t, name)
		if status != "success" || count != 2 || version != today || failures != 0 {
			t.Fatalf("源 %s 行=(%s,%d,%q,fail=%d), want (success,2,%q,0)", name, status, count, version, failures, today)
		}
	}
}

// 单源失败不中断其余源；失败源行 failed+message+consecutive_failures+1；
// 失败源名单内容保持上次成功值（不被清空）。
func TestThreatUpdate_sourceFailureKeepsOldListAndContinues(t *testing.T) {
	overrideWafDirForTest(t)
	newClusterTestService(t)
	setupThreatTest(t, nil, nil, nil)

	if err := GetThreatUpdateManager().RunUpdate("manual", nil); err != nil {
		t.Fatalf("first run: %v", err)
	}
	// 第二轮：firehol_l1 失败、ustc 换内容
	server500 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(server500.Close)
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET url=? WHERE name='firehol_l1'`, server500.URL); err != nil {
		t.Fatal(err)
	}
	ustc2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("198.51.100.9\n"))
	}))
	t.Cleanup(ustc2.Close)
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET url=? WHERE name='ustc'`, ustc2.URL); err != nil {
		t.Fatal(err)
	}

	// F-L1-68-01（第 68 轮）：任一源失败即整体失败——RunUpdate 回传
	// ErrThreatUpdateFailed（引擎 task_runs 记 failed）；单源失败仍不中断其余源。
	if err := GetThreatUpdateManager().RunUpdate("manual", nil); !errors.Is(err, ErrThreatUpdateFailed) {
		t.Fatalf("second run err=%v, want ErrThreatUpdateFailed", err)
	}

	status, _, message, _, failures := readThreatRow(t, "firehol_l1")
	if status != "failed" || message == "" || failures != 1 {
		t.Fatalf("失败源行=(%s,%q,fail=%d), want (failed,非空 message,1)", status, message, failures)
	}
	if status, _, _, _, _ := readThreatRow(t, "ustc"); status != "success" {
		t.Fatalf("ustc 应继续成功, got %s", status)
	}
	// ustc 名单更新为新内容；firehol 名单保持首轮内容
	if got := readThreatListEntries(t, "ustc"); len(got) != 1 || got[0] != "198.51.100.9/32" {
		t.Fatalf("ustc 名单=%v, want [198.51.100.9/32]", got)
	}
	if got := readThreatListEntries(t, "firehol_l1"); len(got) != 2 {
		t.Fatalf("失败源名单须保留旧内容, got=%v", got)
	}
}

// 解析守卫：可解析行比例 <50% 判失败（防错页/HTML 劫持）；条目 >200000 拒绝。
func TestThreatUpdate_parseGuards(t *testing.T) {
	overrideWafDirForTest(t)
	newClusterTestService(t)
	setupThreatTest(t, nil, nil, map[string]string{
		"ustc": "<html><body>not a list</body></html>\n203.0.113.1\n", // 1/2 可解析=50% 边界 → 通过
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html>\n<body>\n203.0.113.1\n"))
	}))
	t.Cleanup(srv.Close)
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET url=? WHERE name='firehol_l1'`, srv.URL); err != nil {
		t.Fatal(err)
	}
	huge := strings.Repeat("203.0.113.1\n", 200001)
	srvHuge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(huge))
	}))
	t.Cleanup(srvHuge.Close)
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET url=? WHERE name='et_compromised'`, srvHuge.URL); err != nil {
		t.Fatal(err)
	}

	// F-L1-68-01（第 68 轮）：两源失败（解析守卫拒绝）→ 整体失败回传。
	if err := GetThreatUpdateManager().RunUpdate("manual", nil); !errors.Is(err, ErrThreatUpdateFailed) {
		t.Fatalf("run err=%v, want ErrThreatUpdateFailed（两源被守卫拒绝）", err)
	}
	if status, _, _, _, _ := readThreatRow(t, "ustc"); status != "success" {
		t.Fatalf("50%% 边界应通过, got %s", status)
	}
	if status, _, _, _, _ := readThreatRow(t, "firehol_l1"); status != "failed" {
		t.Fatalf("可解析比例 <50%% 必须失败, got %s", status)
	}
	if status, _, _, _, _ := readThreatRow(t, "et_compromised"); status != "failed" {
		t.Fatalf("超 200000 条目必须拒绝, got %s", status)
	}
}

// update_enabled=0 的源被跳过（不下载、不动行、不写名单）。
func TestThreatUpdate_updateDisabledSourceSkipped(t *testing.T) {
	overrideWafDirForTest(t)
	newClusterTestService(t)
	setupThreatTest(t, nil, nil, nil)
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET update_enabled=0 WHERE name='firehol_l1'`); err != nil {
		t.Fatal(err)
	}
	if err := GetThreatUpdateManager().RunUpdate("manual", nil); err != nil {
		t.Fatalf("run: %v", err)
	}
	if status, _, _, _, _ := readThreatRow(t, "firehol_l1"); status != "idle" {
		t.Fatalf("禁用更新的源不得被触碰, got status=%s", status)
	}
	if got := readThreatListEntries(t, "firehol_l1"); len(got) != 0 {
		t.Fatalf("禁用更新的源不得写名单: %v", got)
	}
}

// 名单内容变化且被启用策略引用时触发一次 Caddy 重载（引用方渲染随新内容
// 收敛）；内容未变化不重载；无引用方的变化同样不重载（2026-09-24 裁定）。
func TestThreatUpdate_listChangeTriggersReload(t *testing.T) {
	overrideWafDirForTest(t)
	newClusterTestService(t)
	setupThreatTest(t, nil, nil, nil)
	var reloads int
	SetThreatReloader(func() error { reloads++; return nil })
	t.Cleanup(func() { SetThreatReloader(nil) })

	if err := GetThreatUpdateManager().RunUpdate("manual", nil); err != nil {
		t.Fatalf("run: %v", err)
	}
	if reloads != 0 {
		t.Fatalf("无策略引用时内容新增也不重载: reloads=%d", reloads)
	}
	// 引用 ustc 名单后，同内容仍不重载
	seedThreatPolicyRefForSource(t, 900, "ustc")
	if err := GetThreatUpdateManager().RunUpdate("manual", nil); err != nil {
		t.Fatalf("run2: %v", err)
	}
	if reloads != 0 {
		t.Fatalf("内容未变化不应重载: reloads=%d", reloads)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("192.0.2.99\n"))
	}))
	t.Cleanup(srv.Close)
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET url=? WHERE name='ustc'`, srv.URL); err != nil {
		t.Fatal(err)
	}
	if err := GetThreatUpdateManager().RunUpdate("manual", nil); err != nil {
		t.Fatalf("run3: %v", err)
	}
	if reloads != 1 {
		t.Fatalf("被引用的名单内容变化须重载: reloads=%d", reloads)
	}
}

// seedThreatPolicyRefForSource 建一条启用策略并引用指定源的内置名单
// （重载门/归因类测试的引用方夹具）。
func seedThreatPolicyRefForSource(t *testing.T, policyID int, source string) {
	t.Helper()
	var listID int
	if err := db.DB.QueryRow(`SELECT id FROM security_ip_lists WHERE name=?`, db.ThreatListNameBySource(source)).Scan(&listID); err != nil {
		t.Fatalf("内置名单缺失 %s: %v", source, err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policies (id, name, mode, ip_acl_enabled, ip_acl_mode, ip_acl_list_refs, policy_type, enabled)
		VALUES (?, ?, 'blocking', 1, 'deny', ?, 'stage1', 1)`, policyID, "引用夹具-"+source, fmt.Sprintf("[%d]", listID)); err != nil {
		t.Fatal(err)
	}
}

// 重载门（2026-09-24 用户裁定）：名单变化且**被启用策略引用**才重载 Caddy——
// 未被引用的源即使内容变化也不重载（重载只服务引用方的渲染收敛）。
func TestThreatUpdate_reloadsOnlyWhenChangedListReferenced(t *testing.T) {
	overrideWafDirForTest(t)
	newClusterTestService(t)
	setupThreatTest(t, nil, nil, nil)
	var reloads int
	SetThreatReloader(func() error { reloads++; return nil })
	t.Cleanup(func() { SetThreatReloader(nil) })

	// When 首轮写入全部名单（无任何策略引用）
	if err := GetThreatUpdateManager().RunUpdate("manual", nil); err != nil {
		t.Fatalf("run1: %v", err)
	}
	// Then 内容新增但零引用 → 不重载
	if reloads != 0 {
		t.Fatalf("无策略引用时不得重载: reloads=%d", reloads)
	}

	// Given 启用策略引用 ustc 内置名单（firehol_l1 不被引用）
	var ustcListID int
	if err := db.DB.QueryRow(`SELECT id FROM security_ip_lists WHERE name=?`, db.ThreatListNameBySource("ustc")).Scan(&ustcListID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policies (id, name, mode, ip_acl_enabled, ip_acl_mode, ip_acl_list_refs, policy_type, enabled)
		VALUES (900, '引用ustc的ACL策略', 'blocking', 1, 'deny', ?, 'stage1', 1)`, fmt.Sprintf("[%d]", ustcListID)); err != nil {
		t.Fatal(err)
	}
	// And 只有 firehol_l1 的内容变化
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("192.0.2.55\n"))
	}))
	t.Cleanup(srv.Close)
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET url=? WHERE name='firehol_l1'`, srv.URL); err != nil {
		t.Fatal(err)
	}

	// When 仅未被引用的源变化
	if err := GetThreatUpdateManager().RunUpdate("manual", nil); err != nil {
		t.Fatalf("run2: %v", err)
	}
	// Then 仍不重载（变化的名单无人引用）
	if reloads != 0 {
		t.Fatalf("未被引用的源变化不得重载: reloads=%d", reloads)
	}

	// When 被引用的 ustc 内容变化
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("192.0.2.77\n"))
	}))
	t.Cleanup(srv2.Close)
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET url=? WHERE name='ustc'`, srv2.URL); err != nil {
		t.Fatal(err)
	}
	if err := GetThreatUpdateManager().RunUpdate("manual", nil); err != nil {
		t.Fatalf("run3: %v", err)
	}
	// Then 重载一次（被引用的名单变了）
	if reloads != 1 {
		t.Fatalf("被引用的名单变化须重载: reloads=%d, want 1", reloads)
	}
}

// 重复触发返回 ErrThreatUpdateRunning（409 语义由 handler 映射）。
func TestThreatUpdate_duplicateStartRejected(t *testing.T) {
	overrideWafDirForTest(t)
	newClusterTestService(t)
	setupThreatTest(t, nil, nil, nil)
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-block
	}))
	t.Cleanup(srv.Close)
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET url=?`, srv.URL); err != nil {
		t.Fatal(err)
	}

	done1, err := GetThreatUpdateManager().StartUpdate("manual", nil)
	if err != nil {
		t.Fatalf("first start: %v", err)
	}
	if _, err := GetThreatUpdateManager().StartUpdate("manual", nil); err == nil {
		t.Fatal("重复启动必须拒绝")
	}
	close(block)
	<-done1
}

// 名单为空视为到期（升级窗口：旧版写文件新版写名单——next_update 未到期但
// 名单空的源必须进 auto 任务；名单有内容且未到期才跳过）。
func TestThreatDueSources_emptyListIsDue(t *testing.T) {
	overrideWafDirForTest(t)
	newClusterTestService(t)
	// Given：三源 next_update 全在未来
	future := time.Now().UTC().Add(24 * time.Hour).Format(crsTimeLayout)
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET next_update=?`, future); err != nil {
		t.Fatal(err)
	}

	// 名单全空 → 全部到期
	due, err := threatDueSources("auto")
	if err != nil {
		t.Fatal(err)
	}
	if len(due) != 3 {
		t.Fatalf("名单为空时应全部到期, got %d", len(due))
	}

	// ustc 名单填内容 + 落地 .iplist 文件（RDB 文件化：文件缺失=升级引导
	// 到期语义）→ 仅剩 2 个到期
	if _, err := db.DB.Exec(`UPDATE security_ip_lists SET entries='[{"value":"203.0.113.1/32","remark":""}]' WHERE name=?`, db.ThreatListNameBySource("ustc")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wafDir, "threat-ustc.iplist"), []byte("203.0.113.1/32\n"), 0644); err != nil {
		t.Fatal(err)
	}
	due, err = threatDueSources("auto")
	if err != nil {
		t.Fatal(err)
	}
	if len(due) != 2 {
		t.Fatalf("ustc 名单有内容后应剩 2 个到期, got %d", len(due))
	}
	for _, s := range due {
		if s.name == "ustc" {
			t.Fatal("ustc 名单有内容且未到期, 不应进 auto 任务")
		}
	}
}

// 内容哈希比对（2026-09-24 用户裁定）：聚合规范字节的 sha256 落
// security_threat_sources.content_hash；同集乱序（USTC 源实测每次请求乱序
// 返回同一集合）不得判变化；重载须留操作日志审计。
func TestThreatUpdate_contentHashCompare_andReloadAudit(t *testing.T) {
	overrideWafDirForTest(t)
	newClusterTestService(t)
	// 任务日志目录自隔离（certjoblog_test.go:23-27 同型）——本测试断言
	// TaskLogPath("threat") 内容，不得依赖包级全局泄漏（A 域新 wire 测试
	// 文件改变全局链后曾读空路径）。
	taskengine.SetLogDir(t.TempDir())
	t.Cleanup(func() { taskengine.SetLogDir("") })
	setupThreatTest(t, nil, nil, nil)
	var reloads int
	SetThreatReloader(func() error { reloads++; return nil })
	t.Cleanup(func() { SetThreatReloader(nil) })

	readHash := func() string {
		var h string
		if err := db.DB.QueryRow(`SELECT COALESCE(content_hash,'') FROM security_threat_sources WHERE name='ustc'`).Scan(&h); err != nil {
			t.Fatal(err)
		}
		return h
	}
	// run1：写入 + 哈希落库（无策略引用 → 不重载）
	if err := GetThreatUpdateManager().RunUpdate("manual", nil); err != nil {
		t.Fatalf("run1: %v", err)
	}
	h1 := readHash()
	if len(h1) != 64 {
		t.Fatalf("run1 后 content_hash 应为 64 位 hex, got %q", h1)
	}

	// 重载门（2026-09-24 裁定）：审计断言前须有引用方——先验证无引用不重载
	if reloads != 0 {
		t.Fatalf("run1 无策略引用不得重载: reloads=%d", reloads)
	}
	seedThreatPolicyRefForSource(t, 901, "ustc")
	// 被引用的 ustc 内容变化 → 重载 + 审计
	srvNew := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("198.51.100.9\n10.9.0.0/24\n"))
	}))
	t.Cleanup(srvNew.Close)
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET url=? WHERE name='ustc'`, srvNew.URL); err != nil {
		t.Fatal(err)
	}
	if err := GetThreatUpdateManager().RunUpdate("manual", nil); err != nil {
		t.Fatalf("run1b: %v", err)
	}
	if reloads != 1 {
		t.Fatalf("被引用名单变化须重载: reloads=%d", reloads)
	}
	h1 = readHash() // 内容已换一轮——后续「同内容不变」断言以新哈希为基线
	var auditCount int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='重载' AND detail LIKE '%威胁情报库%'`).Scan(&auditCount); err != nil {
		t.Fatalf("读审计库: %v", err)
	}
	if auditCount == 0 {
		t.Fatal("名单变化触发的重载须写操作日志（来源：威胁情报库更新）")
	}

	// run2：同内容（同序）→ 不重载、哈希不变、更新日志留痕「未变化」
	if err := GetThreatUpdateManager().RunUpdate("manual", nil); err != nil {
		t.Fatalf("run2: %v", err)
	}
	if reloads != 1 {
		t.Fatalf("同内容不应重载: reloads=%d", reloads)
	}
	logRaw, lerr := os.ReadFile(taskengine.TaskLogPath("threat"))
	if lerr != nil {
		t.Fatalf("读更新日志: %v", lerr)
	}
	if !strings.Contains(string(logRaw), "名单内容未变化") {
		t.Fatalf("无变化须留更新日志痕迹:\n%s", logRaw)
	}
	// 两层哈希（2026-09-24 用户裁定）：原始字节哈希一致 → 快速路径跳过
	// 解析/聚合/写库（日志口径可辨）；原始不同才聚合规范哈希终判。
	if !strings.Contains(string(logRaw), "原始内容哈希一致") {
		t.Fatalf("同内容再跑须命中原始哈希快速路径:\n%s", logRaw)
	}
	if readHash() != h1 {
		t.Fatal("同内容哈希不应变化")
	}

	// run3：同集乱序（USTC 实测形态）→ 哈希不变、不重载
	ustcBody := []string{"10.9.0.0/24", "198.51.100.9"} // 与 run1b 同集、顺序颠倒
	shuffled := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Join(ustcBody, "\n") + "\n"))
	}))
	t.Cleanup(shuffled.Close)
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET url=? WHERE name='ustc'`, shuffled.URL); err != nil {
		t.Fatal(err)
	}
	if err := GetThreatUpdateManager().RunUpdate("manual", nil); err != nil {
		t.Fatalf("run3: %v", err)
	}
	if reloads != 1 {
		t.Fatalf("乱序同集不应重载: reloads=%d", reloads)
	}
	if readHash() != h1 {
		t.Fatal("乱序同集哈希应不变（聚合规范字节口径）")
	}
}

// F49-4：原始哈希快速路径中的名单存在性 COUNT 查询失败时，不得按「存在」
// 走跳过分支标 success——必须记错并继续完整聚合/写库路径（本测试用 DROP
// TABLE 使 COUNT 与后续写库一并失败，可观察终态=failed 而非 success）。
func TestThreatUpdate_listExistenceQueryErrorNotFastPathSuccess(t *testing.T) {
	overrideWafDirForTest(t)
	newClusterTestService(t)
	setupThreatTest(t, nil, nil, nil)

	// Given：run1 成功（raw_hash 落库，名单行存在）
	if err := GetThreatUpdateManager().RunUpdate("manual", nil); err != nil {
		t.Fatalf("run1: %v", err)
	}
	if status, _, _, _, _ := readThreatRow(t, "ustc"); status != "success" {
		t.Fatalf("run1 ustc status=%s, want success", status)
	}
	// 存在性 COUNT 必失败的环境；聚焦 ustc 单源
	if _, err := db.DB.Exec(`DROP TABLE security_ip_lists`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET update_enabled=0 WHERE name!='ustc'`); err != nil {
		t.Fatal(err)
	}

	// When：同内容 run2 —— 原始哈希一致进入快速路径，COUNT 失败。
	// F-L1-68-01（第 68 轮）后失败回传引擎：源失败必须返回错误（旧契约
	// 断言返回 nil 已随迁）；行级 failed 落库仍是本测试真契约。
	if err := GetThreatUpdateManager().RunUpdate("manual", nil); err == nil {
		t.Fatal("run2: 源写库失败必须返回错误（F-L1-68-01 失败回传契约）")
	}

	// Then：不得标 success 快速返回——完整路径写库失败落 failed
	status, _, message, _, _ := readThreatRow(t, "ustc")
	if status != "failed" {
		t.Fatalf("COUNT 失败时被按「存在」跳过并标 success: status=%s message=%q, want failed", status, message)
	}
	if message == "" {
		t.Fatal("failed 行必须携带失败原因")
	}
}

// P5-10（第 50 轮审计）：策略 refs JSON 解析失败按「可能被引用」处理——与
// 同函数查询失败口径一致（宁可多一次重载，不欠引用方的渲染收敛）。
func TestThreatListsReferenced_invalidRefsTreatedAsReferenced(t *testing.T) {
	overrideWafDirForTest(t)
	newClusterTestService(t)
	// Given：启用策略持有不可解析的 refs JSON
	if _, err := db.DB.Exec(`INSERT INTO security_policies (id, name, mode, ip_acl_enabled, ip_acl_mode, ip_acl_list_refs, policy_type, enabled)
		VALUES (901, '坏引用策略', 'blocking', 1, 'deny', 'not-json', 'stage1', 1)`); err != nil {
		t.Fatal(err)
	}

	// When/Then：按被引用处理（true）
	if !threatListsReferencedByEnabledPolicy([]int{424242}) {
		t.Fatal("refs JSON 解析失败须按可能被引用处理（true）——与查询失败口径一致")
	}
}

// 回归形状：可解析且不含目标 id 的 refs 不受影响（false）。
func TestThreatListsReferenced_parseableRefsMiss(t *testing.T) {
	overrideWafDirForTest(t)
	newClusterTestService(t)
	if _, err := db.DB.Exec(`INSERT INTO security_policies (id, name, mode, ip_acl_enabled, ip_acl_mode, ip_acl_list_refs, policy_type, enabled)
		VALUES (902, '正常引用策略', 'blocking', 1, 'deny', '[7,8]', 'stage1', 1)`); err != nil {
		t.Fatal(err)
	}

	if threatListsReferencedByEnabledPolicy([]int{424242}) {
		t.Fatal("可解析 refs 不含目标 id 时应为 false")
	}
	if !threatListsReferencedByEnabledPolicy([]int{8}) {
		t.Fatal("可解析 refs 含目标 id 时应为 true")
	}
}

// 第 59 轮 R59-P2：重载失败必须自愈——失败后置 pending，下一轮即使内容未变
// 也强制重载一次（对齐 CRS restoreBackup+failed / ip2region rollback+fail 家族；
// 哈希已持久化使「unchanged」快路径永不再触发重载的缺口）。成功后清 pending，
// 后续轮次恢复「内容未变不重载」口径。
func TestThreatUpdate_reloadFailureRetriedOnNextRun(t *testing.T) {
	overrideWafDirForTest(t)
	newClusterTestService(t)
	setupThreatTest(t, nil, nil, nil)
	failReload := true
	var reloads int
	SetThreatReloader(func() error {
		reloads++
		if failReload {
			return errors.New("reload boom")
		}
		return nil
	})
	t.Cleanup(func() { SetThreatReloader(nil) })

	mgr := GetThreatUpdateManager()
	// 轮 1：建名单（无引用，不重载）
	if err := mgr.RunUpdate("manual", nil); err != nil {
		t.Fatalf("run1: %v", err)
	}
	if reloads != 0 {
		t.Fatalf("run1 不应重载: %d", reloads)
	}
	seedThreatPolicyRefForSource(t, 900, "ustc")
	// 轮 2：内容变化 + 引用 → 重载#1 失败
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("192.0.2.99\n"))
	}))
	t.Cleanup(srv.Close)
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET url=? WHERE name='ustc'`, srv.URL); err != nil {
		t.Fatal(err)
	}
	if err := mgr.RunUpdate("manual", nil); err != nil {
		t.Fatalf("run2: %v", err)
	}
	if reloads != 1 {
		t.Fatalf("run2 应尝试重载一次: %d", reloads)
	}
	// 轮 3：内容未变——失败自愈：必须强制重载（#2 成功）
	failReload = false
	if err := mgr.RunUpdate("manual", nil); err != nil {
		t.Fatalf("run3: %v", err)
	}
	if reloads != 2 {
		t.Fatalf("run3 应自愈重试重载: %d", reloads)
	}
	// 轮 4：pending 已清——内容未变不再重载
	if err := mgr.RunUpdate("manual", nil); err != nil {
		t.Fatalf("run4: %v", err)
	}
	if reloads != 2 {
		t.Fatalf("run4 不应重载: %d", reloads)
	}
}

// 第 59 轮 R59-P3（U6-1）：run() 起点 is_master 复查（R54-N5 家族收敛——
// crsupdate/ip2regionupdate 均有，威胁库为漏点）：tick 守卫与任务发出之间的
// demote 竞态窗口内，从节点继续执行会写 security_ip_lists 并触发重载，
// 打破从节点只读不变量。
func TestThreatUpdate_runRejectedOnSlave(t *testing.T) {
	overrideWafDirForTest(t)
	newClusterTestService(t)
	setupThreatTest(t, nil, nil, nil)
	if _, err := db.DB.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if err := GetThreatUpdateManager().RunUpdate("manual", nil); err != nil {
		t.Fatalf("从节点 RunUpdate 应静默返回而非报错: %v", err)
	}
	// 从节点不得写内置名单内容（种子行恒存在——断言条目仍为空、源状态未被改写）
	rows, err := db.DB.Query(`SELECT entries FROM security_ip_lists WHERE system=1`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var entries string
		if err := rows.Scan(&entries); err != nil {
			t.Fatal(err)
		}
		if entries != "[]" {
			t.Fatalf("从节点不得写入内置名单条目: entries=%s", entries)
		}
	}
	var touched int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_threat_sources WHERE last_checked IS NOT NULL`).Scan(&touched); err != nil {
		t.Fatal(err)
	}
	if touched != 0 {
		t.Fatalf("从节点不得改写源状态: touched=%d", touched)
	}
}

// F-L1-68-01（第 68 轮，P4）：RunUpdate 恒返 nil——源失败仅内部落行，引擎
// task_runs 把失败轮记成 success（终态失真）。修复：失败终态回传
// ErrThreatUpdateFailed（「任一源失败即失败」，与 run 内 anyFailed/
// failSourceRow 口径对齐）；skipped/cancelled 各有终态通道，不算失败。
func TestThreatRunUpdate_returnsErrorOnSourceFailure(t *testing.T) {
	overrideWafDirForTest(t)
	newClusterTestService(t)
	setupThreatTest(t, nil, map[string]bool{"firehol_l1": true}, nil)

	err := GetThreatUpdateManager().RunUpdate("manual", nil)
	if !errors.Is(err, ErrThreatUpdateFailed) {
		t.Fatalf("源失败时 RunUpdate err=%v, want ErrThreatUpdateFailed（引擎据此把 task_runs 记 failed）", err)
	}
	if got := GetThreatUpdateManager().StatusSnapshot().Outcome; got != "failed" {
		t.Fatalf("outcome=%q, want failed", got)
	}
	// 行级语义回归：失败源落 failed+message+consecutive_failures+1，健康源不受影响
	if status, _, message, _, failures := readThreatRow(t, "firehol_l1"); status != "failed" || message == "" || failures != 1 {
		t.Fatalf("失败源行=(%s,%q,fail=%d), want (failed,非空 message,1)", status, message, failures)
	}
	if status, _, _, _, _ := readThreatRow(t, "ustc"); status != "success" {
		t.Fatalf("健康源应继续成功, got %s", status)
	}
}

// F-L1-68-01 引擎侧契约钉：经 wire Run 体透传——源失败轮 task_runs 必须落
// failed（曾恒 success）。Given 一源必败；When 引擎手动触发 threat；
// Then Trigger 回传 ErrThreatUpdateFailed 且 task_runs 终态 failed。
func TestWireThreatRun_failureLandsTaskRunsFailed(t *testing.T) {
	overrideWafDirForTest(t)
	stubUpdateRetrySleep(t)    // 任务内重试等待即时化（失败源 3 次重试真睡 90s）
	te := newWireTestEngine(t) // 先于 seed——newWireTestEngine 重初始化库
	setupThreatTest(t, nil, map[string]bool{"firehol_l1": true}, nil)
	if err := te.Trigger("threat", "manual", ""); !errors.Is(err, ErrThreatUpdateFailed) {
		t.Fatalf("Trigger err=%v, want ErrThreatUpdateFailed", err)
	}
	var status string
	if err := db.DB.QueryRow(`SELECT status FROM task_runs WHERE task_id='threat' ORDER BY id DESC LIMIT 1`).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "failed" {
		t.Fatalf("task_runs status=%q, want failed（失败轮曾记 success——终态失真）", status)
	}
}

// SEC-C-N3（第 71 轮 P5）：CancelRunning 补 running 门——runCancel 一次运行后
// 不清空，无运行中任务时（running=false）仍返回 true、与注释「无运行中任务
// 返回 false」不符；对齐 CRS/IP2Region 同形（cancel!=nil && running）。
func TestThreatCancelRunning_falseWhenIdleAfterRun(t *testing.T) {
	overrideWafDirForTest(t)
	newClusterTestService(t)
	setupThreatTest(t, nil, nil, nil)

	m := GetThreatUpdateManager()
	if err := m.RunUpdate("manual", nil); err != nil {
		t.Fatalf("run update: %v", err)
	}
	// 运行已结束：CancelRunning 必须返回 false（无运行中任务）
	if m.CancelRunning() {
		t.Fatal("CancelRunning()=true after run finished, want false（runCancel 残留致 idle 返 true）")
	}
}

// R71-⑪（第 71 轮主审补漏）：threatListsReferencedByEnabledPolicy 的引用查询
// 迭代失败（rows.Err）须按「被引用」处理（fail-closed）——与查询失败/解析
// 失败同口径；漏查会跳过名单重载，引用该名单的启用策略渲染不收敛。
type refsFailingConnector struct{}

func (refsFailingConnector) Connect(context.Context) (driver.Conn, error) {
	return refsFailingConn{}, nil
}

func (refsFailingConnector) Driver() driver.Driver { return refsFailingDriver{} }

type refsFailingDriver struct{}

func (refsFailingDriver) Open(string) (driver.Conn, error) { return refsFailingConn{}, nil }

type refsFailingConn struct{}

func (refsFailingConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}

func (refsFailingConn) Close() error { return nil }

func (refsFailingConn) Begin() (driver.Tx, error) { return nil, errors.New("no tx") }

func (refsFailingConn) QueryContext(_ context.Context, _ string, _ []driver.NamedValue) (driver.Rows, error) {
	// 语句执行成功、迭代第一步即失败——只有检查 rows.Err() 才能被发现
	return refsFailingRows{}, nil
}

type refsFailingRows struct{}

func (refsFailingRows) Columns() []string { return []string{"ip_acl_list_refs", "ip_whitelist_refs"} }

func (refsFailingRows) Close() error { return nil }

func (refsFailingRows) Next([]driver.Value) error { return errors.New("注入的引用迭代失败") }

func TestThreatListsReferenced_iterationErrorTreatedAsReferenced(t *testing.T) {
	overrideWafDirForTest(t)
	newClusterTestService(t)
	broken := sql.OpenDB(refsFailingConnector{})
	t.Cleanup(func() { _ = broken.Close() })
	orig := db.DB
	db.DB = broken
	t.Cleanup(func() { db.DB = orig })

	if !threatListsReferencedByEnabledPolicy([]int{424242}) {
		t.Fatal("迭代错误须按被引用处理（true）——与查询失败/解析失败同口径（fail-closed）")
	}
}
