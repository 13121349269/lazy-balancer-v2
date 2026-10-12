package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// 受信代理网段引用 IP 地址列表（trusted_proxy_range_refs，2026-10-12）：
// 保存侧四道关卡——引用存在、总 CIDR ≤2000（内联+展开）、引用名单条目
// 格式合法、round-trip 回读；删除守卫——被引用名单 400 拒绝删除。

func newTrustedProxyRefsRouter(t *testing.T) *gin.Engine {
	t.Helper()
	handler := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/config", handler.UpdateConfig)
	router.GET("/config", handler.GetConfig)
	router.POST("/config/preview", handler.PreviewConfigUpdate)
	router.DELETE("/security/ip-lists/:id", handler.DeleteIPList)
	router.POST("/security/ip-lists", handler.CreateIPList)
	return router
}

func putConfig(t *testing.T, router *gin.Engine, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPut, "/config", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

// seedTrustedRefList 直插一条自定义名单（绕过条目数/形状门，供超限与
// 非法条目形状测试使用），返回 id。
func seedTrustedRefList(t *testing.T, name, entriesJSON string) int64 {
	t.Helper()
	res, err := db.DB.Exec(`INSERT INTO security_ip_lists (name, entries) VALUES (?, ?)`, name, entriesJSON)
	if err != nil {
		t.Fatalf("seed ip list %s: %v", name, err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestUpdateConfig_trustedProxyRefs_roundtrip(t *testing.T) {
	router := newTrustedProxyRefsRouter(t)
	listID := seedTrustedRefList(t, "cdn-ref-list", `[{"value":"198.51.100.0/24","remark":""}]`)

	body := fmt.Sprintf(`{"source":"caddy","trusted_proxy_enabled":true,"trusted_proxy_ranges":"[\"203.0.113.0/24\"]","trusted_proxy_range_refs":"[%d]"}`, listID)
	if rec := putConfig(t, router, body); rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}

	getReq := httptest.NewRequest(http.MethodGet, "/config", nil)
	getResp := httptest.NewRecorder()
	router.ServeHTTP(getResp, getReq)
	if getResp.Code != http.StatusOK {
		t.Fatalf("get status=%d", getResp.Code)
	}
	var payload struct {
		Data struct {
			TrustedProxyRangeRefs string `json:"trusted_proxy_range_refs"`
		} `json:"data"`
	}
	if err := json.Unmarshal(getResp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if payload.Data.TrustedProxyRangeRefs != fmt.Sprintf("[%d]", listID) {
		t.Fatalf("trusted_proxy_range_refs=%q, want [%d]", payload.Data.TrustedProxyRangeRefs, listID)
	}
}

func TestUpdateConfig_trustedProxyRefs_rejectsMissingList(t *testing.T) {
	router := newTrustedProxyRefsRouter(t)
	body := `{"source":"caddy","trusted_proxy_ranges":"[]","trusted_proxy_range_refs":"[424242]"}`
	if rec := putConfig(t, router, body); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "不存在") {
		t.Fatalf("missing ref must 400 with 不存在, got %d %s", rec.Code, rec.Body.String())
	}
	// 预览端点同校验（未过校验的载荷不得给出变更清单）
	preview := httptest.NewRequest(http.MethodPost, "/config/preview", strings.NewReader(body))
	preview.Header.Set("Content-Type", "application/json")
	previewResp := httptest.NewRecorder()
	router.ServeHTTP(previewResp, preview)
	if previewResp.Code != http.StatusBadRequest {
		t.Fatalf("preview status=%d body=%s, want 400", previewResp.Code, previewResp.Body.String())
	}
}

func TestUpdateConfig_trustedProxyRefs_rejectsOverTotalCap(t *testing.T) {
	router := newTrustedProxyRefsRouter(t)
	// 2001 条有效条目（直插绕过 500 条形状门——总上限门独立于写侧形状门）
	entries := make([]string, 0, 2001)
	for i := range 2001 {
		entries = append(entries, fmt.Sprintf(`{"value":"10.1.%d.%d/24","remark":""}`, i/250, i%250))
	}
	listID := seedTrustedRefList(t, "huge-ref-list", "["+strings.Join(entries, ",")+"]")

	body := fmt.Sprintf(`{"source":"caddy","trusted_proxy_ranges":"[]","trusted_proxy_range_refs":"[%d]"}`, listID)
	if rec := putConfig(t, router, body); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "2000") {
		t.Fatalf("over-cap refs must 400 with 2000 上限, got %d %s", rec.Code, rec.Body.String())
	}
}

func TestUpdateConfig_trustedProxyRefs_rejectsInvalidListEntry(t *testing.T) {
	router := newTrustedProxyRefsRouter(t)
	listID := seedTrustedRefList(t, "bad-entry-list", `[{"value":"not-an-ip","remark":""}]`)

	body := fmt.Sprintf(`{"source":"caddy","trusted_proxy_ranges":"[]","trusted_proxy_range_refs":"[%d]"}`, listID)
	if rec := putConfig(t, router, body); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "无效") {
		t.Fatalf("invalid entry must 400 with 无效, got %d %s", rec.Code, rec.Body.String())
	}
}

// 名单删除被 trusted_proxy_range_refs 引用 → 拒绝删除（参照策略引用守卫）；
// 解除引用后删除恢复 200。
func TestDeleteIPList_blockedByTrustedProxyRefs(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newTrustedProxyRefsRouter(t)
	listID := seedTrustedRefList(t, "trusted-refd", `[{"value":"198.51.100.0/24","remark":""}]`)
	if _, err := db.DB.Exec(`UPDATE global_config SET trusted_proxy_range_refs=? WHERE id=1`, fmt.Sprintf("[%d]", listID)); err != nil {
		t.Fatal(err)
	}

	if rec := deleteRequest(t, router, fmt.Sprintf("/security/ip-lists/%d", listID)); rec.Code != http.StatusConflict {
		t.Fatalf("referenced list delete must 409, got %d %s", rec.Code, rec.Body.String())
	}

	// 解除引用 → 删除放行
	if _, err := db.DB.Exec(`UPDATE global_config SET trusted_proxy_range_refs='[]' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if rec := deleteRequest(t, router, fmt.Sprintf("/security/ip-lists/%d", listID)); rec.Code != http.StatusOK {
		t.Fatalf("unreferenced list delete must 200, got %d %s", rec.Code, rec.Body.String())
	}
}

// 全局配置区 round-trip（2026-10-12）：dumpTable 按列全集导出、Config 区
// PATCH 语义导入——trusted_proxy_range_refs 随备份往返不丢。
func TestConfigBackup_trustedProxyRangeRefsRoundTrip(t *testing.T) {
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO users (id, username, password_hash, role, display_name, is_enabled) VALUES (2, 'backup-admin', 'hash', 'admin', 'Backup Admin', 1) ON CONFLICT(id) DO NOTHING`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`UPDATE global_config SET trusted_proxy_range_refs='[3,7]' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.GET("/config/export", h.ExportConfigBackup)

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/config/export", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("export status=%d body=%s", response.Code, response.Body.String())
	}
	var backup configBackup
	if err := json.Unmarshal(unpackExportBody(t, response.Body.Bytes()), &backup); err != nil {
		t.Fatalf("decode export: %v", err)
	}
	if got, _ := backup.Config["trusted_proxy_range_refs"].(string); got != "[3,7]" {
		t.Fatalf("export config region trusted_proxy_range_refs=%v, want [3,7]", backup.Config["trusted_proxy_range_refs"])
	}

	// 清空后导入同一备份（校验和原样携带）→ 值还原
	if _, err := db.DB.Exec(`UPDATE global_config SET trusted_proxy_range_refs='[]' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	backupJSON, err := json.Marshal(backup)
	if err != nil {
		t.Fatal(err)
	}
	importRouter := gin.New()
	importRouter.POST("/config/import", h.ImportConfigBackup)
	importReq := httptest.NewRequest(http.MethodPost, "/config/import", bytes.NewReader(backupJSON))
	importReq.Header.Set("Content-Type", "application/json")
	importResp := httptest.NewRecorder()
	importRouter.ServeHTTP(importResp, importReq)
	if importResp.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s", importResp.Code, importResp.Body.String())
	}
	var got string
	if err := db.DB.QueryRow(`SELECT COALESCE(trusted_proxy_range_refs,'[]') FROM global_config WHERE id=1`).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != "[3,7]" {
		t.Fatalf("imported trusted_proxy_range_refs=%q, want [3,7]", got)
	}
}
