package handlers

// LBS-A-L1（第 69 轮 P1）：HTTP 规则混合 http/https 上游池在 Caddy 无逐上游
// 协议概念（shouldUseTLS 传输级+except_ports 例外表，v2.11.6 httptransport.go:
// 674-680）——任一 https 上游使池级 TLS 传输生效，http 上游明文打 TLS 端口
// 静默全灭 502。保存/导入侧显式拒绝混布（用户裁定修法①）。

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

func TestRulePayload_rejectsMixedHttpHttpsUpstreamPool(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules", handler.CreateRule)

	cases := []struct {
		name      string
		upstreams string
		wantCode  int
	}{
		{"混合 http+https 拒绝", `[{"host":"10.0.0.1","port":8080,"protocol":"http","enabled":true},{"host":"10.0.0.2","port":8443,"protocol":"https","enabled":true}]`, http.StatusBadRequest},
		{"纯 http 池放行（回归）", `[{"host":"10.0.0.1","port":8080,"protocol":"http","enabled":true},{"host":"10.0.0.2","port":8081,"protocol":"http","enabled":true}]`, http.StatusCreated},
		{"纯 https 池放行（回归）", `[{"host":"10.0.0.1","port":8443,"protocol":"https","enabled":true},{"host":"10.0.0.2","port":8444,"protocol":"https","enabled":true}]`, http.StatusCreated},
		{"单 https 上游放行（回归）", `[{"host":"10.0.0.1","port":8443,"protocol":"https","enabled":true}]`, http.StatusCreated},
		{"混合但 https 上游禁用放行（禁用不参与渲染）", `[{"host":"10.0.0.1","port":8080,"protocol":"http","enabled":true},{"host":"10.0.0.2","port":8443,"protocol":"https","enabled":false}]`, http.StatusCreated},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := fmt.Sprintf(`{"name":"mixpool-%d","protocol":"http","domain":"mix-%d.test","listen_port":%d,"upstreams":%s}`,
				i, i, 19300+i, tc.upstreams)
			req := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != tc.wantCode {
				t.Fatalf("status=%d, want %d; body=%s", rec.Code, tc.wantCode, rec.Body.String())
			}
			if tc.wantCode == http.StatusBadRequest && !strings.Contains(rec.Body.String(), "协议") {
				t.Fatalf("body must mention 协议, got %s", rec.Body.String())
			}
		})
	}
}

// 备份侧同门（R62 C3-F2 同位）：手造备份带混布池须 400。
func TestValidateBackupRuleReferences_rejectsMixedHttpHttpsPool(t *testing.T) {
	tables := map[string][]map[string]any{
		"lb_rules": {{"caddy_id": "lb_mixbak", "protocol": "http"}},
		"upstreams": {
			{"rule_id": "lb_mixbak", "protocol": "http", "enabled": true},
			{"rule_id": "lb_mixbak", "protocol": "https", "enabled": true},
		},
	}
	err := validateBackupRuleReferences(tables)
	if err == nil || !strings.Contains(err.Error(), "混布") && !strings.Contains(err.Error(), "混合") {
		t.Fatalf("mixed pool backup must be rejected, got %v", err)
	}
}

// 同族（路径规则自定义上游池，R-12 收敛面）：路径级自定义上游混布同样拒绝。
func TestRulePayload_rejectsMixedPathRuleUpstreamPool(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules", handler.CreateRule)

	body := `{"name":"mixpath","protocol":"http","domain":"mixpath.test","listen_port":19320,"custom_routes_enabled":true,` +
		`"upstreams":[{"host":"10.0.0.1","port":9000,"enabled":true}],` +
		`"path_rules":[{"sort_order":0,"match_type":"prefix","path":"/api/","upstreams":[` +
		`{"address":"10.0.0.1","port":8080,"protocol":"http"},{"address":"10.0.0.2","port":8443,"protocol":"https"}]}]}`
	req := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "混布") {
		t.Fatalf("path-rule mixed pool must 400, got %d %s", rec.Code, rec.Body.String())
	}
}

// LBH-A-1（第 70 轮 P2）：混布门收敛三链——存量混布行（69 轮修复前落库/
// 直改 DB）不得经启用/复制静默投入运行，启动聚合校验须点名告警。保存门与
// v2 导入链已拦新数据（上方两测试）；此前启用链/聚合校验/复制链零检查。

func seedMixedStoredRule(t *testing.T, id string, enabled bool) {
	t.Helper()
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,health_check_path,enabled,enable_compress,tls_source,enable_tls)
		VALUES (?,?,'','http','mixed.example.test',19400,'weighted_round_robin','',?,1,'manual',0)`, id, id, enabled); err != nil {
		t.Fatalf("seed mixed rule %s: %v", id, err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES
		(?,'10.0.0.1',8080,1,1,'http'),(?,'10.0.0.2',8443,1,1,'https')`, id, id); err != nil {
		t.Fatalf("seed mixed upstreams %s: %v", id, err)
	}
}

// 链①：EnableRule 对存量混布行 400（与保存门同款文案），规则保持禁用。
func TestEnableRule_rejectsMixedHttpHttpsStoredPool(t *testing.T) {
	handler, _, _ := newAuditRuleHandlers(t, 0)
	seedMixedStoredRule(t, "lb_mix_enable", false)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules/:caddy_id/enable", handler.EnableRule)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/rules/lb_mix_enable/enable", nil))

	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "混布") {
		t.Fatalf("enable status=%d body=%s, want 400 点名混布", rec.Code, rec.Body.String())
	}
	var enabled bool
	if err := db.DB.QueryRow("SELECT enabled FROM lb_rules WHERE caddy_id='lb_mix_enable'").Scan(&enabled); err != nil {
		t.Fatalf("read enabled state: %v", err)
	}
	if enabled {
		t.Fatal("被拒规则不得进入启用态")
	}
}

// 链③：DuplicateRule 复制存量混布源行 400，无副本落库（保存门只拦新建/
// 更新载荷，复制是对存量行的旁路放大通道）。
func TestDuplicateRule_rejectsMixedHttpHttpsSourcePool(t *testing.T) {
	handler, _, _ := newAuditRuleHandlers(t, 0)
	seedMixedStoredRule(t, "lb_mix_dup", true)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules/:caddy_id/duplicate", handler.DuplicateRule)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/rules/lb_mix_dup/duplicate", nil))

	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "混布") {
		t.Fatalf("duplicate status=%d body=%s, want 400 点名混布", rec.Code, rec.Body.String())
	}
	var copies int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM lb_rules WHERE name LIKE '%（副本）'`).Scan(&copies); err != nil {
		t.Fatalf("count copies: %v", err)
	}
	if copies != 0 {
		t.Fatalf("被拒复制不得落库, copies=%d", copies)
	}
}

// 链②：启动/UpdateConfig 聚合校验对启用混布行点名 warn（镜像 portTLSMix
// 形态——不阻断启动），而非静默通过。
func TestValidateEnabledStoredRuleConfigs_warnsMixedPoolWithoutBlocking(t *testing.T) {
	newAuditRuleHandlers(t, 0)
	seedMixedStoredRule(t, "lb_mix_agg", true)

	var logs strings.Builder
	oldWriter := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(oldWriter) })

	if err := validateEnabledStoredRuleConfigs(context.Background()); err != nil {
		t.Fatalf("混布是告警不是阻断（存量行不拦启动）: %v", err)
	}
	out := logs.String()
	if !strings.Contains(out, "lb_mix_agg") || !strings.Contains(out, "混布") {
		t.Fatalf("聚合校验未点名混布规则（warn）: %q", out)
	}
}
