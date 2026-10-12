package handlers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/services"
)

// 策略侧批量绑定端点（第 72 轮，用户裁定）：POST /security/policies/:id/bindings/bulk
// {"bind":["lb_a"],"unbind":["lb_c"]}——「策略保存/绑定规则弹框（策略模式）」
// 前端此前逐规则调 bind/unbind 单条端点，每条独立全链渲染+validate+/load
//（N×~500ms，后端配置锁串行化）。本端点单事务内批量增删**本策略**的绑定行，
// 不触碰兄弟绑定（第 48 轮并发安全语义保持：additive/精确删除），全程恰好
// 一次 finishTxApply（单渲染）。任一规则校验失败=400 整体拒绝且事务回滚。

func newBulkBindingsRouter(t *testing.T) (*gin.Engine, *atomic.Int64) {
	t.Helper()
	var loads atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/load" {
			loads.Add(1)
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	gin.SetMode(gin.TestMode)
	h := &Handlers{caddyService: services.NewCaddyService(srv.URL)}
	router := gin.New()
	router.POST("/security/policies", h.CreateSecurityPolicy)
	router.POST("/security/policies/:id/bind", h.BindRuleToPolicy)
	router.POST("/security/policies/:id/bindings/bulk", h.BulkUpdatePolicyBindings)
	return router, &loads
}

// 主形状：bind 两条+unbind 一条一次提交 → 200、绑定终态正确、/load 恰好 1 次
// （单渲染是本端点的存在意义）。
func TestBulkUpdatePolicyBindings_mixedBindUnbindSingleRender(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router, loads := newBulkBindingsRouter(t)
	seedHTTPRule(t, "lb_bulk_a")
	seedHTTPRule(t, "lb_bulk_b")
	seedHTTPRule(t, "lb_bulk_c")
	policy := createMultiPolicy(t, router, "bulk-p1")
	// 预置：c 已绑定本策略（将被 unbind）
	if r := postJSON(t, router, fmt.Sprintf("/security/policies/%d/bind", policy), map[string]any{"rule_caddy_id": "lb_bulk_c"}); r.Code != http.StatusOK {
		t.Fatalf("preset bind: status=%d", r.Code)
	}
	baseline := loads.Load()

	body := map[string]any{"bind": []string{"lb_bulk_a", "lb_bulk_b"}, "unbind": []string{"lb_bulk_c"}}
	recorder := postJSON(t, router, fmt.Sprintf("/security/policies/%d/bindings/bulk", policy), body)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	assertIDSlice(t, queryBoundPolicyIDs(t, "lb_bulk_a"), []int{policy})
	assertIDSlice(t, queryBoundPolicyIDs(t, "lb_bulk_b"), []int{policy})
	assertIDSlice(t, queryBoundPolicyIDs(t, "lb_bulk_c"), nil)
	if n := loads.Load() - baseline; n != 1 {
		t.Fatalf("caddy /load delta=%d, want exactly 1 (single render)", n)
	}
}

// 原子性：任一规则不存在 → 400 整体拒绝，合法部分的绑定不得写入，零重载。
func TestBulkUpdatePolicyBindings_atomicRejectOnMissingRule(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router, loads := newBulkBindingsRouter(t)
	seedHTTPRule(t, "lb_bulk_d")
	policy := createMultiPolicy(t, router, "bulk-atomic")
	baseline := loads.Load()

	recorder := postJSON(t, router, fmt.Sprintf("/security/policies/%d/bindings/bulk", policy), map[string]any{
		"bind":   []string{"lb_bulk_d", "lb_missing"},
		"unbind": []string{},
	})
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", recorder.Code, recorder.Body.String())
	}
	assertIDSlice(t, queryBoundPolicyIDs(t, "lb_bulk_d"), nil)
	if n := loads.Load() - baseline; n != 0 {
		t.Fatalf("rejected bulk must not reload caddy, got %d extra loads", n)
	}
}

// TCP 规则 → 400 整体拒绝（与单条端点同口径）。
func TestBulkUpdatePolicyBindings_rejectsTCPRule(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router, _ := newBulkBindingsRouter(t)
	seedHTTPRule(t, "lb_bulk_e")
	seedTCPRule(t, "lb_bulk_tcp")
	policy := createMultiPolicy(t, router, "bulk-tcp")

	recorder := postJSON(t, router, fmt.Sprintf("/security/policies/%d/bindings/bulk", policy), map[string]any{
		"bind":   []string{"lb_bulk_tcp"},
		"unbind": []string{},
	})
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", recorder.Code)
	}
	assertIDSlice(t, queryBoundPolicyIDs(t, "lb_bulk_e"), nil)
}

// 幂等：bind 已绑定/unbind 未绑定的规则 → 200（INSERT OR IGNORE/DELETE 0 行）。
func TestBulkUpdatePolicyBindings_idempotent(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router, _ := newBulkBindingsRouter(t)
	seedHTTPRule(t, "lb_bulk_f")
	policy := createMultiPolicy(t, router, "bulk-idem")
	if r := postJSON(t, router, fmt.Sprintf("/security/policies/%d/bind", policy), map[string]any{"rule_caddy_id": "lb_bulk_f"}); r.Code != http.StatusOK {
		t.Fatalf("preset bind: status=%d", r.Code)
	}

	recorder := postJSON(t, router, fmt.Sprintf("/security/policies/%d/bindings/bulk", policy), map[string]any{
		"bind":   []string{"lb_bulk_f"},
		"unbind": []string{"lb_nope"},
	})
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200（幂等重放不得报错）", recorder.Code, recorder.Body.String())
	}
	assertIDSlice(t, queryBoundPolicyIDs(t, "lb_bulk_f"), []int{policy})
}

// 规模上限：bind+unbind 合计 >100 → 400。
func TestBulkUpdatePolicyBindings_enforcesSizeLimit(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router, _ := newBulkBindingsRouter(t)
	policy := createMultiPolicy(t, router, "bulk-limit")
	bind := make([]string, 0, 101)
	for i := range 101 {
		bind = append(bind, fmt.Sprintf("lb_bulk_x%d", i))
	}
	recorder := postJSON(t, router, fmt.Sprintf("/security/policies/%d/bindings/bulk", policy), map[string]any{
		"bind":   bind,
		"unbind": []string{},
	})
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("101 entries: status=%d, want 400", recorder.Code)
	}
}
