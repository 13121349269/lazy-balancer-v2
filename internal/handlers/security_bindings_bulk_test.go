package handlers

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
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

func seedPolicyWithType(t *testing.T, id int, name, policyType string) {
	t.Helper()
	if _, err := db.DB.Exec(`INSERT INTO security_policies (id,name,mode,policy_type,enabled) VALUES (?,?,?,?,1)`, id, name, "off", policyType); err != nil {
		t.Fatalf("seed policy %d: %v", id, err)
	}
}

func seedBinding(t *testing.T, caddyID string, policyID int) {
	t.Helper()
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES (?,?)`, caddyID, policyID); err != nil {
		t.Fatalf("seed binding %s→%d: %v", caddyID, policyID, err)
	}
}

// NEW-1(a)：bind 侧 maxBindingsPerRule 门——规则现有绑定数（不含本策略）≥8 时
// 再 bind 新策略 → 400，且不写入、零重载（与单条 bind / batch-bind 端点同源）。
func TestBulkUpdatePolicyBindings_enforcesRuleBindingLimit(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router, loads := newBulkBindingsRouter(t)
	seedHTTPRule(t, "lb_bulk_cap")
	for id := 1; id <= 8; id++ {
		seedPolicyWithType(t, id, fmt.Sprintf("cap-%d", id), "stage3")
		seedBinding(t, "lb_bulk_cap", id)
	}
	seedPolicyWithType(t, 9, "cap-target", "stage3")
	baseline := loads.Load()

	recorder := postJSON(t, router, "/security/policies/9/bindings/bulk", map[string]any{
		"bind":   []string{"lb_bulk_cap"},
		"unbind": []string{},
	})
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400（已达 8 条上限）", recorder.Code, recorder.Body.String())
	}
	assertIDSlice(t, queryBoundPolicyIDs(t, "lb_bulk_cap"), []int{1, 2, 3, 4, 5, 6, 7, 8})
	if n := loads.Load() - baseline; n != 0 {
		t.Fatalf("rejected bulk must not reload caddy, got %d extra loads", n)
	}
}

// NEW-1(b)：bind 侧 stage2 唯一门——本策略为 stage2 且该规则已绑其他 stage2 →
// 400；同规则绑 stage3 策略仍放行（门只针对限流叠加）。
func TestBulkUpdatePolicyBindings_rejectsSecondStage2Binding(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router, _ := newBulkBindingsRouter(t)
	seedHTTPRule(t, "lb_bulk_rl")
	seedPolicyWithType(t, 10, "rl-a", "stage2")
	seedPolicyWithType(t, 11, "rl-b", "stage2")
	seedPolicyWithType(t, 12, "waf-a", "stage3")
	seedBinding(t, "lb_bulk_rl", 10)

	recorder := postJSON(t, router, "/security/policies/11/bindings/bulk", map[string]any{
		"bind":   []string{"lb_bulk_rl"},
		"unbind": []string{},
	})
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("bind second stage2: status=%d body=%s, want 400", recorder.Code, recorder.Body.String())
	}
	assertIDSlice(t, queryBoundPolicyIDs(t, "lb_bulk_rl"), []int{10})

	// 回归：已有 stage2 时绑 stage3 策略照常放行（门不误伤非限流策略）。
	recorder = postJSON(t, router, "/security/policies/12/bindings/bulk", map[string]any{
		"bind":   []string{"lb_bulk_rl"},
		"unbind": []string{},
	})
	if recorder.Code != http.StatusOK {
		t.Fatalf("bind stage3 alongside stage2: status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	assertIDSlice(t, queryBoundPolicyIDs(t, "lb_bulk_rl"), []int{10, 12})
}

// NEW-3：bind/unbind 规则 id 归一（TrimSpace）——带空白 id 按去空白后处理，
// 不得因首尾空白被判「规则不存在」。
func TestBulkUpdatePolicyBindings_trimsRuleIDs(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router, _ := newBulkBindingsRouter(t)
	seedHTTPRule(t, "lb_bulk_trim")
	policy := createMultiPolicy(t, router, "trim-p")

	recorder := postJSON(t, router, fmt.Sprintf("/security/policies/%d/bindings/bulk", policy), map[string]any{
		"bind":   []string{"  lb_bulk_trim  "},
		"unbind": []string{},
	})
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200（id 应去空白后绑定）", recorder.Code, recorder.Body.String())
	}
	assertIDSlice(t, queryBoundPolicyIDs(t, "lb_bulk_trim"), []int{policy})
}

// F2（第 73 轮）：bulk unbind 精确删除本策略绑定，不触碰兄弟绑定——DELETE 若
// 漏掉 AND policy_id=? 会被本用例拦住。
func TestBulkUpdatePolicyBindings_unbindKeepsSiblingBindings(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router, _ := newBulkBindingsRouter(t)
	seedHTTPRule(t, "lb_bulk_sib")
	seedPolicyWithType(t, 20, "sib-a", "stage3")
	seedPolicyWithType(t, 21, "sib-b", "stage3")
	seedBinding(t, "lb_bulk_sib", 20)
	seedBinding(t, "lb_bulk_sib", 21)

	recorder := postJSON(t, router, "/security/policies/20/bindings/bulk", map[string]any{
		"bind":   []string{},
		"unbind": []string{"lb_bulk_sib"},
	})
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	assertIDSlice(t, queryBoundPolicyIDs(t, "lb_bulk_sib"), []int{21})
}

// F3（第 73 轮）：同一规则同时出现在 bind 与 unbind → 400（语义冲突，早于写入）。
func TestBulkUpdatePolicyBindings_rejectsBindUnbindConflict(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router, loads := newBulkBindingsRouter(t)
	seedHTTPRule(t, "lb_bulk_clash")
	seedPolicyWithType(t, 30, "clash-p", "stage3")
	baseline := loads.Load()

	recorder := postJSON(t, router, "/security/policies/30/bindings/bulk", map[string]any{
		"bind":   []string{"lb_bulk_clash"},
		"unbind": []string{"lb_bulk_clash"},
	})
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", recorder.Code, recorder.Body.String())
	}
	assertIDSlice(t, queryBoundPolicyIDs(t, "lb_bulk_clash"), nil)
	if n := loads.Load() - baseline; n != 0 {
		t.Fatalf("conflict must not reload caddy, got %d extra loads", n)
	}
}

// bindingWriteErrConnector：注入绑定写路径的规则查询故障——策略/绑定前置查询
// 成功，规则查询即失败（第 73 轮 NEW-2：DB 错误须映射 500，而非 400 裸串外泄）。
type bindingWriteErrConnector struct{}

func (bindingWriteErrConnector) Connect(context.Context) (driver.Conn, error) {
	return bindingWriteErrConn{}, nil
}

func (bindingWriteErrConnector) Driver() driver.Driver { return bindingWriteErrDriver{} }

type bindingWriteErrDriver struct{}

func (bindingWriteErrDriver) Open(string) (driver.Conn, error) { return bindingWriteErrConn{}, nil }

type bindingWriteErrConn struct{}

func (bindingWriteErrConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}
func (bindingWriteErrConn) Close() error              { return nil }
func (bindingWriteErrConn) Begin() (driver.Tx, error) { return bindingWriteErrTx{}, nil }

func (bindingWriteErrConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	switch {
	case strings.Contains(query, "COALESCE(SUM(policy_type='mixed')"):
		return &bindingWriteErrRows{cols: []string{"c", "m"}, rows: [][]driver.Value{{int64(1), int64(0)}}}, nil
	case strings.Contains(query, "COALESCE(MAX(policy_type)"):
		return &bindingWriteErrRows{cols: []string{"c", "t"}, rows: [][]driver.Value{{int64(1), "stage3"}}}, nil
	case strings.Contains(query, "policy_type='mixed'"):
		return &bindingWriteErrRows{cols: []string{"c"}, rows: [][]driver.Value{{int64(0)}}}, nil
	case strings.Contains(query, "GROUP BY rule_caddy_id"):
		return &bindingWriteErrRows{cols: []string{"r", "c"}}, nil
	case strings.Contains(query, "SELECT COUNT(*), COALESCE(MAX(protocol)"):
		return nil, errors.New("注入的规则查询失败")
	default:
		return nil, fmt.Errorf("unexpected query: %s", query)
	}
}

type bindingWriteErrTx struct{}

func (bindingWriteErrTx) Commit() error   { return nil }
func (bindingWriteErrTx) Rollback() error { return nil }

type bindingWriteErrRows struct {
	cols []string
	rows [][]driver.Value
}

func (r *bindingWriteErrRows) Columns() []string { return r.cols }
func (r *bindingWriteErrRows) Close() error      { return nil }

func (r *bindingWriteErrRows) Next(dest []driver.Value) error {
	if len(r.rows) == 0 {
		return io.EOF
	}
	copy(dest, r.rows[0])
	r.rows = r.rows[1:]
	return nil
}

// NEW-2（bulk applyOne）：规则查询 DB 故障 → 500「读取/写入策略绑定失败」，
// 而非把裸错误串当 400 校验失败外泄。
func TestBulkUpdatePolicyBindings_dbErrorReturns500(t *testing.T) {
	orig := db.DB
	db.DB = sql.OpenDB(bindingWriteErrConnector{})
	t.Cleanup(func() { _ = db.DB.Close(); db.DB = orig })
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/security/policies/:id/bindings/bulk", (&Handlers{}).BulkUpdatePolicyBindings)

	recorder := postJSON(t, router, "/security/policies/7/bindings/bulk", map[string]any{
		"bind":   []string{"lb_x"},
		"unbind": []string{},
	})
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "读取/写入策略绑定失败") {
		t.Fatalf("body=%s, want 读取/写入策略绑定失败", recorder.Body.String())
	}
}

// NEW-2（setRulePoliciesInTx）：规则查询 DB 故障 → 500「读取/写入策略绑定失败」。
func TestSetRuleSecurityPolicies_dbErrorReturns500(t *testing.T) {
	orig := db.DB
	db.DB = sql.OpenDB(bindingWriteErrConnector{})
	t.Cleanup(func() { _ = db.DB.Close(); db.DB = orig })
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/security/rules/:caddy_id/policies", (&Handlers{}).SetRuleSecurityPolicies)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPut, "/security/rules/lb_x/policies", strings.NewReader(`{"policy_ids":[1]}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "读取/写入策略绑定失败") {
		t.Fatalf("body=%s, want 读取/写入策略绑定失败", recorder.Body.String())
	}
}
