package services

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"lazy-balancer-v2/internal/models"
)

func TestCAProviderQueries_returns_credentials(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	credentials := `{"eab_kid":"kid","eab_hmac_key":"secret"}`
	result, err := database.Exec(`INSERT INTO ca_providers (name,provider,directory_url,credentials,max_concurrent,min_interval_ms,enabled) VALUES ('private','zerossl',?,?,1,1000,1)`, ZeroSSLDirectoryURL, credentials)
	if err != nil {
		t.Fatalf("seed CA provider: %v", err)
	}
	providerID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read CA provider ID: %v", err)
	}

	// When
	listed, err := NewCAProviderService().ListCAProviders()
	if err != nil {
		t.Fatalf("list CA providers: %v", err)
	}
	loaded, err := loadCAProvider(int(providerID))
	if err != nil {
		t.Fatalf("load CA provider for business use: %v", err)
	}

	// Then: both list and business load return actual credentials
	var listedCredentials string
	for _, provider := range listed {
		if provider.ID == int(providerID) {
			listedCredentials = provider.Credentials
			break
		}
	}
	if !strings.Contains(listedCredentials, "secret") {
		t.Fatalf("listed credentials=%q, want actual HMAC key", listedCredentials)
	}
	if loaded.Credentials != credentials {
		t.Fatalf("business credentials=%q, want actual credentials", loaded.Credentials)
	}
}

func TestCAProviderService_TestCAProviderWithContext_honors_parent_cancellation(t *testing.T) {
	// 自有 DB 隔离（U4b-01）：不得隐式依赖前置测试泄漏的 db.DB 全局。
	newClusterTestService(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := NewCAProviderService().TestCAProviderWithContext(ctx, 1)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("test provider error=%v, want context canceled", err)
	}
}

func TestCAProviderService_TestCAProviderWithContext_cancels_while_query_waits(t *testing.T) {
	_, database := newClusterTestService(t)
	database.SetMaxOpenConns(1)
	connection, err := database.Conn(context.Background())
	if err != nil {
		t.Fatalf("hold database connection: %v", err)
	}
	defer connection.Close()

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- NewCAProviderService().TestCAProviderWithContext(ctx, 1)
	}()
	for database.Stats().WaitCount == 0 {
		runtime.Gosched()
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("test provider error=%v, want context canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("provider query did not stop after context cancellation")
	}
}

func TestCAProviderService_TestCAProviderWithContext_bounds_EAB_auto_provision_with_deadline(t *testing.T) {
	_, database := newClusterTestService(t)
	result, err := database.Exec(`INSERT INTO ca_providers (name,provider,directory_url,credentials,max_concurrent,min_interval_ms,enabled) VALUES ('eab','zerossl',?,'',1,1000,1)`, ZeroSSLDirectoryURL)
	if err != nil {
		t.Fatalf("seed CA provider: %v", err)
	}
	providerID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read CA provider ID: %v", err)
	}
	if _, err := database.Exec("UPDATE global_config SET acme_email='admin@example.test' WHERE id=1"); err != nil {
		t.Fatalf("seed acme email: %v", err)
	}

	// N+13 H3-S：伪 ZeroSSL EAB 端点延迟响应，晚于注入的 100ms 时限。父 ctx
	// 为 Background（永不取消），服务端不自败——若 EAB 自动获取未被独立超时
	// 包裹（原实现仅 RegisterAccount 有 10s 界），本调用将阻塞至 30s HTTP
	// 客户端兜底；唯一可能的快速取消源即子超时。
	oldTimeout := zerosslEABProvisionTimeout
	zerosslEABProvisionTimeout = 100 * time.Millisecond
	t.Cleanup(func() { zerosslEABProvisionTimeout = oldTimeout })
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"success":false,"error":"fixture"}`))
	}))
	defer server.Close()
	oldURL := zerosslEABURL
	zerosslEABURL = server.URL
	t.Cleanup(func() { zerosslEABURL = oldURL })

	done := make(chan error, 1)
	go func() {
		done <- NewCAProviderService().TestCAProviderWithContext(context.Background(), int(providerID))
	}()
	select {
	case err := <-done:
		var testErr *CAProviderTestError
		if !errors.As(err, &testErr) || testErr.Phase != "config" {
			t.Fatalf("test provider error=%v, want CAProviderTestError phase=config", err)
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("test provider error=%v, want context.DeadlineExceeded from the EAB bound", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("EAB auto-provision hung — test path is unbounded without its own timeout")
	}
}

func TestAutoProvisionZeroSSLEAB_email_is_url_encoded(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	if _, err := database.Exec("UPDATE global_config SET acme_email='user+tag@example.com' WHERE id=1"); err != nil {
		t.Fatalf("seed acme email: %v", err)
	}
	var gotForm string
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		gotForm = string(body)
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(map[string]any{"success": true, "eab_kid": "fetched-kid", "eab_hmac_key": "fetched-secret"})
	}))
	defer server.Close()
	defer overrideZeroSSLEABURL(server.URL)()
	result, err := database.Exec(`INSERT INTO ca_providers (name,provider,directory_url,credentials,max_concurrent,min_interval_ms,enabled) VALUES ('eab','zerossl',?,'',1,1000,1)`, ZeroSSLDirectoryURL)
	if err != nil {
		t.Fatalf("seed CA provider: %v", err)
	}
	providerID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read CA provider ID: %v", err)
	}
	provider := models.CAProvider{ID: int(providerID), Provider: ProviderZeroSSL, Credentials: ""}

	// When
	if err := AutoProvisionZeroSSLEAB(context.Background(), &provider); err != nil {
		t.Fatalf("auto provision EAB: %v", err)
	}

	// Then：'+' 与 '@' 必须转义，不能以裸 '+' 上送（会被解析成空格）
	if want := "email=" + url.QueryEscape("user+tag@example.com"); gotForm != want {
		t.Fatalf("request body=%q, want %q", gotForm, want)
	}
	if !strings.Contains(provider.Credentials, "fetched-kid") {
		t.Fatalf("provider credentials=%q, want fetched EAB", provider.Credentials)
	}
}

func TestAutoProvisionZeroSSLEAB_cas_loses_memory_follows_db(t *testing.T) {
	// Given：并发 worker 已把另一份 EAB 写入 DB，本调用内存中的 credentials 仍是旧的空值
	_, database := newClusterTestService(t)
	if _, err := database.Exec("UPDATE global_config SET acme_email='user@example.com' WHERE id=1"); err != nil {
		t.Fatalf("seed acme email: %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(map[string]any{"success": true, "eab_kid": "fetched-kid", "eab_hmac_key": "fetched-secret"})
	}))
	defer server.Close()
	defer overrideZeroSSLEABURL(server.URL)()
	const concurrentCredentials = `{"eab_kid":"db-kid","eab_hmac_key":"db-secret"}`
	result, err := database.Exec(`INSERT INTO ca_providers (name,provider,directory_url,credentials,max_concurrent,min_interval_ms,enabled) VALUES ('eab','zerossl',?,?,1,1000,1)`, ZeroSSLDirectoryURL, concurrentCredentials)
	if err != nil {
		t.Fatalf("seed CA provider: %v", err)
	}
	providerID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read CA provider ID: %v", err)
	}
	provider := models.CAProvider{ID: int(providerID), Provider: ProviderZeroSSL, Credentials: ""}

	// When
	if err := AutoProvisionZeroSSLEAB(context.Background(), &provider); err != nil {
		t.Fatalf("auto provision EAB: %v", err)
	}

	// Then：CAS 未命中时内存必须回读 DB 实际值，而不是持有未持久化的新值
	if provider.Credentials != concurrentCredentials {
		t.Fatalf("memory credentials=%q, want DB value %q", provider.Credentials, concurrentCredentials)
	}
	var stored string
	if err := database.QueryRow("SELECT COALESCE(credentials,'') FROM ca_providers WHERE id=?", providerID).Scan(&stored); err != nil {
		t.Fatalf("read stored credentials: %v", err)
	}
	if stored != concurrentCredentials {
		t.Fatalf("DB credentials=%q, want unchanged %q", stored, concurrentCredentials)
	}
}

func overrideZeroSSLEABURL(serverURL string) func() {
	original := zerosslEABURL
	zerosslEABURL = serverURL
	return func() { zerosslEABURL = original }
}

func TestCAProviderService_UpdateCAProvider_rejects_disabling_last_enabled(t *testing.T) {
	_, database := newClusterTestService(t)
	if _, err := database.Exec("DELETE FROM ca_providers"); err != nil {
		t.Fatalf("clear CA providers: %v", err)
	}
	result, err := database.Exec(`INSERT INTO ca_providers (name,provider,directory_url,credentials,max_concurrent,min_interval_ms,enabled) VALUES ('only','letsencrypt',?,'',1,1000,1)`, LetsEncryptDirectoryURL)
	if err != nil {
		t.Fatalf("seed CA provider: %v", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read CA provider ID: %v", err)
	}
	disabled := false

	_, err = NewCAProviderService().UpdateCAProvider(int(id), models.UpdateCAProviderRequest{Enabled: &disabled})
	if !errors.Is(err, ErrCAProviderLastEnabled) {
		t.Fatalf("disable last provider error=%v, want %v", err, ErrCAProviderLastEnabled)
	}
	var enabled bool
	if err := database.QueryRow("SELECT enabled FROM ca_providers WHERE id=?", id).Scan(&enabled); err != nil {
		t.Fatalf("read CA provider after rollback: %v", err)
	}
	if !enabled {
		t.Fatal("last CA provider was disabled despite rollback")
	}
}

// CERT-N2（第 72 轮）：LE 凭证纯空白（如 "  "）通过空判定后原样落库，
// 前端 parseCACredentials 对非空串走 JSON.parse 即抛错——归一为空串落库
// （parseCACredentials 对空串走 falsy 分支）。
func TestCAProviderService_UpdateCAProvider_normalizes_letsencrypt_whitespace_credentials(t *testing.T) {
	// Given：凭证为空的 LE 提供商
	_, database := newClusterTestService(t)
	if _, err := database.Exec("DELETE FROM ca_providers"); err != nil {
		t.Fatalf("clear CA providers: %v", err)
	}
	result, err := database.Exec(`INSERT INTO ca_providers (name,provider,directory_url,credentials,max_concurrent,min_interval_ms,enabled) VALUES ('le-ws','letsencrypt',?,'',1,1000,1)`, LetsEncryptDirectoryURL)
	if err != nil {
		t.Fatalf("seed CA provider: %v", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read CA provider ID: %v", err)
	}
	whitespace := "   "

	// When：把凭证更新为纯空白
	if _, err := NewCAProviderService().UpdateCAProvider(int(id), models.UpdateCAProviderRequest{Credentials: &whitespace}); err != nil {
		t.Fatalf("update LE credentials with whitespace: %v", err)
	}

	// Then：落库为空串
	var stored string
	if err := database.QueryRow("SELECT COALESCE(credentials,'') FROM ca_providers WHERE id=?", id).Scan(&stored); err != nil {
		t.Fatalf("read stored credentials: %v", err)
	}
	if stored != "" {
		t.Fatalf("stored credentials=%q, want 空串（前端 parseCACredentials 可消费）", stored)
	}
	// 回归形状 1：LE 带实际凭证仍拒绝（语义不变，仅空白归一）。
	nonEmpty := `{"eab_kid":"k"}`
	if _, err := NewCAProviderService().UpdateCAProvider(int(id), models.UpdateCAProviderRequest{Credentials: &nonEmpty}); !errors.Is(err, ErrCAProviderLetsEncryptCredentialsNotEmpty) {
		t.Fatalf("LE non-empty credentials error=%v, want %v", err, ErrCAProviderLetsEncryptCredentialsNotEmpty)
	}
	// 回归形状 2：非 LE（ZeroSSL）空白凭证仍走 JSON 门拒绝——归一只适用于 LE。
	result, err = database.Exec(`INSERT INTO ca_providers (name,provider,directory_url,credentials,max_concurrent,min_interval_ms,enabled) VALUES ('zs-ws','zerossl',?,'',1,1000,1)`, ZeroSSLDirectoryURL)
	if err != nil {
		t.Fatalf("seed ZeroSSL provider: %v", err)
	}
	zsID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read ZeroSSL provider ID: %v", err)
	}
	if _, err := NewCAProviderService().UpdateCAProvider(int(zsID), models.UpdateCAProviderRequest{Credentials: &whitespace}); !errors.Is(err, ErrCAProviderInvalidCredentials) {
		t.Fatalf("ZeroSSL whitespace credentials error=%v, want %v", err, ErrCAProviderInvalidCredentials)
	}
}

// CERT-N1（第 72 轮）：UpdateCAProvider 返回事务内读到的旧行——handler 审计
// changed 清单的比对基线不再依赖事务外预读（预读与事务提交之间的并发写入
// 会让清单基于陈旧旧值，漏记/多记变更字段）。
func TestCAProviderService_UpdateCAProvider_returns_in_transaction_old_row(t *testing.T) {
	// Given：两个启用的 ZeroSSL 提供商，target 保有非默认凭证与限流参数
	_, database := newClusterTestService(t)
	if _, err := database.Exec("DELETE FROM ca_providers"); err != nil {
		t.Fatalf("clear CA providers: %v", err)
	}
	result, err := database.Exec(`INSERT INTO ca_providers (name,provider,directory_url,credentials,max_concurrent,min_interval_ms,enabled) VALUES ('target','zerossl',?,'{"eab_kid":"k"}',3,2000,1)`, ZeroSSLDirectoryURL)
	if err != nil {
		t.Fatalf("seed target provider: %v", err)
	}
	targetID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read target id: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO ca_providers (name,provider,directory_url,credentials,max_concurrent,min_interval_ms,enabled) VALUES ('other','zerossl',?,'',1,1000,1)`, ZeroSSLDirectoryURL); err != nil {
		t.Fatalf("seed other provider: %v", err)
	}
	newName := "renamed"
	disabled := false

	// When：改名称+禁用（other 仍启用，last-enabled 守卫放行）
	old, err := NewCAProviderService().UpdateCAProvider(int(targetID), models.UpdateCAProviderRequest{Name: &newName, Enabled: &disabled})
	if err != nil {
		t.Fatalf("update provider: %v", err)
	}

	// Then：返回行是事务内的旧值，DB 已是新值
	if old.ID != int(targetID) || old.Name != "target" || !old.Enabled || old.Credentials != `{"eab_kid":"k"}` || old.MaxConcurrent != 3 || old.MinIntervalMS != 2000 {
		t.Fatalf("returned old row = %+v, want pre-update in-transaction row", old)
	}
	var name string
	var enabled bool
	if err := database.QueryRow("SELECT name, enabled FROM ca_providers WHERE id=?", targetID).Scan(&name, &enabled); err != nil {
		t.Fatalf("read provider after update: %v", err)
	}
	if name != "renamed" || enabled {
		t.Fatalf("db state name=%q enabled=%v, want renamed/disabled", name, enabled)
	}
}

func TestMaskEmail_multibyteLocalPartStaysValidUTF8(t *testing.T) {
	// F49-P5-15（第 49 轮审计）：@ 前缀为多字节 UTF-8（如 CJK 邮箱本地部分）
	// 时，按字节截断前两个「字符」会切在 rune 中间产出非法 UTF-8 残片——
	if got := maskEmail("张小三abc@example.com"); got != "张小***@example.com" {
		t.Fatalf("maskEmail(张小三abc@example.com)=%q, want 张小***@example.com（前两个 rune）", got)
	}
	if got := maskEmail("张三@x.cn"); got != "***@x.cn" {
		t.Fatalf("maskEmail(张三@x.cn)=%q, want ***@x.cn（rune 数 <=3 不保留首字符）", got)
	}
	for _, email := range []string{"张小三abc@example.com", "张三@x.cn", "admin@example.com", "ab@x.cn", "a@b.c", "nosign", "@"} {
		if got := maskEmail(email); !utf8.ValidString(got) {
			t.Fatalf("maskEmail(%q)=%q 不是合法 UTF-8", email, got)
		}
	}
}

// CERT-L1（第 69 轮）：「最后一个启用」守卫的语义矩阵钉测试。守卫已收敛为
// 原子条件 UPDATE（WHERE 子查询），逐形状钉住：放行形态/拦截形态/错误优先级/
// 非禁用写不受守卫影响。
func TestCAProviderService_UpdateCAProvider_lastEnabledGuard_matrix(t *testing.T) {
	// Given：两个启用提供商
	_, database := newClusterTestService(t)
	if _, err := database.Exec("DELETE FROM ca_providers"); err != nil {
		t.Fatalf("clear CA providers: %v", err)
	}
	seed := func(name string, enabled bool) int64 {
		result, err := database.Exec(`INSERT INTO ca_providers (name,provider,directory_url,credentials,max_concurrent,min_interval_ms,enabled) VALUES (?,'letsencrypt',?,'',1,1000,?)`, name, LetsEncryptDirectoryURL, enabled)
		if err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
		id, err := result.LastInsertId()
		if err != nil {
			t.Fatalf("read %s id: %v", name, err)
		}
		return id
	}
	idA := seed("provider-a", true)
	idB := seed("provider-b", true)
	enabledFlag := func(value bool) *bool { return &value }
	providerEnabled := func(id int64) bool {
		var enabled bool
		if err := database.QueryRow("SELECT enabled FROM ca_providers WHERE id=?", id).Scan(&enabled); err != nil {
			t.Fatalf("read enabled state: %v", err)
		}
		return enabled
	}
	svc := NewCAProviderService()

	// When/Then 1：禁用 A（B 仍启用）放行
	if _, err := svc.UpdateCAProvider(int(idA), models.UpdateCAProviderRequest{Enabled: enabledFlag(false)}); err != nil {
		t.Fatalf("disable one-of-two should succeed: %v", err)
	}
	if providerEnabled(idA) {
		t.Fatal("provider A should be disabled")
	}

	// When/Then 2：禁用已禁用的 A（wasEnabled=false，守卫不触发）放行
	if _, err := svc.UpdateCAProvider(int(idA), models.UpdateCAProviderRequest{Enabled: enabledFlag(false)}); err != nil {
		t.Fatalf("re-disable already-disabled provider should succeed: %v", err)
	}

	// When/Then 3：禁用最后一个启用的 B → ErrCAProviderLastEnabled，B 保持启用
	if _, err := svc.UpdateCAProvider(int(idB), models.UpdateCAProviderRequest{Enabled: enabledFlag(false)}); !errors.Is(err, ErrCAProviderLastEnabled) {
		t.Fatalf("disable last enabled error=%v, want %v", err, ErrCAProviderLastEnabled)
	}
	if !providerEnabled(idB) {
		t.Fatal("last enabled provider B must stay enabled after guard rejection")
	}

	// When/Then 4：校验错误优先于守卫——禁用最后一个启用且名字非法时返回
	// 名字校验错误（校验在 UPDATE 之前，与旧实现错误顺序一致）
	emptyName := ""
	if _, err := svc.UpdateCAProvider(int(idB), models.UpdateCAProviderRequest{Name: &emptyName, Enabled: enabledFlag(false)}); !errors.Is(err, ErrCAProviderInvalidName) {
		t.Fatalf("invalid name + disable last error=%v, want %v", err, ErrCAProviderInvalidName)
	}
	if !providerEnabled(idB) {
		t.Fatal("provider B must stay enabled after validation rejection")
	}

	// When/Then 5：非禁用写（不改 enabled）不受守卫影响
	newName := "provider-b-renamed"
	if _, err := svc.UpdateCAProvider(int(idB), models.UpdateCAProviderRequest{Name: &newName}); err != nil {
		t.Fatalf("name-only update on last enabled should succeed: %v", err)
	}

	// When/Then 6：启用 A 后禁用 B 放行（A 成为新的唯一启用）
	if _, err := svc.UpdateCAProvider(int(idA), models.UpdateCAProviderRequest{Enabled: enabledFlag(true)}); err != nil {
		t.Fatalf("re-enable A should succeed: %v", err)
	}
	if _, err := svc.UpdateCAProvider(int(idB), models.UpdateCAProviderRequest{Enabled: enabledFlag(false)}); err != nil {
		t.Fatalf("disable B while A enabled should succeed: %v", err)
	}
	if providerEnabled(idB) || !providerEnabled(idA) {
		t.Fatalf("final state wrong: A enabled=%v, B enabled=%v, want A enabled / B disabled", providerEnabled(idA), providerEnabled(idB))
	}
}

// CERT-L1（第 69 轮）：并发禁用仅剩的两个启用提供商时，启用计数恒不为零——
// 一个禁用成功、另一个必须被守卫拒绝（ErrCAProviderLastEnabled），禁止静默
// 击穿到「零启用」（该状态会让全部 ACME 签发/续签失败）。原子条件 UPDATE
// 形态下该不变量由数据库在写锁内保证，本测试钉住端到端可观察结果。
func TestCAProviderService_UpdateCAProvider_concurrentDisable_neverReachesZeroEnabled(t *testing.T) {
	_, database := newClusterTestService(t)
	svc := NewCAProviderService()
	disabled := false
	for round := range 25 {
		// Given：每轮重置为恰好两个启用提供商
		if _, err := database.Exec("DELETE FROM ca_providers"); err != nil {
			t.Fatalf("round %d clear: %v", round, err)
		}
		ids := make([]int64, 0, 2)
		for _, name := range []string{"race-a", "race-b"} {
			result, err := database.Exec(`INSERT INTO ca_providers (name,provider,directory_url,credentials,max_concurrent,min_interval_ms,enabled) VALUES (?,'letsencrypt',?,'',1,1000,1)`, name, LetsEncryptDirectoryURL)
			if err != nil {
				t.Fatalf("round %d seed %s: %v", round, name, err)
			}
			id, err := result.LastInsertId()
			if err != nil {
				t.Fatalf("round %d read id: %v", round, err)
			}
			ids = append(ids, id)
		}

		// When：并发禁用两者
		var wg sync.WaitGroup
		errs := make(chan error, 2)
		for _, id := range ids {
			wg.Add(1)
			go func(providerID int64) {
				defer wg.Done()
				_, err := svc.UpdateCAProvider(int(providerID), models.UpdateCAProviderRequest{Enabled: &disabled})
				errs <- err
			}(id)
		}
		wg.Wait()
		close(errs)

		// Then：错误仅允许 nil 或 ErrCAProviderLastEnabled，且终态恰好一个启用
		for err := range errs {
			if err != nil && !errors.Is(err, ErrCAProviderLastEnabled) {
				t.Fatalf("round %d: unexpected error %v (want nil or ErrCAProviderLastEnabled)", round, err)
			}
		}
		var enabledCount int
		if err := database.QueryRow("SELECT COUNT(*) FROM ca_providers WHERE enabled=1").Scan(&enabledCount); err != nil {
			t.Fatalf("round %d count enabled: %v", round, err)
		}
		if enabledCount != 1 {
			t.Fatalf("round %d: enabled count=%d, want exactly 1（守卫必须拦住第二个禁用）", round, enabledCount)
		}
	}
}
