package handlers

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// R10（第 72 轮，用户裁定）：规则脱离 ACME（证书源改手动 / 禁用 TLS）时，
// 该规则关联的证书签发任务必须**直接删除**（全部状态，含 failed/issued），
// 不再残留失败行于任务列表。此前 acme→manual 仅翻转非终态行（failed 有意
// 排除——L4-66-01），失败任务永久残留且「重签」按钮误导（实际 409）；
// 禁用 TLS 路径则完全无 cert_jobs 处理。

func countRuleCertJobs(t *testing.T, caddyID string) int {
	t.Helper()
	var n int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM cert_jobs WHERE rule_id=?", caddyID).Scan(&n); err != nil {
		t.Fatalf("count cert jobs: %v", err)
	}
	return n
}

// 主形状一：acme→manual 切换时 failed（与 issued）任务一并删除——
// 未实现时 failed 行残留（RED）。
func TestUpdateRule_acmeToManual_deletesAllCertJobsIncludingFailed(t *testing.T) {
	oldCertDir := testServicesCertDir
	testServicesCertDir = t.TempDir()
	t.Cleanup(func() { testServicesCertDir = oldCertDir })
	harness := newUpdateAuditRuleHandlers(t, "lb_r10_manual", 0, false)
	failedID := seedACMEManualSwitchFixture(t, "lb_r10_manual", "r10.example.test", "failed")
	// 补一条 issued 形态（切换后证书不再被规则引用，任务行一并退役）；
	// cert_jobs UNIQUE(rule_id,domain)——用第二域名形态。
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,ca_provider_id) SELECT ?,'www.r10.example.test','issued',ca_provider_id FROM cert_jobs WHERE id=?`,
		"lb_r10_manual", failedID); err != nil {
		t.Fatalf("seed issued job: %v", err)
	}
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil }, t.TempDir())
	t.Cleanup(services.ResetCAQueueManagerForTest)
	certPEM, keyPEM, err := generateTestCert("r10.example.test", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatalf("generate test cert: %v", err)
	}

	response := putUpdateRule(t, harness, "lb_r10_manual", fmt.Sprintf(
		`{"name":"after","enable_tls":true,"tls_source":"manual","tls_cert":%q,"tls_key":%q}`, certPEM, keyPEM))

	if response.Code != http.StatusOK {
		t.Fatalf("switch status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	if n := countRuleCertJobs(t, "lb_r10_manual"); n != 0 {
		t.Fatalf("cert jobs remaining=%d, want 0（脱离 ACME 必须删除全部关联任务，含 failed/issued）", n)
	}
	var tlsSource string
	if err := db.DB.QueryRow("SELECT tls_source FROM lb_rules WHERE caddy_id='lb_r10_manual'").Scan(&tlsSource); err != nil || tlsSource != "manual" {
		t.Fatalf("rule tls_source=%q err=%v, want manual", tlsSource, err)
	}
}

// 主形状二：禁用 TLS 时关联任务一并删除——此前该路径无任何 cert_jobs
// 处理，failed 行残留（RED）。
func TestUpdateRule_disableTLS_deletesAllCertJobs(t *testing.T) {
	oldCertDir := testServicesCertDir
	testServicesCertDir = t.TempDir()
	t.Cleanup(func() { testServicesCertDir = oldCertDir })
	harness := newUpdateAuditRuleHandlers(t, "lb_r10_nodtls", 0, false)
	seedACMEManualSwitchFixture(t, "lb_r10_nodtls", "nodtls.example.test", "failed")
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil }, t.TempDir())
	t.Cleanup(services.ResetCAQueueManagerForTest)

	response := putUpdateRule(t, harness, "lb_r10_nodtls", `{"name":"after","enable_tls":false}`)

	if response.Code != http.StatusOK {
		t.Fatalf("disable-TLS status=%d body=%s, want 200（此前在途任务 409 挡切换；本裁定改为允许切换并删任务）", response.Code, response.Body.String())
	}
	if n := countRuleCertJobs(t, "lb_r10_nodtls"); n != 0 {
		t.Fatalf("cert jobs remaining=%d, want 0（禁用 TLS 必须删除全部关联任务）", n)
	}
	var enableTLS int
	if err := db.DB.QueryRow("SELECT enable_tls FROM lb_rules WHERE caddy_id='lb_r10_nodtls'").Scan(&enableTLS); err != nil || enableTLS != 0 {
		t.Fatalf("rule enable_tls=%d err=%v, want 0", enableTLS, err)
	}
}

// 事务性回归：禁用 TLS 路径的删除同样随事务回滚（应用失败时任务行必须
// 原样保留——与 acme→manual 回滚形状对称）。
func TestUpdateRule_disableTLS_deleteRollsBackWhenApplyFails(t *testing.T) {
	oldCertDir := testServicesCertDir
	testServicesCertDir = t.TempDir()
	t.Cleanup(func() { testServicesCertDir = oldCertDir })
	harness := newUpdateAuditRuleHandlers(t, "lb_r10_rbnod", 1, false) // /load 首次必失败
	jobID := seedACMEManualSwitchFixture(t, "lb_r10_rbnod", "rbnod.example.test", "failed")

	response := putUpdateRule(t, harness, "lb_r10_rbnod", `{"name":"after","enable_tls":false}`)

	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "Caddy 配置应用失败") {
		t.Fatalf("status=%d body=%s, want 400 Caddy 配置应用失败（必须经应用失败路径回滚）", response.Code, response.Body.String())
	}
	var status string
	if err := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE id=?", jobID).Scan(&status); err != nil {
		t.Fatalf("read cert job: %v（删除必须随事务回滚，行应保留）", err)
	}
	if status != "failed" {
		t.Fatalf("cert job status=%q, want failed（回滚后维持原状）", status)
	}
}

// 回归：仅改名（TLS 维持 acme+启用）不受影响——任务行原样，非终态仍 409。
func TestUpdateRule_tlsUnchanged_keepsCertJobs(t *testing.T) {
	harness := newUpdateAuditRuleHandlers(t, "lb_r10_keep", 0, false)
	jobID := seedACMEManualSwitchFixture(t, "lb_r10_keep", "keep10.example.test", "queued")

	response := putUpdateRule(t, harness, "lb_r10_keep", `{"name":"after"}`)

	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s, want 409（TLS 不变的更新仍受非终态守卫）", response.Code, response.Body.String())
	}
	if n := countRuleCertJobs(t, "lb_r10_keep"); n != 1 {
		t.Fatalf("cert jobs=%d, want 1（非脱离路径不得删任务）", n)
	}
	var status string
	if err := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE id=?", jobID).Scan(&status); err != nil || status != "queued" {
		t.Fatalf("job status=%q err=%v, want queued", status, err)
	}
}

// 孤儿自愈（第 72 轮用户裁定）：规则**早已**是手动证书（v2.3.5 时代转换语义
// 遗留的残留行），重存（manual→manual，无转换事件）同样按终态删除孤儿行。
// 实现与钉测同批落盘（终态判定超集自然覆盖）——基线钉豁免 RED。
func TestUpdateRule_manualResave_healsOrphanCertJobs(t *testing.T) {
	oldCertDir := testServicesCertDir
	testServicesCertDir = t.TempDir()
	t.Cleanup(func() { testServicesCertDir = oldCertDir })
	harness := newUpdateAuditRuleHandlers(t, "lb_r10_heal", 0, false)
	seedAuditRule(t, "lb_r10_heal", "before", "heal.example.test", 8080, true, "manual", true)
	seedAuditUpstream(t, "lb_r10_heal")
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,ca_provider_id) VALUES ('lb_r10_heal','heal.example.test','failed',1)`); err != nil {
		t.Fatalf("seed orphan job: %v", err)
	}
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil }, t.TempDir())
	t.Cleanup(services.ResetCAQueueManagerForTest)
	certPEM, keyPEM, err := generateTestCert("heal.example.test", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatalf("generate test cert: %v", err)
	}

	response := putUpdateRule(t, harness, "lb_r10_heal", fmt.Sprintf(
		`{"name":"after","enable_tls":true,"tls_source":"manual","tls_cert":%q,"tls_key":%q}`, certPEM, keyPEM))

	if response.Code != http.StatusOK {
		t.Fatalf("resave status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	if n := countRuleCertJobs(t, "lb_r10_heal"); n != 0 {
		t.Fatalf("orphan cert jobs=%d, want 0（manual→manual 重存必须收敛历史残留）", n)
	}
}
