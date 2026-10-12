package services

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

func TestClusterService_Nodes_degrades_bad_health_json_per_node(t *testing.T) {
	// Given：一个节点 health_json 损坏，另一个节点正常
	service, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO nodes (name,ip_address,is_approved,status,health_json) VALUES ('bad-health','10.0.0.2',1,'online','not-json{')`); err != nil {
		t.Fatalf("seed broken node: %v", err)
	}
	validHealth, err := json.Marshal(models.ClusterHealth{CaddyOK: true, RulesCount: 3})
	if err != nil {
		t.Fatalf("encode valid health: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO nodes (name,ip_address,is_approved,status,health_json) VALUES ('good-health','10.0.0.3',1,'online',?)`, string(validHealth)); err != nil {
		t.Fatalf("seed healthy node: %v", err)
	}

	// When
	nodes, err := service.Nodes(context.Background(), time.Now())

	// Then：列表不因单节点损坏而整体失败，损坏节点 Health=nil
	if err != nil {
		t.Fatalf("nodes list failed on single bad health_json: %v", err)
	}
	byName := map[string]*models.ClusterNodeView{}
	for i := range nodes {
		byName[nodes[i].Name] = &nodes[i]
	}
	if len(nodes) != 2 {
		t.Fatalf("nodes count=%d, want 2", len(nodes))
	}
	if bad := byName["bad-health"]; bad == nil || bad.Health != nil {
		t.Fatalf("bad-health node present=%v, want present with nil Health", byName["bad-health"] != nil)
	}
	if good := byName["good-health"]; good == nil || good.Health == nil || good.Health.RulesCount != 3 {
		t.Fatalf("good-health node health=%v, want decoded health", nodeHealth(byName["good-health"]))
	}
}

func nodeHealth(node *models.ClusterNodeView) *models.ClusterHealth {
	if node == nil {
		return nil
	}
	return node.Health
}

// CLUSTER-2（第 72 轮审计·归类漂移）：ZeroSSL EAB 自动获取测试
// （TestAutoProvisionZeroSSLEAB_email_is_url_encoded /
// TestAutoProvisionZeroSSLEAB_cas_loses_memory_follows_db 及
// overrideZeroSSLEABURL helper）原寄居本文件，已迁证书域 caproviders_test.go
// （AutoProvisionZeroSSLEAB 实现于 caproviders.go）。

func TestSyncService_Report_failure_audit_throttles_and_resets_on_recovery(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	deadMaster := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := deadMaster.URL
	deadMaster.Close()
	liveMaster := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = response.Write([]byte(`{"code":0,"message":"ok"}`))
	}))
	defer liveMaster.Close()
	caddy := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) { response.WriteHeader(http.StatusOK) }))
	defer caddy.Close()
	if _, err := database.Exec("UPDATE global_config SET is_master=0, master_url=?, cluster_token='tok-1' WHERE id=1", deadURL); err != nil {
		t.Fatalf("seed slave state: %v", err)
	}
	service := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, NewCaddyService(caddy.URL))
	countAudit := func() int {
		var count int
		if err := db.AuditDB.QueryRow("SELECT COUNT(*) FROM audit_log WHERE action='上报失败'").Scan(&count); err != nil {
			t.Fatalf("count audit rows: %v", err)
		}
		return count
	}

	// When/Then：首次失败记录审计，重复同样失败被节流
	if err := service.Report(context.Background()); err == nil {
		t.Fatal("report to dead master unexpectedly succeeded")
	}
	if got := countAudit(); got != 1 {
		t.Fatalf("audit rows after first failure=%d, want 1", got)
	}
	if err := service.Report(context.Background()); err == nil {
		t.Fatal("report to dead master unexpectedly succeeded")
	}
	if got := countAudit(); got != 1 {
		t.Fatalf("audit rows after repeated failure=%d, want 1 (throttled)", got)
	}

	// When/Then：上报恢复后节流状态重置，再次失败重新记录一次
	if _, err := database.Exec("UPDATE global_config SET master_url=? WHERE id=1", liveMaster.URL); err != nil {
		t.Fatalf("point to live master: %v", err)
	}
	if err := service.Report(context.Background()); err != nil {
		t.Fatalf("report to live master: %v", err)
	}
	if got := countAudit(); got != 1 {
		t.Fatalf("audit rows after recovery=%d, want 1", got)
	}
	if _, err := database.Exec("UPDATE global_config SET master_url=? WHERE id=1", deadURL); err != nil {
		t.Fatalf("point back to dead master: %v", err)
	}
	if err := service.Report(context.Background()); err == nil {
		t.Fatal("report to dead master unexpectedly succeeded")
	}
	if got := countAudit(); got != 2 {
		t.Fatalf("audit rows after post-recovery failure=%d, want 2", got)
	}
}
