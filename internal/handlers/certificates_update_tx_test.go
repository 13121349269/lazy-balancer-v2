package handlers

// LBS/LBH-4（第 73 轮 P5）：UpdateCertificateConfig 旧行读取与动态 UPDATE 分属
// 两个 autocommit 语句（SELECT 旧值 → UPDATE），审计 changed 清单的比对基线
// 取自事务外预读——预读与写入之间的并发提交会让基线陈旧（漏记/多记变更字段）。
// 镜像 CERT-N1：旧行快照与写入同事务（BEGIN IMMEDIATE），基线即写入前那一刻
// 的真实行。本用例以「并发持写锁改行 + 请求提交同值」的交错暴露差异：
//   - 修复前：事务外 SELECT 读到未提交前的 'orig'，与请求 'concurrent' 不等
//     → 记「变更：名称」并写库（响应 Config updated）。
//   - 修复：BEGIN IMMEDIATE 先取写锁，待并发提交后再读 → 读到 'concurrent'
//     == 请求值 → 无变化（响应 Config unchanged）。

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

func TestUpdateCertificateConfig_readsOldRowInsideTransaction(t *testing.T) {
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO certificate_configs (id, name, dns_provider, dns_credentials, enabled) VALUES
		(1, 'orig', 'dnspod', '{"auth_mode":"dnspod","app_id":"old-id","app_token":"old-token"}', 1)`); err != nil {
		t.Fatalf("seed certificate config: %v", err)
	}
	router := gin.New()
	router.PUT("/certificate-configs/:id", h.UpdateCertificateConfig)

	ctx := context.Background()
	// Given：并发写持写锁把 name 改成 'concurrent'（未提交）
	holdTx, err := db.DB.BeginTx(ctx, &sql.TxOptions{}) // _txlock=immediate → BEGIN IMMEDIATE 持写锁
	if err != nil {
		t.Fatalf("begin hold tx: %v", err)
	}
	defer holdTx.Rollback()
	if _, err := holdTx.ExecContext(ctx, `UPDATE certificate_configs SET name='concurrent' WHERE id=1`); err != nil {
		t.Fatalf("hold tx update: %v", err)
	}

	// When：PUT 把 name 改成 'concurrent'（与并发写目标同值）
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		req := httptest.NewRequest(http.MethodPut, "/certificate-configs/1", strings.NewReader(`{"name":"concurrent"}`))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(rec, req)
	}()
	// 让修复前的事务外 SELECT 先于并发提交发生（WAL 下读不被写锁阻塞）
	time.Sleep(200 * time.Millisecond)
	if err := holdTx.Commit(); err != nil {
		t.Fatalf("commit hold tx: %v", err)
	}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("UpdateCertificateConfig 未在并发提交后完成")
	}

	// Then：事务内旧行 = 'concurrent'（已提交）→ 与请求同值 → 无变化
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "unchanged") {
		t.Fatalf("body=%s, want unchanged（changed 基线须取事务内旧行）", rec.Body.String())
	}
	var name string
	if err := db.DB.QueryRow(`SELECT name FROM certificate_configs WHERE id=1`).Scan(&name); err != nil {
		t.Fatalf("read config: %v", err)
	}
	if name != "concurrent" {
		t.Fatalf("name=%q, want concurrent（并发提交不得被陈旧基线覆盖）", name)
	}
}
