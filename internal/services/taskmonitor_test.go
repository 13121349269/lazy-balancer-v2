package services

import (
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

// TASK-L3（第 69 轮 P3）：聚合视图两处 db.DB 裸用（collectCertJobRows 的
// cert_jobs 查询、cluster-sync 节奏的 sync_interval 查询）补 nil 防护——与
// 引擎侧导出 DB 函数（History/Stats24h 等 7 处）同形契约。
//
// Given db.DB 未初始化（nil）。
// When 调用 cert 任务行收集与引擎族聚合（含 cluster-sync 节奏查询）。
// Then 不 panic：cert 行返回 nil，引擎族聚合返回降级视图（节奏兜底文案）。
func TestCollectSystemTasks_nilDBGuards(t *testing.T) {
	old := db.DB
	db.DB = nil
	t.Cleanup(func() { db.DB = old })

	if rows := collectCertJobRows(); rows != nil {
		t.Fatalf("nil DB 时 collectCertJobRows=%v, want nil", rows)
	}

	e := taskengine.NewEngine(taskengine.Options{})
	t.Cleanup(e.Stop)
	e.Register(taskengine.Descriptor{ID: "cluster-sync", Family: "cluster", Name: "集群同步",
		Kind: taskengine.KindPeriodic, IntervalFn: func() time.Duration { return 60 * time.Second },
		Run: func(taskengine.RunContext) error { return nil }})
	out := collectEngineFamilies(e)
	if len(out) != 1 {
		t.Fatalf("nil DB 时 collectEngineFamilies 行数=%d, want 1（降级视图）", len(out))
	}
	if out[0].Cadence == "" {
		t.Fatal("nil DB 时节奏列应有兜底文案（每 1 分钟）")
	}
}

// TASK-3（第 70 轮 P4）：disabled 证书行 Triggerable 必须 false——行级重试门
// 对 disabled 恒 429（certJobRetryBlocked 首条），按钮亮着是交互噪音（点了必 429）。
func TestCollectCertJobRows_disabledRowNotTriggerable(t *testing.T) {
	oldDB, oldM, oldA := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldM, oldA
	})
	seedCertJobRowForTaskMonitor(t, "lb_tm_disabled", "disabled.example.com", "disabled")
	seedCertJobRowForTaskMonitor(t, "lb_tm_queued", "queued.example.com", "queued")

	rows := collectCertJobRows()
	byDomain := map[string]TaskInfo{}
	for _, r := range rows {
		byDomain[strings.TrimPrefix(r.Name, "ACME 签发 · ")] = r
	}
	disabled, ok := byDomain["disabled.example.com"]
	if !ok {
		t.Fatalf("disabled 行缺失: %+v", rows)
	}
	if disabled.Triggerable {
		t.Fatal("disabled 证书行 Triggerable=true——重试门恒 429，按钮应为禁用态")
	}
	queued, ok := byDomain["queued.example.com"]
	if !ok {
		t.Fatalf("queued 行缺失: %+v", rows)
	}
	if !queued.Triggerable {
		t.Fatal("queued 证书行 Triggerable 应保持 true（回归）")
	}
}

func seedCertJobRowForTaskMonitor(t *testing.T, ruleID, domain, status string) {
	t.Helper()
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status) VALUES (?,?,?)`, ruleID, domain, status); err != nil {
		t.Fatalf("seed cert job %s: %v", ruleID, err)
	}
}
