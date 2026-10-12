package services

import (
	"bytes"
	"context"
	"log"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

func TestRefreshLocation_updates_current_location_without_mutating_timeLocal(t *testing.T) {
	// Given
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
	if _, err := db.DB.Exec("UPDATE global_config SET timezone='UTC' WHERE id=1"); err != nil {
		t.Fatalf("set timezone: %v", err)
	}
	localBefore := time.Local

	// When
	err := refreshLocation()

	// Then
	if err != nil {
		t.Fatalf("refresh location: %v", err)
	}
	if time.Local != localBefore {
		t.Fatal("runtime timezone refresh mutated time.Local")
	}
	if CurrentLocation() != time.UTC {
		t.Fatalf("current location=%v, want UTC", CurrentLocation())
	}
}

func TestTimezoneRefresh_stops_and_waits_when_context_is_canceled(t *testing.T) {
	// Given
	StopTimezoneRefresh()
	ctx, cancel := context.WithCancel(context.Background())
	done := StartTimezoneRefresh(ctx)

	// When
	cancel()

	// Then: <-done 返回即证明循环已停止且等待闭合（阻塞则测试超时失败；
	// SYS-T3 第 72 轮：原 <-done 之后的 select-default 分支恒不可达，已删）。
	<-done

	t.Cleanup(func() { StartTimezoneRefresh(context.Background()) })
}

func TestApplicationLogWriterFiltersRawStandardLogsAtConfiguredThreshold(t *testing.T) {
	tests := []struct {
		name    string
		level   string
		message string
		want    bool
	}{
		{name: "info allows ordinary lines", level: "info", message: "startup complete", want: true},
		{name: "warn drops ordinary lines", level: "warn", message: "startup complete", want: false},
		{name: "warn allows warning lines", level: "warn", message: "Warning: degraded startup", want: true},
		{name: "error drops warning lines", level: "error", message: "Warning: degraded startup", want: false},
		{name: "error allows error lines", level: "error", message: "ERROR: startup failed", want: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			var output bytes.Buffer
			if err := ConfigureLogLevel(test.level); err != nil {
				t.Fatal(err)
			}
			logger := log.New(NewApplicationLogWriter(&output), "", 0)

			// When
			logger.Print(test.message)

			// Then
			if strings.Contains(output.String(), test.message) != test.want {
				t.Fatalf("output=%q want_visible=%v", output.String(), test.want)
			}
		})
	}
	t.Cleanup(func() { _ = ConfigureLogLevel("info") })
}

// U7b-F2（第 66 轮审计）：DB 初始化完成点即时刷新时区——init 期 worker 首查时
// DB 未就绪恒空转，配置时区此前最长要等 30s ticker 才生效（FixedZone+8 占位
// 窗口）。ApplyLogLevel 是 main 在 db.Initialize 完成后的首个 services 装配点
// （亦为集群导入 users 节后的调用点），在此追加一次即时 refreshLocation。
func TestApplyLogLevel_refreshesTimezoneImmediately(t *testing.T) {
	oldLoc := CurrentLocation()
	StopTimezoneRefresh()
	t.Cleanup(func() {
		currentLocation.Store(oldLoc)
		StartTimezoneRefresh(context.Background())
	})
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
	if _, err := db.DB.Exec("UPDATE global_config SET timezone='America/New_York' WHERE id=1"); err != nil {
		t.Fatalf("set timezone: %v", err)
	}

	// When：DB 就绪后的装配点调用（不等 30s ticker）
	ApplyLogLevel()

	// Then：DST 时区立即生效
	if got := CurrentLocation().String(); got != "America/New_York" {
		t.Fatalf("current location=%q, want America/New_York（DB 就绪后必须即时刷新，不得等 ticker）", got)
	}
}

// U7b-F5（第 66 轮审计）：applicationLogWriter 透传 sink 的真实返回值——短写
// 返回 len(p) 偏离 io.Writer 契约（装饰器不得替 sink 谎报写入量）。
func TestApplicationLogWriter_writeReturnsSinkWrittenCount(t *testing.T) {
	oldLevel := CurrentLogLevel()
	t.Cleanup(func() { _ = ConfigureLogLevel(oldLevel) })
	if err := ConfigureLogLevel("warn"); err != nil { // 进入过滤分支（info 直通分支本就透传）
		t.Fatal(err)
	}
	sink := &shortWriteSink{n: 3}
	w := NewApplicationLogWriter(sink)
	// 载荷带 WARN 前缀——warn 档放行进入写入分支（不带前缀会在过滤分支被丢弃，
	// 触达不到 sink）。
	n, err := w.Write([]byte("WARN hello world"))
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if n != 3 {
		t.Fatalf("Write returned %d, want sink's 3（短写必须如实返回 written）", n)
	}
}

// shortWriteSink 恒短写返回 (n, nil) 的 sink。
type shortWriteSink struct{ n int }

func (s *shortWriteSink) Write(p []byte) (int, error) {
	if s.n > len(p) {
		return len(p), nil
	}
	return s.n, nil
}
