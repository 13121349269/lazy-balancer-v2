package taskengine

// 24h 分小时桶聚合（任务监控图表重构，2026-10-11 用户裁定方案 A）：
// 时间序列替代任务名柱状图——高频任务不再压制其他任务，且新增时间分布信息。
// 口径：配置时区墙面小时（engineNowStr 同基准，与 task_runs 存储串一致）。

import (
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

func TestEngine_Stats24hHourlySeries(t *testing.T) {
	e := newTestEngine(t)
	_ = e
	now := time.Now().In(engineLocPtr())
	curHour := now.Truncate(time.Hour)
	mk := func(h time.Time, status string) {
		if _, err := db.DB.Exec(`INSERT INTO task_runs (task_id, family, trigger, operator, status, started_at) VALUES ('t-x','t','auto','',?,?)`,
			status, h.Format("2006-01-02 15:04:05")); err != nil {
			t.Fatal(err)
		}
	}
	// 本小时 2 成功 1 失败；3 小时前 1 失败；25 小时前 1 成功（出窗不计）
	mk(curHour, "success")
	mk(curHour.Add(10*time.Minute), "success")
	mk(curHour.Add(20*time.Minute), "failed")
	mk(curHour.Add(-3*time.Hour), "failed")
	mk(curHour.Add(-25*time.Hour), "success")

	series := e.Stats24hHourlySeries()
	if len(series) != 24 {
		t.Fatalf("桶数=%d, want 24（now-23h..now 逐小时）", len(series))
	}
	// 首桶=now-23h，逐小时递增，末桶=当前小时
	first, _ := time.ParseInLocation("2006-01-02 15:04:05", series[0].Hour, engineLocPtr())
	last, _ := time.ParseInLocation("2006-01-02 15:04:05", series[23].Hour, engineLocPtr())
	if !first.Equal(curHour.Add(-23 * time.Hour)) {
		t.Fatalf("首桶=%s, want %s", series[0].Hour, curHour.Add(-23*time.Hour).Format("2006-01-02 15:04:05"))
	}
	if !last.Equal(curHour) {
		t.Fatalf("末桶=%s, want 当前小时 %s", series[23].Hour, curHour.Format("2006-01-02 15:04:05"))
	}
	// 计数落桶正确
	if series[23].Success != 2 || series[23].Failed != 1 {
		t.Fatalf("本小时桶=%+v, want 2 成功 1 失败", series[23])
	}
	if series[20].Failed != 1 || series[20].Success != 0 {
		t.Fatalf("3 小时前桶=%+v, want 1 失败 0 成功", series[20])
	}
	// 空桶零填
	if series[21].Success != 0 || series[21].Failed != 0 {
		t.Fatalf("空桶=%+v, want 零填", series[21])
	}
}
