package services

// SEC-C-1（第 70 轮 P2，镜像 SEC-C-U2）：schedulerTick 先触发后写槽——在途
// （含手动插队）时 StartUpdate 是唯一原子门，不推进 next_update；旧序先写槽
// 会空耗排程槽且不回填。微秒竞态窗口无确定性复现手段，本钉测锁定新契约
// 「在途不推槽」（旧码该形状亦过——结构性修复，R-11 披露，同 CRS 侧口径）。

import (
	"context"
	"errors"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

func TestIP2RegionSchedulerTick_inFlightDoesNotAdvanceSlot(t *testing.T) {
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.0.0", true)
	// 排程槽到期（过去时刻）
	past := time.Now().UTC().Add(-time.Hour).Format(crsTimeLayout)
	if _, err := db.DB.Exec("UPDATE security_ip2region_version SET next_update=? WHERE id=1", past); err != nil {
		t.Fatal(err)
	}
	// 手动更新在途（阻塞 fetch 持锁；select 形态兼容任务内重试——release
	// 关闭后重试即时返回错误）
	release := make(chan struct{})
	m.fetchLatestTag = func(ctx context.Context) (string, error) {
		select {
		case <-release:
			return "", errors.New("查询失败")
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	done, err := m.StartUpdate("manual", nil)
	if err != nil {
		t.Fatalf("manual StartUpdate: %v", err)
	}
	defer func() { close(release); <-done }()

	// When：在途期间 tick 到期槽
	m.schedulerTick(time.Now().UTC())
	// Then：槽不推进（仍为过期的原槽）
	_, _, _, _, _, nextUpdate, _ := ip2RegionVersionRow(t)
	if nextUpdate != past {
		t.Fatalf("next_update=%q, want 原槽 %q（在途不推进）", nextUpdate, past)
	}
}
