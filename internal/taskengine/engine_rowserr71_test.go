package taskengine

// 第 71 轮域 A（rows.Err 家族收敛，taskengine 侧）：
//   - TASK-A3：History 迭代错误/Scan 失败须 warn 留痕（此前静默 continue）
//   - LNK71-2：Stats24hHourlySeries 同族（与 services/certificates.go 的
//     reconcileMissingCertFiles 正面对照——本文件两处为此前唯二漏网点）

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// taskRowsIterFailConnector：task_runs 查询「语句执行成功、迭代第一步即失败」
// ——只有循环后检查 rows.Err() 才能发现，否则表现为部分/空数据静默返回。
type taskRowsIterFailConnector struct{}

func (taskRowsIterFailConnector) Connect(context.Context) (driver.Conn, error) {
	return taskRowsIterFailConn{}, nil
}
func (taskRowsIterFailConnector) Driver() driver.Driver { return taskRowsIterFailDriver{} }

type taskRowsIterFailDriver struct{}

func (taskRowsIterFailDriver) Open(string) (driver.Conn, error) { return taskRowsIterFailConn{}, nil }

type taskRowsIterFailConn struct{}

func (taskRowsIterFailConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}
func (taskRowsIterFailConn) Close() error              { return nil }
func (taskRowsIterFailConn) Begin() (driver.Tx, error) { return nil, errors.New("no tx") }

func (taskRowsIterFailConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	cols := 0
	switch {
	case strings.Contains(query, "GROUP BY"):
		cols = 3 // Stats24hHourlySeries 聚合列
	case strings.Contains(query, "FROM task_runs"):
		cols = 10 // History 行列
	default:
		return taskIterZeroRows{}, nil
	}
	names := make([]string, cols)
	for i := range names {
		names[i] = fmt.Sprintf("c%d", i)
	}
	return taskIterFailRows{cols: names}, nil
}

type taskIterFailRows struct{ cols []string }

func (r taskIterFailRows) Columns() []string { return r.cols }
func (taskIterFailRows) Close() error        { return nil }
func (taskIterFailRows) Next([]driver.Value) error {
	return errors.New("注入的 task_runs 迭代失败")
}

type taskIterZeroRows struct{}

func (taskIterZeroRows) Columns() []string         { return []string{"c"} }
func (taskIterZeroRows) Close() error              { return nil }
func (taskIterZeroRows) Next([]driver.Value) error { return io.EOF }

// captureEngineLog 捕获标准库日志（taskengine warn 落点——包内无 services
// 依赖，经 "WARNING:" 前缀走 main.go applicationLogWriter 级别过滤）。
func captureEngineLog(t *testing.T) *strings.Builder {
	t.Helper()
	var buf strings.Builder
	old := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(old) })
	return &buf
}

// TASK-A3（第 71 轮 P5）：History 循环 rows.Err() 未检查——迭代错误表现为
// 「部分历史 + 静默」；Scan 失败同样静默 continue。修复：两者均 warn 留痕
// （返回形状不变——历史页降级展示已读行，与 taskmonitor 读取侧容错一致）。
func TestEngine_History_iterationErrorWarns(t *testing.T) {
	e := newTestEngine(t)
	buf := captureEngineLog(t)

	orig := db.DB
	broken := sql.OpenDB(taskRowsIterFailConnector{})
	t.Cleanup(func() { _ = broken.Close() })
	db.DB = broken
	t.Cleanup(func() { db.DB = orig })

	runs := e.History("t-x", 20)
	if len(runs) != 0 {
		t.Fatalf("迭代失败轮 runs=%d, want 0（无行可读）", len(runs))
	}
	if !strings.Contains(buf.String(), "任务历史") {
		t.Fatalf("History 迭代错误须 warn 留痕, log=%q", buf.String())
	}
}

// LNK71-2（第 71 轮 P5）：Stats24hHourlySeries 聚合循环 rows.Err() 未检查+
// Scan 静默——TASK-1（第 70 轮）同批触碰未同步收敛。修复：warn 留痕，24 桶
// 零填形状不变（图表降级为空序列，不崩不缺桶）。
func TestEngine_Stats24hHourlySeries_iterationErrorWarns(t *testing.T) {
	e := newTestEngine(t)
	buf := captureEngineLog(t)

	orig := db.DB
	broken := sql.OpenDB(taskRowsIterFailConnector{})
	t.Cleanup(func() { _ = broken.Close() })
	db.DB = broken
	t.Cleanup(func() { db.DB = orig })

	series := e.Stats24hHourlySeries()
	if len(series) != 24 {
		t.Fatalf("迭代失败轮桶数=%d, want 24（形状不变）", len(series))
	}
	if !strings.Contains(buf.String(), "24h") {
		t.Fatalf("Stats24hHourlySeries 迭代错误须 warn 留痕, log=%q", buf.String())
	}
}
