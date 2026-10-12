package services

// TASK-2（第 72 轮）：wire EnabledFn 读库失败方向统一 fail-closed——
// crs/ip2region 曾 err→true（读库失败显示「启用」，实际调度面读不到开关
// 状态）；auto-backup 曾 err!=nil||enabled（同向 fail-open）。读错时应
// 显示「已暂停」（Enabled=false），与 threat 既有 fail-closed 口径一致。

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

// queryFailing*：一切查询 Prepare 即失败——QueryRow().Scan 恒返回 err。
type queryFailingConnector struct{}

func (queryFailingConnector) Connect(context.Context) (driver.Conn, error) {
	return queryFailingConn{}, nil
}

func (queryFailingConnector) Driver() driver.Driver { return queryFailingDriver{} }

type queryFailingDriver struct{}

func (queryFailingDriver) Open(string) (driver.Conn, error) { return queryFailingConn{}, nil }

type queryFailingConn struct{}

func (queryFailingConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("注入的查询失败")
}

func (queryFailingConn) Close() error { return nil }

func (queryFailingConn) Begin() (driver.Tx, error) { return nil, errors.New("no tx") }

// swapBrokenDB 把 db.DB 换成恒失败驱动（LIFO：本清理先于夹具清理跑，
// 恢复真实 DB 后再 StopTaskEngine/db.Close）。
func swapBrokenDB(t *testing.T) {
	t.Helper()
	broken := sql.OpenDB(queryFailingConnector{})
	t.Cleanup(func() { _ = broken.Close() })
	orig := db.DB
	db.DB = broken
	t.Cleanup(func() { db.DB = orig })
}

func enabledOf(t *testing.T, te *taskengine.Engine, id string) bool {
	t.Helper()
	m, ok := te.Lookup(id)
	if !ok {
		t.Fatalf("task %s 未注册", id)
	}
	return m.Enabled
}

// Given crs EnabledFn 的 DB 读失败。
// When 查询任务元数据。
// Then Enabled=false（状态列「已暂停」）——读库失败不得误报启用（fail-closed）。
func TestTaskEngineWire_CRSEnabledFnFailsClosedOnDBError(t *testing.T) {
	te := newWireTestEngine(t)
	swapBrokenDB(t)
	if enabledOf(t, te, "crs") {
		t.Fatal("crs EnabledFn 读库失败应 fail-closed（Enabled=false/已暂停），得到 true")
	}
}

// Given ip2region EnabledFn 的 DB 读失败。
// When 查询任务元数据。
// Then Enabled=false（fail-closed，与 crs/threat 同口径）。
func TestTaskEngineWire_IP2RegionEnabledFnFailsClosedOnDBError(t *testing.T) {
	te := newWireTestEngine(t)
	swapBrokenDB(t)
	if enabledOf(t, te, "ip2region") {
		t.Fatal("ip2region EnabledFn 读库失败应 fail-closed（Enabled=false/已暂停），得到 true")
	}
}

// Given auto-backup loadAutoBackupSettings 读失败。
// When 查询任务元数据。
// Then Enabled=false（fail-closed）——曾 err!=nil||enabled 把读错当启用。
func TestTaskEngineWire_AutoBackupEnabledFnFailsClosedOnDBError(t *testing.T) {
	te := newWireTestEngine(t)
	swapBrokenDB(t)
	if enabledOf(t, te, "auto-backup") {
		t.Fatal("auto-backup EnabledFn 读库失败应 fail-closed（Enabled=false/已暂停），得到 true")
	}
}
