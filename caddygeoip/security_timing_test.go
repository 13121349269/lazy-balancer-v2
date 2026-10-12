package caddygeoip

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// F62-30(第 62 轮审计):写侧三文件此前零测试——补并发追加/空 ID 短路/目录
// 惰性创建的行为钉。

// Given: 并发 50 goroutine 各追加一行
// When: AppendSecurityTiming
// Then: 有界队列+专职写 goroutine 保证 50 行完整落盘(无交错/丢行;
// 50 < 队列容量 4096 无丢弃;PLUG-N1 第 72 轮由互斥锁串行写改造)
func TestAppendSecurityTiming_concurrentAppend(t *testing.T) {
	logPath, flush := setupSecurityTimingWriter(t)

	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			AppendSecurityTiming(strings.Repeat("a", 8), int64(n))
		}(i)
	}
	wg.Wait()
	flush() // 停写排空——断言前所有已入队行落盘

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 50 {
		t.Errorf("lines=%d; want 50 (mutex must serialize appends)", len(lines))
	}
	for _, l := range lines {
		if !strings.HasPrefix(l, "aaaaaaaa ") {
			t.Errorf("malformed line: %q", l)
		}
	}
}

// Given: 空 ID
// When: AppendSecurityTiming
// Then: 短路(不建文件)
func TestAppendSecurityTiming_emptyIdShortCircuit(t *testing.T) {
	logPath, flush := setupSecurityTimingWriter(t)

	AppendSecurityTiming("", 100)
	flush()

	if _, err := os.Stat(logPath); !os.IsNotExist(err) {
		t.Error("empty ID must short-circuit without creating file")
	}
}

// Given: 目录不存在
// When: AppendSecurityTiming
// Then: MkdirAll 兜底后正常写入
func TestAppendSecurityTiming_mkdirFallback(t *testing.T) {
	nested, flush := setupSecurityTimingWriter(t, "a", "b", "timing.log")

	AppendSecurityTiming("testid01", 42)
	flush()

	data, err := os.ReadFile(nested)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(data)) != "testid01 42" {
		t.Errorf("content=%q; want %q", data, "testid01 42")
	}
}

// Given: 正常调用
// When: securityTimingID
// Then: 16 字符 hex(8 字节;F62-29 扩容后)
func TestSecurityTimingID_length(t *testing.T) {
	id := securityTimingID()
	if len(id) != 16 {
		t.Errorf("len=%d; want 16 (8 bytes hex)", len(id))
	}
	for _, c := range id {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			t.Errorf("non-hex char %q in %q", c, id)
		}
	}
}

// setupSecurityTimingWriter 重定向侧车路径到临时文件并启动写 goroutine
// （PLUG-N1 第 72 轮：落盘改由 handler 生命周期内的专职写 goroutine 承担，
// 测试须显式 acquire）。返回路径与 flush（停写排空——已入队行全部落盘，
// fd 随写 goroutine 退出关闭，无泄漏；幂等，t.Cleanup 兜底再调一次并还原
// 路径）。rel 缺省为 "timing.log"。
func setupSecurityTimingWriter(t *testing.T, rel ...string) (logPath string, flush func()) {
	t.Helper()
	if len(rel) == 0 {
		rel = []string{"timing.log"}
	}
	parts := append([]string{t.TempDir()}, rel...)
	logPath = filepath.Join(parts...)
	orig := securityTimingLogPath
	securityTimingLogPath = logPath
	securityTimingWriterAcquire()
	released := false
	flush = func() {
		if released {
			return
		}
		released = true
		securityTimingWriterRelease()
	}
	t.Cleanup(func() {
		flush()
		securityTimingLogPath = orig
	})
	return logPath, flush
}

// PLUG-R1（第 69 轮 P4）：security_timing_pre/end 两 ServeHTTP 逐字重复收敛为
// recordSecurityTiming helper——钉 helper 契约：合法头对写一行「<id><suffix> <us>」，
// 缺头对零写入（静默降级语义不变）。
func TestRecordSecurityTiming_writesSuffixedLine(t *testing.T) {
	// Given 临时侧车路径（写 goroutine 在役）+ 携带关联头对的请求（起始时间 12345µs 前）
	logPath, flush := setupSecurityTimingWriter(t)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(securityTimingHeader, "abcdef0123456789")
	req.Header.Set(securityTimingStartHeader, strconv.FormatInt(time.Now().UnixNano()-12345000, 10))

	// When
	recordSecurityTiming(req, ":pre")
	flush() // 停写排空后断言

	// Then：恰好一行 <id>:pre <us>，耗时为正整数
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(string(data))
	parts := strings.SplitN(line, " ", 2)
	if len(parts) != 2 || parts[0] != "abcdef0123456789:pre" {
		t.Fatalf("line=%q, want %q", line, "abcdef0123456789:pre <us>")
	}
	if us, perr := strconv.ParseInt(parts[1], 10, 64); perr != nil || us <= 0 {
		t.Fatalf("duration=%q, want positive integer µs", parts[1])
	}

	// And 畸形形状：缺头对的请求零写入（写 goroutine 在役时同样静默跳过）
	securityTimingWriterAcquire()
	recordSecurityTiming(httptest.NewRequest(http.MethodGet, "/", nil), ":end")
	securityTimingWriterRelease()
	dataAfter, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(dataAfter) != string(data) {
		t.Fatalf("missing headers must write nothing: before=%q after=%q", data, dataAfter)
	}
}

// PLUG-N1（第 72 轮）：写 goroutine 未启动（无计时写点 handler 在役）时
// Append 必须静默丢弃——不建文件、不阻塞、不 panic。耗时是增强信息，
// 降级语义保持；落盘由 handler 生命周期内的专职写 goroutine 承担，
// 请求路径不再直接持有/惰性创建 fd。
func TestAppendSecurityTiming_dropsWhenWriterNotStarted(t *testing.T) {
	// Given 临时侧车路径，但不启动写 goroutine
	dir := t.TempDir()
	orig := securityTimingLogPath
	logPath := filepath.Join(dir, "timing.log")
	securityTimingLogPath = logPath
	t.Cleanup(func() { securityTimingLogPath = orig })

	// When
	AppendSecurityTiming("deadbeef01", 7)

	// Then 不建文件（静默丢弃，而非请求路径惰性写盘）
	if _, err := os.Stat(logPath); !os.IsNotExist(err) {
		t.Fatalf("append without writer must drop silently, stat err=%v", err)
	}
}

// PLUG-N1（第 72 轮）：队列有界满丢——请求路径 Append 永不阻塞在磁盘 I/O
// 上；队列满时新打点丢弃（耗时增强信息可丢，阻塞主路径不可接受）。
func TestAppendSecurityTiming_queueFullDropsOverflow(t *testing.T) {
	// Given 容量 2 的拥塞队列（无写 goroutine 排空，直接构造满态）
	securityTimingStateMu.Lock()
	origCh, origDone, origRefs := securityTimingCh, securityTimingDone, securityTimingRefs
	securityTimingCh = make(chan string, 2)
	securityTimingDone = nil
	securityTimingRefs = 1 // 标记在役，防测试内 release 误关闭
	securityTimingStateMu.Unlock()
	t.Cleanup(func() {
		securityTimingStateMu.Lock()
		securityTimingCh, securityTimingDone, securityTimingRefs = origCh, origDone, origRefs
		securityTimingStateMu.Unlock()
	})

	// When 连续追加 10 行（远超容量）
	for i := range 10 {
		AppendSecurityTiming("overflowid", int64(i))
	}

	// Then 只保留前 2 行、其余丢弃——Append 全程无阻塞返回
	securityTimingStateMu.RLock()
	queued := len(securityTimingCh)
	securityTimingStateMu.RUnlock()
	if queued != 2 {
		t.Fatalf("queued=%d; want 2 (bounded queue must drop overflow, not block)", queued)
	}
}

// PLUG-N1（第 72 轮）：写 goroutine 生命周期——acquire 启动、release 停写
// 并排空降盘（不丢已入队行）；release 后再 Append 静默丢弃。
func TestSecurityTimingWriter_releaseDrainsQueue(t *testing.T) {
	// Given 启动写 goroutine 的临时侧车
	dir := t.TempDir()
	orig := securityTimingLogPath
	logPath := filepath.Join(dir, "timing.log")
	securityTimingLogPath = logPath
	t.Cleanup(func() { securityTimingLogPath = orig })
	securityTimingWriterAcquire()

	// When 追加 100 行（< 队列容量 4096）后立即 release
	for i := range 100 {
		AppendSecurityTiming("drainid001", int64(i))
	}
	securityTimingWriterRelease()

	// Then 全部 100 行落盘（release 排空而非丢弃）
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 100 {
		t.Fatalf("lines=%d; want 100 (release must drain queue before stopping)", len(lines))
	}

	// And release 后 Append 静默丢弃（写 goroutine 已停）
	AppendSecurityTiming("afterstop1", 1)
	dataAfter, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(dataAfter) != string(data) {
		t.Fatal("append after release must drop silently (writer stopped)")
	}
}
