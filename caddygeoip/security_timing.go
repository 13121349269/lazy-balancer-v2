package caddygeoip

import (
	cryptorand "crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// securityTimingLogPath 是耗时侧车日志路径——与 coraza 审计日志同目录
// (auditLogPath = /app/logs/waf-audit/audit.log 的同族约定),lazy-balancer
// 进程的摄取管道按行读「<timing_id>:<pre|end> <duration_us>」与审计条目按
// timing ID 关联(读侧 tick 级合并 map,见 securityevents.go securityTimingLoad)。跨进程经文件通信(caddygeoip 编译进 Caddy 二进制,摄取管道在
// lazy-balancer 二进制——不同进程,内存共享不可达)。
var securityTimingLogPath = "/app/logs/waf-audit/security-timing.log"

// securityTimingHeader 是耗时关联头——blocked_counter 注入、coraza 审计日志
// request.headers 收录、摄取管道读出后查耗时侧车文件。渲染链在该头抵达
// reverse_proxy 前删除(caddy.go 渲染层),不上泄上游。
const securityTimingHeader = "X-Lb-Security-Timing-Id"

// securityTimingStartHeader 是起始纳秒时间戳头——blocked_counter 注入,
// SecurityTimingEnd 在安全链末尾读取计算 passed 事件的纯评估耗时(不含
// reverse_proxy 上游往返)。与 timing ID 头同清单剥离。
const securityTimingStartHeader = "X-Lb-Security-Timing-Start-Ns"

// securityTimingStateMu/securityTimingCh 等是耗时侧车的写管线状态——PLUG-N1
// （第 72 轮）：原「单锁串行 Fprintf」让每个计时写点在请求路径上排队等
// 磁盘 I/O（安全链每请求 2-3 个写点，高并发下锁竞争+写盘时延直接叠加进
// 请求耗时）。改造为有界缓冲 channel + 专职写 goroutine：Append 只做
// 非阻塞入队（满则丢弃——耗时是增强信息，可丢不可堵）；写 goroutine 惰性
// 打开 fd（打开失败丢行、下一行重试，保持原静默降级语义），串行落盘。
// 生命周期由三个写点 handler（blocked_counter/timing_pre/timing_end）的
// Provision/Cleanup 引用计数启停：最后一个 Cleanup 关闭 channel 并排空
// 落盘后退出，重载期新旧配置并存时引用计数保证写管线不断。
var (
	securityTimingStateMu sync.RWMutex
	securityTimingCh      chan string   // 在役时非 nil；nil=写管线未启动（Append 静默丢弃）
	securityTimingDone    chan struct{} // 写 goroutine 排空退出时关闭
	securityTimingRefs    int           // 在役写点 handler 数
	// securityTimingQueueSize 队列容量——超限丢弃（防抖盘打爆内存的反向
	// 也一样成立：4096 行 × 约 30B ≈ 120KB 上限）。var 供测试收窄。
	securityTimingQueueSize = 4096
)

// securityTimingWriterAcquire/securityTimingWriterRelease 由写点 handler 的
// Provision/Cleanup 调用（引用计数启停写管线）。
func securityTimingWriterAcquire() {
	securityTimingStateMu.Lock()
	defer securityTimingStateMu.Unlock()
	securityTimingRefs++
	if securityTimingCh != nil {
		return
	}
	ch := make(chan string, securityTimingQueueSize)
	done := make(chan struct{})
	securityTimingCh = ch
	securityTimingDone = done
	go securityTimingWriter(ch, done)
}

func securityTimingWriterRelease() {
	securityTimingStateMu.Lock()
	if securityTimingRefs > 0 {
		securityTimingRefs--
	}
	if securityTimingRefs != 0 || securityTimingCh == nil {
		securityTimingStateMu.Unlock()
		return
	}
	ch := securityTimingCh
	done := securityTimingDone
	securityTimingCh = nil
	securityTimingDone = nil
	securityTimingStateMu.Unlock()
	// close 与 Append 的入队互斥（入队持 RLock，此处持 Lock 完成关闭后才
	// 有后续入队读到 nil 丢弃），不会 send-on-closed。排空等待在锁外——
	// Cleanup 路径可阻塞，请求路径不经此。
	close(ch)
	<-done
}

// securityTimingWriter 专职落盘 goroutine：惰性打开 fd（失败丢行、下一行
// 重试，静默降级语义不变），channel 关闭后排空剩余行再退出。
func securityTimingWriter(ch <-chan string, done chan<- struct{}) {
	defer close(done)
	var fd *os.File
	defer func() {
		if fd != nil {
			_ = fd.Close()
		}
	}()
	for line := range ch {
		if fd == nil {
			_ = os.MkdirAll(filepath.Dir(securityTimingLogPath), 0755)
			f, err := os.OpenFile(securityTimingLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
			if err != nil {
				continue
			}
			fd = f
		}
		_, _ = fmt.Fprintln(fd, line)
	}
}

// AppendSecurityTiming 追加一行「<id> <us>」到耗时侧车日志(写侧:blocked_counter/timing_pre/timing_end 三点)。
// 非阻塞入队：队列满或写管线未启动（无写点 handler 在役）时静默丢弃——
// 耗时是增强信息,不产生任何请求路径错误、不阻塞请求路径。
func AppendSecurityTiming(id string, durationUs int64) {
	if id == "" {
		return
	}
	line := id + " " + strconv.FormatInt(durationUs, 10)
	securityTimingStateMu.RLock()
	defer securityTimingStateMu.RUnlock()
	if securityTimingCh == nil {
		return
	}
	select {
	case securityTimingCh <- line:
	default: // 队列满丢弃
	}
}

// recordSecurityTiming 读耗时关联头对（timing ID + 起始纳秒）并记录一段耗时——
// PLUG-R1（第 69 轮 P4）：SecurityTimingPre/End 两 ServeHTTP 原逐字重复，收敛为
// 本 helper，suffix 区分收点（":pre" 预检段 / ":end" 全链）。头对缺失或起始
// 时间戳不可解析时静默跳过（耗时是增强信息，不产生请求路径错误）。
func recordSecurityTiming(r *http.Request, suffix string) {
	timingID := r.Header.Get(securityTimingHeader)
	startNsStr := r.Header.Get(securityTimingStartHeader)
	if timingID != "" && startNsStr != "" {
		if startNs, perr := strconv.ParseInt(startNsStr, 10, 64); perr == nil {
			AppendSecurityTiming(timingID+suffix, (time.Now().UnixNano()-startNs)/1000) // ns→µs
		}
	}
}

// securityTimingID 生成 16 字符随机 hex 作 timing 关联 ID(第 62 轮 F62-29:
// 原 4 字节生日界下 1 万在途即 ~1.2% 任意对碰撞概率——扩到 8 字节对齐
// coraza tx.ID 长度,碰撞面消除;rand 失败返回空串=该请求不计耗时,静默降级)。
func securityTimingID() string {
	b := make([]byte, 8)
	if _, err := cryptorand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}
