package caddygeoip

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/prometheus/client_golang/prometheus"
)

// securityBlockedMetricName 是安全拦截计数器指标名。
const securityBlockedMetricName = "security_blocked_total"

// newSecurityBlockedCounterVec 每次 Provision 新建 CounterVec 并注册——
// caddy-l4 newProxyMetrics 同模式(l4proxy/metrics.go:54):同 registry 时
// registerOrExisting 复用已注册实例(不丢数据),跨 reload 新 registry 时
// 全新注册(归零,与 caddy_http_* 同纪元)——P3-1(第 28.5 轮审计):包级
// singleton 跨 reload 不归零,与 caddy_http_* 纪元错位,扣除常态钳 4xx 到 0。
func newSecurityBlockedCounterVec(reg *prometheus.Registry) *prometheus.CounterVec {
	return registerOrExisting(reg, prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "lazybalancer",
			Name:      securityBlockedMetricName,
			Help:      "Requests interrupted by the security engine (WAF/GeoIP/IP ACL) with a 4xx status.",
		},
		[]string{"rule"},
	))
}

// registerOrExisting 注册到 reg,已注册时复用既有实例——Caddy reload 会重
// Provision,重复注册 MustRegister 会 panic(崩溃风险,用户裁定零容忍);
// 与 caddy-l4 的 registerOrExisting(l4proxy/metrics.go:34)同模式。
func registerOrExisting[C prometheus.Collector](reg *prometheus.Registry, c C) C {
	if err := reg.Register(c); err != nil {
		var are prometheus.AlreadyRegisteredError
		if errors.As(err, &are) {
			if existing, ok := are.ExistingCollector.(C); ok {
				return existing
			}
		}
		// 其他注册错误=指标不可用——回落未注册实例(计数 no-op 而非崩溃)。
	}
	return c
}

func init() {
	caddy.RegisterModule(SecurityBlockedCounter{})
}

// SecurityBlockedCounter 是安全拦截计数中间件:包装 WAF handler,检测安全层
// 中断(caddyhttp.HandlerError 且 4xx status,且 len(ID)==16 或 status==429)并
// 按规则计数。覆盖:coraza 中断(WAF/GeoIP/IP ACL,ID=tx.ID() 16 字符)+限流 429;
// 排除:proxy 499/request_body 413/其他 caddyhttp.Error 4xx(ID 9 字符)/coraza
// 引擎 500(4xx 约束);上游 4xx 不产 HandlerError 不误计。
// 稳定优先设计(2026-09-15 用户裁定,负载均衡/WAF 稳定最重要):
//   - Provision 无操作——无 I/O/无外部依赖/无失败模式,配置加载零风险;
//   - ServeHTTP 只读检测——不修改请求/响应/错误,链语义与无插件时逐字节一致;
//   - 无锁/无共享态——prometheus counter 线程安全,reload 幂等;
//   - API 兼容面:caddy.Module/caddyhttp.HandlerError 稳定(v2.0 起);
//     ctx.GetMetricsRegistry() 是 EXPERIMENTAL(Caddy 标注 subject to change)
//     ——已 nil 守卫(移除则降级为不计数而非崩溃),P5-3(第 28.5 轮审计)。
type SecurityBlockedCounter struct {
	// Rule 是所属负载均衡规则的 caddy_id(渲染期静态注入)。
	Rule string `json:"rule,omitempty"`

	metrics *prometheus.CounterVec
}

// CaddyModule returns the Caddy module information.
func (SecurityBlockedCounter) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.lb_security_blocked_counter",
		New: func() caddy.Module { return new(SecurityBlockedCounter) },
	}
}

// Provision 注册计数器到 Caddy 的 metrics registry(非默认 registry——
// 默认 registry 的指标不暴露在 Caddy /metrics 端点);registerOrExisting
// 保证 reload 幂等(重复注册复用实例,不 panic)。同时启动耗时侧车写管线
// 引用（PLUG-N1 第 72 轮——本 handler 是拦截点耗时写点之一）。
func (h *SecurityBlockedCounter) Provision(ctx caddy.Context) error {
	if reg := ctx.GetMetricsRegistry(); reg != nil {
		h.metrics = newSecurityBlockedCounterVec(reg)
	}
	securityTimingWriterAcquire()
	return nil
}

// Cleanup 释放本 handler 的耗时侧车写管线引用（PLUG-N1 第 72 轮）。
func (h *SecurityBlockedCounter) Cleanup() error {
	securityTimingWriterRelease()
	return nil
}

// ServeHTTP 调用链下游处理器,只读检查返回错误:安全层中断(HandlerError 且
// 4xx status,且 len(ID)==16[coraza tx.ID] 或 status==429[限流])时按规则计数;
// 上游 4xx 不产 HandlerError(反向代理直写响应)不误计;返回值原样透传。
//
// 安全处理耗时(2026-09-27 用户裁定):请求进入时注入 X-Lb-Security-Timing-Id
// 请求头(coraza 审计日志的 request.headers 天然收录该头——摄取管道从审计
// 条目读出同一 ID 即可对上),next 返回后记录耗时到共享表——弹框「处理耗时」
// 的数据源。写侧在本方法(拦截事件)+security_timing_pre/end(放行事件);
// 读侧在 internal/services/securityevents.go 的 securityTimingLoad(tick 级
// 合并 map+读后截断)。
func (h *SecurityBlockedCounter) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// 安全处理耗时:注入 timing ID + 起始纳秒双头(coraza 审计日志收录 ID;
	// SecurityTimingEnd 处理器在安全链末尾读起始头计算 passed 事件的纯评估
	// 耗时)。起始头与 ID 头均在 proxyRequestHeaders 删除清单剥离,不上泄上游。
	timingID := securityTimingID()
	if timingID != "" {
		r.Header.Set(securityTimingHeader, timingID)
		r.Header.Set(securityTimingStartHeader, strconv.FormatInt(time.Now().UnixNano(), 10))
	}
	start := time.Now()

	err := next.ServeHTTP(w, r)

	var herr caddyhttp.HandlerError
	// P3-2(第 28.5 轮审计):「ID 非空+4xx」误纳非安全 4xx——caddyhttp.Error
	// 恒生成 ID(randString 9 字符),proxy 499/request_body 413 也被计入。
	// 精确判定:len(ID)==16(coraza tx.ID,randomString(16))或 status==429
	// (限流,caddyhttp.Error 生成 9 字符 ID)——覆盖安全拦截全部,排除
	// proxy 499/request_body 413/其他 caddyhttp.Error 4xx(全 9 字符)。
	// 脆弱点:coraza 若改 tx.ID 长度→断;但 v2.x 一直 16 且 coraza 由
	// Dockerfile pin+构建断言控制——可控。
	isSecurityBlock := err != nil && errors.As(err, &herr) &&
		herr.StatusCode >= 400 && herr.StatusCode < 500 &&
		(len(herr.ID) == 16 || herr.StatusCode == http.StatusTooManyRequests)

	// 安全处理耗时——双点计时的「拦截点」:安全中断(HandlerError 返回)时
	// 链未到 reverse_proxy,此处耗时=纯安全评估;放行事件的耗时由安全链末尾
	// 的 SecurityTimingEnd 处理器记录(此处 next 返回值混入上游代理往返,
	// 不能用——实测 329ms 中主要是上游响应时间而非 WAF 评估)。
	if timingID != "" && isSecurityBlock {
		AppendSecurityTiming(timingID+":end", time.Since(start).Microseconds()) // 分段键:end(预检拦时=end 即预检耗时)
	}

	if isSecurityBlock {
		// F1(第 28.6 轮审计):P3-2 判定丢失 4xx 约束——coraza 引擎 500
		// (16 字符 tx.ID)被误计为安全拦截且吃掉一个合法 4xx。恢复 4xx 约束。
		if h.metrics != nil {
			h.metrics.WithLabelValues(h.Rule).Inc()
		}
	}
	return err
}

// Interface guards(编译期契约,零运行时成本)。
var (
	_ caddy.Provisioner           = (*SecurityBlockedCounter)(nil)
	_ caddy.CleanerUpper          = (*SecurityBlockedCounter)(nil)
	_ caddyhttp.MiddlewareHandler = (*SecurityBlockedCounter)(nil)
)
