package services

import "testing"

// 重试窗口（方案 C，2026-10-12 用户裁定）：HTTP 与 TCP 的 tcp_try_duration 值域
// 通用（[-1,60000]），但 td==0/-1 渲染语义按协议分叉——td>0 按值发射窗口/间隔
// （间隔缺省 250ms）；HTTP 侧 td==0 兜底 5s/250ms（存量 HTTP 行恒 0，零行为变化）、
// td==-1 显式禁用重试（发射 retries=0，不发射 try_duration/try_interval）；TCP 侧
// td==0/-1 均零窗口不发射（l4 proxy 无 retries 字段）。NTLM 接管态由 UI 修改器
// 把 td 落 -1，渲染对 ntlm_compatible 零感知。

func httpRoutesWithTryDuration(t *testing.T, td, ti int) map[string]interface{} {
	t.Helper()
	rule := baseHTTPRule()
	rule.TCPTryDuration = td
	rule.TCPTryInterval = ti
	routes := renderedHTTPRoutes(t, GenerateSingleRuleCaddyConfig(rule))
	return mustMap(t, reverseProxyHandler(t, routes[len(routes)-1])["load_balancing"], "load_balancing")
}

func TestGenerateSingleRuleCaddyConfig_retryWindow_zero_keepsDefaultFallback(t *testing.T) {
	// Given：存量 HTTP 行恒 td=0（TCP 专属语义时代落库）——兜底 5s/250ms 不变
	loadBalancing := httpRoutesWithTryDuration(t, 0, 0)

	// Then
	if _, exists := loadBalancing["retries"]; exists {
		t.Fatalf("td=0 must not emit retries, got %v", loadBalancing["retries"])
	}
	if loadBalancing["try_duration"] != "5s" || loadBalancing["try_interval"] != "250ms" {
		t.Fatalf("td=0 try_duration=%v try_interval=%v, want 5s/250ms", loadBalancing["try_duration"], loadBalancing["try_interval"])
	}
}

func TestGenerateSingleRuleCaddyConfig_retryWindow_positive_emitsWindow(t *testing.T) {
	// Given：td>0 → 按值发射窗口；间隔缺省 250ms
	loadBalancing := httpRoutesWithTryDuration(t, 3000, 0)
	if loadBalancing["try_duration"] != "3000ms" || loadBalancing["try_interval"] != "250ms" {
		t.Fatalf("td=3000 got try_duration=%v try_interval=%v", loadBalancing["try_duration"], loadBalancing["try_interval"])
	}

	// 显式间隔
	loadBalancing = httpRoutesWithTryDuration(t, 3000, 500)
	if loadBalancing["try_interval"] != "500ms" {
		t.Fatalf("ti=500 got try_interval=%v", loadBalancing["try_interval"])
	}
	if _, exists := loadBalancing["retries"]; exists {
		t.Fatalf("td>0 must not emit retries, got %v", loadBalancing["retries"])
	}
}

func TestGenerateSingleRuleCaddyConfig_retryWindow_disabled_disablesCrossUpstreamRetry(t *testing.T) {
	// Given：td=-1（NTLM 接管态的库级表达——挑战-应答必须固定同一上游）
	loadBalancing := httpRoutesWithTryDuration(t, -1, 0)

	// Then：retries=0 且不发射 try_duration/try_interval
	if got, ok := loadBalancing["retries"]; !ok || got != 0 {
		t.Fatalf("td=-1 retries=%v (present=%v), want 0", got, ok)
	}
	if _, exists := loadBalancing["try_duration"]; exists {
		t.Fatalf("td=-1 must not emit try_duration, got %v", loadBalancing["try_duration"])
	}
	if _, exists := loadBalancing["try_interval"]; exists {
		t.Fatalf("td=-1 must not emit try_interval, got %v", loadBalancing["try_interval"])
	}
}

// 上游强制 HTTP/1.1（通用列，2026-10-12）：仅 https 上游发射
// transport{protocol:http, versions:["1.1"]}（Caddy HTTPTransport.Versions——
// 限定协议版本集即禁 h2，TLS 上游同时从 ALPN 剔除）；http 明文上游不输出。
func TestGenerateSingleRuleCaddyConfig_forceHTTP1_httpsUpstreamEmitsTransportVersions(t *testing.T) {
	rule := baseHTTPRule()
	rule.UpstreamForceHTTP1 = 1
	rule.Upstreams = []UpstreamConfig{
		{Host: "10.0.0.10", Port: 8443, Weight: 1, Protocol: "https", Enabled: true},
	}

	routes := renderedHTTPRoutes(t, GenerateSingleRuleCaddyConfig(rule))
	proxy := reverseProxyHandler(t, routes[len(routes)-1])
	transport := mustMap(t, proxy["transport"], "transport")
	if transport["protocol"] != "http" {
		t.Fatalf("transport protocol=%v, want http", transport["protocol"])
	}
	assertEqual(t, transport["versions"], []string{"1.1"})
}

func TestGenerateSingleRuleCaddyConfig_forceHTTP1_plainHTTPUpstreamOmitsTransport(t *testing.T) {
	rule := baseHTTPRule()
	rule.UpstreamForceHTTP1 = 1

	routes := renderedHTTPRoutes(t, GenerateSingleRuleCaddyConfig(rule))
	proxy := reverseProxyHandler(t, routes[len(routes)-1])
	if _, exists := proxy["transport"]; exists {
		t.Fatalf("http 明文上游不应输出 transport（无 ALPN/协商面）, got %v", proxy["transport"])
	}

	// 开关关闭 + https 上游：transport 照常（tls 块），但不得携带 versions
	rule.UpstreamForceHTTP1 = 0
	rule.Upstreams = []UpstreamConfig{
		{Host: "10.0.0.10", Port: 8443, Weight: 1, Protocol: "https", Enabled: true},
	}
	routes = renderedHTTPRoutes(t, GenerateSingleRuleCaddyConfig(rule))
	proxy = reverseProxyHandler(t, routes[len(routes)-1])
	transport := mustMap(t, proxy["transport"], "transport")
	if _, exists := transport["versions"]; exists {
		t.Fatalf("force_http1=0 不应输出 versions, got %v", transport["versions"])
	}
}
