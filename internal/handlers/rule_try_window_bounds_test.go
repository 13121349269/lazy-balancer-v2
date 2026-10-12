package handlers

// LBH-1（第 73 轮 P4·设计漂移）：重试窗口上界缺失——rule_features.go 注释
// 宣称 http 侧 [-1,60000]、TCP 侧 [0,60000]，但 TCP 分支只拒负值
//（tcp_try_duration/tcp_try_interval 均无 >60000 上界）、http 侧
// tcp_try_interval 亦无上界。999999ms/10^12ms 可经 API/MCP/导入/集群快照
// 落库并渲染（L4 proxy try_duration 溢出）。本文件锁定三道面：
//   ① 保存门（validateRuleFeatures）两协议上界；
//   ② UpdateRule 存量越界行的编辑自愈（镜像 LBH-A-N1 负值先例）；
//   ③ DuplicateRule 源行越界值不放大到副本。
// 存量为纯测试文件（唯一写点），不触碰既有钉测。

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// LBH-1①：保存门上界——两协议、两字段的 >60000 值一律拒绝；60000 边界与
// http 侧 td=-1（NTLM 接管态）仍放行。
func TestValidateRuleFeatures_rejectsOutOfRangeTryWindow(t *testing.T) {
	base := func(protocol string) ruleFeatureInput {
		input := ruleFeatureInput{
			Protocol:           protocol,
			Strategy:           "weighted_round_robin",
			ListenPort:         19099,
			TCPTryInterval:     250,
			TCPTryDuration:     3,
			TCPHealthCheckPort: 9123,
		}
		if protocol == "http" {
			input.ListenPort = 8080

			input.TCPHealthCheckPort = 0
		}
		return input
	}

	rejectCases := []struct {
		name   string
		mutate func(*ruleFeatureInput)
	}{
		{"tcp duration above max", func(i *ruleFeatureInput) { i.TCPTryDuration = 60001 }},
		{"tcp interval above max", func(i *ruleFeatureInput) { i.TCPTryInterval = 60001 }},
		{"tcp duration far above max", func(i *ruleFeatureInput) { i.TCPTryDuration = 1_000_000 }},
		{"http interval above max", func(i *ruleFeatureInput) { i.Protocol = "http"; i.TCPHealthCheckPort = 0; i.TCPTryInterval = 60001 }},
		{"http duration above max", func(i *ruleFeatureInput) { i.Protocol = "http"; i.TCPHealthCheckPort = 0; i.TCPTryDuration = 60001 }},
	}
	for _, tc := range rejectCases {
		t.Run(tc.name, func(t *testing.T) {
			input := base("tcp")
			tc.mutate(&input)
			if err := validateRuleFeatures(input); err == nil {
				t.Fatalf("%s must be rejected, got nil error", tc.name)
			}
		})
	}

	// 边界放行形状：60000 两协议、两字段均为合法上界
	validCases := []struct {
		name   string
		mutate func(*ruleFeatureInput)
	}{
		{"tcp at upper bound", func(i *ruleFeatureInput) { i.TCPTryDuration = 60000; i.TCPTryInterval = 60000 }},
		{"http at upper bound", func(i *ruleFeatureInput) {
			i.Protocol = "http"
			i.TCPHealthCheckPort = 0
			i.TCPTryDuration = 60000
			i.TCPTryInterval = 60000
		}},
		{"http ntlm sentinel -1", func(i *ruleFeatureInput) {
			i.Protocol = "http"
			i.TCPHealthCheckPort = 0
			i.TCPTryDuration = -1
			i.TCPTryInterval = 250
		}},
	}
	for _, tc := range validCases {
		t.Run(tc.name, func(t *testing.T) {
			input := base("tcp")
			tc.mutate(&input)
			if err := validateRuleFeatures(input); err != nil {
				t.Fatalf("%s must pass, got %v", tc.name, err)
			}
		})
	}
}

// LBH-1②（TCP）：直改 DB 的越界 TCP 行随任意同协议编辑自愈归零（0=默认窗口），
// 修复前会命中新增上界门 400 死端（与 LBH-A-N1 负值自愈同格）。
func TestUpdateRule_tcpEditHealsOutOfRangeTryWindowResidue(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)

	// Given：直改 DB 的 TCP 行带 td=60001/ti=70000（越界存量）
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,enabled,tcp_try_duration,tcp_try_interval)
		VALUES ('lb_tcptrymax','tcptrymax','','tcp','',18611,'weighted_round_robin',1,60001,70000)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES ('lb_tcptrymax','up.test',9000,1,1,'tcp')`); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}

	// When：同协议编辑（纯改名，不携带重试窗口字段）
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_tcptrymax", strings.NewReader(`{"name":"tcptrymax-renamed","protocol":"tcp"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	// Then：200（修复前 400 上界门死端）且越界值归零
	if response.Code != http.StatusOK {
		t.Fatalf("tcp edit: status=%d body=%s", response.Code, response.Body.String())
	}
	var tryDuration, tryInterval int
	if err := db.DB.QueryRow(`SELECT COALESCE(tcp_try_duration,0), COALESCE(tcp_try_interval,0) FROM lb_rules WHERE caddy_id='lb_tcptrymax'`).
		Scan(&tryDuration, &tryInterval); err != nil {
		t.Fatal(err)
	}
	if tryDuration != 0 || tryInterval != 0 {
		t.Fatalf("越界重试窗口未自愈: tcp_try_duration=%d tcp_try_interval=%d, want 0/0", tryDuration, tryInterval)
	}
}

// LBH-1②（http）：越界 tcp_try_interval 在 http 侧同样无自救路径（新增上界门
// 后任意编辑 400），编辑自愈归零；-1 合法哨兵不归零（本用例只带 ti 越界）。
func TestUpdateRule_httpEditHealsOutOfRangeTryIntervalResidue(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)

	// Given：直改 DB 的 http 行带 ti=70000（越界存量）
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,enabled,tcp_try_duration,tcp_try_interval)
		VALUES ('lb_httptrymax','httptrymax','','http','httptrymax.test',18612,'weighted_round_robin',1,0,70000)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES ('lb_httptrymax','up.test',80,1,1,'http')`); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}

	// When：同协议编辑（纯改名）
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_httptrymax", strings.NewReader(`{"name":"httptrymax-renamed"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	// Then：200 且越界 interval 归零
	if response.Code != http.StatusOK {
		t.Fatalf("http edit: status=%d body=%s", response.Code, response.Body.String())
	}
	var tryInterval int
	if err := db.DB.QueryRow(`SELECT COALESCE(tcp_try_interval,0) FROM lb_rules WHERE caddy_id='lb_httptrymax'`).Scan(&tryInterval); err != nil {
		t.Fatal(err)
	}
	if tryInterval != 0 {
		t.Fatalf("越界重试间隔未自愈: tcp_try_interval=%d, want 0", tryInterval)
	}
}

// LBH-1③：DuplicateRule 把源行越界窗口原样喂进 validateRuleFeatures——tcp 与
// http 源行复制均命中上界门 400 死端；越界值不放大到副本，非越界值原样复制。
func TestDuplicateRule_healsOutOfRangeTryWindowResidue(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules/:caddy_id/duplicate", handler.DuplicateRule)

	// tcp 源行
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,enabled,tcp_try_duration,tcp_try_interval)
		VALUES ('lb_tcpdupwin','tcpdupwin','','tcp','',18613,'weighted_round_robin',1,60001,70000)`); err != nil {
		t.Fatalf("seed tcp rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES ('lb_tcpdupwin','up.test',9000,1,1,'tcp')`); err != nil {
		t.Fatalf("seed tcp upstream: %v", err)
	}
	// http 源行（越界 interval）
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,enabled,tcp_try_duration,tcp_try_interval)
		VALUES ('lb_httpdupwin','httpdupwin','','http','httpdupwin.test',18614,'weighted_round_robin',1,0,65535)`); err != nil {
		t.Fatalf("seed http rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES ('lb_httpdupwin','up.test',80,1,1,'http')`); err != nil {
		t.Fatalf("seed http upstream: %v", err)
	}

	cases := []struct {
		name       string
		sourceID   string
		copyName   string
		wantStatus int
	}{
		{"tcp source", "lb_tcpdupwin", "tcpdupwin（副本）", http.StatusCreated},
		{"http source", "lb_httpdupwin", "httpdupwin（副本）", http.StatusCreated},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/rules/"+tc.sourceID+"/duplicate", nil))
			if response.Code != tc.wantStatus {
				t.Fatalf("duplicate %s: status=%d body=%s, want %d", tc.name, response.Code, response.Body.String(), tc.wantStatus)
			}
			var tryDuration, tryInterval sql.NullInt64
			if err := db.DB.QueryRow(`SELECT tcp_try_duration, tcp_try_interval FROM lb_rules WHERE name=?`, tc.copyName).
				Scan(&tryDuration, &tryInterval); err != nil {
				t.Fatalf("read copy %s: %v", tc.copyName, err)
			}
			if tryDuration.Int64 != 0 || tryInterval.Int64 != 0 {
				t.Fatalf("副本越界窗口未归零: tcp_try_duration=%d tcp_try_interval=%d, want 0/0", tryDuration.Int64, tryInterval.Int64)
			}
		})
	}
}
