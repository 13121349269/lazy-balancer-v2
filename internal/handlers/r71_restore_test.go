package handlers

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"

	"github.com/gin-gonic/gin"
)

// fakeCaddyRecorder 记录 /load POST 的配置体，供恢复断言。
type fakeCaddyRecorder struct {
	loads []string
}

func newFakeCaddyServer(t *testing.T, rec *fakeCaddyRecorder) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/load":
			// LBH-B-R4（第 69 轮）：io.ReadAll 收满请求体——单次 Read 不保证
			// 读满（io.Reader 契约），且 ContentLength=-1（chunked）时
			// make([]byte,-1) 直接 panic。
			body, _ := io.ReadAll(r.Body)
			rec.loads = append(rec.loads, string(body))
			w.WriteHeader(http.StatusOK)
		case "/config/":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"apps":{}}`))
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// R71 N-4/N-1（2026-09-06 裁定 ④' 后重述；第 72 轮孤儿自愈迁移）：UpdateRule
// 对 **ACME 规则** 的 409（证书在途）早退仍零扰动（acmeToAcme 守卫测试覆盖）。
// 本场景（TCP 规则+遗留 queued 死形态任务）在第 72 轮孤儿自愈语义下改为：
// 保存 200 且遗留任务行被删除——孤儿自愈优先于 409 守卫（用户裁定：脱离
// ACME 的规则不得被遗留任务挡住，残留行直接清理）。
func TestUpdateRule_409_restoresRuntimeForTCP(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	rec := &fakeCaddyRecorder{}
	fake := newFakeCaddyServer(t, rec)
	h.caddyService = services.NewCaddyService(fake.URL)

	// Given：一条启用中的 TCP 规则 + 一个非终态证书任务（遗留死形态）
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source)
		VALUES ('lb_409tcp','orig','tcp','',9471,1,0,'manual');
		UPDATE lb_rules SET description='' WHERE caddy_id='lb_409tcp';
		INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES ('lb_409tcp','10.0.0.1',9471,1,1,'tcp');
		INSERT INTO cert_jobs (rule_id,domain,status) VALUES ('lb_409tcp','','queued')`); err != nil {
		t.Fatalf("seed: %v", err)
	}

	router := gin.New()
	router.PUT("/rules/:caddy_id", h.UpdateRule)
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_409tcp", strings.NewReader(
		`{"name":"edited","protocol":"tcp","listen_port":9471,"strategy":"weighted_round_robin","upstreams":[{"host":"10.9.9.9","port":9999,"weight":1,"enabled":true,"protocol":"tcp"}]}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200（孤儿自愈：TCP 规则不被遗留任务挡住）", response.Code, response.Body.String())
	}
	var remaining int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM cert_jobs WHERE rule_id='lb_409tcp'").Scan(&remaining); err != nil || remaining != 0 {
		t.Fatalf("cert jobs=%d err=%v, want 0（遗留任务随保存清理）", remaining, err)
	}
}
