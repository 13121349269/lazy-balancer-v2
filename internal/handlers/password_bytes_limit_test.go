package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// 密码策略（2026-09-28 用户裁定）：8-24 个可打印 ASCII 字符。
// 汉字/非 ASCII 在策略层以 400 拒绝（bcrypt 之前）；超长(>24)同理。
func TestUserPasswordEndpoints_reject_passwords_over_24_chars(t *testing.T) {
	// 40 个中文 rune = 120 字节——超限且含非 ASCII,策略层双违反
	multibytePassword := strings.Repeat("密", 40)
	tests := []struct {
		name   string
		method string
		path   string
		body   string
		mount  func(*gin.Engine, *Handlers)
	}{
		{name: "create user", method: http.MethodPost, path: "/users", body: `{"username":"mb-create","password":"` + multibytePassword + `","role":"user"}`, mount: func(r *gin.Engine, h *Handlers) { r.POST("/users", h.CreateUser) }},
		{name: "update user", method: http.MethodPut, path: "/users/1", body: `{"password":"` + multibytePassword + `"}`, mount: func(r *gin.Engine, h *Handlers) { r.PUT("/users/:id", h.UpdateUser) }},
		{name: "reset password", method: http.MethodPost, path: "/users/1/reset-password", body: `{"new_password":"` + multibytePassword + `"}`, mount: func(r *gin.Engine, h *Handlers) { r.POST("/users/:id/reset-password", h.ResetUserPassword) }},
		{name: "update current user", method: http.MethodPatch, path: "/users/me", body: `{"password":"` + multibytePassword + `"}`, mount: func(r *gin.Engine, h *Handlers) {
			r.PATCH("/users/me", func(c *gin.Context) { c.Set("user_id", 1); h.UpdateCurrentUser(c) })
		}},
		{name: "setup admin", method: http.MethodPost, path: "/auth/setup", body: `{"username":"mb-setup","password":"` + multibytePassword + `"}`, mount: func(r *gin.Engine, h *Handlers) {
			r.POST("/auth/setup", h.SetupAdmin)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			h := newBackupTestHandlers(t)
			if test.name != "setup admin" {
				if _, err := db.DB.Exec("INSERT INTO users (id,username,password_hash,role,display_name) VALUES (1,'existing','old-hash','admin','Before')"); err != nil {
					t.Fatalf("seed user: %v", err)
				}
			}
			router := gin.New()
			test.mount(router, h)
			request := httptest.NewRequest(test.method, test.path, strings.NewReader(test.body))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()

			router.ServeHTTP(response, request)

			// 超限/非 ASCII 密码在 bcrypt 之前以 400 拒绝(策略层或绑定层均可)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s, want 400", response.Code, response.Body.String())
			}
			if test.name != "setup admin" {
				var passwordHash string
				if err := db.DB.QueryRow("SELECT password_hash FROM users WHERE id=1").Scan(&passwordHash); err != nil {
					t.Fatalf("read user: %v", err)
				}
				if passwordHash != "old-hash" {
					t.Fatalf("password hash=%q, want unchanged", passwordHash)
				}
			}
		})
	}
}

// 恰好 24 个可打印 ASCII 字符的密码应被接受(边界上界)。
func TestCreateUser_accepts_password_of_exactly_24_chars(t *testing.T) {
	h := newBackupTestHandlers(t)
	router := gin.New()
	router.POST("/users", h.CreateUser)
	body := `{"username":"edge32","password":"` + strings.Repeat("a", 24) + `","role":"user"}`
	request := httptest.NewRequest(http.MethodPost, "/users", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s, want 201 (24 chars at limit should pass)", response.Code, response.Body.String())
	}
}

// 25 个字符超出上限应被拒绝(边界外)。
func TestCreateUser_rejects_password_of_25_chars(t *testing.T) {
	h := newBackupTestHandlers(t)
	router := gin.New()
	router.POST("/users", h.CreateUser)
	body := `{"username":"edge33","password":"` + strings.Repeat("a", 25) + `","role":"user"}`
	request := httptest.NewRequest(http.MethodPost, "/users", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400 (25 chars over limit)", response.Code, response.Body.String())
	}
}
