package config

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoad_parses_metrics_interval_with_safe_minimum(t *testing.T) {
	t.Setenv("JWT_SECRET", "test-secret")
	tests := []struct {
		name     string
		interval int
		want     int
	}{
		{name: "configured interval", interval: 12, want: 12},
		{name: "positive interval below minimum", interval: 1, want: 5},
		{name: "zero keeps default", interval: 0, want: 30},
		{name: "negative keeps default", interval: -10, want: 30},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			configPath := filepath.Join(t.TempDir(), "config.json")
			content := fmt.Sprintf(`{"metrics_interval":%d}`, test.interval)
			if err := os.WriteFile(configPath, []byte(content), 0600); err != nil {
				t.Fatalf("write config: %v", err)
			}

			// When
			loaded := Load(configPath)

			// Then
			if loaded.MetricsInterval != test.want {
				t.Fatalf("metrics interval=%d, want %d", loaded.MetricsInterval, test.want)
			}
		})
	}
}

func TestLoad_resolves_log_file_with_default(t *testing.T) {
	t.Setenv("JWT_SECRET", "test-secret")
	tests := []struct {
		name     string
		envValue string
		wantPath string
	}{
		{name: "env override", envValue: "/tmp/custom.log", wantPath: "/tmp/custom.log"},
		{name: "empty env falls back to default", envValue: "", wantPath: "/app/logs/lazy-balancer.log"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			t.Setenv("LOG_FILE", test.envValue)

			// When
			loaded := Load("")

			// Then
			if loaded.LogFile != test.wantPath {
				t.Fatalf("log file=%q, want %q", loaded.LogFile, test.wantPath)
			}
		})
	}
}

// ADNS-N1（第 72 轮）：jwt_secret 文件存在但内容过短（非空且 <32 字节）时，
// 覆写重生成必须 log warn——对齐同文件端口回退/密钥目录创建失败分支的可见性
// 准则；此前静默覆写，旧令牌全部失效且零信号。
func TestLoadOrCreateJWTSecret_shortSecretWarnsAndRegenerates(t *testing.T) {
	// Given 过短的既有密钥文件 + 捕获日志
	dir := t.TempDir()
	secretPath := filepath.Join(dir, "jwt_secret")
	if err := os.WriteFile(secretPath, []byte("too-short"), 0600); err != nil {
		t.Fatalf("seed short secret: %v", err)
	}
	var logBuf bytes.Buffer
	origOut := log.Writer()
	log.SetOutput(&logBuf)
	t.Cleanup(func() { log.SetOutput(origOut) })

	// When
	secret := loadOrCreateJWTSecret(dir)

	// Then：重生成 64 字符 hex 并覆写持久化
	if secret == "too-short" || len(secret) != 64 {
		t.Fatalf("secret=%q (len %d); want regenerated 64-char hex", secret, len(secret))
	}
	data, err := os.ReadFile(secretPath)
	if err != nil {
		t.Fatalf("read secret: %v", err)
	}
	if string(data) != secret {
		t.Fatalf("file=%q; want persisted regenerated secret", data)
	}
	// And：过短覆写必须 warn 可见
	if !strings.Contains(logBuf.String(), "过短") {
		t.Fatalf("short-secret overwrite must log a warning, got %q", logBuf.String())
	}
}

// 回归/边界形状：≥32 字节的既有密钥原样复用且零日志；空文件按缺失处理
// 重生成但不 warn（warn 仅针对非空过短——空文件等同未初始化）。
func TestLoadOrCreateJWTSecret_validReusedAndEmptyQuiet(t *testing.T) {
	t.Run("valid secret reused quietly", func(t *testing.T) {
		// Given 合法长度密钥文件
		dir := t.TempDir()
		want := strings.Repeat("s", 48)
		if err := os.WriteFile(filepath.Join(dir, "jwt_secret"), []byte(want), 0600); err != nil {
			t.Fatal(err)
		}
		var logBuf bytes.Buffer
		origOut := log.Writer()
		log.SetOutput(&logBuf)
		t.Cleanup(func() { log.SetOutput(origOut) })

		// When
		secret := loadOrCreateJWTSecret(dir)

		// Then
		if secret != want {
			t.Fatalf("secret=%q; want existing valid secret reused", secret)
		}
		if logBuf.Len() != 0 {
			t.Fatalf("valid secret reuse must not log, got %q", logBuf.String())
		}
	})
	t.Run("empty file regenerates without short-warning", func(t *testing.T) {
		// Given 空密钥文件（等同未初始化，非「过短」形态）
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "jwt_secret"), nil, 0600); err != nil {
			t.Fatal(err)
		}
		var logBuf bytes.Buffer
		origOut := log.Writer()
		log.SetOutput(&logBuf)
		t.Cleanup(func() { log.SetOutput(origOut) })

		// When
		secret := loadOrCreateJWTSecret(dir)

		// Then
		if len(secret) != 64 {
			t.Fatalf("secret=%q (len %d); want regenerated 64-char hex", secret, len(secret))
		}
		if strings.Contains(logBuf.String(), "过短") {
			t.Fatalf("empty file must not trigger short-secret warning, got %q", logBuf.String())
		}
	})
}
