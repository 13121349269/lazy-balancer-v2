package services

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"lazy-balancer-v2/internal/db"
)

// AdminTLSConfig holds the admin-panel HTTPS settings stored in global_config.
type AdminTLSConfig struct {
	Enabled bool
	Mode    string // selfsigned | upload（acme 未实现：handlers/admintls.go:91,309 仅放行这两者）
	Cert    string
	Key     string
}

type adminTLSFingerprint struct {
	Enabled     bool
	Mode        string
	Certificate [sha256.Size]byte
}

var runtimeAdminTLS atomic.Pointer[adminTLSFingerprint]

func fingerprintAdminTLS(cfg AdminTLSConfig) adminTLSFingerprint {
	return adminTLSFingerprint{
		Enabled: cfg.Enabled,
		Mode:    cfg.Mode,
		// LBH-B-N2（第 72 轮）：\x00 分隔消除 cert/key 无分隔拼接的理论双解
		// （"A"+"BC" 与 "AB"+"C" 同串同哈希，真实轮换会被误判为未变化）；
		// PEM 内容不含 NUL，分隔符不引入新的碰撞面。
		Certificate: sha256.Sum256([]byte(cfg.Cert + "\x00" + cfg.Key)),
	}
}

// RecordRuntimeAdminTLS captures the state the process actually started with;
// the sync applier compares later states against it.
func RecordRuntimeAdminTLS(cfg AdminTLSConfig) {
	fingerprint := fingerprintAdminTLS(cfg)
	runtimeAdminTLS.Store(&fingerprint)
}

// RuntimeAdminTLSChanged reports whether the given config differs from the
// state the process started with, meaning a restart is required to apply it.
func RuntimeAdminTLSChanged(cfg AdminTLSConfig) bool {
	v := runtimeAdminTLS.Load()
	if v == nil {
		return false
	}
	return *v != fingerprintAdminTLS(cfg)
}

func LoadAdminTLSConfig() AdminTLSConfig {
	cfg := AdminTLSConfig{Mode: "selfsigned"}
	if db.DB == nil {
		return cfg
	}
	var enabled int
	var mode, cert, key string
	err := db.DB.QueryRow(`SELECT COALESCE(admin_tls_enabled,0), COALESCE(admin_tls_mode,'selfsigned'),
		COALESCE(admin_tls_cert,''), COALESCE(admin_tls_key,'')
		FROM global_config WHERE id=1`).Scan(&enabled, &mode, &cert, &key)
	if err != nil {
		// U8-P5-4：查询失败不得无声吞掉——一次性 warn 留痕后按默认形态返回
		//（API 形态不变，4 消费点无感；db nil 分支属启动窗口正常路径不告警）。
		Logf("warn", "LoadAdminTLSConfig: query failed, falling back to selfsigned default: %v", err)
		return cfg
	}
	cfg.Enabled = enabled == 1
	cfg.Mode = mode
	cfg.Cert = cert
	cfg.Key = key
	return cfg
}

// ResolveCertificate returns the TLS certificate for the admin panel,
// generating a self-signed one on first use when configured so.
func (c AdminTLSConfig) ResolveCertificate(dataDir string) (tls.Certificate, error) {
	switch c.Mode {
	case "upload":
		if c.Cert == "" || c.Key == "" {
			return tls.Certificate{}, fmt.Errorf("上传证书模式但未提供证书内容")
		}
		return tls.X509KeyPair([]byte(c.Cert), []byte(c.Key))
	default:
		return selfSignedCert(dataDir)
	}
}

// selfSignedCert loads or generates a self-signed admin certificate so it is
// stable across restarts; cluster peers skip verification for it anyway.
func selfSignedCert(dataDir string) (tls.Certificate, error) {
	certPath := filepath.Join(dataDir, "admin_tls.crt")
	keyPath := filepath.Join(dataDir, "admin_tls.key")
	// LBH-B-N1（第 72 轮）：先读后验——「双文件可读」不代表是合法证书对；
	// 存在但损坏的对（截断/换位/垃圾内容）原样上抛会让启动进入崩溃循环且
	// 面板无清除入口。X509KeyPair 验证通过才复用，否则记 warn 落既有重生成
	// 路径自愈。
	if certPEM, err1 := os.ReadFile(certPath); err1 == nil {
		if keyPEM, err2 := os.ReadFile(keyPath); err2 == nil {
			cert, err3 := tls.X509KeyPair(certPEM, keyPEM)
			if err3 == nil {
				return cert, nil
			}
			Logf("warn", "管理面板自签名证书对损坏（%s / %s），将重新生成: %v", certPath, keyPath, err3)
		}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("生成自签名私钥失败: %w", err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Lazy Balancer V2", Organization: []string{"XiaoBao"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(50, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("生成自签名证书失败: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("编码私钥失败: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := writeAdminTLSCertPair(certPath, keyPath, certPEM, keyPEM); err != nil {
		return tls.Certificate{}, fmt.Errorf("保存自签名证书: %w", err)
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

func writeAdminTLSCertPair(certPath, keyPath string, certPEM, keyPEM []byte) error {
	return writeCertPair(certPath, keyPath, string(certPEM), string(keyPEM))
}
