package services

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"
)

func TestRuntimeAdminTLSChanged_detects_uploaded_certificate_rotation(t *testing.T) {
	t.Cleanup(func() { runtimeAdminTLS.Store(nil) })
	RecordRuntimeAdminTLS(AdminTLSConfig{Enabled: true, Mode: "upload", Cert: "old-cert", Key: "old-key"})

	if !RuntimeAdminTLSChanged(AdminTLSConfig{Enabled: true, Mode: "upload", Cert: "new-cert", Key: "new-key"}) {
		t.Fatal("certificate content changed without changing admin TLS mode")
	}
}

// LBH-B-N1（第 72 轮）：存在但损坏的自签证书对必须自愈——读侧仅验「双文件
// 可读」不够，X509KeyPair 解析失败（截断/换位/垃圾内容）原样上抛会让启动
// 进入崩溃循环且面板无清除入口。先读后验：损坏对记 warn 并落既有重生成路径。
func TestSelfSignedCert_corrupt_pair_regenerates(t *testing.T) {
	// Given：两文件可读但不是合法 PEM 证书对
	dir := t.TempDir()
	certPath := filepath.Join(dir, "admin_tls.crt")
	keyPath := filepath.Join(dir, "admin_tls.key")
	if err := os.WriteFile(certPath, []byte("not-a-cert"), 0644); err != nil {
		t.Fatalf("seed corrupt certificate: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("not-a-key"), 0600); err != nil {
		t.Fatalf("seed corrupt key: %v", err)
	}

	// When：默认（selfsigned）模式解析证书
	cert, err := AdminTLSConfig{}.ResolveCertificate(dir)
	if err != nil {
		t.Fatalf("resolve certificate with corrupt on-disk pair: %v", err)
	}
	if len(cert.Certificate) == 0 || cert.PrivateKey == nil {
		t.Fatal("regenerated certificate is incomplete")
	}

	// Then：磁盘对已被重生成（合法 PEM），且二次解析直接命中新对
	regenCert, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read regenerated certificate: %v", err)
	}
	regenKey, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read regenerated key: %v", err)
	}
	if string(regenCert) == "not-a-cert" || string(regenKey) == "not-a-key" {
		t.Fatal("corrupt pair still on disk — regeneration path did not run")
	}
	if _, err := tls.X509KeyPair(regenCert, regenKey); err != nil {
		t.Fatalf("regenerated pair does not parse: %v", err)
	}
	if _, err := (AdminTLSConfig{}).ResolveCertificate(dir); err != nil {
		t.Fatalf("second resolve after regeneration: %v", err)
	}
}

// LBH-B-N2（第 72 轮）：指纹对 cert/key 无分隔拼接存在理论双解——
// cert="A",key="BC" 与 cert="AB",key="C" 同串同哈希，真实轮换会被误判为
// 未变化。钉住「边界组合必须产生不同指纹」。
func TestFingerprintAdminTLS_separates_cert_key_boundary(t *testing.T) {
	t.Cleanup(func() { runtimeAdminTLS.Store(nil) })
	RecordRuntimeAdminTLS(AdminTLSConfig{Enabled: true, Mode: "upload", Cert: "A", Key: "BC"})

	if !RuntimeAdminTLSChanged(AdminTLSConfig{Enabled: true, Mode: "upload", Cert: "AB", Key: "C"}) {
		t.Fatal("different cert/key boundary split produced identical fingerprint")
	}
}

func TestWriteAdminTLSCertPair_second_file_failure_restores_previous_pair(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "admin_tls.crt")
	keyPath := filepath.Join(dir, "admin_tls.key")
	if err := os.WriteFile(certPath, []byte("old-cert"), 0644); err != nil {
		t.Fatalf("seed certificate: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("old-key"), 0600); err != nil {
		t.Fatalf("seed private key: %v", err)
	}
	if err := os.Mkdir(keyPath+".tmp", 0700); err != nil {
		t.Fatalf("block temporary private key write: %v", err)
	}

	if err := writeAdminTLSCertPair(certPath, keyPath, []byte("new-cert"), []byte("new-key")); err == nil {
		t.Fatal("second file write unexpectedly succeeded")
	}
	cert, certErr := os.ReadFile(certPath)
	key, keyErr := os.ReadFile(keyPath)
	if certErr != nil || keyErr != nil {
		t.Fatalf("read pair after rollback: cert=%v key=%v", certErr, keyErr)
	}
	if string(cert) != "old-cert" || string(key) != "old-key" {
		t.Fatalf("pair after rollback=(%q,%q), want previous pair", cert, key)
	}
}
