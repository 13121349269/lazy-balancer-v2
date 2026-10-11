package db

import "testing"

// CL-2（第 70 轮审计 P2）：migrateTCPRuleDeadFields 的 WHERE TLS 段此前要求
// 「enable_tls=1 且证书或私钥非空」——TCP+enable_tls=1+双空证书的存量行不被
// 迁移选中（归一函数 normalizeRuleForTransport 只要 EnableTLS=true 就清），
// 主端 DB/导出 canonical/从端落库三面同值不变量对该形态不成立。修复=WHERE
// TLS 段放宽为 OR enable_tls=1，与归一函数谓词逐字对齐。
func TestMigrateTCPRuleDeadFields_clears_tcp_enable_tls_with_empty_certs(t *testing.T) {
	// Given：真实 DB。TCP 行唯一入选特征是 enable_tls=1（其余七字段全零、
	// 证书双空=列默认 NULL）；另放一行 HTTP+TLS 控制行（迁移不得触碰非 TCP 行）。
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec("INSERT OR IGNORE INTO global_config (id, caddy_config) VALUES (1,'{}')"); err != nil {
		t.Fatalf("seed global config: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO lb_rules (id, caddy_id, name, protocol, domain, listen_port, enable_tls, compress_types)
		VALUES (1, 'lb_cl2tcp', 'cl2-tcp', 'tcp', '', 9443, 1, '')`); err != nil {
		t.Fatalf("seed tcp rule: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO lb_rules (id, caddy_id, name, protocol, domain, listen_port, enable_tls, tls_cert, tls_key)
		VALUES (2, 'lb_cl2http', 'cl2-http', 'http', 'cl2.example.test', 8443, 1, 'cert', 'key')`); err != nil {
		t.Fatalf("seed http rule: %v", err)
	}

	// When
	if err := migrateTCPRuleDeadFields(); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// Then：TCP 行 enable_tls 归 0、证书材料清空；HTTP 行原样保留。
	var tcpTLS, httpTLS int
	var tcpCert, tcpKey string
	if err := database.QueryRow(`SELECT COALESCE(enable_tls,0), COALESCE(tls_cert,''), COALESCE(tls_key,'') FROM lb_rules WHERE caddy_id='lb_cl2tcp'`).
		Scan(&tcpTLS, &tcpCert, &tcpKey); err != nil {
		t.Fatalf("read tcp rule: %v", err)
	}
	if tcpTLS != 0 || tcpCert != "" || tcpKey != "" {
		t.Fatalf("tcp rule after migration: enable_tls=%d cert=%q key=%q, want 0/''/''", tcpTLS, tcpCert, tcpKey)
	}
	if err := database.QueryRow(`SELECT COALESCE(enable_tls,0) FROM lb_rules WHERE caddy_id='lb_cl2http'`).Scan(&httpTLS); err != nil {
		t.Fatalf("read http rule: %v", err)
	}
	if httpTLS != 1 {
		t.Fatalf("http rule enable_tls=%d, want untouched 1", httpTLS)
	}
}
