package handlers

// CORE-F2（第 73 轮 P4）：TCP 死值清零 SQL 双实现 parity 钉——启动迁移
// db.migrateTCPRuleDeadFields（db.go）与导入归一
// handlers.normalizeRuleRowsForTransport（config_backup.go:tcpRuleDeadFieldsResetSQL）
// 持有两份逐字相同的 UPDATE 字面量（11 列 SET + TCP 谓词），跨包无法共享常量，
// 无门禁时一侧改动另一侧静默漂移（启动迁移与导入归一对同一存量行产出不同终态）。
// 本测试读取两侧源码/常量，断言 SET 列集合与 WHERE 谓词逐字一致。

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

var goRawStringLiteral = regexp.MustCompile("`[^`]*`")

func TestTCPRuleDeadFieldsSQL_parityWithStartupMigration(t *testing.T) {
	src, err := os.ReadFile("../db/db.go")
	if err != nil {
		t.Fatalf("read db.go: %v", err)
	}
	// 锚定到 migrateTCPRuleDeadFields 函数体后第一个原始字符串字面量（db.go 内
	// 另有多个含 protocol='tcp' 的 UPDATE 字面量，仅按内容过滤会歧义）。
	body := string(src)
	anchor := strings.Index(body, "func migrateTCPRuleDeadFields(")
	if anchor < 0 {
		t.Fatalf("db.go 未找到 migrateTCPRuleDeadFields 函数")
	}
	loc := goRawStringLiteral.FindStringIndex(body[anchor:])
	if loc == nil {
		t.Fatalf("migrateTCPRuleDeadFields 内未找到 SQL 字面量")
	}
	migrationSQL := strings.Trim(body[anchor+loc[0]:anchor+loc[1]], "`")
	if !strings.Contains(migrationSQL, "UPDATE lb_rules SET") || !strings.Contains(migrationSQL, "protocol='tcp'") {
		t.Fatalf("migrateTCPRuleDeadFields 首个字面量非 TCP 死值 SQL: %q", migrationSQL)
	}

	migCols, migWhere := splitTCPDeadFieldsSQL(t, migrationSQL)
	localCols, localWhere := splitTCPDeadFieldsSQL(t, tcpRuleDeadFieldsResetSQL)

	if strings.Join(migCols, ",") != strings.Join(localCols, ",") {
		t.Fatalf("SET 列集合分叉:\n  db.go        = %v\n  config_backup = %v", migCols, localCols)
	}
	if len(migCols) != 12 {
		t.Fatalf("SET 列数=%d, want 12（七 HTTP 专属 + NTLM + force_http1 + TLS 三列）: %v", len(migCols), migCols)
	}
	if migWhere != localWhere {
		t.Fatalf("WHERE 谓词分叉:\n  db.go        = %q\n  config_backup = %q", migWhere, localWhere)
	}
	// 整体兜底：空白归一后两份字面量须逐字一致（列集合/谓词之外的值部分同样受钉）
	if normalizeSQLWhitespace(migrationSQL) != normalizeSQLWhitespace(tcpRuleDeadFieldsResetSQL) {
		t.Fatalf("TCP 死值 SQL 逐字分叉:\n  db.go        = %q\n  config_backup = %q",
			normalizeSQLWhitespace(migrationSQL), normalizeSQLWhitespace(tcpRuleDeadFieldsResetSQL))
	}
}

// splitTCPDeadFieldsSQL 从 "UPDATE lb_rules SET <cols> WHERE <pred>" 形态解析出
// SET 列名（有序）与 WHERE 谓词（空白归一后的子串）。
func splitTCPDeadFieldsSQL(t *testing.T, sqlText string) (cols []string, where string) {
	t.Helper()
	norm := normalizeSQLWhitespace(sqlText)
	const setPrefix = "UPDATE lb_rules SET "
	setIdx := strings.Index(norm, setPrefix)
	whereIdx := strings.Index(norm, " WHERE ")
	if setIdx != 0 || whereIdx < 0 || whereIdx <= setIdx {
		t.Fatalf("SQL 形状异常（须 UPDATE lb_rules SET ... WHERE ...）: %q", norm)
	}
	for _, clause := range strings.Split(norm[len(setPrefix):whereIdx], ",") {
		clause = strings.TrimSpace(clause)
		if clause == "" {
			continue
		}
		cols = append(cols, strings.TrimSpace(strings.SplitN(clause, "=", 2)[0]))
	}
	return cols, norm[whereIdx:]
}

func normalizeSQLWhitespace(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
