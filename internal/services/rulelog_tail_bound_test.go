package services

// U8-P3-1（Round 62 审计）：ReadRuleLogTail 反向扫描必须受 maxBackwardScan
// 约束。maxBackwardScan 常量曾声明但扫描循环从不引用（F63-B5e2-2 修复未接线），
// 无换行的损坏/二进制日志会一路回扫到文件头（每轮 64KiB 前置拷贝，
// 100MB 无换行 ≈ 数十 GB 级复制）。本文件钉两形状：
//   - 无换行大文件：返回非空部分 tail、长度受扫描上限约束、offset 不变量保持
//   - 正常多行文件：tail 语义（最后 N 行 + 起始 offset）不变

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeRuleLogFile(t *testing.T, ruleID string, data []byte) string {
	t.Helper()
	dir := t.TempDir()
	origDir := ruleLogDir
	ruleLogDir = dir
	t.Cleanup(func() { ruleLogDir = origDir })
	path := filepath.Join(dir, sanitizeRuleLogName(ruleID)+".log")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write rule log %s: %v", path, err)
	}
	return path
}

func TestReadRuleLogTail_noNewlineFileBounded(t *testing.T) {
	// 8MB 无换行：旧实现全量回扫（buf 达 8MB），新实现须停在 maxBackwardScan。
	size := 8 << 20
	writeRuleLogFile(t, "probe", bytes.Repeat([]byte{0x41}, size))

	content, offset := ReadRuleLogTail("probe", 100)

	if content == "" {
		t.Fatal("tail of newline-free log returned empty content, want bounded partial tail")
	}
	if int64(len(content)) > maxBackwardScan+64*1024 {
		t.Fatalf("tail length %d exceeds maxBackwardScan bound %d", len(content), maxBackwardScan+64*1024)
	}
	if offset+int64(len(content)) != int64(size) {
		t.Fatalf("offset invariant broken: offset=%d len=%d size=%d, want offset+len==size", offset, len(content), size)
	}
}

func TestReadRuleLogTail_multilineTailSemanticsUnchanged(t *testing.T) {
	var b strings.Builder
	for i := 1; i <= 3000; i++ {
		b.WriteString(fmt.Sprintf("line-%d\n", i))
	}
	writeRuleLogFile(t, "multi", []byte(b.String()))

	content, offset := ReadRuleLogTail("multi", 100)

	lines := strings.Split(strings.TrimSuffix(content, "\n"), "\n")
	if len(lines) != 100 {
		t.Fatalf("got %d lines, want last maxLines=100", len(lines))
	}
	if lines[0] != "line-2901" || lines[99] != "line-3000" {
		t.Fatalf("tail window wrong: first=%s last=%s, want line-2901..line-3000", lines[0], lines[99])
	}
	if offset+int64(len(content)) != int64(b.Len()) {
		t.Fatalf("offset invariant broken: offset=%d len=%d total=%d", offset, len(content), b.Len())
	}
}

// F-68-U7b2-01（第 68 轮审计）：removeTimberjackRotations 数字边界守卫——
// 兄弟规则（caddy_id 以本 stem 为前缀，lb_abc 与 lb_abc-extra）的轮转副本
// 此前被本规则的清扫按前缀+后缀整体误删（logstats.go B-2 同族先例：
// stem 后 '-<ts>' 段首字符必须为数字）。
func TestRemoveRuleLogFiles_siblingRuleRotationsUntouched(t *testing.T) {
	dir := t.TempDir()
	origDir := ruleLogDir
	ruleLogDir = dir
	t.Cleanup(func() { ruleLogDir = origDir })

	for _, name := range []string{
		"lb_abc.log", "lb_abc-extra.log",
		"lb_abc-20260910T15-04-05.123-size.log",
		"lb_abc-extra-20260910T15-04-05.123-size.log",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	RemoveRuleLogFiles("lb_abc")

	if _, err := os.Stat(filepath.Join(dir, "lb_abc.log")); !os.IsNotExist(err) {
		t.Fatal("lb_abc.log 应已删除")
	}
	if _, err := os.Stat(filepath.Join(dir, "lb_abc-20260910T15-04-05.123-size.log")); !os.IsNotExist(err) {
		t.Fatal("lb_abc 自身轮转副本应已清扫")
	}
	if _, err := os.Stat(filepath.Join(dir, "lb_abc-extra-20260910T15-04-05.123-size.log")); err != nil {
		t.Fatalf("兄弟规则轮转副本被误删: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "lb_abc-extra.log")); err != nil {
		t.Fatalf("兄弟规则活文件被误删: %v", err)
	}
}

// LBS-A-1（第 70 轮 P4）：ReadRuleLogTail 两段式倒扫改写的窗口等价钉——
// 多块窗口/块边界跨行/cap 边界/未终结尾行/少于 maxLines 五形状的 content 与
// offset 期望按旧实现语义手算钉死（改写前后同输入同输出，逐字节等价）。
func TestReadRuleLogTail_windowEquivalenceShapes(t *testing.T) {
	t.Run("多块窗口取尾5行", func(t *testing.T) {
		var b strings.Builder
		for i := 1; i <= 30000; i++ {
			fmt.Fprintf(&b, "L%07d\n", i)
		}
		writeRuleLogFile(t, "eq-multi", []byte(b.String()))
		content, offset := ReadRuleLogTail("eq-multi", 5)
		var want strings.Builder
		for i := 29996; i <= 30000; i++ {
			fmt.Fprintf(&want, "L%07d\n", i)
		}
		if content != want.String() {
			t.Fatalf("多块尾窗内容不等价: got %q, want %q", content, want.String())
		}
		if wantOffset := int64(b.Len() - want.Len()); offset != wantOffset {
			t.Fatalf("offset=%d, want %d", offset, wantOffset)
		}
	})
	t.Run("行跨64KB块边界", func(t *testing.T) {
		data := append(append(bytes.Repeat([]byte{'A'}, 65530), '\n'), append(bytes.Repeat([]byte{'B'}, 100), '\n')...)
		writeRuleLogFile(t, "eq-boundary", data)
		content, offset := ReadRuleLogTail("eq-boundary", 1)
		if content != string(bytes.Repeat([]byte{'B'}, 100))+"\n" {
			t.Fatalf("块边界行尾窗不等价: %q", content)
		}
		if offset != 65531 {
			t.Fatalf("offset=%d, want 65531（B 行起点）", offset)
		}
		content2, offset2 := ReadRuleLogTail("eq-boundary", 2)
		if content2 != string(data) || offset2 != 0 {
			t.Fatalf("maxLines=2 应整窗: offset=%d len=%d", offset2, len(content2))
		}
	})
	t.Run("cap边界部分尾窗", func(t *testing.T) {
		size := 5 << 20
		data := make([]byte, size)
		for i := range data {
			data[i] = 'C'
		}
		data[0] = '\n'
		writeRuleLogFile(t, "eq-cap", data)
		content, offset := ReadRuleLogTail("eq-cap", 10)
		if l := int64(len(content)); l != maxBackwardScan {
			t.Fatalf("cap 部分尾窗长度=%d, want %d", l, maxBackwardScan)
		}
		if offset != int64(size)-maxBackwardScan {
			t.Fatalf("offset=%d, want %d", offset, int64(size)-maxBackwardScan)
		}
		if offset+int64(len(content)) != int64(size) {
			t.Fatal("offset 不变量破坏: offset+len != size")
		}
	})
	t.Run("未终结尾行计为一行", func(t *testing.T) {
		writeRuleLogFile(t, "eq-partial", []byte("a\nb\nc"))
		content, offset := ReadRuleLogTail("eq-partial", 2)
		if content != "b\nc" || offset != 2 {
			t.Fatalf("未终结尾行不等价: content=%q offset=%d", content, offset)
		}
	})
	t.Run("行数少于maxLines整窗返回", func(t *testing.T) {
		writeRuleLogFile(t, "eq-short", []byte("x\ny\n"))
		content, offset := ReadRuleLogTail("eq-short", 100)
		if content != "x\ny\n" || offset != 0 {
			t.Fatalf("短文件不等价: content=%q offset=%d", content, offset)
		}
	})
}
