package services

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// CC 防护显式化（中优 #6）：把现有限流（rate_limit，QPS/突发，caddy-ratelimit
// 处理器）显式化为「CC 防护」，并补齐「触发后自动封禁时长」联动——周期扫描各
// 站点访问日志中的限流拦截（HTTP 429），把窗口内命中次数过阈值的源 IP 写入
// 自动封禁列表（与 WAF 自动封禁共用同一 category=auto_ban 列表），经策略 deny
// 型 ACL 引用在限流与 CRS 之前前置拦截。封禁条目用独立 remark 前缀 cc_ban: 标记，
// 与 WAF 自动封禁（auto_ban:）各自按自身时长独立过期，互不干扰。

const (
	ccBanRemarkPrefix    = "cc_ban:"
	ccBanEventTimeLayout = "2006-01-02 15:04:05"
)

// ccBanLogDir 是各站点访问日志所在目录（默认与 ruleLogDir 一致，测试注入
// 临时目录避免触碰生产日志）。
var ccBanLogDir = ruleLogDir

// ccBanLogPath 返回规则访问日志路径（与 RuleLogPath 同目录、同净化规则，
// 但目录可注入以便测试）。
func ccBanLogPath(ruleID string) string {
	return filepath.Join(ccBanLogDir, sanitizeRuleLogName(ruleID)+".log")
}

type ccBanConfig struct {
	Enabled       bool
	Threshold     int
	WindowMinutes int
	DurationHours int
}

// readCCBanConfig 读取全局 CC 封禁配置；列缺失或读取失败回退默认值（开关默认关闭）。
func (m *WafAutoBanManager) readCCBanConfig() (ccBanConfig, error) {
	cfg := ccBanConfig{Threshold: 10, WindowMinutes: 10, DurationHours: 1}
	err := db.DB.QueryRow(`SELECT COALESCE(cc_ban_enabled,0), COALESCE(cc_ban_threshold,10),
		COALESCE(cc_ban_window_minutes,10), COALESCE(cc_ban_duration_hours,1) FROM global_config WHERE id=1`).
		Scan(&cfg.Enabled, &cfg.Threshold, &cfg.WindowMinutes, &cfg.DurationHours)
	if err != nil {
		return cfg, err
	}
	if cfg.Threshold < 1 {
		cfg.Threshold = 10
	}
	if cfg.WindowMinutes < 1 {
		cfg.WindowMinutes = 10
	}
	if cfg.DurationHours < 0 {
		cfg.DurationHours = 1
	}
	return cfg, nil
}

// ccBanAccessLine mirrors the Caddy JSON access-log line fields needed to
// attribute rate-limit (429) blocks to a client IP within a time window.
type ccBanAccessLine struct {
	Ts      float64 `json:"ts"`
	Status  int     `json:"status"`
	Request struct {
		RemoteIP string `json:"remote_ip"`
	} `json:"request"`
}

// ccBanScanLogFile scans an access-log file (plus its first rotation) for 429
// lines within [windowStart, now], returning per-IP counts. Only the tail of
// each file is read (8 MiB cap), so a minute-level sweep never loads a full
// 100 MiB log into memory; a partially-consumed leading line simply fails JSON
// parse and is skipped.
func ccBanScanLogFile(path string, windowStart time.Time) (map[string]int, error) {
	counts := make(map[string]int)
	for _, p := range []string{path, path + ".1"} {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		info, statErr := f.Stat()
		if statErr != nil || info.Size() == 0 {
			f.Close()
			continue
		}
		const maxTail = 8 << 20
		start := info.Size() - maxTail
		if start < 0 {
			start = 0
		}
		if _, err := f.Seek(start, 0); err != nil {
			f.Close()
			continue
		}
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)
		for scanner.Scan() {
			var line ccBanAccessLine
			if err := json.Unmarshal(scanner.Bytes(), &line); err != nil {
				continue
			}
			if line.Status != 429 || line.Request.RemoteIP == "" {
				continue
			}
			if line.Ts > 0 && line.Ts < float64(windowStart.Unix()) {
				continue
			}
			counts[line.Request.RemoteIP]++
		}
		f.Close()
	}
	return counts, nil
}

// ccBanCandidates aggregates 429 counts across all enabled HTTP rules with
// access logging on and returns IPs meeting the configured threshold.
func (m *WafAutoBanManager) ccBanCandidates(cfg ccBanConfig, windowStart time.Time) ([]string, error) {
	rows, err := db.DB.Query(`SELECT caddy_id FROM lb_rules WHERE enabled=1 AND COALESCE(protocol,'')='http' AND COALESCE(log_enabled,0)=1`)
	if err != nil {
		return nil, err
	}
	var ruleIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ruleIDs = append(ruleIDs, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	combined := make(map[string]int)
	for _, id := range ruleIDs {
		counts, err := ccBanScanLogFile(ccBanLogPath(id), windowStart)
		if err != nil {
			continue
		}
		for ip, n := range counts {
			combined[ip] += n
		}
	}

	out := make([]string, 0, len(combined))
	for ip, n := range combined {
		if n >= cfg.Threshold {
			out = append(out, ip)
		}
	}
	return out, nil
}

func ccBanParseRemark(remark string) (time.Time, bool) {
	if !strings.HasPrefix(remark, ccBanRemarkPrefix) {
		return time.Time{}, false
	}
	sec, err := strconv.ParseInt(strings.TrimPrefix(remark, ccBanRemarkPrefix), 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	return time.Unix(sec, 0).UTC(), true
}

// ccBanPruneExpired removes expired cc_ban entries (auto_ban entries are left
// to the WAF auto-ban sweep's own pruning).
func ccBanPruneExpired(entries []models.IPListEntry, now time.Time, duration time.Duration) (bool, []models.IPListEntry) {
	kept := entries[:0]
	pruned := false
	for _, e := range entries {
		if banTime, ok := ccBanParseRemark(e.Remark); ok {
			if now.Sub(banTime) >= duration {
				pruned = true
				continue
			}
		}
		kept = append(kept, e)
	}
	return pruned, kept
}

// ccBanSweep executes one CC-ban sweep: config → resolve list → enforce →
// prune → aggregate → append → apply. Mirrors WafAutoBanManager.sweep but
// sources candidates from rate-limit (429) access logs instead of WAF events.
func (m *WafAutoBanManager) ccBanSweep(now time.Time) (AutoBanSweepResult, error) {
	m.runMu.Lock()
	if m.running {
		m.runMu.Unlock()
		return AutoBanSweepResult{}, nil
	}
	m.running = true
	m.runMu.Unlock()
	defer func() {
		m.runMu.Lock()
		m.running = false
		m.runMu.Unlock()
	}()

	cfg, err := m.readCCBanConfig()
	if err != nil {
		return AutoBanSweepResult{}, err
	}
	if !cfg.Enabled {
		return AutoBanSweepResult{}, nil
	}

	listID, err := m.resolveTargetListID()
	if err != nil {
		return AutoBanSweepResult{}, err
	}
	if listID <= 0 {
		return AutoBanSweepResult{}, fmt.Errorf("无法解析自动封禁目标列表")
	}
	if err := m.ensureAutoBanEnforcement(listID); err != nil {
		return AutoBanSweepResult{}, err
	}

	entries, err := m.loadEntries(listID)
	if err != nil {
		return AutoBanSweepResult{}, err
	}

	changed := false
	if cfg.DurationHours > 0 {
		if pruned, next := ccBanPruneExpired(entries, now, time.Duration(cfg.DurationHours)*time.Hour); pruned {
			entries = next
			changed = true
		}
	}

	windowStart := now.Add(-time.Duration(cfg.WindowMinutes) * time.Minute)
	candidates, err := m.ccBanCandidates(cfg, windowStart)
	if err != nil {
		return AutoBanSweepResult{}, err
	}

	membership := autoBanMembership(entries)
	var newlyBanned []string
	for _, ip := range candidates {
		normalized, err := NormalizeCIDRs([]string{ip})
		if err != nil || len(normalized) != 1 {
			continue
		}
		value := normalized[0]
		if autoBanSkipIP(value) {
			continue
		}
		if _, exists := membership[value]; exists {
			continue
		}
		if len(entries) >= autoBanListMaxEntries {
			Logf("warn", "cc ban: 封禁列表已达上限 %d 条，跳过 %s", autoBanListMaxEntries, value)
			continue
		}
		entries = append(entries, models.IPListEntry{Value: value, Remark: ccBanRemarkPrefix + strconv.FormatInt(now.Unix(), 10)})
		membership[value] = struct{}{}
		newlyBanned = append(newlyBanned, value)
		changed = true
	}

	if !changed {
		return AutoBanSweepResult{}, nil
	}
	if err := m.applyEntries(listID, entries); err != nil {
		return AutoBanSweepResult{}, err
	}
	return AutoBanSweepResult{Changed: true, NewlyBanned: newlyBanned}, nil
}

// RunCCBanNow manually triggers one CC-ban sweep (master only).
func (m *WafAutoBanManager) RunCCBanNow() (AutoBanSweepResult, error) {
	if !m.isMaster() {
		return AutoBanSweepResult{}, fmt.Errorf("当前节点为从节点，无法执行 CC 封禁扫描")
	}
	return m.ccBanSweep(time.Now().UTC())
}

func ccBanSweepDetail(res AutoBanSweepResult) string {
	if len(res.NewlyBanned) > 0 {
		return FormatAuditDetail(fmt.Sprintf("CC 防护新增封禁 %d 个 IP：%s", len(res.NewlyBanned), AutoBanSummarize(res.NewlyBanned)), AuditResultPart("success"))
	}
	return FormatAuditDetail("CC 封禁条目已过期清理", AuditResultPart("success"))
}
