package services

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// WAF 自动封禁（fail2ban 风格）：周期扫描安全事件表，把超过阈值或扫描特征
// 命中的攻击源 IP 写入专用 security_ip_lists 行；任何以 deny 型 ACL 引用该
// 列表的启用策略都会经 buildIPPrecheckDirectives 发射 id:2 前置 deny，实现
// 在限流与 CRS 之前的自动拦截。列表行由 category 标记自愈发现，无需手工创建。

const (
	autoBanListName        = "自动封禁IP"
	autoBanListCategory    = "auto_ban"
	autoBanListMaxEntries  = 500
	autoBanRemarkPrefix    = "auto_ban:"
	autoBanTickInterval    = time.Minute
	autoBanEventTimeLayout = "2006-01-02 15:04:05"

	// 自动绑定（开箱即用）：系统自愈维护的 deny 型 ACL 策略与每规则绑定上限。
	autoBanPolicyName         = "自动封禁策略"
	autoBanPolicyDescription  = "WAF 自动封禁系统维护策略（deny 型 ACL 引用自动封禁IP列表）"
	autoBanMaxBindingsPerRule = 5
)

type autoBanConfig struct {
	Enabled       bool
	Threshold     int
	WindowMinutes int
	DurationHours int
	ScanEnabled   bool
	ScanThreshold int
	TargetListID  int64
}

// AutoBanSweepResult 是单次封禁扫描的结果：Changed 表示列表是否被修改，
// NewlyBanned 为本轮新追加的封禁 IP。
type AutoBanSweepResult struct {
	Changed     bool
	NewlyBanned []string
}

// autoBanSweepDetail 生成封禁扫描审计详情（新增封禁/过期清理）。
func autoBanSweepDetail(res AutoBanSweepResult) string {
	if len(res.NewlyBanned) > 0 {
		return FormatAuditDetail(fmt.Sprintf("新增封禁 %d 个 IP：%s", len(res.NewlyBanned), AutoBanSummarize(res.NewlyBanned)), AuditResultPart("success"))
	}
	return FormatAuditDetail("过期封禁条目已清理", AuditResultPart("success"))
}

// WafAutoBanManager 持有 Caddy 服务引用，周期执行封禁扫描并事务内下发配置。
type WafAutoBanManager struct {
	caddyService *CaddyService

	runMu   sync.Mutex
	running bool

	schedulerMu       sync.Mutex
	schedulerStop     chan struct{}
	schedulerDone     chan struct{}
	schedulerInterval time.Duration
}

var (
	wafAutoBanManager     *WafAutoBanManager
	wafAutoBanManagerOnce sync.Once
)

// InitWafAutoBanManager 初始化单例。caddyService 用于事务内应用封禁变更。
func InitWafAutoBanManager(caddyService *CaddyService) {
	wafAutoBanManagerOnce.Do(func() {
		wafAutoBanManager = &WafAutoBanManager{
			caddyService:      caddyService,
			schedulerInterval: autoBanTickInterval,
		}
	})
}

func GetWafAutoBanManager() *WafAutoBanManager {
	return wafAutoBanManager
}

func ResetWafAutoBanManagerForTest() {
	if wafAutoBanManager != nil {
		wafAutoBanManager.StopScheduler()
	}
	wafAutoBanManager = nil
	wafAutoBanManagerOnce = sync.Once{}
}

// StartScheduler 启动周期扫描循环；重复调用为 no-op。
func (m *WafAutoBanManager) StartScheduler() {
	m.schedulerMu.Lock()
	defer m.schedulerMu.Unlock()
	if m.schedulerStop != nil {
		return
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	m.schedulerStop = stop
	m.schedulerDone = done
	go func() {
		defer close(done)
		m.schedulerTick(time.Now().UTC())
		ticker := time.NewTicker(m.schedulerInterval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case now := <-ticker.C:
				m.schedulerTick(now.UTC())
			}
		}
	}()
}

func (m *WafAutoBanManager) StopScheduler() {
	m.schedulerMu.Lock()
	stop := m.schedulerStop
	done := m.schedulerDone
	m.schedulerStop = nil
	m.schedulerDone = nil
	m.schedulerMu.Unlock()
	if stop != nil {
		close(stop)
	}
	if done != nil {
		<-done
	}
}

// SetMasterRole 按集群角色启停调度器：主节点启动，从节点停止；重复调用安全。
func (m *WafAutoBanManager) SetMasterRole(isMaster bool) {
	if isMaster {
		m.StartScheduler()
		return
	}
	m.StopScheduler()
}

func (m *WafAutoBanManager) schedulerTick(now time.Time) {
	if !m.isMaster() {
		return
	}
	res, err := m.sweep(now)
	if err != nil {
		Logf("warn", "waf auto-ban: sweep failed: %v", err)
		return
	}
	if res.Changed {
		RecordAuditLog("system", "自动封禁", "封禁IP列表", autoBanSweepDetail(res), "")
	}

	ccRes, ccErr := m.ccBanSweep(now)
	if ccErr != nil {
		Logf("warn", "cc ban: sweep failed: %v", ccErr)
		return
	}
	if ccRes.Changed {
		RecordAuditLog("system", "CC 封禁", "封禁IP列表", ccBanSweepDetail(ccRes), "")
	}
}

// RunNow 手动触发一次封禁扫描（供 API 调用）。仅在主节点执行，审计由调用方
// （handler）按操作者归因记录——服务自身只负责扫描与落库。
func (m *WafAutoBanManager) RunNow() (AutoBanSweepResult, error) {
	if !m.isMaster() {
		return AutoBanSweepResult{}, fmt.Errorf("当前节点为从节点，无法执行自动封禁扫描")
	}
	return m.sweep(time.Now().UTC())
}

func (m *WafAutoBanManager) isMaster() bool {
	var isMaster bool
	if err := db.DB.QueryRow("SELECT COALESCE(is_master,1) FROM global_config WHERE id=1").Scan(&isMaster); err != nil || !isMaster {
		return false
	}
	return true
}

// sweep 执行单次封禁扫描：读取配置 → 解析目标列表 → 清理过期条目 → 聚合事件
// → 追加新封禁 IP → 事务内应用（失败分支遵循全局事务契约）。审计由调用方
// （调度 tick / 手动 handler）归因记录，本函数只返回扫描结果。
func (m *WafAutoBanManager) sweep(now time.Time) (AutoBanSweepResult, error) {
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

	cfg, err := m.readConfig()
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

	// 自动绑定（开箱即用）：确保存在启用 deny 型 ACL 策略引用本列表并绑定到
	// 全部 HTTP 规则，否则 buildIPPrecheckDirectives 不会发射 id:2 前置 deny，
	// 封禁条目落库后也不会真正生效。
	if err := m.ensureAutoBanEnforcement(listID); err != nil {
		return AutoBanSweepResult{}, err
	}

	entries, err := m.loadEntries(listID)
	if err != nil {
		return AutoBanSweepResult{}, err
	}

	changed := false
	if cfg.DurationHours > 0 {
		if pruned, next := m.pruneExpired(entries, now, time.Duration(cfg.DurationHours)*time.Hour); pruned {
			entries = next
			changed = true
		}
	}

	windowStart := now.Add(-time.Duration(cfg.WindowMinutes) * time.Minute).Format(autoBanEventTimeLayout)
	candidates, err := m.candidateIPs(cfg, windowStart)
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
			Logf("warn", "waf auto-ban: 封禁列表已达上限 %d 条，跳过 %s", autoBanListMaxEntries, value)
			continue
		}
		entries = append(entries, models.IPListEntry{Value: value, Remark: autoBanRemarkPrefix + strconv.FormatInt(now.Unix(), 10)})
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

// readConfig 读取全局自动封禁配置；列缺失或读取失败回退默认值（开关默认关闭）。
func (m *WafAutoBanManager) readConfig() (autoBanConfig, error) {
	cfg := autoBanConfig{
		Threshold:     20,
		WindowMinutes: 10,
		DurationHours: 24,
		ScanEnabled:   true,
		ScanThreshold: 10,
	}
	err := db.DB.QueryRow(`SELECT COALESCE(auto_ban_enabled,0), COALESCE(auto_ban_threshold,20),
		COALESCE(auto_ban_window_minutes,10), COALESCE(auto_ban_duration_hours,24),
		COALESCE(auto_ban_scan_enabled,1), COALESCE(auto_ban_scan_threshold,10),
		COALESCE(auto_ban_target_list_id,0) FROM global_config WHERE id=1`).
		Scan(&cfg.Enabled, &cfg.Threshold, &cfg.WindowMinutes, &cfg.DurationHours, &cfg.ScanEnabled, &cfg.ScanThreshold, &cfg.TargetListID)
	if err != nil {
		return cfg, err
	}
	if cfg.Threshold < 1 {
		cfg.Threshold = 20
	}
	if cfg.WindowMinutes < 1 {
		cfg.WindowMinutes = 10
	}
	if cfg.DurationHours < 0 {
		cfg.DurationHours = 24
	}
	if cfg.ScanThreshold < 1 {
		cfg.ScanThreshold = 10
	}
	return cfg, nil
}

// resolveTargetListID 解析自动封禁目标列表：优先读全局配置 id，否则按 category
// /名称标记自愈发现，再否则创建专用列表行并回写 id。
func (m *WafAutoBanManager) resolveTargetListID() (int64, error) {
	var listID int64
	if err := db.DB.QueryRow("SELECT COALESCE(auto_ban_target_list_id,0) FROM global_config WHERE id=1").Scan(&listID); err == nil && listID > 0 {
		var exists int
		if err := db.DB.QueryRow("SELECT COUNT(*) FROM security_ip_lists WHERE id=?", listID).Scan(&exists); err == nil && exists > 0 {
			return listID, nil
		}
	}
	if err := db.DB.QueryRow("SELECT id FROM security_ip_lists WHERE category=? OR name=? ORDER BY id LIMIT 1",
		autoBanListCategory, autoBanListName).Scan(&listID); err == nil && listID > 0 {
		if _, err := db.DB.Exec("UPDATE global_config SET auto_ban_target_list_id=? WHERE id=1", listID); err != nil {
			Logf("warn", "waf auto-ban: 回写目标列表 id 失败: %v", err)
		}
		return listID, nil
	}
	res, err := db.DB.Exec(`INSERT INTO security_ip_lists (name, description, category, entries, created_by, created_at, updated_by, updated_at)
		VALUES (?,?,?,'[]',0,datetime('now'),0,datetime('now'))`,
		autoBanListName, "WAF 自动封禁系统维护列表（deny 型 ACL 引用生效）", autoBanListCategory)
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	if _, err := db.DB.Exec("UPDATE global_config SET auto_ban_target_list_id=? WHERE id=1", id); err != nil {
		Logf("warn", "waf auto-ban: 回写目标列表 id 失败: %v", err)
	}
	return id, nil
}

// ensureAutoBanEnforcement 保证自动封禁列表被真正强制：定位/创建一条启用 deny
// 型 ACL 策略引用 listID，并把它绑定到全部 HTTP 规则。任何持久化变更都遵循
// finishTxApply 事务契约（配置被拒回滚、传输失败提交并标记 caddy_apply_error）。
// 幂等：策略与绑定已就绪时零写、零下发。
func (m *WafAutoBanManager) ensureAutoBanEnforcement(listID int64) error {
	if m.caddyService == nil {
		return fmt.Errorf("Caddy 服务未就绪，无法自动绑定封禁策略")
	}
	tx, err := db.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	policyID, found, err := findAutoBanPolicyTx(tx, listID)
	if err != nil {
		return err
	}
	changed := false
	if !found {
		policyID, err = createAutoBanPolicyTx(tx, listID)
		if err != nil {
			return err
		}
		changed = true
		Logf("info", "waf auto-ban: 已创建自动封禁策略 #%d（引用自动封禁列表 #%d）", policyID, listID)
	}

	boundChanged, err := ensurePolicyBoundToHTTPRulesTx(tx, policyID)
	if err != nil {
		return err
	}
	changed = changed || boundChanged
	if !changed {
		return nil
	}

	if err := m.caddyService.ApplyConfigFromTx(tx); err != nil {
		if IsConfigRejected(err) {
			return err
		}
		if commitErr := tx.Commit(); commitErr != nil {
			return commitErr
		}
		m.persistApplyResult(err)
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	m.persistApplyResult(nil)
	return nil
}

// findAutoBanPolicyTx 定位已启用且为 deny 型 ACL 并引用 listID 的策略。
// found=false 表示需要新建系统策略（不改动任何既有策略，避免副作用）。
func findAutoBanPolicyTx(tx *sql.Tx, listID int64) (int64, bool, error) {
	rows, err := tx.Query(`SELECT id, COALESCE(ip_acl_enabled,0), COALESCE(ip_acl_mode,''), COALESCE(ip_acl_list_refs,'[]'), COALESCE(enabled,0) FROM security_policies`)
	if err != nil {
		return 0, false, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var aclEnabled, enabled int
		var aclMode, refs string
		if err := rows.Scan(&id, &aclEnabled, &aclMode, &refs, &enabled); err != nil {
			return 0, false, err
		}
		if enabled != 1 || aclEnabled != 1 || aclMode != "deny" {
			continue
		}
		for _, refID := range parseIPListRefs(refs) {
			if refID == listID {
				return id, true, nil
			}
		}
	}
	if err := rows.Err(); err != nil {
		return 0, false, err
	}
	return 0, false, nil
}

// createAutoBanPolicyTx 新建系统自动封禁策略：mode=off（不启用 CRS 拦截），仅以
// deny 型 ACL 引用自动封禁列表（buildIPPrecheckDirectives 与 mode 无关，恒发射
// id:2 前置 deny）。
func createAutoBanPolicyTx(tx *sql.Tx, listID int64) (int64, error) {
	refsJSON, err := json.Marshal([]int64{listID})
	if err != nil {
		return 0, err
	}
	res, err := tx.Exec(`INSERT INTO security_policies (name, description, mode, ip_acl_mode, ip_acl_list, ip_acl_enabled, ip_acl_list_refs, enabled, updated_by)
		VALUES (?, ?, 'off', 'deny', '[]', 1, ?, 1, 0)`,
		autoBanPolicyName, autoBanPolicyDescription, string(refsJSON))
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	return id, nil
}

// ensurePolicyBoundToHTTPRulesTx 把策略绑定到全部 HTTP 规则（幂等 INSERT OR
// IGNORE）。遵守每规则最多 5 条绑定上限：已满的规则跳过并留痕，不覆盖既有绑定。
func ensurePolicyBoundToHTTPRulesTx(tx *sql.Tx, policyID int64) (bool, error) {
	rows, err := tx.Query("SELECT caddy_id FROM lb_rules WHERE COALESCE(protocol,'')='http'")
	if err != nil {
		return false, err
	}
	var ruleIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return false, err
		}
		ruleIDs = append(ruleIDs, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return false, err
	}

	changed := false
	for _, ruleID := range ruleIDs {
		var alreadyBound int
		if err := tx.QueryRow("SELECT COUNT(*) FROM security_policy_bindings WHERE rule_caddy_id=? AND policy_id=?", ruleID, policyID).Scan(&alreadyBound); err != nil {
			return false, err
		}
		if alreadyBound > 0 {
			continue
		}
		var siblingCount int
		if err := tx.QueryRow("SELECT COUNT(*) FROM security_policy_bindings WHERE rule_caddy_id=?", ruleID).Scan(&siblingCount); err != nil {
			return false, err
		}
		if siblingCount >= autoBanMaxBindingsPerRule {
			Logf("warn", "waf auto-ban: 规则 %s 已绑定 %d 条策略，跳过自动封禁策略绑定", ruleID, siblingCount)
			continue
		}
		if _, err := tx.Exec("INSERT OR IGNORE INTO security_policy_bindings (rule_caddy_id, policy_id) VALUES (?, ?)", ruleID, policyID); err != nil {
			return false, err
		}
		changed = true
	}
	return changed, nil
}

func (m *WafAutoBanManager) loadEntries(listID int64) ([]models.IPListEntry, error) {
	var raw string
	if err := db.DB.QueryRow("SELECT COALESCE(entries,'[]') FROM security_ip_lists WHERE id=?", listID).Scan(&raw); err != nil {
		return nil, err
	}
	var entries []models.IPListEntry
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		return nil, fmt.Errorf("自动封禁列表条目解析失败: %w", err)
	}
	if entries == nil {
		entries = []models.IPListEntry{}
	}
	return entries, nil
}

// pruneExpired 清理已过期的自动封禁条目；返回是否有条目被移除。
func (m *WafAutoBanManager) pruneExpired(entries []models.IPListEntry, now time.Time, duration time.Duration) (bool, []models.IPListEntry) {
	kept := entries[:0]
	pruned := false
	for _, e := range entries {
		if banTime, ok := autoBanParseRemark(e.Remark); ok {
			if now.Sub(banTime) >= duration {
				pruned = true
				continue
			}
		}
		kept = append(kept, e)
	}
	return pruned, kept
}

// candidateIPs 聚合窗口内的封禁候选：blocked 事件计数过阈值、913* 扫描事件
// 计数过阈值，两者取并集。
func (m *WafAutoBanManager) candidateIPs(cfg autoBanConfig, windowStart string) ([]string, error) {
	if db.MetricsDB == nil {
		return nil, nil
	}
	set := make(map[string]struct{})
	if cfg.Threshold > 0 {
		rows, err := db.MetricsDB.Query(`SELECT client_ip FROM security_events
			WHERE action='blocked' AND client_ip<>'' AND event_time>=?
			GROUP BY client_ip HAVING COUNT(*)>=?`, windowStart, cfg.Threshold)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var ip string
			if err := rows.Scan(&ip); err != nil {
				rows.Close()
				return nil, err
			}
			set[ip] = struct{}{}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	if cfg.ScanEnabled && cfg.ScanThreshold > 0 {
		rows, err := db.MetricsDB.Query(`SELECT client_ip FROM security_events
			WHERE rule_triggered LIKE '913%' AND client_ip<>'' AND event_time>=?
			GROUP BY client_ip HAVING COUNT(*)>=?`, windowStart, cfg.ScanThreshold)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var ip string
			if err := rows.Scan(&ip); err != nil {
				rows.Close()
				return nil, err
			}
			set[ip] = struct{}{}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	out := make([]string, 0, len(set))
	for ip := range set {
		out = append(out, ip)
	}
	return out, nil
}

// applyEntries 事务内更新列表条目并下发 Caddy 配置。契约对齐 finishTxApply：
// 配置被拒 → 回滚不落库；传输/系统失败 → 提交并标记 caddy_apply_error。
func (m *WafAutoBanManager) applyEntries(listID int64, entries []models.IPListEntry) error {
	if m.caddyService == nil {
		return fmt.Errorf("Caddy 服务未就绪，无法下发自动封禁")
	}
	mergedJSON, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	tx, err := db.DB.Begin()
	if err != nil {
		return err
	}
	if _, err := tx.Exec("UPDATE security_ip_lists SET entries=?, updated_by=0, updated_at=datetime('now') WHERE id=?", string(mergedJSON), listID); err != nil {
		tx.Rollback()
		return err
	}
	if err := m.caddyService.ApplyConfigFromTx(tx); err != nil {
		if IsConfigRejected(err) {
			tx.Rollback()
			return err
		}
		if commitErr := tx.Commit(); commitErr != nil {
			tx.Rollback()
			return commitErr
		}
		m.persistApplyResult(err)
		return err
	}
	if err := tx.Commit(); err != nil {
		tx.Rollback()
		return err
	}
	m.persistApplyResult(nil)
	return nil
}

func (m *WafAutoBanManager) persistApplyResult(err error) {
	if err == nil {
		if _, derr := db.DB.Exec("UPDATE global_config SET caddy_apply_error='' WHERE id=1 AND caddy_apply_error<>''"); derr != nil {
			Logf("warn", "waf auto-ban: 清除 caddy_apply_error 失败: %v", derr)
		}
		return
	}
	wrapped := fmt.Sprintf("Caddy 配置应用失败（旧配置已保留）：%v", err)
	Logf("error", "%s", wrapped)
	if _, derr := db.DB.Exec("UPDATE global_config SET caddy_apply_error=? WHERE id=1", wrapped); derr != nil {
		Logf("warn", "waf auto-ban: 持久化 caddy_apply_error 失败: %v", derr)
	}
}

func autoBanMembership(entries []models.IPListEntry) map[string]struct{} {
	out := make(map[string]struct{}, len(entries))
	for _, e := range entries {
		value := strings.TrimSpace(e.Value)
		if value == "" {
			continue
		}
		if normalized, err := NormalizeCIDRs([]string{value}); err == nil && len(normalized) == 1 {
			out[normalized[0]] = struct{}{}
			continue
		}
		out[value] = struct{}{}
	}
	return out
}

// autoBanSkipIP 跳过回环与未指定地址，避免误封本地探测/健康检查来源。
func autoBanSkipIP(value string) bool {
	ipStr := value
	if idx := strings.IndexByte(value, '/'); idx >= 0 {
		ipStr = value[:idx]
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return true
	}
	return ip.IsLoopback() || ip.IsUnspecified()
}

func autoBanParseRemark(remark string) (time.Time, bool) {
	if !strings.HasPrefix(remark, autoBanRemarkPrefix) {
		return time.Time{}, false
	}
	sec, err := strconv.ParseInt(strings.TrimPrefix(remark, autoBanRemarkPrefix), 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	return time.Unix(sec, 0).UTC(), true
}

func AutoBanSummarize(ips []string) string {
	if len(ips) <= 10 {
		return strings.Join(ips, ",")
	}
	return strings.Join(ips[:10], ",") + fmt.Sprintf(" 等 %d 个", len(ips))
}
