package services

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

func SelectRuleCertificate(candidates []CertificateCandidate, ruleDomains string, now time.Time) (string, bool) {
	selection, selected := SelectCertificate(candidates, ruleDomains, now)
	if selected {
		return selection.Candidate.CertPEM, true
	}
	return "", false
}

// GetCertExpiryThreshold returns the configured cert expiry warning threshold in days.
func GetCertExpiryThreshold() int {
	// SVC-F2（第 73 轮）：同包多数配置读取 helper 有 db.DB==nil 守卫——
	// 未初始化库回退默认值，不得 nil deref（当前不可达，防御性一致）。
	if db.DB == nil {
		return 30
	}
	var days int
	err := db.DB.QueryRow("SELECT COALESCE(cert_expiry_days, 30) FROM global_config WHERE id = 1").Scan(&days)
	if err != nil {
		Logf("error", "GetCertExpiryThreshold: failed to read global_config, using default 30: %v", err)
		return 30
	}
	if days <= 0 {
		return 30
	}
	return days
}

// GetCertRenewalDays returns the configured certificate renewal window in days.
// U7-P5-2（第 62 轮审计）：cert_renewal_days 读取收敛到本 helper（原四处内联：
// certificates.go 启动恢复/续签巡检/首发失败重试 + certissuer.go 快速路径）。
// CERT42-5（第 42 轮审计）：读取失败降级默认值必须告警——静默落 30 天默认会让
// 配置读取退化无任何可观测痕迹。2026-09-07 C2 核实：UI 输入 min=1，0/负值仅
// API 直写/导入可达——按默认 30 天兜底（非「禁用续签」语义）。
func GetCertRenewalDays() int {
	// SVC-F2（第 73 轮）：未初始化库回退默认 30 天（同 GetCertExpiryThreshold）。
	if db.DB == nil {
		return 30
	}
	var days int
	err := db.DB.QueryRow("SELECT COALESCE(cert_renewal_days, 30) FROM global_config WHERE id = 1").Scan(&days)
	if err != nil {
		Logf("error", "GetCertRenewalDays: failed to read global_config, using default 30: %v", err)
		return 30
	}
	if days <= 0 {
		return 30
	}
	return days
}

// GetCertRenewalAttempts returns the configured max renewal attempts.
func GetCertRenewalAttempts() int {
	// SVC-F2（第 73 轮）：未初始化库回退默认 5 次（同 GetCertExpiryThreshold）。
	if db.DB == nil {
		return 5
	}
	var attempts int
	err := db.DB.QueryRow("SELECT COALESCE(cert_renewal_attempts, 5) FROM global_config WHERE id = 1").Scan(&attempts)
	if err != nil {
		Logf("error", "GetCertRenewalAttempts: failed to read global_config, using default 5: %v", err)
		return 5
	}
	if attempts <= 0 {
		return 5
	}
	return attempts
}

// FormatRuleCertInfo 从 PEM 证书内容生成展示用 RuleCertInfo——批量
// (handlers.GetRulesCertInfo)与单规则(ParseCertInfo)两路径同用（R73 LBH-F7
// 收敛：原 handlers.parseBatchRuleCertInfo 与本文件 ParseCertInfo 两份实现历史
// 三度分叉）。参数显式化：expiryDays=expiring 阈值天数、now=判定基准（批量取
// 统一快照，避免逐规则 time.Now 漂移）；caddyID 非空时回填。source=acme_dns 且
// PEM 为空时给出 ACME 专属「尚未签发」文案（其余来源「证书不存在」）。
func FormatRuleCertInfo(certPEM, source, ruleDomains, caddyID string, expiryDays int, now time.Time) *models.RuleCertInfo {
	info := &models.RuleCertInfo{
		CaddyID: caddyID,
		Source:  source,
		Domains: ruleDomains,
		Status:  "unknown",
	}

	if strings.TrimSpace(certPEM) == "" {
		if source == "acme_dns" {
			info.Error = "ACME 证书尚未签发或不存在"
		} else {
			info.Error = "证书不存在"
		}
		return info
	}

	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		info.Error = "证书格式无效"
		return info
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		info.Error = fmt.Sprintf("证书解析失败: %v", err)
		return info
	}

	// Domains：证书 DNSNames 优先，CommonName 兜底，去重后均无则保留 ruleDomains
	domainSet := make(map[string]struct{}, len(cert.DNSNames)+1)
	parsedDomains := make([]string, 0, len(cert.DNSNames)+1)
	for _, name := range append(cert.DNSNames, cert.Subject.CommonName) {
		if name == "" {
			continue
		}
		if _, exists := domainSet[name]; exists {
			continue
		}
		domainSet[name] = struct{}{}
		parsedDomains = append(parsedDomains, name)
	}
	if len(parsedDomains) > 0 {
		info.Domains = strings.Join(parsedDomains, ", ")
	}

	// Issuer：Organization 优先，CommonName 兜底
	issuer := cert.Issuer.CommonName
	if len(cert.Issuer.Organization) > 0 && cert.Issuer.Organization[0] != "" {
		issuer = cert.Issuer.Organization[0]
		if cert.Issuer.CommonName != "" {
			issuer = fmt.Sprintf("%s (%s)", issuer, cert.Issuer.CommonName)
		}
	}
	info.Issuer = issuer
	if info.Issuer == "" {
		info.Issuer = "-"
	}

	const timeFmt = "2006-01-02 15:04:05"
	info.NotBefore = cert.NotBefore.Format(timeFmt)
	info.NotAfter = cert.NotAfter.Format(timeFmt)
	info.DaysRemaining = int(cert.NotAfter.Sub(now).Hours() / 24)

	switch {
	case !now.Before(cert.NotAfter):
		info.Status = "expired"
	case info.DaysRemaining <= expiryDays:
		info.Status = "expiring"
	default:
		info.Status = "valid"
	}

	return info
}

// ParseCertInfo parses a PEM certificate and returns structured display info.
// 阈值取配置值(cert_expiry_days)、基准取当前时刻——批量路径改用
// FormatRuleCertInfo 显式传参（同一实现）。
func ParseCertInfo(certPEM, source, ruleDomains string) *models.RuleCertInfo {
	return FormatRuleCertInfo(certPEM, source, ruleDomains, "", GetCertExpiryThreshold(), time.Now())
}

// GetRuleCertInfo returns parsed certificate info for a single rule.
func GetRuleCertInfo(caddyID string) *models.RuleCertInfo {
	var enableTLS bool
	var tlsSource, ruleDomain, tlsCert string
	err := db.DB.QueryRow(`
		SELECT COALESCE(enable_tls, 0), COALESCE(tls_source, 'manual'), COALESCE(domain, ''), COALESCE(tls_cert, '')
		FROM lb_rules WHERE caddy_id = ?`, caddyID).Scan(&enableTLS, &tlsSource, &ruleDomain, &tlsCert)
	if err != nil {
		Logf("error", "GetRuleCertInfo: failed to read rule %s: %v", caddyID, err)
		return nil
	}

	if !enableTLS {
		return nil
	}

	switch tlsSource {
	case "manual":
		info := ParseCertInfo(tlsCert, "manual", ruleDomain)
		info.CaddyID = caddyID
		return info
	case "acme_dns":
		return getACMECertInfo(caddyID, ruleDomain)
	default:
		// Fallback to manual cert if source is unrecognized but tls_cert exists
		info := ParseCertInfo(tlsCert, tlsSource, ruleDomain)
		info.CaddyID = caddyID
		return info
	}
}

// getACMECertInfo returns parsed certificate info for an ACME-issued rule.
// It reads the issued certificate from cert_jobs.cert_pem.
func getACMECertInfo(caddyID, ruleDomain string) *models.RuleCertInfo {
	rows, err := db.DB.Query(`
		SELECT id, status, COALESCE(cert_pem, ''), COALESCE(key_pem, ''),
		       COALESCE(julianday(COALESCE(updated_at, created_at)), 0), COALESCE(domain, '')
		FROM cert_jobs
		WHERE rule_id = ? AND COALESCE(cert_pem, '') != '' AND COALESCE(key_pem, '') != ''
		ORDER BY updated_at DESC, id DESC`, caddyID)
	if err != nil {
		Logf("error", "GetRuleCertInfo: failed to read ACME certificates for %s: %v", caddyID, err)
		return missingACMECertInfo(caddyID, ruleDomain)
	}
	defer rows.Close()
	candidates := make([]CertificateCandidate, 0)
	for rows.Next() {
		var candidate CertificateCandidate
		if err := rows.Scan(&candidate.ID, &candidate.Status, &candidate.CertPEM, &candidate.KeyPEM, &candidate.UpdatedAt, &candidate.Domain); err != nil {
			Logf("error", "GetRuleCertInfo: failed to scan ACME certificate for %s: %v", caddyID, err)
			return missingACMECertInfo(caddyID, ruleDomain)
		}
		candidates = append(candidates, candidate)
	}
	if err := rows.Err(); err != nil {
		Logf("error", "GetRuleCertInfo: failed to iterate ACME certificates for %s: %v", caddyID, err)
		return missingACMECertInfo(caddyID, ruleDomain)
	}
	if certPEM, selected := SelectRuleCertificate(candidates, ruleDomain, time.Now()); selected {
		info := ParseCertInfo(certPEM, "acme_dns", ruleDomain)
		info.CaddyID = caddyID
		return info
	}
	// CERT40-1:选中失败区分「已过期」与「尚未签发」。
	if info := ExpiredACMECertInfoFallback(candidates, caddyID, ruleDomain); info != nil {
		return info
	}
	return missingACMECertInfo(caddyID, ruleDomain)
}

// ExpiredACMECertInfoFallback(CERT40-1/CERT42-1 共享):候选集 PEM 非空但
// SelectRuleCertificate 无一可选中时,逐个解析——首个非 disabled 且 PEM 非空
// 的已过期候选按 expired 呈现(Error=「ACME 证书已过期」),不再误报「尚未
// 签发或不存在」;无已过期候选(解析失败/未过期)返回 nil,调用方维持原口径。
// 单规则(GetRuleCertInfo)与批量(handlers GetRulesCertInfo)两路径同用。
func ExpiredACMECertInfoFallback(candidates []CertificateCandidate, caddyID, ruleDomain string) *models.RuleCertInfo {
	for _, candidate := range candidates {
		if strings.TrimSpace(candidate.CertPEM) == "" || candidate.Status == "disabled" {
			continue
		}
		info := ParseCertInfo(candidate.CertPEM, "acme_dns", ruleDomain)
		info.CaddyID = caddyID
		if info.Status == "expired" {
			info.Error = "ACME 证书已过期"
			return info
		}
	}
	return nil
}

func missingACMECertInfo(caddyID, ruleDomain string) *models.RuleCertInfo {
	return &models.RuleCertInfo{
		CaddyID: caddyID,
		Source:  "acme_dns",
		Domains: ruleDomain,
		Status:  "unknown",
		Error:   "ACME 证书尚未签发或不存在",
	}
}
