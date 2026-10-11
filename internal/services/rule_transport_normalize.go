package services

// 规则传输规范（2026-10-11 用户裁定「如果没有就都应该没有，同步后就应该一致」）：
// 单一事实源 normalizeRuleForTransport——主端快照导出（snapshotRules）、从端快照
// 应用（insertSnapshotRules）、备份导入后置归一共用的规则归一函数。
//
// 第 69 轮事故根因：从端 insertSnapshotRules 新增 TCP 七字段归零时，导出侧
// snapshotRules 的平行手写归一块未同步——主端 canonical 与从端落库数据不同形，
// 从端本地重建哈希（56e3）≠主端快照哈希（9855），drifted 分支落本地口径后面板
// 「分区滞后」在版本相同、fingerprint 304 稳态下永不自愈。
// 结构性防治：归一逻辑只此一份，任何消费方（导出/应用/导入）都调它。
//
// 时间戳说明：快照模型时间为 time.Time——主从 DB 字符串（RFC3339 Z / Go time
// +00:00 / SQLite 平面）解析为同一 UTC 时刻后 json.Marshal 输出相同，天然同构；
// DB 存储格式的统一（消除三种并存）由迁移层 normalizeRuleTimestampsMigration
// 与从端写入侧（平面格式直写）承担，与本函数正交。

import "lazy-balancer-v2/internal/models"

// normalizeRuleForTransport 规则传输归一（单一事实源）：
// ① body 上限钳 [0,4096]（R59 C-F1）；
// ② TCP+TLS 死形态清除（R63 A-N1）；
// ③ TCP 行 HTTP 专属七字段归零（LBH-A-U1 同族，2026-10-11 裁定并入导出侧）。
// 调用方：snapshotRules（主端导出）、insertSnapshotRules（从端落库）、
// 备份导入后置归一——三面同构是 rules 节哈希主从相等的不变量基础。
func normalizeRuleForTransport(rule *models.LbRule) {
	if rule.RequestBodyMaxSizeMB < 0 {
		rule.RequestBodyMaxSizeMB = 0
	} else if rule.RequestBodyMaxSizeMB > 4096 {
		rule.RequestBodyMaxSizeMB = 4096
	}
	if rule.Protocol == "tcp" {
		if rule.EnableTLS {
			rule.EnableTLS = false
			rule.TLSCert, rule.TLSKey = "", ""
		}
		// TCP 渲染零消费字段族（buildTCPServer/buildTCPProxyRoute）——
		// 「没有就都应该没有」：主端存储、导出、从端落库三面全零。
		rule.HostHeader = ""
		rule.HealthCheckPath = ""
		rule.EnableCompress = false
		rule.CompressTypes = ""
		rule.RequestBodyMaxSizeMB = 0
		rule.UpstreamKeepaliveTimeout = 0
		rule.ServerTokensHidden = 0
	}
}
