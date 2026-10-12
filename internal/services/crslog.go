package services

import (
	"lazy-balancer-v2/internal/taskengine"
	"time"
)

// WriteCRSUpdateLog 规则库变更流水唯一写口（R63-P2-2/P2-3：tee 单点在写口；
// 旧 crs-update.log 已退役——tasks/crs.log 为唯一数据源，轮转/保留由
// taskLogsHousekeeping 统一执行）。导出供非更新器路径（lbbak 导入/集群
// 同步，2026-09-18 用户裁定：同步/导入有变动也要留痕）跨包调用——
// SEC-C-1（第 72 轮）：纯转发别名 AppendCRSUpdateLog 已收敛删除。
func WriteCRSUpdateLog(level, stage, message string) {
	taskengine.TeeTaskLog("crs", time.Now().In(CurrentLocation()).Format("2006/01/02 15:04:05"), level, stage, message)
}
