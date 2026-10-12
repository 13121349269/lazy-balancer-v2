package services

import (
	"lazy-balancer-v2/internal/taskengine"
	"time"
)

// WriteIP2RegionUpdateLog IP 库变更流水唯一写口（R63-P2-2/P2-3：tee 单点；
// 旧 ip2region-update.log 已退役——tasks/ip2region.log 唯一数据源）。导出
// 供 lbbak 导入/集群同步路径跨包留痕——SEC-C-3（第 72 轮）：纯转发别名
// AppendIP2RegionUpdateLog 已收敛删除。
func WriteIP2RegionUpdateLog(level, stage, message string) {
	taskengine.TeeTaskLog("ip2region", time.Now().In(CurrentLocation()).Format("2006/01/02 15:04:05"), level, stage, message)
}
