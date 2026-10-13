package handlers

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

// WAF 自动封禁（v2.3.x）：调度扫描在 internal/services/wafautoban.go（仅主节点
// 启动），本文件提供设置读写与手动触发端点。自动封禁目标列表由服务按 category
// 自愈发现或创建，用户无需手工维护；任何以 deny 型 ACL 引用该列表的启用策略
// 都会经前置 deny 指令在限流与 CRS 之前拦截封禁 IP。

func (h *Handlers) requireAutoBanMaster(c *gin.Context) bool {
	if isMaster, err := h.clusterService.IsMaster(c.Request.Context()); err != nil || !isMaster {
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: "仅主节点支持管理自动封禁"})
		return false
	}
	return true
}

// WafAutoBanSettings GET /api/v1/settings/auto-ban：读取六项设置 + 目标列表 id。
func (h *Handlers) WafAutoBanSettings(c *gin.Context) {
	if !h.requireAutoBanMaster(c) {
		return
	}
	var enabled, scanEnabled bool
	var threshold, windowMinutes, durationHours, scanThreshold, targetListID int
	if err := db.DB.QueryRow(`SELECT COALESCE(auto_ban_enabled,0), COALESCE(auto_ban_threshold,20),
		COALESCE(auto_ban_window_minutes,10), COALESCE(auto_ban_duration_hours,24),
		COALESCE(auto_ban_scan_enabled,1), COALESCE(auto_ban_scan_threshold,10),
		COALESCE(auto_ban_target_list_id,0) FROM global_config WHERE id=1`).
		Scan(&enabled, &threshold, &windowMinutes, &durationHours, &scanEnabled, &scanThreshold, &targetListID); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取自动封禁设置失败: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "ok", Data: gin.H{
		"enabled":        enabled,
		"threshold":      threshold,
		"window_minutes": windowMinutes,
		"duration_hours": durationHours,
		"scan_enabled":   scanEnabled,
		"scan_threshold": scanThreshold,
		"target_list_id": targetListID,
	}})
}

// UpdateWafAutoBanSettings PUT /api/v1/settings/auto-ban：全量保存六项设置。
// 校验：阈值 1-100000；统计窗口 1-1440 分钟；封禁时长 0-8760 小时
// （0 表示永不自动解封）；扫描阈值 1-100000。
func (h *Handlers) UpdateWafAutoBanSettings(c *gin.Context) {
	if !h.requireAutoBanMaster(c) {
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 16<<10)
	var req struct {
		Enabled       *bool `json:"enabled"`
		Threshold     *int  `json:"threshold"`
		WindowMinutes *int  `json:"window_minutes"`
		DurationHours *int  `json:"duration_hours"`
		ScanEnabled   *bool `json:"scan_enabled"`
		ScanThreshold *int  `json:"scan_threshold"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求格式不正确"})
		return
	}
	if req.Enabled == nil || req.Threshold == nil || req.WindowMinutes == nil || req.DurationHours == nil || req.ScanEnabled == nil || req.ScanThreshold == nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "缺少必填字段（enabled/threshold/window_minutes/duration_hours/scan_enabled/scan_threshold）"})
		return
	}
	if *req.Threshold < 1 || *req.Threshold > 100000 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "封禁阈值必须在 1-100000 之间"})
		return
	}
	if *req.WindowMinutes < 1 || *req.WindowMinutes > 1440 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "统计窗口必须在 1-1440 分钟之间"})
		return
	}
	if *req.DurationHours < 0 || *req.DurationHours > 8760 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "封禁时长必须在 0-8760 小时之间"})
		return
	}
	if *req.ScanThreshold < 1 || *req.ScanThreshold > 100000 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "扫描阈值必须在 1-100000 之间"})
		return
	}
	if _, err := db.DB.Exec(`UPDATE global_config SET auto_ban_enabled=?, auto_ban_threshold=?, auto_ban_window_minutes=?, auto_ban_duration_hours=?, auto_ban_scan_enabled=?, auto_ban_scan_threshold=? WHERE id=1`,
		*req.Enabled, *req.Threshold, *req.WindowMinutes, *req.DurationHours, *req.ScanEnabled, *req.ScanThreshold); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "保存自动封禁设置失败: " + err.Error()})
		return
	}
	recordAudit(c, "封禁设置", "自动封禁", services.FormatAuditDetail(
		fmt.Sprintf("启用：%s", boolText(*req.Enabled)),
		fmt.Sprintf("封禁阈值：%d 次/%d 分钟", *req.Threshold, *req.WindowMinutes),
		fmt.Sprintf("封禁时长：%d 小时", *req.DurationHours),
		fmt.Sprintf("扫描检测：%s（%d 次）", boolText(*req.ScanEnabled), *req.ScanThreshold),
		services.AuditResultPart("success")))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "自动封禁设置已保存"})
}

// RunWafAutoBanNow POST /api/v1/auto-ban/run：手动触发一次封禁扫描。
func (h *Handlers) RunWafAutoBanNow(c *gin.Context) {
	if !h.requireAutoBanMaster(c) {
		return
	}
	operator := c.GetString("username")
	if operator == "" {
		operator = "system"
	}
	mgr := services.GetWafAutoBanManager()
	if mgr == nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "自动封禁服务未就绪"})
		return
	}
	res, err := mgr.RunNow()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "封禁扫描执行失败: " + err.Error()})
		return
	}
	if res.Changed {
		detail := "过期封禁条目已清理"
		message := "封禁列表已更新"
		if len(res.NewlyBanned) > 0 {
			detail = fmt.Sprintf("新增封禁 %d 个 IP：%s", len(res.NewlyBanned), services.AutoBanSummarize(res.NewlyBanned))
			message = fmt.Sprintf("已封禁 %d 个 IP", len(res.NewlyBanned))
		}
		recordAudit(c, "手动封禁", "自动封禁", services.FormatAuditDetail(detail, services.AuditResultPart("success")))
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: message, Data: gin.H{"newly_banned": res.NewlyBanned}})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "扫描完成，无新增封禁"})
}

// WafCCBanSettings GET /api/v1/settings/cc-ban：读取 CC 防护封禁联动四项设置。
func (h *Handlers) WafCCBanSettings(c *gin.Context) {
	if !h.requireAutoBanMaster(c) {
		return
	}
	var enabled bool
	var threshold, windowMinutes, durationHours int
	if err := db.DB.QueryRow(`SELECT COALESCE(cc_ban_enabled,0), COALESCE(cc_ban_threshold,10),
		COALESCE(cc_ban_window_minutes,10), COALESCE(cc_ban_duration_hours,1) FROM global_config WHERE id=1`).
		Scan(&enabled, &threshold, &windowMinutes, &durationHours); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取 CC 封禁设置失败: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "ok", Data: gin.H{
		"enabled":        enabled,
		"threshold":      threshold,
		"window_minutes": windowMinutes,
		"duration_hours": durationHours,
	}})
}

// UpdateWafCCBanSettings PUT /api/v1/settings/cc-ban：全量保存 CC 封禁联动设置。
func (h *Handlers) UpdateWafCCBanSettings(c *gin.Context) {
	if !h.requireAutoBanMaster(c) {
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 16<<10)
	var req struct {
		Enabled       *bool `json:"enabled"`
		Threshold     *int  `json:"threshold"`
		WindowMinutes *int  `json:"window_minutes"`
		DurationHours *int  `json:"duration_hours"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求格式不正确"})
		return
	}
	if req.Enabled == nil || req.Threshold == nil || req.WindowMinutes == nil || req.DurationHours == nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "缺少必填字段（enabled/threshold/window_minutes/duration_hours）"})
		return
	}
	if *req.Threshold < 1 || *req.Threshold > 100000 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "封禁阈值必须在 1-100000 之间"})
		return
	}
	if *req.WindowMinutes < 1 || *req.WindowMinutes > 1440 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "统计窗口必须在 1-1440 分钟之间"})
		return
	}
	if *req.DurationHours < 0 || *req.DurationHours > 8760 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "封禁时长必须在 0-8760 小时之间"})
		return
	}
	if _, err := db.DB.Exec(`UPDATE global_config SET cc_ban_enabled=?, cc_ban_threshold=?, cc_ban_window_minutes=?, cc_ban_duration_hours=? WHERE id=1`,
		*req.Enabled, *req.Threshold, *req.WindowMinutes, *req.DurationHours); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "保存 CC 封禁设置失败: " + err.Error()})
		return
	}
	recordAudit(c, "封禁设置", "CC 封禁", services.FormatAuditDetail(
		fmt.Sprintf("启用：%s", boolText(*req.Enabled)),
		fmt.Sprintf("封禁阈值：%d 次/%d 分钟", *req.Threshold, *req.WindowMinutes),
		fmt.Sprintf("封禁时长：%d 小时", *req.DurationHours),
		services.AuditResultPart("success")))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "CC 封禁设置已保存"})
}

// RunCCBanNow POST /api/v1/cc-ban/run：手动触发一次 CC 封禁扫描。
func (h *Handlers) RunCCBanNow(c *gin.Context) {
	if !h.requireAutoBanMaster(c) {
		return
	}
	mgr := services.GetWafAutoBanManager()
	if mgr == nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "自动封禁服务未就绪"})
		return
	}
	res, err := mgr.RunCCBanNow()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "CC 封禁扫描执行失败: " + err.Error()})
		return
	}
	if res.Changed {
		detail := "CC 封禁条目已过期清理"
		message := "封禁列表已更新"
		if len(res.NewlyBanned) > 0 {
			detail = fmt.Sprintf("CC 防护新增封禁 %d 个 IP：%s", len(res.NewlyBanned), services.AutoBanSummarize(res.NewlyBanned))
			message = fmt.Sprintf("已封禁 %d 个 IP", len(res.NewlyBanned))
		}
		recordAudit(c, "手动封禁", "CC 封禁", services.FormatAuditDetail(detail, services.AuditResultPart("success")))
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: message, Data: gin.H{"newly_banned": res.NewlyBanned}})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "扫描完成，无新增封禁"})
}
