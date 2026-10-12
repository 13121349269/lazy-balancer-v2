package services

import (
	"strconv"
	"strings"
	"testing"
)

// R73 LBH-F8 一致性钉：Stage1PrecheckSegmentSQL / Stage1PrecheckIDSQLList 与
// Go 谓词 IsStage1PrecheckID 三处同源——固定族、GeoIP 段任一处漏改即在此失败。
func TestStage1PrecheckSegmentSQL_matchesGoPredicate(t *testing.T) {
	// 1) Go 谓词固定族 {2,4,7,8,14} 必须逐项在 SQL 清单中（带引号形态），
	//    且 SQL 清单必须内联进段谓词（防止两常量分叉）。
	fixedIDs := []int{2, 4, 7, 8, 14}
	for _, id := range fixedIDs {
		if !IsStage1PrecheckID(id) {
			t.Fatalf("IsStage1PrecheckID(%d)=false，固定族失守", id)
		}
		quoted := "'" + strconv.Itoa(id) + "'"
		if !strings.Contains(Stage1PrecheckIDSQLList, quoted) {
			t.Fatalf("Stage1PrecheckIDSQLList 缺固定族 id %d：%s", id, Stage1PrecheckIDSQLList)
		}
		if !strings.Contains(Stage1PrecheckSegmentSQL, quoted) {
			t.Fatalf("Stage1PrecheckSegmentSQL 未内联固定族 id %d：%s", id, Stage1PrecheckSegmentSQL)
		}
	}

	// 2) SQL 清单恰为 8 项（"（8 段）"）——数量漂移即暴露新增/漏删。
	if got := strings.Count(Stage1PrecheckIDSQLList, ",") + 1; got != 8 {
		t.Fatalf("Stage1PrecheckIDSQLList 项数=%d，want 8：%s", got, Stage1PrecheckIDSQLList)
	}
	// 防御性包含的 3/5/12（SQL 计入阶段 1，Go 谓词不判 true——nolog pass 不产事件）。
	for _, id := range []int{3, 5, 12} {
		if !strings.Contains(Stage1PrecheckIDSQLList, "'"+strconv.Itoa(id)+"'") {
			t.Fatalf("Stage1PrecheckIDSQLList 缺防御性 id %d：%s", id, Stage1PrecheckIDSQLList)
		}
	}

	// 3) GeoIP 段：段谓词含 6 位 8 开头形态；谓词对段内为 true、段外（上界）为 false。
	if !strings.Contains(Stage1PrecheckSegmentSQL, "LIKE '8%'") {
		t.Fatalf("Stage1PrecheckSegmentSQL 未含 GeoIP 段形态：%s", Stage1PrecheckSegmentSQL)
	}
	for _, id := range []int{geoipPrecheckRuleBase, geoipPrecheckRuleBase + 1, geoipPrecheckRuleBase + 99999} {
		if !IsStage1PrecheckID(id) {
			t.Fatalf("IsStage1PrecheckID(%d)=false，GeoIP 段失守", id)
		}
	}
	for _, id := range []int{geoipPrecheckRuleBase - 1, geoipPrecheckRuleBase + 100000} {
		if IsStage1PrecheckID(id) {
			t.Fatalf("IsStage1PrecheckID(%d)=true，超出 GeoIP 段界", id)
		}
	}
}
