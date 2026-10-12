package services

import "testing"

// SVC-C1（第 73 轮）：routeClaimedByAny/claimedRoutePrefixes 行为等价钉——
// 预建前缀集合判定必须与旧式 `routeID == caddyID || strings.HasPrefix(routeID,
// caddyID+"_")` 逐形状同结果（精确匹配 / 子路由归属主规则 / 前缀兄弟不得误认 /
// 无下划线边界不得认领 / 空集恒 false）。
func TestRouteClaimedByAny_prefixSetEquivalence(t *testing.T) {
	expected := map[string]string{
		"lb_abc":       "rule-a",
		"lb_abc-extra": "rule-b", // 前缀兄弟：lb_abc 不得认领 lb_abc-extra*
		"lb_xy":        "rule-c",
	}
	claimed := claimedRoutePrefixes(expected)
	cases := []struct {
		routeID string
		want    bool
	}{
		{"lb_abc", true},              // 精确匹配
		{"lb_abc_path_0", true},       // 子路由归主规则
		{"lb_abc_redirect", true},     // 子路由归主规则
		{"lb_abc_", true},             // 恰好 "<id>_"
		{"lb_abc-extra", true},        // 前缀兄弟自身精确匹配
		{"lb_abc-extra_path_0", true}, // 前缀兄弟的子路由
		{"lb_xy", true},
		{"lb_xy_", true},
		{"lb_unknown", false},
		{"lb_abcx", false}, // 无下划线标签边界 → 不认领
		{"lb_abc-extrax", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := routeClaimedByAny(tc.routeID, claimed); got != tc.want {
			t.Errorf("routeClaimedByAny(%q)=%v, want %v", tc.routeID, got, tc.want)
		}
	}
	if routeClaimedByAny("lb_anything", claimedRoutePrefixes(nil)) {
		t.Error("empty expected set must claim nothing")
	}
}
