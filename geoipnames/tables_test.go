package geoipnames

import "testing"

// 共享表内容钉（PLUG-N3，第 72 轮）：四张表从 internal/services 与
// caddygeoip 的镜像双份收敛为单源——钉条目数（防意外截断/漏行）与关键
// 映射（防键值漂移）。条目数基线取自收敛前镜像测试的核验值
// （22/13/45/31，两侧逐条人工比对一致）。
func TestGeoipNamesTables_pinnedCountsAndSpotMappings(t *testing.T) {
	// Given/When/Then：条目数钉
	counts := []struct {
		name string
		got  int
		want int
	}{
		{"ProvinceAliases", len(ProvinceAliases), 22},
		{"TaiwanCities", len(TaiwanCities), 13},
		{"CityPinyinFixes", len(CityPinyinFixes), 45},
		{"AutonomousPrefectures", len(AutonomousPrefectures), 31},
	}
	for _, c := range counts {
		if c.got != c.want {
			t.Errorf("%s entries=%d; want %d (表内容变动须显式更新本钉——漂移曾致城市级地域规则静默恒不命中)", c.name, c.got, c.want)
		}
	}

	// And：关键映射抽查（每表至少一对键值/成员）
	if got := ProvinceAliases["广西"]; got != "广西壮族自治区" {
		t.Errorf("ProvinceAliases[广西]=%q; want 广西壮族自治区", got)
	}
	if got := ProvinceAliases["UEruemqi"]; got != "新疆维吾尔自治区" {
		t.Errorf("ProvinceAliases[UEruemqi]=%q; want 新疆维吾尔自治区（乱码段回收）", got)
	}
	if !TaiwanCities["台中市"] {
		t.Error("TaiwanCities must contain 台中市（误入省列的台湾城市）")
	}
	if got := CityPinyinFixes["Wulumuqi"]; got != "乌鲁木齐市" {
		t.Errorf("CityPinyinFixes[Wulumuqi]=%q; want 乌鲁木齐市", got)
	}
	if got := AutonomousPrefectures["大理"]; got != "大理白族自治州" {
		t.Errorf("AutonomousPrefectures[大理]=%q; want 大理白族自治州（不可盲加市字）", got)
	}
	if _, ok := AutonomousPrefectures["九龙"]; ok {
		t.Error("九龙是地区名非城市，不得入 AutonomousPrefectures（保持原值）")
	}
}
