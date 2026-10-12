// Package geoipnames 承载 ip2region 地理规范化的四张共享表——单一数据源
// （PLUG-N3，第 72 轮）。消费方两侧：
//
//   - internal/services（选项树构建 regionTreeFromXDB → GetIP2RegionRegions）
//   - caddygeoip（发射 X-LB-GeoIP-Loc 匹配键，normalizeCity/normalizeProvince）
//
// 此前四张表两侧手工镜像（叶子 Caddy 模块不可 import internal 包），靠
// geoip_mirror_tables_test.go 解析对侧源文本绊线防漂移——本包取代镜像：
// 中立叶模块，根 go.mod 与 caddygeoip/go.mod 各经 replace 引用（与
// wafiplist 叶模块同接线：Dockerfile xcaddy --with + COPY，backend 阶段
// go.mod 先拷）。漂移失效形态（选项树提供某省/市而发射变量发另一形态 →
// 城市级地域规则静默恒不命中）由单源根治，修改只改本包一处。
package geoipnames

// ProvinceAliases 省列别名规范化（R72 二十三次）：xdb 原始省列存在双形态
// （上海/上海市、广西/广西壮族自治区）、台湾城市误入省列（台中市等）与个别
// 乱码（UEruemqi）。选项树与 CEL 发射变量统一用规范名，两边一致才能命中。
var ProvinceAliases = map[string]string{
	// v3.17.0 段 (UEruemqi, Wulumuqi)：省列是城市名 Ürümqi 的乱码转写、城市列
	// 拼音已可映射——别名把该段回收为 新疆维吾尔自治区/乌鲁木齐市（此前整段
	// 被丢弃，树缺这对省市）。
	"UEruemqi": "新疆维吾尔自治区",
	"北京":       "北京市", "上海市": "上海市", "上海": "上海市", "天津市": "天津市", "天津": "天津市",
	"重庆市": "重庆市", "重庆": "重庆市",
	"广西壮族自治区": "广西壮族自治区", "广西": "广西壮族自治区",
	"内蒙古自治区": "内蒙古自治区", "内蒙古": "内蒙古自治区",
	"西藏自治区": "西藏自治区", "西藏": "西藏自治区",
	"宁夏回族自治区": "宁夏回族自治区", "宁夏": "宁夏回族自治区",
	"新疆维吾尔自治区": "新疆维吾尔自治区", "新疆": "新疆维吾尔自治区",
	"台湾省": "台湾省", "台湾": "台湾省",
	"香港特别行政区": "香港特别行政区", "澳门特别行政区": "澳门特别行政区",
}

// TaiwanCities 台湾地区在 xdb 中误置于省列的城市——归入台湾省城市集。
var TaiwanCities = map[string]bool{
	"台北市": true, "新北市": true, "台中市": true, "台南市": true, "高雄市": true,
	"基隆市": true, "新竹市": true, "嘉义市": true, "新竹县": true, "彰化县": true,
	"桃园市": true, "云林县": true, "苗栗县": true,
}

// CityPinyinFixes xdb 部分段的城市列为拼音/英文形态（v3.17.0 实测 45 条，
// 如 Guangzhou Shi/Shanghai/Taipei City）——映射为规范中文名；不在此表的
// ASCII 城市由选项树侧过滤（宁缺勿乱，无法可靠音译）、发射侧原样通过
// （恒不命中，与不可识别省同语义）。R72 二十五次起发射侧同步映射——
// 城市级 CEL 规则对拼音段可命中。
var CityPinyinFixes = map[string]string{
	"Wulumuqi": "乌鲁木齐市", "Shanghai": "上海市", "Beijing": "北京市",
	"Fengyuan": "丰原市", "Taipei City": "台北市", "Zhongli District": "中坜区",
	"Changchun Shi": "长春市", "Chengdu Shi": "成都市", "Tianjin": "天津市",
	"Fuyang Shi": "阜阳市", "Hefei Shi": "合肥市", "Heze Shi": "菏泽市",
	"Jining Shi": "济宁市", "Linyi Xian": "临沂县", "Weifang Shi": "潍坊市",
	"Dongguan Shi": "东莞市", "Foshan Shi": "佛山市", "Guangzhou Shi": "广州市",
	"Maoming Shi": "茂名市", "Shenzhen": "深圳市", "Zhuhai Shi": "珠海市",
	"Nanning Shi": "南宁市", "Nanjing Shi": "南京市", "Nantong Shi": "南通市",
	"Tongshan": "铜山区", "Yancheng Shi": "盐城市", "Ganzhou Shi": "赣州市",
	"Baoding Shi": "保定市", "Hanshan Qu": "含山区", "Langfang Shi": "廊坊市",
	"Shijiazhuang Shi": "石家庄市", "Nanyang Shi": "南阳市", "Zhengzhou Shi": "郑州市",
	"Zhoukou Shi": "周口市", "Zhumadian Shi": "驻马店市", "Ningbo Shi": "宁波市",
	"Wuhan Shi": "武汉市", "Xiangyang": "襄阳市", "Changsha Shi": "长沙市",
	"Hengyang Xian": "衡阳县", "Shenyang Shi": "沈阳市", "Chongqing": "重庆市",
	"Guozhen": "郭镇", "Xi'an Shi": "西安市", "Kowloon": "九龙",
}

// AutonomousPrefectures（R72 二十八次，用户反馈：「大理/怒江/凉山缺市字」——
// 实为少数民族自治州的简称）xdb 对自治州存简称、对普通地级市存全称
// （如「呼和浩特市」），选项树里「大理」与「呼和浩特市」并列显得缺字。
// 简称 → 全称 映射。
// 注意不可盲加「市」：「大理市」是另一个县级市，全称是「大理白族自治州」。
// 港澳的「九龙/将军澳/新界/香港岛/澳门」是地区名非城市，不在此表（保持原值）。
var AutonomousPrefectures = map[string]string{
	// 云南（8 个自治州）
	"大理": "大理白族自治州", "怒江": "怒江傈僳族自治州", "楚雄": "楚雄彝族自治州",
	"红河": "红河哈尼族彝族自治州", "文山": "文山壮族苗族自治州", "西双版纳": "西双版纳傣族自治州",
	"德宏": "德宏傣族景颇族自治州", "迪庆": "迪庆藏族自治州",
	// 四川（3）
	"凉山": "凉山彝族自治州", "甘孜": "甘孜藏族自治州", "阿坝": "阿坝藏族羌族自治州",
	// 贵州（3）
	"黔东南": "黔东南苗族侗族自治州", "黔南": "黔南布依族苗族自治州", "黔西南": "黔西南布依族苗族自治州",
	// 湖南/湖北/吉林（3）
	"湘西": "湘西土家族苗族自治州", "恩施": "恩施土家族苗族自治州", "延边": "延边朝鲜族自治州",
	// 新疆（5）
	"伊犁": "伊犁哈萨克自治州", "昌吉": "昌吉回族自治州", "巴音郭楞": "巴音郭楞蒙古自治州",
	"克孜勒苏": "克孜勒苏柯尔克孜自治州", "博尔塔拉": "博尔塔拉蒙古自治州",
	// 青海（6）
	"海西": "海西蒙古族藏族自治州", "海北": "海北藏族自治州", "黄南": "黄南藏族自治州",
	"海南": "海南藏族自治州", "果洛": "果洛藏族自治州", "玉树": "玉树藏族自治州",
	// 甘肃（2）
	"临夏": "临夏回族自治州", "甘南": "甘南藏族自治州",
	// 地区（1：xdb 缺「地区」后缀）
	"大兴安岭": "大兴安岭地区",
}
