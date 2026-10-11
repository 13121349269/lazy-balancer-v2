// echarts 统一注册（2026-10-11 用户裁定方向）：全站单一注册点——此前
// Dashboard/SecurityOverview/TaskMonitor 三页面各自 import 并本地 use()，
// 但 echarts.use 是**全局单例注册**：注册面随路由懒加载顺序漂移（先到
// Dashboard 才注册 LineChart；直接刷新任务监控页则只有 PieChart/BarChart
// ——折线图在直刷形态下静默缺注册，轴渲染而序列缺失）。
// 三个页面改为 import 本模块（副作用即注册完成），不再各自 use()。
import { use } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'
import { LineChart, PieChart, BarChart } from 'echarts/charts'
import { GridComponent, TooltipComponent, LegendComponent } from 'echarts/components'

use([CanvasRenderer, LineChart, PieChart, BarChart, GridComponent, TooltipComponent, LegendComponent])
