# 任务引擎标准 v2.0（四类型）

> 2026-10-01 用户裁定重构。任务类型决定一切——调度方式、记录策略、日志行为、控制面。
> 零 flag、零补丁、零特判；任务体只写业务逻辑，引擎处理全部基础设施。

## 1. 四类型定义

| 维度 | 定时 Scheduled | 常驻 Daemon | 循环 Periodic | 触发 Oneshot |
|---|---|---|---|---|
| **调度方式** | `NextSlotFn() → time.Time` 引擎每 tick 重读，槽到点执行 | `Run(ctx)` 引擎启动时调用一次，阻塞直到 ctx 取消 | `IntervalFn() → Duration` 每间隔执行一次 | 仅 `Trigger()`（手动/代码） |
| **中间空窗** | **零活动**（零执行/零 task_runs/零日志） | Run 持续运行，引擎不干预 | 间隔等待 | 空闲 |
| **task_runs** | 每次排程执行 1 行 | 每生命周期 1 行（boot 落行，终态随停止更新） | 每轮 1 行 | 每次触发 1 行 |
| **日志（tasks/{id}.log）** | [done]+业务行 | [start]+[done]+失败行+业务行 | 每轮 [done]+业务行 | [start]/[done]+业务行 |
| **调度开关** | ✅ 暂停/恢复排程 | ✅ 启停自管理循环 | ✅ 暂停/恢复循环 | ❌ 显示禁用开关（页面一致性） |
| **手动触发** | ✅ | ❌（启停即可） | ✅ | ✅（唯一执行方式） |
| **取消** | ✅ 执行中可取消 | 用停止代替 | 每轮自动完成 | 每次自动完成 |

### 1.1 引擎调度循环（每 1s tick）

```
Scheduled: loopEnabled && !running && NextSlotFn() ≤ now → Run（每 tick 重读槽——µs 级 SELECT）
Periodic : loopEnabled && !running && now-lastCheck ≥ IntervalFn() → Run
Daemon   : 不进 tick——StartLoop 启动 Run 一次（阻塞）；StopLoop 取消 ctx
Oneshot  : 不进 tick——仅 Trigger
```

单飞：引擎 CAS 强制（in-flight 拒绝重入，全部 Kind 统一）。

### 1.2 Descriptor 接口

```go
type Descriptor struct {
    ID, Family, Name, Description, Category string
    Kind Kind // Scheduled | Daemon | Periodic | Oneshot
    NextSlotFn func() time.Time      // Scheduled：返回下次执行时间（zero=无配置）
    IntervalFn func() time.Duration  // Periodic：固定间隔
    Run        func(RunContext) error // Daemon: 阻塞直到 ctx.Done()
    CancelHook func() bool; EnabledFn func() bool
    StatusFn func() string
    ManualRun, Cancelable bool
    RunsOn Role; MasterOnly bool
}
```

已删除：`SilentProbes`/`RecordFailuresOnly`/`SignalledWork`/`AsKind`/`Cadence`/`Singleton`——Kind 单独决定全部行为；`ToggleFn`/`ToggleName`（LNK71-3，2026-10-11）——v2.0 调度开关统一（StartLoop/StopLoop）后声明族零消费退役，TaskMeta/TaskInfo 的 `toggleable`/`toggle_name` 序列化字段一并删除。

## 2. 任务清单（16 注册任务）

### 定时（4）——排程槽驱动，Run 纯业务

| 任务 | NextSlotFn 数据源 | Run 体 |
|---|---|---|
| threat | `security_threat_sources.next_update` 最早值（UTC） | `m.RunUpdate(trigger)` 直达 |
| crs | `security_crs_version.next_update` | `StartUpdate`+wait |
| ip2region | `security_ip2region_version.next_update` | `StartUpdate`+wait |
| auto-backup | `nextAutoBackupSlot()`（last_run 感知——漏跑追补/已跑步进） | `runAutoBackupScheduled` |

到期检查全部移出 Run 体——引擎保证在排程槽调用，Run 只执行业务。

### 常驻（3）——Run 阻塞自管理循环

| 任务 | Run 体 | 实际工作 |
|---|---|---|
| security-events-ingestion | `runIngestionLoop(ctx)`（内部 2s ticker） | 尾读 coraza 审计日志 |
| cert-issuance | daemonLifecycleRun（真实 StartACME/StopACME 挂钩——B 完全标准化） | CAQueueManager+证书 worker（引擎 daemon 即生命周期所有者）——**RunsOn=MasterOnly** |
| cluster-sync | daemonLifecycleRun（真实 SyncService.Start/Stop 挂钩） | SyncService 轮询（引擎 daemon 即生命周期所有者）——**RunsOn=SlaveOnly**（同步=从节点职能；角色翻转真实启停；Halted/Resume 内部状态机保留） |

系统启动即运行（默认 StartLoop）；关闭调度=启动也不运行；允许手动停止和启用。

**Daemon 角色门（2026-10-01 追加）**：StartLoop 仅在 roleAllows 时启动 Run；
SetRole（promote/demote）自动拉起/停止角色不符的 daemon（loopEnabled 保留——
再 promote 自动恢复）。显示用实际运行态（TaskMeta.Running）：Run 存活=运行中；
调度开但角色不符=空闲；调度关=空闲（方案 A，2026-10-12：状态列只承载执行语义，调度语义归开关列）。

**Daemon 启动计数（2026-10-01 用户裁定）**：启动即记 success 1 行（启动是既成
事实——成功列体现启动计数）；异常退出（Run 返回错误且非 ctx 取消）补记
failed 行（真实时长与错误）；取消/正常停止不增行。

### 循环（8）——固定间隔，每轮独立执行+记录

| 任务 | 间隔 |
|---|---|
| config-watchdog | 60s |
| cert-renewal-scan | 6h（入队时唤醒 cert-waiting-ca） |
| cert-reconcile | 6h |
| cert-manual-poll | 10min |
| cert-waiting-ca | 30s（**默认调度关闭**——见 §3） |
| log-cleanup | 24h |
| audit-retention | 24h |
| security-events-retention | 24h |


另：cert-job 动态行（`cert_jobs` 表逐单镜像）为签发工作项视图，不入引擎注册表。
**行存在即显示**（2026-10-01 用户裁定——无状态/时间过滤，曾按「issued 超 1 天
隐藏」过滤致主节点签发行消失；24h 计数仍按窗口）；仅排除从节点材料物化行
（message=「从主节点同步…」——非签发任务，从节点禁签发）。

### 触发（1）

| 任务 | 说明 |
|---|---|
| startup:config-load | 启动单次（main 记录）+手动重载 |

另：cert-job 动态行（`cert_jobs` 表逐单镜像）为签发工作项视图，不入引擎注册表。

## 3. cert-waiting-ca 特例（默认关闭 + 唤醒/自停）

```
默认：调度关闭（不在默认 StartLoop 清单）——引擎不 tick，页面状态列「空闲」+开关列「已暂停」（方案 A，2026-10-12）
唤醒（U1-66-05 勘误：非单点——四处入队成功路径各自唤醒）：
      cert-renewal-scan Run 体入队后 certJobsActive → StartLoop
      CreateOrRequeueCertJobWithChange 成功路径（规则写路径 Create/Retry/Renew 收敛点）
      RetryCertJob 成功路径（handlers/certjobs.go）
      DeleteCertJob 删除失败恢复重入队成功路径（handlers/certjobs.go）
自停：Run 体发现 certJobsActive()==false → StopLoop（回到默认关闭态）
```

30s 循环为循环任务正常定义；调度关闭期间零执行零记录。

## 4. 控制面（API + 页面）

| 操作 | 端点 | 语义 |
|---|---|---|
| 手动触发 | `POST /system/tasks/{id}/trigger` | 定时/循环/触发类；单飞由引擎 CAS |
| 调度开关 | `POST /system/tasks/{id}/toggle` `{enabled}` | 统一路由 StartLoop/StopLoop（按 Kind 分语义）；触发类 400 |
| 重启 | `POST /system/tasks/{id}/control` `{action:"restart"}` | 仅常驻族 |
| 取消 | `POST /system/tasks/{id}/cancel` | 仅 Cancelable 声明族 |

页面（任务监控）：
- 类型标签四色：定时(蓝)/常驻(绿)/循环(青)/触发(橙)
- 筛选：全部/定时/常驻/循环/触发
- 调度列：非触发类=开关（绑定 loop_on）；触发类=禁用开关（一致性）；cert-job 动态行=「—」
- 常驻族停止需确认弹框；操作列常驻族有「重启」

### 4.1 业务开关联动（2026-10-01 用户裁定）

四个定时任务的**业务开关**（安全设置页的 threat/CRS/IP2Region 自动更新、备份设置页的自动备份启用）与任务监控联动：

- EnabledFn（DB 直读）暴露业务开关态 → 视图 `enabled=false`（方案 A，2026-10-12：状态列=空闲，开关列并判 loop_on&&enabled 显示「已暂停」；cert-waiting-ca 的 StatusFn stopped 借用同轮废除）
- NextSlotFn 同源判断——业务关=零调度零下次执行
- 引擎调度开关（loop_on）与业务开关两层独立：调度开关暂停=引擎不投递；业务开关关闭=无排程槽可投递

## 5. 记录与日志口径

| 场景 | task_runs | 日志 |
|---|---|---|
| 定时槽间隙 | 0 行 | 0 行 |
| 定时执行 | 1 行（引擎预插 running→终态） | [done]+业务 |
| 常驻生命周期 | 启动即记 success；异常退出补 failed 行 | [start]；停止 [done stopped]；失败 [done failed] |
| 循环每轮 | 1 行 | [done]+业务 |
| 触发执行 | 1 行 | [start]/[done]+业务 |
| 手动触发 | 1 行（trigger=manual） | 同上 |
| 崩溃恢复 | 残留 running → interrupted | — |

task_runs 保留 90 天（audit-retention 每日清理）。

## 6. 业务侧 helper

- `TaskLogf(taskID, stage, format, ...)` — 业务摘要行（tee 到任务日志）
- `taskengine.TeeTaskLog` — 分阶段流水
- `RecordRunStart/RecordRunFinish` — legacy 直调路径（引擎外执行）

## 7. 修订记录

- v2.0（2026-10-01）：四类型标准重构。Kind 枚举 4 值替代 Continuous/Queue/Info；删除 SilentProbes/RecordFailuresOnly/SignalledWork/Singleton/AsKind/Cadence；NextSlotFn 返回 time.Time；Daemon 生命周期（StartLoop 调 Run 一次+阻塞）；cert-waiting-ca 默认调度关闭+唤醒/自停；自动备份遗留 1min 调度器删除（追补语义移入 nextAutoBackupSlot 的 last_run 感知）；ingestion 改自管理循环。
