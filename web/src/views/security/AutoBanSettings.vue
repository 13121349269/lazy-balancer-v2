<template>
  <div class="page">
    <div class="page-header">
      <div class="header-left">
        <h2 class="page-title">
          <el-icon class="title-icon"><Aim /></el-icon>
          自动封禁
        </h2>
        <p class="page-desc">按攻击频次与扫描特征自动封禁来源 IP（fail2ban 风格），封禁在限流与 OWASP CRS 之前生效</p>
      </div>
      <div class="header-actions">
        <el-button :disabled="isReadOnly || running || loading" @click="handleRunNow">
          <el-icon><Refresh /></el-icon>
          立即执行一次
        </el-button>
      </div>
    </div>

    <el-alert v-if="isReadOnly" :title="readOnlyText" type="info" :closable="false" show-icon class="readonly-alert" />

    <el-card v-loading="loading" class="settings-card">
      <template #header>
        <div class="card-header">
          <span class="card-header-title">封禁参数</span>
          <span class="card-header-sub">攻击源 IP 累计命中阈值后自动进入封禁列表</span>
        </div>
      </template>

      <el-form :model="form" label-width="160px" label-position="left" class="autoban-form" :disabled="isReadOnly">
        <el-form-item label="启用自动封禁">
          <el-switch v-model="form.enabled" />
          <span class="form-hint">关闭后仅停止新增封禁，已封禁条目保持不变</span>
        </el-form-item>

        <el-divider content-position="left">攻击封禁</el-divider>

        <el-form-item label="封禁阈值（次）">
          <el-input-number v-model="form.threshold" :min="1" :max="100000" :step="1" step-strictly />
          <span class="form-hint">统计窗口内被拦截次数达到该值即封禁</span>
        </el-form-item>

        <el-form-item label="统计窗口（分钟）">
          <el-input-number v-model="form.window_minutes" :min="1" :max="1440" :step="1" step-strictly />
          <span class="form-hint">封禁阈值统计的时间窗口</span>
        </el-form-item>

        <el-form-item label="封禁时长（小时）">
          <el-input-number v-model="form.duration_hours" :min="0" :max="8760" :step="1" step-strictly />
          <span class="form-hint">0 表示永不自动解封</span>
        </el-form-item>

        <el-divider content-position="left">扫描检测</el-divider>

        <el-form-item label="启用扫描检测">
          <el-switch v-model="form.scan_enabled" />
          <span class="form-hint">识别 OWASP CRS 913* 扫描器/探测特征</span>
        </el-form-item>

        <el-form-item label="扫描阈值（次）">
          <el-input-number v-model="form.scan_threshold" :min="1" :max="100000" :step="1" step-strictly />
          <span class="form-hint">统计窗口内扫描特征命中次数达到该值即封禁</span>
        </el-form-item>

        <el-divider content-position="left">生效列表</el-divider>

        <el-form-item label="目标封禁列表 ID">
          <el-input :model-value="form.target_list_id ? String(form.target_list_id) : '-'" disabled class="target-list-input" />
          <span class="form-hint">系统自动创建并维护的「自动封禁IP」列表，由 deny 型 ACL 引用生效</span>
        </el-form-item>

        <el-form-item v-if="!isReadOnly" label-width="0" class="submit-item">
          <el-button type="primary" :loading="saving" @click="handleSave">保存设置</el-button>
          <el-button :disabled="saving" @click="resetForm">重置</el-button>
        </el-form-item>
      </el-form>
    </el-card>

    <el-card v-loading="ccLoading" class="settings-card cc-card">
      <template #header>
        <div class="card-header">
          <span class="card-header-title">CC 防护封禁联动</span>
          <span class="card-header-sub">窗口内单 IP 触发限流拦截（429）次数过阈值后自动封禁</span>
        </div>
      </template>

      <el-form :model="ccForm" label-width="160px" label-position="left" class="autoban-form" :disabled="isReadOnly">
        <el-form-item label="启用 CC 封禁">
          <el-switch v-model="ccForm.enabled" />
          <span class="form-hint">依赖各站点访问日志记录限流拦截（规则需开启访问日志）</span>
        </el-form-item>

        <el-form-item label="封禁阈值（次）">
          <el-input-number v-model="ccForm.threshold" :min="1" :max="100000" :step="1" step-strictly />
          <span class="form-hint">统计窗口内单 IP 限流拦截次数达到该值即封禁</span>
        </el-form-item>

        <el-form-item label="统计窗口（分钟）">
          <el-input-number v-model="ccForm.window_minutes" :min="1" :max="1440" :step="1" step-strictly />
          <span class="form-hint">限流拦截次数统计的时间窗口</span>
        </el-form-item>

        <el-form-item label="封禁时长（小时）">
          <el-input-number v-model="ccForm.duration_hours" :min="0" :max="8760" :step="1" step-strictly />
          <span class="form-hint">0 表示永不自动解封</span>
        </el-form-item>

        <el-form-item v-if="!isReadOnly" label-width="0" class="submit-item">
          <el-button type="primary" :loading="ccSaving" @click="handleSaveCC">保存设置</el-button>
          <el-button :loading="ccRunning" :disabled="ccSaving" @click="handleRunCCNow">立即执行一次</el-button>
        </el-form-item>
      </el-form>
    </el-card>

    <el-card class="result-card" v-if="lastRunResult">
      <template #header>
        <span class="card-header-title">最近执行结果</span>
      </template>
      <el-tag v-if="lastRunResult.banned.length" type="danger" effect="plain" class="result-tag">
        新增封禁 {{ lastRunResult.banned.length }} 个 IP
      </el-tag>
      <el-tag v-else type="success" effect="plain">扫描完成，无新增封禁</el-tag>
      <p v-if="lastRunResult.banned.length" class="result-list">{{ lastRunResult.banned.join('、') }}</p>
      <p class="result-time">执行时间：{{ lastRunResult.time }}</p>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { Aim, Refresh } from '@element-plus/icons-vue'
import { request, mfaAwareSuccess } from '@/utils/api'
import { useAuthStore } from '@/stores/auth'
import type { APIResponse } from '@/types'

interface AutoBanSettings {
  enabled: boolean
  threshold: number
  window_minutes: number
  duration_hours: number
  scan_enabled: boolean
  scan_threshold: number
  target_list_id: number
}

interface CCBanSettings {
  enabled: boolean
  threshold: number
  window_minutes: number
  duration_hours: number
}

const authStore = useAuthStore()
const isReadOnly = computed(() => authStore.readOnlyReason !== null)
const readOnlyText = computed(() => authStore.readOnlyMessage || '当前节点/角色只读')

const loading = ref(false)
const saving = ref(false)
const running = ref(false)

const defaultForm = (): AutoBanSettings => ({
  enabled: false,
  threshold: 20,
  window_minutes: 10,
  duration_hours: 24,
  scan_enabled: true,
  scan_threshold: 10,
  target_list_id: 0,
})

const form = ref<AutoBanSettings>(defaultForm())
const lastRunResult = ref<{ banned: string[]; time: string } | null>(null)

const fetchData = async () => {
  loading.value = true
  try {
    const res = await request.get<APIResponse<AutoBanSettings>>('/settings/auto-ban')
    if (res.data) form.value = { ...defaultForm(), ...res.data }
  } catch (error: unknown) {
    console.error('Failed to load auto-ban settings:', error)
  } finally {
    loading.value = false
  }
}

const resetForm = () => {
  void fetchData()
}

const handleSave = async () => {
  if (isReadOnly.value || saving.value) return
  if (form.value.threshold < 1 || form.value.window_minutes < 1 || form.value.duration_hours < 0 || form.value.scan_threshold < 1) {
    authStore.showToast('warning', '请检查参数是否在允许范围内')
    return
  }
  saving.value = true
  try {
    const res = await request.put('/settings/auto-ban', {
      enabled: form.value.enabled,
      threshold: form.value.threshold,
      window_minutes: form.value.window_minutes,
      duration_hours: form.value.duration_hours,
      scan_enabled: form.value.scan_enabled,
      scan_threshold: form.value.scan_threshold,
    })
    mfaAwareSuccess(res.message || '自动封禁设置已保存')
    await fetchData()
  } catch (error: unknown) {
    console.error('Failed to save auto-ban settings:', error)
  } finally {
    saving.value = false
  }
}

const handleRunNow = async () => {
  if (isReadOnly.value || running.value) return
  running.value = true
  try {
    const res = await request.post<APIResponse<{ newly_banned?: string[] }>>('/auto-ban/run')
    const banned = res.data?.newly_banned ?? []
    lastRunResult.value = { banned, time: new Date().toLocaleString() }
    if (banned.length) {
      authStore.showToast('success', `已封禁 ${banned.length} 个 IP`)
    } else {
      authStore.showToast('info', '扫描完成，无新增封禁')
    }
  } catch (error: unknown) {
    console.error('Failed to run auto-ban now:', error)
  } finally {
    running.value = false
  }
}

const defaultCCForm = (): CCBanSettings => ({
  enabled: false,
  threshold: 10,
  window_minutes: 10,
  duration_hours: 1,
})

const ccForm = ref<CCBanSettings>(defaultCCForm())
const ccLoading = ref(false)
const ccSaving = ref(false)
const ccRunning = ref(false)

const fetchCCData = async () => {
  ccLoading.value = true
  try {
    const res = await request.get<APIResponse<CCBanSettings>>('/settings/cc-ban')
    if (res.data) ccForm.value = { ...defaultCCForm(), ...res.data }
  } catch (error: unknown) {
    console.error('Failed to load cc-ban settings:', error)
  } finally {
    ccLoading.value = false
  }
}

const handleSaveCC = async () => {
  if (isReadOnly.value || ccSaving.value) return
  if (ccForm.value.threshold < 1 || ccForm.value.window_minutes < 1 || ccForm.value.duration_hours < 0) {
    authStore.showToast('warning', '请检查参数是否在允许范围内')
    return
  }
  ccSaving.value = true
  try {
    const res = await request.put('/settings/cc-ban', {
      enabled: ccForm.value.enabled,
      threshold: ccForm.value.threshold,
      window_minutes: ccForm.value.window_minutes,
      duration_hours: ccForm.value.duration_hours,
    })
    mfaAwareSuccess(res.message || 'CC 封禁设置已保存')
    await fetchCCData()
  } catch (error: unknown) {
    console.error('Failed to save cc-ban settings:', error)
  } finally {
    ccSaving.value = false
  }
}

const handleRunCCNow = async () => {
  if (isReadOnly.value || ccRunning.value) return
  ccRunning.value = true
  try {
    const res = await request.post<APIResponse<{ newly_banned?: string[] }>>('/cc-ban/run')
    const banned = res.data?.newly_banned ?? []
    lastRunResult.value = { banned, time: new Date().toLocaleString() }
    if (banned.length) {
      authStore.showToast('success', `已封禁 ${banned.length} 个 IP`)
    } else {
      authStore.showToast('info', '扫描完成，无新增封禁')
    }
  } catch (error: unknown) {
    console.error('Failed to run cc-ban now:', error)
  } finally {
    ccRunning.value = false
  }
}

onMounted(() => {
  void fetchData()
  void fetchCCData()
})
</script>

<style scoped>
.readonly-alert { margin-bottom: 16px; }
.settings-card { max-width: 860px; }
.cc-card { margin-top: 16px; }
.header-actions { display: flex; gap: 8px; }
.card-header { display: flex; align-items: baseline; gap: 10px; }
.card-header-title { font-size: 15px; font-weight: 600; color: var(--text-primary, #111827); }
.card-header-sub { font-size: 12.5px; color: var(--text-secondary, #6b7280); }
.autoban-form { padding-top: 4px; }
.form-hint { margin-left: 12px; font-size: 12.5px; color: var(--text-secondary, #6b7280); }
.target-list-input { width: 220px; }
.submit-item { margin-top: 8px; }
.result-card { max-width: 860px; margin-top: 16px; }
.result-tag { margin-bottom: 10px; }
.result-list { margin: 0 0 8px; color: var(--text-primary, #111827); font-size: 13px; line-height: 1.7; word-break: break-all; }
.result-time { margin: 0; color: var(--text-secondary, #6b7280); font-size: 12.5px; }
</style>
