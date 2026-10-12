<template>
  <span class="takeover-badge"><slot>{{ label }}</slot></span>
</template>

<script setup lang="ts">
// 统一「配置接管」徽标（2026-10-12 用户裁定：与刷新间隔（ProxyTimeoutFields）形态一致
// ——tip 文本流内前置徽标，不置于 label 侧）。使用规范：接管态字段的提示行开头。
// 全部消费方（代理超时接管/Keepalive/主动健康检查/强制 HTTP/1.1）迁移自此。
withDefaults(defineProps<{
  readonly label?: string
}>(), { label: 'NTLM 接管' })
</script>

<style scoped>
.takeover-badge {
  display: inline-block;
  margin-right: 6px;
  padding: 0 6px;
  border: 1px solid var(--el-border-color);
  border-radius: 4px;
  background: var(--el-fill-color-light);
  color: var(--el-text-color-secondary);
  font-size: 11px;
  line-height: 18px;
  white-space: nowrap;
}
</style>
