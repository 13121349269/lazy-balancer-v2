<template>
  <el-tooltip placement="top" :popper-class="popperClass" :disabled="!content && !$slots.content">
    <template #content>
      <slot name="content">{{ content }}</slot>
    </template>
    <el-icon class="field-help-icon" :style="iconStyle"><QuestionFilled /></el-icon>
  </el-tooltip>
</template>

<script setup lang="ts">
import { QuestionFilled } from '@element-plus/icons-vue'

// 统一字段帮助角标（2026-10-12 用户裁定：角标应有统一规范及实现，不再各处手写 icon+CSS）。
// 规范：紧跟标题文字后、顶部对齐（vertical-align 一次性定死于本组件）、
// 灰色 QuestionFilled 14px、hover 提示（支持纯文本 content 或 #content 插槽多行）。
// 全部消费方迁移自此（表头/表单 label/开关行）；新增 ？ 角标一律用本组件，禁止手写。
withDefaults(defineProps<{
  readonly content?: string
  readonly popperClass?: string
}>(), { content: '' })

const iconStyle = { verticalAlign: '1px' as const }
</script>

<style scoped>
.field-help-icon {
  color: #9ca3af;
  font-size: 14px;
  margin-left: 2px;
  cursor: help;
}
</style>
