<template>
  <el-tooltip placement="top" :popper-class="popperClass" :disabled="!content && !$slots.content">
    <template #content>
      <slot name="content">{{ content }}</slot>
    </template>
    <el-icon class="field-help-icon"><QuestionFilled /></el-icon>
  </el-tooltip>
</template>

<script setup lang="ts">
import { QuestionFilled } from '@element-plus/icons-vue'

// 统一字段帮助角标（2026-10-12 用户裁定：角标应有统一规范及实现，不再各处手写 icon+CSS）。
// 规范：紧跟标题文字后、默认 inline 形态（无额外定位——与表头原生态逐像素一致）、
// 灰色 QuestionFilled 14px、hover 提示（支持纯文本 content 或 #content 插槽多行）。
// 全部消费方迁移自此（表头/表单 label/开关行）；新增 ？ 角标一律用本组件，禁止手写。
withDefaults(defineProps<{
  readonly content?: string
  readonly popperClass?: string
}>(), { content: '' })
</script>

<style scoped>
.field-help-icon {
  color: #9ca3af;
  font-size: 14px;
}
</style>
