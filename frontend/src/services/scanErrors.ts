import type { ScanErrorInfo } from '../types/ui';
import { ApiError } from './apiClient';

const FIELD_LABELS: Record<string, string> = {
  source_code: '代码',
  file: '文件',
  language: '语言',
  filename: '文件名',
  analysis_options: '分析选项',
  raw_request: '请求报文',
  enable_llm: 'LLM 开关',
  confirm_send: '发送确认',
  preview_fingerprint: '预览指纹',
};

function fieldLabel(field: string | null): string {
  if (!field) {
    return '请求';
  }
  return FIELD_LABELS[field] ?? field;
}

/**
 * 把请求异常翻译成用户可据此行动的界面文案。
 *
 * 源码扫描与请求包审计共用一个映射；标题可按场景覆盖，避免请求审计失败时
 * 显示“扫描失败”这类不准确的说法。
 */
export function toScanErrorInfo(
  error: unknown,
  titles: { fallback?: string; server?: string } = {},
): ScanErrorInfo {
  const fallbackTitle = titles.fallback ?? '扫描失败';
  const serverTitle = titles.server ?? '后端扫描失败';

  if (!(error instanceof ApiError)) {
    return {
      title: fallbackTitle,
      message: '发生未预期的错误，请稍后重试。',
      details: [],
    };
  }

  const details = error.details.map((detail) =>
    detail.field ? `${fieldLabel(detail.field)}：${detail.message}` : detail.message,
  );

  if (error.kind === 'network') {
    return { title: '无法连接后端', message: error.message, details };
  }
  if (error.kind === 'timeout') {
    return { title: '请求超时', message: error.message, details };
  }
  if (error.kind === 'invalid_response') {
    return {
      title: '响应格式异常',
      message: '后端返回了无法识别的响应，请确认前后端版本一致。',
      details,
    };
  }
  if (error.kind === 'aborted') {
    return { title: '请求已取消', message: error.message, details };
  }

  if (error.status === 413) {
    return { title: '输入超过限制', message: error.message, details };
  }
  if (error.status === 415) {
    return { title: '文件类型不支持', message: error.message, details };
  }
  if (error.status === 409) {
    return { title: '预览已过期', message: error.message, details };
  }
  if (error.status === 422) {
    return { title: '输入校验未通过', message: error.message, details };
  }
  if (error.status !== undefined && error.status >= 500) {
    return { title: serverTitle, message: error.message, details };
  }

  return {
    title: '请求被拒绝',
    message: error.message,
    details,
  };
}
