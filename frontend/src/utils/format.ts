/** 纯格式化函数：只影响展示，不推导任何扫描结论。 */

/** 行号缺失时显示“未能可靠定位”，绝不显示 0 或编造行号。 */
export function formatLineRange(start: number | null, end: number | null): string {
  if (start === null) {
    return '未能可靠定位';
  }
  if (end === null || end === start) {
    return `第 ${start} 行`;
  }
  return `第 ${start}–${end} 行`;
}

export function formatDuration(milliseconds: number): string {
  if (milliseconds <= 0) {
    // 后端用整数毫秒计时，0 表示不足 1 ms，而不是“没有耗时”。
    return '不足 1 ms';
  }
  if (milliseconds < 1000) {
    return `${milliseconds} ms`;
  }
  return `${(milliseconds / 1000).toFixed(2)} s`;
}

export function formatConfidence(confidence: number): string {
  return `${Math.round(confidence * 100)}%`;
}

/**
 * 把后端返回的 UTC ISO 时间转换为本地时间展示。
 *
 * 解析失败时原样显示：历史时间来自数据库，宁可展示原始值，
 * 也不要显示一个看似正常、实际由猜测得到的本地时间。
 */
export function formatDateTime(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return date.toLocaleString('zh-CN', { hour12: false });
}
