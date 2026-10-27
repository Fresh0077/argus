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
