import { severityRank } from '../constants/labels';
import type { Finding } from '../types/scan';
import type { FindingFilterState } from '../types/ui';

export const EMPTY_FINDING_FILTERS: FindingFilterState = {
  severities: [],
  types: [],
};

/**
 * 稳定的默认排序：严重程度从高到低，同等级按起始行号从小到大。
 *
 * 无法可靠定位的发现排在最后，不参与行号比较；最后用 id 兜底，
 * 保证相同输入每次得到相同顺序。
 */
export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((left, right) => {
    const severityDelta = severityRank(left.severity) - severityRank(right.severity);
    if (severityDelta !== 0) {
      return severityDelta;
    }

    const leftLine = left.line_start ?? Number.POSITIVE_INFINITY;
    const rightLine = right.line_start ?? Number.POSITIVE_INFINITY;
    if (leftLine !== rightLine) {
      return leftLine - rightLine;
    }

    return left.id.localeCompare(right.id);
  });
}

/** 各维度内部为“或”，维度之间为“且”；空数组表示该维度不筛选。 */
export function filterFindings(
  findings: Finding[],
  filters: FindingFilterState,
): Finding[] {
  return findings.filter((finding) => {
    if (filters.severities.length > 0 && !filters.severities.includes(finding.severity)) {
      return false;
    }
    if (filters.types.length > 0 && !filters.types.includes(finding.vulnerability_type)) {
      return false;
    }
    return true;
  });
}

export function hasActiveFilters(filters: FindingFilterState): boolean {
  return filters.severities.length > 0 || filters.types.length > 0;
}
