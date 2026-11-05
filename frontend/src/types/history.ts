/**
 * 与后端 `app/schemas/history.py` 对齐的扫描历史类型。
 *
 * 历史只保存扫描元数据、摘要与候选发现，不保存完整源代码；
 * 因此这里没有 `source_code` 字段，详情中的 `findings[].evidence`
 * 也只是分析器给出的最小片段。
 */

import type {
  AnalyzerStatus,
  Finding,
  FindingSource,
  ScanStatus,
  SeverityCounts,
} from './scan';

export interface HistoryItem {
  scan_id: string;
  /** UTC ISO 时间；展示前转换为本地时间。 */
  created_at: string;
  filename: string | null;
  language: string | null;
  status: ScanStatus;
  source_encoding: string | null;
  duration_ms: number;
  total_findings: number;
  severity_counts: SeverityCounts;
  source_counts: Partial<Record<FindingSource, number>>;
}

export interface HistoryDetail extends HistoryItem {
  findings: Finding[];
  analyzer_status: AnalyzerStatus[];
}

export interface HistoryListResponse {
  /** false 表示服务端通过 HISTORY_ENABLED=false 关闭了历史功能。 */
  enabled: boolean;
  items: HistoryItem[];
  total: number;
  page: number;
  page_size: number;
  /** 没有记录时为 0。 */
  total_pages: number;
}
