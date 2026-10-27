import type {
  AnalyzerName,
  AnalyzerState,
  FindingSource,
  ScanStatus,
  Severity,
} from '../types/scan';

export interface LabelMeta {
  label: string;
  /** 用于 antd Tag 与统计块；文字标签始终同时出现，颜色不是唯一标识。 */
  color: string;
}

const UNKNOWN_COLOR = '#8c8c8c';

const SEVERITY_META: Record<Severity, LabelMeta> = {
  critical: { label: '严重', color: '#cf1322' },
  high: { label: '高危', color: '#d4380d' },
  medium: { label: '中危', color: '#d48806' },
  low: { label: '低危', color: '#1668dc' },
  info: { label: '提示', color: '#8c8c8c' },
};

/** 未知严重等级按中性样式展示原始取值，不猜测等级。 */
export function severityMeta(value: string): LabelMeta {
  return SEVERITY_META[value as Severity] ?? { label: value || '未知等级', color: UNKNOWN_COLOR };
}

const SOURCE_META: Record<FindingSource, LabelMeta> = {
  static_rule: { label: '本地规则', color: '#1668dc' },
  heuristic: { label: '特征线索', color: '#d48806' },
  semgrep: { label: 'Semgrep', color: '#722ed1' },
  llm: { label: 'LLM', color: '#13c2c2' },
};

export function sourceMeta(value: string): LabelMeta {
  return SOURCE_META[value as FindingSource] ?? { label: value || '未知来源', color: UNKNOWN_COLOR };
}

const ANALYZER_NAME_META: Record<AnalyzerName, string> = {
  language_detection: '语言识别',
  feature_extraction: '特征提取',
  clue_extraction: '候选线索',
  rules: '本地规则',
  semgrep: 'Semgrep',
  llm: 'LLM',
};

export function analyzerNameLabel(value: string): string {
  return ANALYZER_NAME_META[value as AnalyzerName] ?? (value || '未知分析器');
}

const ANALYZER_STATE_META: Record<AnalyzerState, LabelMeta> = {
  success: { label: '成功', color: '#237804' },
  skipped: { label: '已跳过', color: '#8c8c8c' },
  unavailable: { label: '不可用', color: '#d46b08' },
  failed: { label: '失败', color: '#cf1322' },
};

export function analyzerStateMeta(value: string): LabelMeta {
  return ANALYZER_STATE_META[value as AnalyzerState] ?? { label: value || '未知状态', color: UNKNOWN_COLOR };
}

const SCAN_STATUS_META: Record<ScanStatus, LabelMeta> = {
  completed: { label: '完成', color: '#237804' },
  partial: { label: '部分完成', color: '#d46b08' },
  failed: { label: '失败', color: '#cf1322' },
};

export function scanStatusMeta(value: string): LabelMeta {
  return SCAN_STATUS_META[value as ScanStatus] ?? { label: value || '未知状态', color: UNKNOWN_COLOR };
}

const LANGUAGE_LABELS: Record<string, string> = {
  python: 'Python',
  javascript: 'JavaScript',
  typescript: 'TypeScript',
  java: 'Java',
  php: 'PHP',
  go: 'Go',
  ruby: 'Ruby',
  html: 'HTML',
  vue: 'Vue',
  c: 'C',
  'c++': 'C++',
  csharp: 'C#',
  rust: 'Rust',
};

export function languageLabel(value: string | null): string {
  if (!value) {
    return '未识别语言';
  }
  return LANGUAGE_LABELS[value] ?? value;
}
