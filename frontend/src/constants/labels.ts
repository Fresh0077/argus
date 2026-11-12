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

// 这些颜色同时用作 antd Tag 的实色背景（白字）和统计块文字色。
// 因此统一选较深的色值，保证小字号文字也有足够对比度。
const UNKNOWN_COLOR = '#595959';

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

const SEVERITY_META: Record<Severity, LabelMeta> = {
  critical: { label: '严重', color: '#cf1322' },
  high: { label: '高危', color: '#d4380d' },
  medium: { label: '中危', color: '#995c00' },
  low: { label: '低危', color: '#1668dc' },
  info: { label: '提示', color: '#595959' },
};

/** 未知严重等级按中性样式展示原始取值，不猜测等级。 */
export function severityMeta(value: string): LabelMeta {
  return SEVERITY_META[value as Severity] ?? { label: value || '未知等级', color: UNKNOWN_COLOR };
}

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

/** 排序用权重；未知等级排在最后，不猜测严重性。 */
export function severityRank(value: string): number {
  return SEVERITY_RANK[value as Severity] ?? Number.MAX_SAFE_INTEGER;
}

export const SOURCE_ORDER: FindingSource[] = ['static_rule', 'heuristic', 'semgrep', 'llm'];

const SOURCE_META: Record<FindingSource, LabelMeta> = {
  static_rule: { label: '本地规则', color: '#1668dc' },
  heuristic: { label: '特征线索', color: '#995c00' },
  semgrep: { label: 'Semgrep', color: '#722ed1' },
  llm: { label: 'LLM', color: '#006d75' },
};

export function sourceMeta(value: string): LabelMeta {
  return SOURCE_META[value as FindingSource] ?? { label: value || '未知来源', color: UNKNOWN_COLOR };
}

const VULNERABILITY_TYPE_LABELS: Record<string, string> = {
  sql_injection: 'SQL 注入',
  command_injection: '命令注入',
  xss: '跨站脚本（XSS）',
  unsafe_dynamic_execution: '不安全动态执行',
  unsafe_deserialization: '不安全反序列化',
  untrusted_input_source: '外部输入来源（线索）',
  // 请求包审计（阶段 19）。这些名称只描述请求报文中可观察的信号。
  sensitive_data_in_url: '敏感信息出现在 URL',
  credentials_in_plaintext: '明文传输凭证',
  missing_csrf_token: '未观察到 CSRF 令牌',
  content_type_mismatch: 'Content-Type 不一致',
  suspicious_payload_pattern: '疑似攻击载荷特征',
};

/** 未知漏洞类型保留后端原始取值，便于后续排查，不猜测含义。 */
export function vulnerabilityTypeLabel(value: string): string {
  return VULNERABILITY_TYPE_LABELS[value] ?? (value || '未知类型');
}

const ANALYZER_NAME_META: Record<string, string> = {
  language_detection: '语言识别',
  feature_extraction: '特征提取',
  clue_extraction: '候选线索',
  rules: '本地规则',
  semgrep: 'Semgrep',
  llm: 'LLM',
  // 请求包审计（阶段 19）。
  http_request_parse: '报文解析',
  http_request_llm: 'LLM 审计',
};

export function analyzerNameLabel(value: string): string {
  return ANALYZER_NAME_META[value as AnalyzerName] ?? (value || '未知分析器');
}

const ANALYZER_STATE_META: Record<AnalyzerState, LabelMeta> = {
  success: { label: '成功', color: '#237804' },
  skipped: { label: '已跳过', color: '#595959' },
  unavailable: { label: '不可用', color: '#995c00' },
  failed: { label: '失败', color: '#cf1322' },
};

export function analyzerStateMeta(value: string): LabelMeta {
  return ANALYZER_STATE_META[value as AnalyzerState] ?? { label: value || '未知状态', color: UNKNOWN_COLOR };
}

const SCAN_STATUS_META: Record<ScanStatus, LabelMeta> = {
  completed: { label: '完成', color: '#237804' },
  partial: { label: '部分完成', color: '#995c00' },
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
