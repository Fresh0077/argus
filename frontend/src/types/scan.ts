/**
 * 与后端 `backend/app/schemas/` 对齐的 TypeScript 类型。
 *
 * 这里的字段名与取值必须和后端契约保持一致；后端是唯一来源。
 * 枚举字段保留字面量联合，方便穷尽处理；渲染未知取值时使用
 * `constants/labels.ts` 中的映射函数兜底，避免白屏。
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type FindingSource = 'static_rule' | 'heuristic' | 'semgrep' | 'llm';

export type ScanStatus = 'completed' | 'partial' | 'failed';

export type AnalyzerName =
  | 'language_detection'
  | 'feature_extraction'
  | 'clue_extraction'
  | 'rules'
  | 'semgrep'
  | 'llm';

export type AnalyzerState = 'success' | 'skipped' | 'unavailable' | 'failed';

export type LanguageSource = 'explicit' | 'extension' | 'heuristic' | 'none';

/** 一条候选发现。它不是已确认的漏洞，仍需人工复核。 */
export interface Finding {
  id: string;
  title: string;
  vulnerability_type: string;
  severity: Severity;
  description: string;
  /** 支持该发现的代码片段；可能为空字符串。 */
  evidence: string;
  /** 无法可靠定位时为 null，不要当作 0 处理。 */
  line_start: number | null;
  line_end: number | null;
  recommendation: string;
  /** 分析置信度（0–1），不是漏洞真实发生的概率。 */
  confidence: number;
  source: FindingSource;
  rule_id: string | null;
  cwe_id: string | null;
}

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface ScanSummary {
  total_findings: number;
  severity_counts: SeverityCounts;
  source_counts: Partial<Record<FindingSource, number>>;
}

export interface AnalyzerStatus {
  name: AnalyzerName;
  state: AnalyzerState;
  /** 非 success 状态必定有原因。 */
  reason: string | null;
  /** 未执行时为 null。 */
  duration_ms: number | null;
  findings_count: number;
}

export interface CodeStats {
  total_lines: number;
  non_blank_lines: number;
  total_chars: number;
  max_line_length: number;
}

export interface CodeStructure {
  function_count: number;
  class_count: number;
  import_count: number;
  imports: string[];
}

export interface FeatureExtractionResult {
  language: string | null;
  language_source: LanguageSource;
  language_evidence: string;
  stats: CodeStats;
  structure: CodeStructure;
  notes: string[];
}

export interface ScanResponse {
  scan_id: string;
  status: ScanStatus;
  /** 无法识别时为 null，界面显示“未识别语言”。 */
  detected_language: string | null;
  /** 仅上传接口会填写实际解码方式。 */
  source_encoding: string | null;
  findings: Finding[];
  summary: ScanSummary;
  duration_ms: number;
  analyzer_status: AnalyzerStatus[];
  /** 为 null 表示特征提取没有执行，与“计数为 0”不同。 */
  features: FeatureExtractionResult | null;
  disclaimer: string;
}

export interface AnalysisOptions {
  enable_llm: boolean;
  enable_semgrep: boolean;
}

/** `POST /api/v1/scan` 的 JSON 请求体。 */
export interface ScanRequest {
  source_code: string;
  language?: string | null;
  filename?: string | null;
  analysis_options?: AnalysisOptions;
}

export interface ErrorDetail {
  field: string | null;
  message: string;
}

/** 后端统一错误响应。`code` 使用字符串，保证未知错误码也能显示。 */
export interface ApiErrorBody {
  error: {
    code: string;
    message: string;
    details: ErrorDetail[];
  };
}
