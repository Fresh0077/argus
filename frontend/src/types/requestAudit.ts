/**
 * 与后端 `backend/app/schemas/http_request.py` 对齐的类型。
 *
 * 请求包审计与源码扫描是两条独立链路：这里复用 `Finding` / `ScanSummary`
 * 的展示语义，但分析器名称使用请求审计自己的取值。
 */

import type {
  AnalyzerState,
  Finding,
  ScanStatus,
  ScanSummary,
} from './scan';

export type RequestAnalyzerName = 'http_request_parse' | 'http_request_llm';

export type RequestBodyKind = 'none' | 'urlencoded' | 'json' | 'multipart' | 'text';

export interface RequestAnalyzerStatus {
  name: RequestAnalyzerName;
  state: AnalyzerState;
  reason: string | null;
  duration_ms: number | null;
  findings_count: number;
}

export interface RequestHeaderSummary {
  name: string;
  line: number;
}

export interface RequestParameterSummary {
  name: string;
  location: 'query' | 'body' | 'cookie';
  line: number;
}

export interface RequestBodySummary {
  kind: RequestBodyKind;
  content_type: string | null;
  length: number;
  line_start: number | null;
}

export interface ParsedRequestSummary {
  method: string;
  target: string;
  path: string;
  http_version: string;
  scheme: string | null;
  header_count: number;
  headers: RequestHeaderSummary[];
  parameter_count: number;
  parameters: RequestParameterSummary[];
  cookie_count: number;
  body: RequestBodySummary;
  line_count: number;
}

export interface RedactionSummary {
  redacted_count: number;
  categories: string[];
}

/** `POST /api/v1/audit/request` 的请求体。 */
export interface RequestAuditRequest {
  raw_request: string;
  /** 预览中手动编辑后的文本；提供时服务端以它为准发送给 LLM。 */
  redacted_request?: string | null;
  preview_only?: boolean;
  confirm_send?: boolean;
  preview_fingerprint?: string | null;
}

export interface RequestAuditResponse {
  audit_id: string;
  status: ScanStatus;
  preview_only: boolean;
  /** 本次审计文本是否经过用户手动编辑。 */
  edited: boolean;
  parsed: ParsedRequestSummary;
  redacted_request: string;
  preview_fingerprint: string;
  redaction: RedactionSummary;
  /** 只含 LLM 发现；预览或 LLM 未执行时为空。 */
  findings: Finding[];
  summary: ScanSummary;
  analyzer_status: RequestAnalyzerStatus[];
  duration_ms: number;
  llm_invoked: boolean;
  disclaimer: string;
}
