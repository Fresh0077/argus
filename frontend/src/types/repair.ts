/**
 * 修复建议相关类型，与后端 `app/schemas/repair.py` 对齐。
 *
 * 这些类型只描述"候选补丁"，不代表已经验证的修复。
 */

import type { Finding } from './scan';

/** 调用的上下文：用户当前查看的扫描结果对应的源代码。 */
export interface RepairContext {
  sourceCode: string;
  /** 未识别时为 null。 */
  language: string | null;
  /** 仅用于展示与建议下载文件名。 */
  filename: string | null;
}

/** `POST /api/v1/repair` 的请求体。 */
export interface RepairRequest {
  source_code: string;
  language?: string | null;
  filename?: string | null;
  finding: Finding;
}

/** 后端生成的一条候选补丁。 */
export interface RepairSuggestion {
  finding_id: string;
  /** 待替换的真实原始代码。 */
  original_code: string;
  /** 模型给出的替换代码。 */
  fixed_code: string;
  /** 服务端计算的 unified diff。 */
  diff: string;
  excerpt_line_start: number;
  excerpt_line_end: number;
  context_line_start: number;
  context_line_end: number;
  repair_idea: string;
  explanation: string;
  compatibility_impact: string;
  unconfirmed_premises: string[];
  disclaimer: string;
}
