/** 仅前端使用的视图类型，不属于后端 API 契约。 */

export type InputMode = 'paste' | 'upload';

/** 已翻译为界面文案的扫描错误，组件不直接依赖具体请求实现。 */
export interface ScanErrorInfo {
  title: string;
  message: string;
  details: string[];
}

/** 发起扫描时用户实际启用的可选分析器，用于区分“主动关闭”和“不可用”。 */
export interface RequestedAnalyzers {
  llm: boolean;
  semgrep: boolean;
}

/**
 * 结果列表的来源视图。
 *
 * - ``risk``：风险发现，默认视图，**不包含启发式线索**；
 * - ``local``：本地规则 + Semgrep；
 * - ``llm``：LLM 语义分析；
 * - ``heuristic``：特征线索（默认折叠，需主动切换）。
 */
export type FindingSourceView = 'risk' | 'local' | 'llm' | 'heuristic';

/** 结果列表的客户端筛选条件；空数组表示该维度不过滤。 */
export interface FindingFilterState {
  severities: string[];
  types: string[];
}
