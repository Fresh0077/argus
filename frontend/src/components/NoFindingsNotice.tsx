import { Alert } from 'antd';
import { analyzerNameLabel } from '../constants/labels';
import type { AnalyzerStatus } from '../types/scan';
import type { RequestedAnalyzers } from '../types/ui';

function names(statuses: AnalyzerStatus[]): string {
  return statuses.map((status) => analyzerNameLabel(status.name)).join('、');
}

/**
 * 零发现时的说明。
 *
 * 必须把“分析器没跑/失败”和“跑完但没报告问题”分开，否则用户会把
 * 不完整的结果误读成代码安全。
 */
export default function NoFindingsNotice({
  statuses,
  requested,
}: {
  statuses: AnalyzerStatus[];
  requested: RequestedAnalyzers;
}) {
  const failedOrUnavailable = statuses.filter(
    (status) => status.state === 'failed' || status.state === 'unavailable',
  );
  const skipped = statuses.filter((status) => status.state === 'skipped');
  const disabledOptional = skipped.filter(
    (status) =>
      (status.name === 'semgrep' && !requested.semgrep) ||
      (status.name === 'llm' && !requested.llm),
  );
  const otherSkipped = skipped.filter((status) => !disabledOptional.includes(status));

  const details: string[] = [];
  if (failedOrUnavailable.length > 0) {
    details.push(`失败或不可用：${names(failedOrUnavailable)}。见上方分析器状态。`);
  }
  if (otherSkipped.length > 0) {
    details.push(`未执行：${names(otherSkipped)}。`);
  }
  if (disabledOptional.length > 0) {
    details.push(`本次未启用：${names(disabledOptional)}。`);
  }
  details.push(
    '没有发现候选问题不等于代码安全；规则、特征与模型分析都可能漏报，请结合人工复核。',
  );

  const incomplete = failedOrUnavailable.length > 0 || otherSkipped.length > 0;
  const title =
    failedOrUnavailable.length > 0
      ? '未发现候选问题，但分析未完整完成'
      : otherSkipped.length > 0
        ? '未发现候选问题，但部分分析未执行'
        : '已启用的分析器未报告候选问题';

  return (
    <Alert
      type={incomplete ? 'warning' : 'info'}
      showIcon
      message={title}
      description={details.join(' ')}
    />
  );
}
