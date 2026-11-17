import { Alert, Space } from 'antd';
import { analyzerNameLabel, analyzerStateMeta } from '../constants/labels';
import type { AnalyzerState, AnalyzerStatus } from '../types/scan';
import type { RequestedAnalyzers } from '../types/ui';

const ALERT_TYPE: Record<AnalyzerState, 'info' | 'warning' | 'error'> = {
  success: 'info',
  skipped: 'info',
  unavailable: 'warning',
  failed: 'error',
};

/**
 * 是否值得展开成提示。
 *
 * - 失败与不可用始终展示；
 * - 用户主动关闭的 LLM 只保留标签，不再占用大块空间；
 * - 其他跳过（例如语言未识别导致线索提取跳过）仍然展示，因为它可能被误读。
 */
function shouldShow(status: AnalyzerStatus, requested: RequestedAnalyzers): boolean {
  if (status.state === 'failed' || status.state === 'unavailable') {
    return true;
  }
  if (status.state !== 'skipped') {
    return false;
  }
  if (status.name === 'llm') {
    return requested.llm;
  }
  return true;
}

/**
 * 把非成功状态的分析器展开成可读提示。
 *
 * 标签上的 tooltip 不足以承载“LLM 未配置”这类关键信息，
 * 因此这里逐条展示原因，避免用户误以为“没发现问题 = 安全”。
 */
export default function AnalyzerNotices({
  statuses,
  requested,
}: {
  statuses: AnalyzerStatus[];
  requested: RequestedAnalyzers;
}) {
  const notices = statuses.filter((status) => shouldShow(status, requested));

  if (notices.length === 0) {
    return null;
  }

  return (
    <Space direction="vertical" size="small" className="analyzer-notices">
      {notices.map((status) => {
        const meta = analyzerStateMeta(status.state);
        return (
          <Alert
            key={status.name}
            type={ALERT_TYPE[status.state]}
            showIcon
            message={`${analyzerNameLabel(status.name)}：${meta.label}`}
            description={status.reason ?? '后端未提供原因。'}
          />
        );
      })}
    </Space>
  );
}
