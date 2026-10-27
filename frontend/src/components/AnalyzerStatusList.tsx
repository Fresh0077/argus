import { Space, Tag, Tooltip } from 'antd';
import { analyzerNameLabel, analyzerStateMeta } from '../constants/labels';
import type { AnalyzerStatus } from '../types/scan';
import { formatDuration } from '../utils/format';

/**
 * 逐项展示分析器状态。
 *
 * 失败、跳过与不可用必须带原因，避免用户把“没跑”误读成“没问题”。
 */
export default function AnalyzerStatusList({ statuses }: { statuses: AnalyzerStatus[] }) {
  if (statuses.length === 0) {
    return null;
  }

  return (
    <Space wrap size={[8, 8]} className="analyzer-status-list">
      {statuses.map((status) => {
        const name = analyzerNameLabel(status.name);
        const meta = analyzerStateMeta(status.state);
        const details: string[] = [];

        if (status.reason) {
          details.push(status.reason);
        }
        if (status.duration_ms !== null) {
          details.push(`耗时 ${formatDuration(status.duration_ms)}`);
        }
        if (status.state === 'success') {
          details.push(`报告 ${status.findings_count} 条候选发现`);
        }

        return (
          <Tooltip key={status.name} title={details.join('；') || `${name}：${meta.label}`}>
            <Tag color={meta.color}>
              {name} · {meta.label}
            </Tag>
          </Tooltip>
        );
      })}
    </Space>
  );
}
