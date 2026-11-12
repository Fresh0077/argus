import { Space, Tag, Tooltip } from 'antd';
import { analyzerNameLabel, analyzerStateMeta } from '../constants/labels';
import type { AnalyzerState } from '../types/scan';
import { formatDuration } from '../utils/format';

/**
 * 源码扫描与请求包审计共用的最小状态结构。
 *
 * 两者的分析器名称取值不同，但展示字段一致；用结构类型接收，避免为请求审计
 * 再复制一份状态列表组件。
 */
export interface AnalyzerStatusLike {
  name: string;
  state: AnalyzerState;
  reason: string | null;
  duration_ms: number | null;
  findings_count: number;
}

/**
 * 逐项展示分析器状态。
 *
 * 失败、跳过与不可用必须带原因，避免用户把“没跑”误读成“没问题”。
 */
export default function AnalyzerStatusList({ statuses }: { statuses: AnalyzerStatusLike[] }) {
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
