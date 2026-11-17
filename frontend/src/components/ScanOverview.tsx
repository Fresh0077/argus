import { Alert, Descriptions, Space, Tag, Typography } from 'antd';
import type { DescriptionsProps } from 'antd';
import { scanStatusMeta } from '../constants/labels';
import type { ScanResponse } from '../types/scan';
import type { RequestedAnalyzers } from '../types/ui';
import { formatDuration } from '../utils/format';
import AnalyzerNotices from './AnalyzerNotices';
import AnalyzerStatusList from './AnalyzerStatusList';

const UTF8_ENCODINGS = new Set(['utf-8', 'utf-8-sig']);

/** 扫描摘要：整体状态、语言、耗时、发现总数、分析器状态与解码提示。 */
export default function ScanOverview({
  result,
  requested,
}: {
  result: ScanResponse;
  requested: RequestedAnalyzers;
}) {
  const statusMeta = scanStatusMeta(result.status);
  const hasEncodingConversion =
    result.source_encoding !== null && !UTF8_ENCODINGS.has(result.source_encoding);

  const items: DescriptionsProps['items'] = [
    {
      key: 'status',
      label: '扫描状态',
      children: <Tag color={statusMeta.color}>{statusMeta.label}</Tag>,
    },
    {
      key: 'duration',
      label: '总耗时',
      children: formatDuration(result.duration_ms),
    },
    {
      key: 'findings',
      label: '候选发现',
      children: `${result.summary.total_findings} 条`,
    },
  ];

  return (
    <Space direction="vertical" size="middle" className="scan-overview">
      <span className="visually-hidden" role="status" aria-live="polite">
        扫描{statusMeta.label}，共 {result.summary.total_findings} 条候选发现。
      </span>
      <Descriptions items={items} size="small" bordered column={{ xs: 1, sm: 2, lg: 3 }} />
      <div className="scan-overview__id">
        <Typography.Text type="secondary">扫描编号：</Typography.Text>
        <Typography.Text code copyable={{ text: result.scan_id }}>
          {result.scan_id}
        </Typography.Text>
      </div>
      <AnalyzerStatusList statuses={result.analyzer_status} />
      <AnalyzerNotices statuses={result.analyzer_status} requested={requested} />
      {hasEncodingConversion && result.source_encoding ? (
        <Alert
          type="warning"
          showIcon
          message={`文件按 ${result.source_encoding} 解码`}
          description="源文件不是 UTF-8 编码，后端已按上述编码解码。若界面中的代码内容与预期不符，请确认文件编码后重新上传。"
        />
      ) : null}
    </Space>
  );
}
