import { Descriptions, Space, Tag, Typography } from 'antd';
import type { DescriptionsProps } from 'antd';
import { languageLabel, scanStatusMeta } from '../constants/labels';
import type { ScanResponse } from '../types/scan';
import { formatDuration } from '../utils/format';
import AnalyzerStatusList from './AnalyzerStatusList';

/** 扫描摘要：整体状态、语言、耗时、发现总数与分析器状态。 */
export default function ScanOverview({ result }: { result: ScanResponse }) {
  const statusMeta = scanStatusMeta(result.status);

  const items: DescriptionsProps['items'] = [
    {
      key: 'status',
      label: '扫描状态',
      children: <Tag color={statusMeta.color}>{statusMeta.label}</Tag>,
    },
    {
      key: 'language',
      label: '识别语言',
      children: languageLabel(result.detected_language),
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
      <Descriptions items={items} size="small" bordered column={{ xs: 1, sm: 2, lg: 4 }} />
      <div className="scan-overview__id">
        <Typography.Text type="secondary">扫描编号：</Typography.Text>
        <Typography.Text code copyable={{ text: result.scan_id }}>
          {result.scan_id}
        </Typography.Text>
      </div>
      <AnalyzerStatusList statuses={result.analyzer_status} />
    </Space>
  );
}
