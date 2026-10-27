import { Alert, Descriptions, Space, Tag, Typography } from 'antd';
import type { DescriptionsProps } from 'antd';
import { languageLabel, scanStatusMeta } from '../constants/labels';
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
  const stateCounts = result.analyzer_status.reduce<Record<string, number>>(
    (counts, status) => {
      counts[status.state] = (counts[status.state] ?? 0) + 1;
      return counts;
    },
    {},
  );
  const knownCount =
    (stateCounts.success ?? 0) +
    (stateCounts.skipped ?? 0) +
    (stateCounts.unavailable ?? 0) +
    (stateCounts.failed ?? 0);
  const unknownCount = result.analyzer_status.length - knownCount;
  const analyzerSummary = [
    `成功 ${stateCounts.success ?? 0}`,
    `跳过 ${stateCounts.skipped ?? 0}`,
    `不可用 ${stateCounts.unavailable ?? 0}`,
    `失败 ${stateCounts.failed ?? 0}`,
    ...(unknownCount > 0 ? [`其他 ${unknownCount}`] : []),
  ].join(' · ');

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
      <span className="visually-hidden" role="status" aria-live="polite">
        扫描{statusMeta.label}，共 {result.summary.total_findings} 条候选发现。
      </span>
      <Descriptions items={items} size="small" bordered column={{ xs: 1, sm: 2, lg: 4 }} />
      <div className="scan-overview__id">
        <Typography.Text type="secondary">扫描编号：</Typography.Text>
        <Typography.Text code copyable={{ text: result.scan_id }}>
          {result.scan_id}
        </Typography.Text>
      </div>
      <AnalyzerStatusList statuses={result.analyzer_status} />
      <Typography.Text type="secondary" className="scan-overview__analyzer-summary">
        分析器状态：{analyzerSummary}
      </Typography.Text>
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
