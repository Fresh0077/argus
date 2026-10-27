import { Space, Typography } from 'antd';
import type { ScanResponse } from '../types/scan';
import type { RequestedAnalyzers } from '../types/ui';
import FindingExplorer from './FindingExplorer';
import NoFindingsNotice from './NoFindingsNotice';
import ScanOverview from './ScanOverview';
import SeverityStats from './SeverityStats';

/**
 * 一份完整扫描结果的组合视图。
 *
 * `key` 由调用方按 `scan_id` 设置，使每次新扫描都重置筛选与选中的发现。
 */
export default function ScanResultView({
  result,
  requested,
}: {
  result: ScanResponse;
  requested: RequestedAnalyzers;
}) {
  return (
    <Space direction="vertical" size="large" className="scan-result">
      <ScanOverview result={result} requested={requested} />
      <SeverityStats counts={result.summary.severity_counts} />

      {result.findings.length === 0 ? (
        <NoFindingsNotice statuses={result.analyzer_status} requested={requested} />
      ) : (
        <FindingExplorer findings={result.findings} />
      )}

      <Typography.Paragraph type="secondary" className="scan-result__disclaimer">
        {result.disclaimer}
      </Typography.Paragraph>
    </Space>
  );
}
