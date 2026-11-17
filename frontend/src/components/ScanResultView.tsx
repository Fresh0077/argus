import { Space, Typography } from 'antd';
import type { RepairContext } from '../types/repair';
import type { ScanResponse } from '../types/scan';
import type { RequestedAnalyzers } from '../types/ui';
import CodeFeaturesPanel from './CodeFeaturesPanel';
import FindingExplorer from './FindingExplorer';
import NoFindingsNotice from './NoFindingsNotice';
import ReportExportButtons from './ReportExportButtons';
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
  repairContext,
  repairUnavailableReason,
}: {
  result: ScanResponse;
  requested: RequestedAnalyzers;
  repairContext?: RepairContext | null;
  repairUnavailableReason?: string;
}) {
  return (
    <Space direction="vertical" size="large" className="scan-result">
      <ScanOverview result={result} requested={requested} />
      <CodeFeaturesPanel features={result.features} />
      <SeverityStats counts={result.summary.severity_counts} />

      {result.findings.length === 0 ? (
        <NoFindingsNotice statuses={result.analyzer_status} requested={requested} />
      ) : (
        <FindingExplorer
          findings={result.findings}
          repairContext={repairContext}
          repairUnavailableReason={repairUnavailableReason}
        />
      )}

      <div className="report-export-block">
        <ReportExportButtons scanId={result.scan_id} />
        <Typography.Text type="secondary" className="report-export-block__hint">
          报告从本地扫描历史生成，不含完整源代码；历史关闭或保存失败时无法导出。
        </Typography.Text>
      </div>

      <Typography.Paragraph type="secondary" className="scan-result__disclaimer">
        {result.disclaimer}
      </Typography.Paragraph>
    </Space>
  );
}
