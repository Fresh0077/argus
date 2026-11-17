import { Tabs } from 'antd';
import type { ReactNode } from 'react';
import type { RepairContext } from '../types/repair';
import type { ScanResponse } from '../types/scan';
import type { RequestedAnalyzers } from '../types/ui';
import CodeFeaturesPanel from './CodeFeaturesPanel';
import FindingExplorer from './FindingExplorer';
import NoFindingsNotice from './NoFindingsNotice';
import ScanOverview from './ScanOverview';
import SeverityStats from './SeverityStats';

/**
 * 一份完整扫描结果的组合视图。
 *
 * 使用 Tabs 把概览、代码特征与候选发现分区，避免所有内容纵向堆叠。
 * `key` 由调用方按 `scan_id` 设置，使每次新扫描都重置筛选、选中项与标签页。
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
  const hasFindings = result.findings.length > 0;

  const items: { key: string; label: string; children: ReactNode }[] = [
    {
      key: 'overview',
      label: '概览',
      children: <ScanOverview result={result} requested={requested} />,
    },
    {
      key: 'features',
      label: '代码特征',
      children: <CodeFeaturesPanel features={result.features} />,
    },
    {
      key: 'findings',
      label: hasFindings ? `候选发现 ${result.summary.total_findings}` : '候选发现',
      children: (
        <>
          <SeverityStats counts={result.summary.severity_counts} />
          {hasFindings ? (
            <FindingExplorer
              findings={result.findings}
              repairContext={repairContext}
              repairUnavailableReason={repairUnavailableReason}
            />
          ) : (
            <NoFindingsNotice statuses={result.analyzer_status} requested={requested} />
          )}
        </>
      ),
    },
  ];

  return (
    <div className="scan-result">
      <Tabs
        className="scan-result__tabs"
        defaultActiveKey={hasFindings ? 'findings' : 'overview'}
        items={items}
      />
    </div>
  );
}
