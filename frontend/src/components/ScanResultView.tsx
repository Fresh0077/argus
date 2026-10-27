import { Alert, Col, Row, Space, Typography } from 'antd';
import { useState } from 'react';
import { severityRank } from '../constants/labels';
import type { Finding, ScanResponse } from '../types/scan';
import type { RequestedAnalyzers } from '../types/ui';
import FindingDetail from './FindingDetail';
import FindingList from './FindingList';
import ScanOverview from './ScanOverview';
import SeverityStats from './SeverityStats';

/** 默认展开风险最高的发现，避免列表首项是低置信度的启发式线索。 */
function defaultFinding(findings: Finding[]): Finding | null {
  return findings.reduce<Finding | null>((best, finding) => {
    if (!best) {
      return finding;
    }
    return severityRank(finding.severity) < severityRank(best.severity) ? finding : best;
  }, null);
}

/**
 * 一份完整扫描结果的组合视图。
 *
 * `key` 由调用方按 `scan_id` 设置，使每次新扫描都重置选中的发现。
 */
export default function ScanResultView({
  result,
  requested,
}: {
  result: ScanResponse;
  requested: RequestedAnalyzers;
}) {
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const selectedFinding =
    result.findings.find((finding) => finding.id === selectedId) ?? defaultFinding(result.findings);

  return (
    <Space direction="vertical" size="large" className="scan-result">
      <ScanOverview result={result} requested={requested} />
      <SeverityStats counts={result.summary.severity_counts} />

      {result.findings.length === 0 ? (
        <Alert
          type="info"
          showIcon
          message="本次分析未发现候选问题"
          description="这不等于代码绝对安全。请先确认下方分析器状态中没有 skipped、unavailable 或 failed，再结合人工复核判断。"
        />
      ) : (
        <Row gutter={[16, 16]}>
          <Col xs={24} xl={10}>
            <FindingList
              findings={result.findings}
              selectedId={selectedFinding?.id ?? null}
              onSelect={setSelectedId}
            />
          </Col>
          <Col xs={24} xl={14}>
            {selectedFinding ? <FindingDetail finding={selectedFinding} /> : null}
          </Col>
        </Row>
      )}

      <Typography.Paragraph type="secondary" className="scan-result__disclaimer">
        {result.disclaimer}
      </Typography.Paragraph>
    </Space>
  );
}
