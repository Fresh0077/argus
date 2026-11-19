import { Col, Empty, Row } from 'antd';
import { useEffect, useMemo, useState } from 'react';
import { useRepairSuggestion } from '../hooks/useRepairSuggestion';
import type { RepairContext } from '../types/repair';
import type { Finding } from '../types/scan';
import { sortFindings } from '../utils/findings';
import FindingDetail from './FindingDetail';
import FindingList from './FindingList';
import RepairSuggestionModal from './RepairSuggestionModal';

/**
 * 请求包审计的发现列表 + 详情。
 *
 * 与源码扫描共用 `FindingList` / `FindingDetail` 和候选补丁弹窗；
 * 修复请求的 `source_code` 是脱敏后的报文文本，行号指向报文行。
 */
export default function RequestFindingsView({
  findings,
  repairContext,
}: {
  findings: Finding[];
  repairContext: RepairContext | null;
}) {
  const sorted = useMemo(() => sortFindings(findings), [findings]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const repair = useRepairSuggestion(repairContext);

  useEffect(() => {
    if (selectedId !== null && !sorted.some((finding) => finding.id === selectedId)) {
      setSelectedId(sorted[0]?.id ?? null);
    }
  }, [sorted, selectedId]);

  if (sorted.length === 0) {
    return (
      <div className="finding-explorer__empty">
        <Empty description="未发现候选风险，不代表请求安全" />
      </div>
    );
  }

  const selected = sorted.find((finding) => finding.id === selectedId) ?? sorted[0];

  return (
    <>
      <Row gutter={[16, 16]}>
        <Col xs={24} xl={10}>
          <FindingList
            findings={sorted}
            selectedId={selected.id}
            onSelect={setSelectedId}
          />
        </Col>
        <Col xs={24} xl={14}>
          <FindingDetail
            finding={selected}
            typeLabel="风险类型"
            repairContext={repairContext}
            repairHint="会将该发现所在行附近少量报文发送给所配置的第三方模型，只生成候选修复报文，不会重放请求或修改文件。"
            onGenerateRepair={repairContext ? repair.generate : undefined}
          />
        </Col>
      </Row>

      <RepairSuggestionModal
        open={repair.target !== null}
        findingTitle={repair.target?.title ?? ''}
        filename={repairContext?.filename ?? null}
        loading={repair.loading}
        error={repair.error}
        suggestion={repair.suggestion}
        onClose={repair.close}
        onRetry={repair.retry}
      />
    </>
  );
}
