import { Button, Col, Empty, Row, Typography } from 'antd';
import { useEffect, useMemo, useState } from 'react';
import {
  SEVERITY_ORDER,
  severityMeta,
  vulnerabilityTypeLabel,
} from '../constants/labels';
import { useRepairSuggestion } from '../hooks/useRepairSuggestion';
import type { RepairContext } from '../types/repair';
import type { Finding } from '../types/scan';
import type { FindingFilterState } from '../types/ui';
import {
  EMPTY_FINDING_FILTERS,
  filterFindings,
  hasActiveFilters,
  sortFindings,
} from '../utils/findings';
import FindingDetail from './FindingDetail';
import FindingFilters from './FindingFilters';
import type { FilterOption } from './FindingFilters';
import FindingList from './FindingList';
import RepairSuggestionModal from './RepairSuggestionModal';

function severityOptions(findings: Finding[]): FilterOption[] {
  const present = new Set<string>(findings.map((finding) => finding.severity));
  const known = new Set<string>(SEVERITY_ORDER);
  const ordered = SEVERITY_ORDER.filter((value) => present.has(value));
  const unknown = [...present].filter((value) => !known.has(value)).sort();
  return [...ordered, ...unknown].map((value) => ({
    value,
    label: severityMeta(value).label,
  }));
}

function typeOptions(findings: Finding[]): FilterOption[] {
  return [...new Set(findings.map((finding) => finding.vulnerability_type))]
    .sort((left, right) =>
      vulnerabilityTypeLabel(left).localeCompare(vulnerabilityTypeLabel(right), 'zh-CN'),
    )
    .map((value) => ({ value, label: vulnerabilityTypeLabel(value) }));
}

interface FindingExplorerProps {
  findings: Finding[];
  /** 当前结果对应的源代码；历史详情没有源代码，传入 null。 */
  repairContext?: RepairContext | null;
  repairUnavailableReason?: string;
  /** 历史详情没有源代码，直接隐藏补丁入口，而不是显示一个不可用按钮。 */
  allowRepair?: boolean;
}

/** 候选发现的筛选、排序与列表/详情联动。 */
export default function FindingExplorer({
  findings,
  repairContext = null,
  repairUnavailableReason,
  allowRepair = true,
}: FindingExplorerProps) {
  const [filters, setFilters] = useState<FindingFilterState>(EMPTY_FINDING_FILTERS);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const repair = useRepairSuggestion(repairContext);

  const sorted = useMemo(() => sortFindings(findings), [findings]);
  const filtered = useMemo(() => filterFindings(sorted, filters), [sorted, filters]);
  const severities = useMemo(() => severityOptions(findings), [findings]);
  const types = useMemo(() => typeOptions(findings), [findings]);

  // 筛选变化后，如果当前详情被排除，自动选中新结果中的第一条（默认风险最高）。
  useEffect(() => {
    if (selectedId !== null && !filtered.some((finding) => finding.id === selectedId)) {
      setSelectedId(filtered[0]?.id ?? null);
    }
  }, [filtered, selectedId]);

  const selectedFinding =
    filtered.find((finding) => finding.id === selectedId) ?? filtered[0] ?? null;
  const hasFilters = hasActiveFilters(filters);

  const handleReset = () => {
    setFilters(EMPTY_FINDING_FILTERS);
    setSelectedId(null);
  };

  return (
    <div className="finding-explorer">
      <FindingFilters
        value={filters}
        onChange={setFilters}
        onReset={handleReset}
        severityOptions={severities}
        typeOptions={types}
        shown={filtered.length}
        total={findings.length}
      />

      {filtered.length === 0 ? (
        <div className="finding-explorer__empty">
          <Empty description="当前筛选条件下没有候选发现">
            <Typography.Paragraph type="secondary" className="finding-explorer__empty-hint">
              清除筛选后可查看全部 {findings.length} 条候选发现。筛选结果为空不代表代码安全。
            </Typography.Paragraph>
            <Button onClick={handleReset} disabled={!hasFilters}>
              清除筛选
            </Button>
          </Empty>
        </div>
      ) : (
        <Row gutter={[16, 16]}>
          <Col xs={24} xl={10}>
            <FindingList
              findings={filtered}
              selectedId={selectedFinding?.id ?? null}
              onSelect={setSelectedId}
            />
          </Col>
          <Col xs={24} xl={14}>
            {selectedFinding ? (
              <FindingDetail
                finding={selectedFinding}
                repairContext={repairContext}
                repairUnavailableReason={repairUnavailableReason}
                onGenerateRepair={allowRepair ? repair.generate : undefined}
              />
            ) : null}
          </Col>
        </Row>
      )}

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
    </div>
  );
}
