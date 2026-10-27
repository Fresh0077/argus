import { Button, Col, Empty, Row, Typography } from 'antd';
import { useEffect, useMemo, useState } from 'react';
import {
  SEVERITY_ORDER,
  SOURCE_ORDER,
  severityMeta,
  sourceMeta,
  vulnerabilityTypeLabel,
} from '../constants/labels';
import type { Finding } from '../types/scan';
import type { FindingFilterState } from '../types/ui';
import {
  EMPTY_FINDING_FILTERS,
  filterFindings,
  sortFindings,
} from '../utils/findings';
import FindingDetail from './FindingDetail';
import FindingFilters from './FindingFilters';
import type { FilterOption } from './FindingFilters';
import FindingList from './FindingList';

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

function sourceOptions(findings: Finding[]): FilterOption[] {
  const present = new Set<string>(findings.map((finding) => finding.source));
  const known = new Set<string>(SOURCE_ORDER);
  const ordered = SOURCE_ORDER.filter((value) => present.has(value));
  const unknown = [...present].filter((value) => !known.has(value)).sort();
  return [...ordered, ...unknown].map((value) => ({
    value,
    label: sourceMeta(value).label,
  }));
}

/** 候选项筛选、默认排序与列表/详情联动。 */
export default function FindingExplorer({ findings }: { findings: Finding[] }) {
  const [filters, setFilters] = useState<FindingFilterState>(EMPTY_FINDING_FILTERS);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const sorted = useMemo(() => sortFindings(findings), [findings]);
  const filtered = useMemo(() => filterFindings(sorted, filters), [sorted, filters]);
  const severities = useMemo(() => severityOptions(findings), [findings]);
  const types = useMemo(() => typeOptions(findings), [findings]);
  const sources = useMemo(() => sourceOptions(findings), [findings]);

  // 筛选变化后，如果当前详情被排除，自动选中新结果中的第一条（默认风险最高）。
  useEffect(() => {
    if (selectedId !== null && !filtered.some((finding) => finding.id === selectedId)) {
      setSelectedId(filtered[0]?.id ?? null);
    }
  }, [filtered, selectedId]);

  const selectedFinding =
    filtered.find((finding) => finding.id === selectedId) ?? filtered[0] ?? null;

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
        sourceOptions={sources}
        shown={filtered.length}
        total={findings.length}
      />

      {filtered.length === 0 ? (
        <div className="finding-explorer__empty">
          <Empty description="当前筛选条件下没有候选发现">
            <Typography.Paragraph type="secondary" className="finding-explorer__empty-hint">
              清除筛选后可查看本次全部 {findings.length} 条候选发现。筛选结果为空不代表代码安全。
            </Typography.Paragraph>
            <Button onClick={handleReset}>清除筛选</Button>
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
            {selectedFinding ? <FindingDetail finding={selectedFinding} /> : null}
          </Col>
        </Row>
      )}
    </div>
  );
}
