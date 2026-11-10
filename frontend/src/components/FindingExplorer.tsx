import { Button, Col, Empty, Row, Segmented, Space, Typography } from 'antd';
import { useEffect, useMemo, useRef, useState } from 'react';
import {
  SEVERITY_ORDER,
  severityMeta,
  vulnerabilityTypeLabel,
} from '../constants/labels';
import { ApiError, generateRepair } from '../services/apiClient';
import type { RepairContext, RepairSuggestion } from '../types/repair';
import type { Finding } from '../types/scan';
import type { FindingFilterState, FindingSourceView } from '../types/ui';
import {
  EMPTY_FINDING_FILTERS,
  filterBySourceView,
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
}

/** 候选项筛选、默认排序与列表/详情联动。 */
export default function FindingExplorer({
  findings,
  repairContext = null,
  repairUnavailableReason,
}: FindingExplorerProps) {
  const [filters, setFilters] = useState<FindingFilterState>(EMPTY_FINDING_FILTERS);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  // 默认只看风险发现；启发式线索单独放在“线索”视图，避免稀释结论。
  const [sourceView, setSourceView] = useState<FindingSourceView>('risk');

  // 候选补丁是用户主动触发的额外请求，与扫描请求分开管理。
  const [repairTarget, setRepairTarget] = useState<Finding | null>(null);
  const [repairSuggestion, setRepairSuggestion] = useState<RepairSuggestion | null>(null);
  const [repairLoading, setRepairLoading] = useState(false);
  const [repairError, setRepairError] = useState<string | null>(null);
  const repairAbortRef = useRef<AbortController | null>(null);

  useEffect(
    () => () => {
      repairAbortRef.current?.abort();
    },
    [],
  );

  const sourceScoped = useMemo(
    () => filterBySourceView(findings, sourceView),
    [findings, sourceView],
  );
  const sorted = useMemo(() => sortFindings(sourceScoped), [sourceScoped]);
  const filtered = useMemo(() => filterFindings(sorted, filters), [sorted, filters]);
  const severities = useMemo(() => severityOptions(sourceScoped), [sourceScoped]);
  const types = useMemo(() => typeOptions(sourceScoped), [sourceScoped]);

  const viewCounts = useMemo(() => {
    let risk = 0;
    let local = 0;
    let llm = 0;
    let heuristic = 0;
    for (const finding of findings) {
      if (finding.source !== 'heuristic') {
        risk += 1;
      }
      if (finding.source === 'static_rule' || finding.source === 'semgrep') {
        local += 1;
      } else if (finding.source === 'llm') {
        llm += 1;
      } else if (finding.source === 'heuristic') {
        heuristic += 1;
      }
    }
    return { risk, local, llm, heuristic };
  }, [findings]);

  const viewOptions = useMemo(
    () => [
      { label: `风险发现 ${viewCounts.risk}`, value: 'risk' },
      { label: `规则/工具 ${viewCounts.local}`, value: 'local' },
      { label: `LLM ${viewCounts.llm}`, value: 'llm' },
      { label: `线索 ${viewCounts.heuristic}`, value: 'heuristic' },
    ],
    [viewCounts],
  );

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

  const handleGenerateRepair = async (finding: Finding) => {
    if (!repairContext) {
      return;
    }

    repairAbortRef.current?.abort();
    const controller = new AbortController();
    repairAbortRef.current = controller;

    setRepairTarget(finding);
    setRepairSuggestion(null);
    setRepairError(null);
    setRepairLoading(true);

    try {
      const suggestion = await generateRepair(
        {
          source_code: repairContext.sourceCode,
          language: repairContext.language,
          filename: repairContext.filename,
          finding,
        },
        { signal: controller.signal },
      );
      if (repairAbortRef.current === controller) {
        setRepairSuggestion(suggestion);
      }
    } catch (requestError) {
      if (requestError instanceof ApiError && requestError.kind === 'aborted') {
        return;
      }
      if (repairAbortRef.current === controller) {
        setRepairError(
          requestError instanceof ApiError
            ? requestError.message
            : '生成候选补丁失败，请稍后重试。',
        );
      }
    } finally {
      if (repairAbortRef.current === controller) {
        setRepairLoading(false);
      }
    }
  };

  const handleCloseRepair = () => {
    repairAbortRef.current?.abort();
    repairAbortRef.current = null;
    setRepairTarget(null);
    setRepairSuggestion(null);
    setRepairError(null);
    setRepairLoading(false);
  };

  const handleRetryRepair = () => {
    if (repairTarget) {
      void handleGenerateRepair(repairTarget);
    }
  };

  return (
    <div className="finding-explorer">
      <div className="finding-explorer__views">
        <Segmented
          block
          size="small"
          options={viewOptions}
          value={sourceView}
          aria-label="按分析来源查看候选发现"
          onChange={(value) => {
            setSourceView(value as FindingSourceView);
            setSelectedId(null);
          }}
        />
      </div>

      <FindingFilters
        value={filters}
        onChange={setFilters}
        onReset={handleReset}
        severityOptions={severities}
        typeOptions={types}
        shown={filtered.length}
        total={sourceScoped.length}
      />

      {sourceScoped.length === 0 ? (
        <div className="finding-explorer__empty">
          <Empty description="当前来源视图没有候选发现">
            <Typography.Paragraph type="secondary" className="finding-explorer__empty-hint">
              {sourceView === 'risk' && viewCounts.heuristic > 0
                ? `另有 ${viewCounts.heuristic} 条特征线索未显示在“风险发现”中，可切换到“线索”查看。`
                : '其他来源视图可能仍有结果；切换上方视图即可查看。'}
            </Typography.Paragraph>
            <Space wrap>
              {sourceView !== 'risk' ? (
                <Button
                  onClick={() => {
                    setSourceView('risk');
                    setSelectedId(null);
                  }}
                >
                  查看风险发现
                </Button>
              ) : null}
              {sourceView !== 'heuristic' && viewCounts.heuristic > 0 ? (
                <Button
                  onClick={() => {
                    setSourceView('heuristic');
                    setSelectedId(null);
                  }}
                >
                  查看特征线索
                </Button>
              ) : null}
            </Space>
          </Empty>
        </div>
      ) : filtered.length === 0 ? (
        <div className="finding-explorer__empty">
          <Empty description="当前筛选条件下没有候选发现">
            <Typography.Paragraph type="secondary" className="finding-explorer__empty-hint">
              清除筛选后可查看当前视图的全部 {sourceScoped.length} 条候选发现。筛选结果为空不代表代码安全。
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
                onGenerateRepair={(finding) => {
                  void handleGenerateRepair(finding);
                }}
              />
            ) : null}
          </Col>
        </Row>
      )}

      <RepairSuggestionModal
        open={repairTarget !== null}
        findingTitle={repairTarget?.title ?? ''}
        filename={repairContext?.filename ?? null}
        loading={repairLoading}
        error={repairError}
        suggestion={repairSuggestion}
        onClose={handleCloseRepair}
        onRetry={handleRetryRepair}
      />
    </div>
  );
}
