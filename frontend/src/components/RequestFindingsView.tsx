import { Col, Empty, Row } from 'antd';
import { useEffect, useMemo, useState } from 'react';
import type { Finding } from '../types/scan';
import { sortFindings } from '../utils/findings';
import FindingDetail from './FindingDetail';
import FindingList from './FindingList';

/**
 * 请求包审计的发现列表 + 详情。
 *
 * 与源码扫描共用 `FindingList` / `FindingDetail` 的展示语义，但**不提供**
 * “生成候选补丁”：请求包不是可修补的源码，行号指向报文行。
 */
export default function RequestFindingsView({ findings }: { findings: Finding[] }) {
  const sorted = useMemo(() => sortFindings(findings), [findings]);
  const [selectedId, setSelectedId] = useState<string | null>(null);

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
    <Row gutter={[16, 16]}>
      <Col xs={24} xl={10}>
        <FindingList
          findings={sorted}
          selectedId={selected.id}
          onSelect={setSelectedId}
        />
      </Col>
      <Col xs={24} xl={14}>
        <FindingDetail finding={selected} typeLabel="风险类型" />
      </Col>
    </Row>
  );
}
