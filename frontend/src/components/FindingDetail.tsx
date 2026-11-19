import { InfoCircleOutlined, ToolOutlined } from '@ant-design/icons';
import { Button, Collapse, Descriptions, Space, Tag, Typography } from 'antd';
import {
  severityMeta,
  sourceMeta,
  vulnerabilityTypeLabel,
} from '../constants/labels';
import type { RepairContext } from '../types/repair';
import type { Finding } from '../types/scan';
import { formatConfidence, formatLineRange } from '../utils/format';
import EvidenceBlock from './EvidenceBlock';

interface FindingDetailProps {
  finding: Finding;
  /** 当前结果对应的源代码；没有时（例如历史详情）无法生成修复建议。 */
  repairContext?: RepairContext | null;
  /** 无法生成修复建议的具体原因，展示给用户。 */
  repairUnavailableReason?: string;
  /** 类型字段的展示名；请求包审计使用“风险类型”，避免暗示已确认漏洞。 */
  typeLabel?: string;
  /** 补丁操作下方的说明；请求包审计需要说明发送的是报文而不是代码。 */
  repairHint?: string;
  onGenerateRepair?: (finding: Finding) => void;
}

/** 单条候选发现的详情。所有用户文本由 React 转义，不使用 HTML 注入。 */
export default function FindingDetail({
  finding,
  repairContext = null,
  repairUnavailableReason,
  typeLabel = '漏洞类型',
  repairHint = '会将该发现所在行附近的少量代码发送给所配置的第三方模型，只生成候选补丁，不会修改原文件。',
  onGenerateRepair,
}: FindingDetailProps) {
  const severity = severityMeta(finding.severity);
  const source = sourceMeta(finding.source);

  return (
    <section className="finding-detail">
      <div className="finding-detail__header">
        <Space wrap size={[8, 8]}>
          <Tag color={severity.color}>{severity.label}</Tag>
          <Tag color={source.color}>{source.label}</Tag>
          {finding.rule_id && finding.source !== 'llm' ? (
            <Tag>规则 {finding.rule_id}</Tag>
          ) : null}
        </Space>
        <Typography.Title level={4} className="finding-detail__title">
          {finding.title}
        </Typography.Title>
      </div>

      <Descriptions
        size="small"
        column={{ xs: 1, sm: 2 }}
        items={[
          {
            key: 'location',
            label: '位置',
            children: formatLineRange(finding.line_start, finding.line_end),
          },
          {
            key: 'type',
            label: typeLabel,
            children: vulnerabilityTypeLabel(finding.vulnerability_type),
          },
          { key: 'cwe', label: 'CWE', children: finding.cwe_id ?? '未标注' },
          {
            key: 'confidence',
            label: '分析置信度',
            children: formatConfidence(finding.confidence),
          },
        ]}
      />

      <Collapse
        ghost
        size="small"
        className="finding-detail__sections"
        defaultActiveKey={['description']}
        items={[
          {
            key: 'description',
            label: '风险说明',
            children: (
              <Typography.Paragraph className="pre-wrap">
                {finding.description}
              </Typography.Paragraph>
            ),
          },
          {
            key: 'evidence',
            label: '代码证据',
            children: (
              <EvidenceBlock
                evidence={finding.evidence}
                lineStart={finding.line_start}
                lineEnd={finding.line_end}
                showHeader={false}
              />
            ),
          },
          {
            key: 'recommendation',
            label: '分析器建议',
            children: (
              <Space direction="vertical" size="small" className="finding-detail__suggestion">
                <Typography.Paragraph className="pre-wrap">
                  {finding.recommendation}
                </Typography.Paragraph>
                {onGenerateRepair ? (
                  <>
                    <Button
                      type="dashed"
                      icon={<ToolOutlined />}
                      disabled={!repairContext}
                      onClick={() => onGenerateRepair(finding)}
                    >
                      生成候选补丁
                    </Button>
                    <Typography.Text type="secondary">
                      {repairContext
                        ? repairHint
                        : (repairUnavailableReason ?? '当前上下文无法生成候选补丁。')}
                    </Typography.Text>
                  </>
                ) : null}
              </Space>
            ),
          },
        ]}
      />

      <Typography.Text type="secondary" className="finding-detail__confidence-note">
        <InfoCircleOutlined /> 置信度是分析器对自身判断的估计，不是漏洞真实发生的概率。
      </Typography.Text>
    </section>
  );
}
