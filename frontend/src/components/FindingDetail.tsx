import { ToolOutlined } from '@ant-design/icons';
import { Alert, Button, Card, Descriptions, Progress, Space, Tag, Typography } from 'antd';
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
  onGenerateRepair?: (finding: Finding) => void;
}

/** 单条候选发现的详情。所有用户文本由 React 转义，不使用 HTML 注入。 */
export default function FindingDetail({
  finding,
  repairContext = null,
  repairUnavailableReason,
  onGenerateRepair,
}: FindingDetailProps) {
  const severity = severityMeta(finding.severity);
  const source = sourceMeta(finding.source);

  return (
    <Card className="finding-detail" size="small" title="发现详情">
      <Space direction="vertical" size="middle" className="finding-detail__body">
        <div>
          <Space wrap size={[8, 8]}>
            <Tag color={severity.color}>{severity.label}</Tag>
            <Tag color={source.color}>{source.label}</Tag>
            {finding.rule_id ? <Tag>规则 {finding.rule_id}</Tag> : null}
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
              label: '漏洞类型',
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

        <Progress
          percent={Math.round(finding.confidence * 100)}
          size="small"
          strokeColor={severity.color}
          format={() => formatConfidence(finding.confidence)}
        />

        <section className="detail-section">
          <Typography.Text strong>风险说明</Typography.Text>
          <Typography.Paragraph className="pre-wrap">{finding.description}</Typography.Paragraph>
        </section>

        <EvidenceBlock
          evidence={finding.evidence}
          lineStart={finding.line_start}
          lineEnd={finding.line_end}
        />

        <section className="detail-section">
          <Typography.Text strong>修复建议</Typography.Text>
          <Typography.Paragraph className="pre-wrap">{finding.recommendation}</Typography.Paragraph>
        </section>

        {onGenerateRepair ? (
          <section className="detail-section">
            <Space direction="vertical" size="small">
              <Button
                type="dashed"
                icon={<ToolOutlined />}
                disabled={!repairContext}
                onClick={() => onGenerateRepair(finding)}
              >
                生成修复建议
              </Button>
              <Typography.Text type="secondary">
                {repairContext
                  ? '会将该发现所在行附近的少量代码发送给所配置的第三方模型，只生成候选补丁，不会修改原文件。'
                  : (repairUnavailableReason ?? '当前上下文无法生成修复建议。')}
              </Typography.Text>
            </Space>
          </section>
        ) : null}

        <Alert
          type="info"
          showIcon
          message="置信度不是漏洞概率"
          description="confidence 只表示分析器对自身判断的估计，不能跨来源比较或相加，也不代表漏洞真实发生的概率。"
        />
      </Space>
    </Card>
  );
}
