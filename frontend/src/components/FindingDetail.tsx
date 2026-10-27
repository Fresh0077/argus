import { Alert, Card, Descriptions, Progress, Space, Tag, Typography } from 'antd';
import { severityMeta, sourceMeta } from '../constants/labels';
import type { Finding } from '../types/scan';
import { formatConfidence, formatLineRange } from '../utils/format';

/** 单条候选发现的详情。所有用户文本由 React 转义，不使用 HTML 注入。 */
export default function FindingDetail({ finding }: { finding: Finding }) {
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
            { key: 'type', label: '类别', children: finding.vulnerability_type },
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

        <section className="detail-section">
          <Typography.Text strong>代码证据</Typography.Text>
          <pre className="evidence-block">
            {finding.evidence || '（本次发现没有可展示的证据片段）'}
          </pre>
        </section>

        <section className="detail-section">
          <Typography.Text strong>修复建议</Typography.Text>
          <Typography.Paragraph className="pre-wrap">{finding.recommendation}</Typography.Paragraph>
        </section>

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
