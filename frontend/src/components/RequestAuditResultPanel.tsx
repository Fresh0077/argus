import { SendOutlined } from '@ant-design/icons';
import { Alert, Button, Card, Empty, Input, Space, Spin, Typography } from 'antd';
import type { RequestAuditResponse } from '../types/requestAudit';
import type { ScanErrorInfo } from '../types/ui';
import RequestFindingsView from './RequestFindingsView';
import SeverityStats from './SeverityStats';

interface RequestAuditResultPanelProps {
  response: RequestAuditResponse | null;
  /** 预览文本，可手动编辑；编辑后需要重新确认。 */
  previewText: string;
  onPreviewTextChange: (value: string) => void;
  loading: 'preview' | 'audit' | null;
  error: ScanErrorInfo | null;
  enableLlm: boolean;
  onAudit: () => void;
  onRetry: () => void;
}

/** 请求包审计的右侧工作区：脱敏预览、发送确认、审计结果。 */
export default function RequestAuditResultPanel({
  response,
  previewText,
  onPreviewTextChange,
  loading,
  error,
  enableLlm,
  onAudit,
  onRetry,
}: RequestAuditResultPanelProps) {
  if (loading !== null) {
    return (
      <Card className="panel-card" aria-busy="true">
        <div className="results-loading" role="status" aria-live="polite">
          <Spin size="large" />
          <Typography.Text strong>
            {loading === 'preview' ? '正在生成脱敏预览…' : '正在审计…'}
          </Typography.Text>
        </div>
      </Card>
    );
  }

  if (error) {
    return (
      <Card className="panel-card">
        <Alert
          type="error"
          showIcon
          message={error.title}
          description={
            <div>
              <p className="error-message">{error.message}</p>
              {error.details.length > 0 ? (
                <ul className="error-details">
                  {error.details.map((detail, index) => (
                    <li key={`${index}-${detail}`}>{detail}</li>
                  ))}
                </ul>
              ) : null}
            </div>
          }
          action={
            <Button size="small" onClick={onRetry}>
              重新预览
            </Button>
          }
        />
      </Card>
    );
  }

  if (!response) {
    return (
      <Card className="panel-card" title="脱敏预览">
        <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="尚未预览" />
      </Card>
    );
  }

  return (
    <Space direction="vertical" size="middle" className="request-audit-result">
      <Card
        className="panel-card"
        title={response.preview_only ? '脱敏预览' : '实际发送的报文'}
        extra={
          response.preview_only ? (
            <Typography.Text type="secondary" className="request-audit__meta">
              {previewText.split(/\r?\n/).length} 行 · 可编辑
            </Typography.Text>
          ) : null
        }
      >
        {response.preview_only ? (
          <Input.TextArea
            className="request-audit__editor"
            value={previewText}
            onChange={(event) => onPreviewTextChange(event.target.value)}
            autoSize={{ minRows: 12, maxRows: 24 }}
            spellCheck={false}
            aria-label="脱敏预览，可编辑"
          />
        ) : (
          <pre className="request-preview" aria-label="实际发送给 LLM 的脱敏报文">
            {response.redacted_request}
          </pre>
        )}
      </Card>

      {response.preview_only ? (
        enableLlm ? (
          <Card className="panel-card" title="发送确认">
            <Space direction="vertical" size="middle" className="request-audit__confirm">
              <Typography.Text type="secondary">
                将把上方脱敏后的报文发送给第三方 LLM。
              </Typography.Text>
              <Button
                type="primary"
                size="large"
                block
                icon={<SendOutlined />}
                disabled={!previewText.trim()}
                onClick={onAudit}
              >
                确认发送并审计
              </Button>
            </Space>
          </Card>
        ) : (
          <Typography.Text type="secondary" className="request-audit__no-llm">
            未开启 LLM 分析，当前仅完成解析与脱敏。
          </Typography.Text>
        )
      ) : (
        <AuditResultCard response={response} />
      )}
    </Space>
  );
}

function AuditResultCard({ response }: { response: RequestAuditResponse }) {
  const llmStatus = response.analyzer_status.find(
    (status) => status.name === 'http_request_llm',
  );

  return (
    <Card className="panel-card" title="审计结果">
      {response.status !== 'completed' ? (
        <Alert
          type="warning"
          showIcon
          message="LLM 审计未完成"
          description={llmStatus?.reason ?? '未获得 LLM 审计结果。'}
        />
      ) : null}

      <SeverityStats counts={response.summary.severity_counts} />
      <RequestFindingsView
        findings={response.findings}
        repairContext={{
          sourceCode: response.redacted_request,
          language: 'http',
          filename: 'request.http',
        }}
      />

      <Typography.Paragraph type="secondary" className="scan-result__disclaimer">
        {response.disclaimer}
      </Typography.Paragraph>
    </Card>
  );
}
