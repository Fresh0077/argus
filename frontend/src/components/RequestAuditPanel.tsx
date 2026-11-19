import { ClearOutlined, EyeOutlined } from '@ant-design/icons';
import { Button, Card, Input, Space, Typography } from 'antd';
import LlmAuthCallout from './LlmAuthCallout';

const { TextArea } = Input;

const PLACEHOLDER = `POST /login?next=/home HTTP/1.1
Host: example.com
Authorization: Bearer <token>
Cookie: session=<session-id>
Content-Type: application/json

{"username":"alice","password":"..."}`;

interface RequestAuditPanelProps {
  rawRequest: string;
  onRawRequestChange: (value: string) => void;
  enableLlm: boolean;
  onEnableLlmChange: (enabled: boolean) => void;
  canPreview: boolean;
  loading: boolean;
  onPreview: () => void;
  onClear: () => void;
}

/**
 * 请求包输入区。
 *
 * 这里不做任何解析：预览、脱敏与发送确认全部由后续步骤完成，前端只负责提交原文。
 */
export default function RequestAuditPanel({
  rawRequest,
  onRawRequestChange,
  enableLlm,
  onEnableLlmChange,
  canPreview,
  loading,
  onPreview,
  onClear,
}: RequestAuditPanelProps) {
  return (
    <Card className="panel-card" title="输入 HTTP 请求报文">
      <Space direction="vertical" size="middle" className="input-panel">
        <TextArea
          className="code-textarea request-audit__textarea"
          value={rawRequest}
          onChange={(event) => onRawRequestChange(event.target.value)}
          placeholder={PLACEHOLDER}
          autoSize={{ minRows: 14, maxRows: 30 }}
          spellCheck={false}
          disabled={loading}
          aria-label="原始 HTTP 请求报文"
        />
        <div className="input-panel__meta">
          <Typography.Text type="secondary">
            {rawRequest.length.toLocaleString('zh-CN')} 字符
          </Typography.Text>
        </div>

        <LlmAuthCallout
          checked={enableLlm}
          onChange={onEnableLlmChange}
          disabled={loading}
          subject="脱敏后的报文"
        />

        <Space wrap>
          <Button
            type="primary"
            size="large"
            icon={<EyeOutlined />}
            onClick={onPreview}
            disabled={!canPreview || loading}
            loading={loading}
          >
            预览脱敏结果
          </Button>
          <Button size="large" icon={<ClearOutlined />} onClick={onClear} disabled={loading}>
            清空
          </Button>
        </Space>
      </Space>
    </Card>
  );
}
