import { SafetyCertificateOutlined } from '@ant-design/icons';
import { Switch, Typography } from 'antd';

interface LlmAuthCalloutProps {
  checked: boolean;
  onChange: (checked: boolean) => void;
  disabled?: boolean;
  /** 发送对象说明，例如“代码”或“脱敏后的报文”。 */
  subject?: string;
}

/**
 * LLM 发送授权。
 *
 * 源码扫描与请求包审计共用同一个组件，避免两处出现不同的隐私授权交互。
 */
export default function LlmAuthCallout({
  checked,
  onChange,
  disabled = false,
  subject = '代码',
}: LlmAuthCalloutProps) {
  const className = checked
    ? 'input-panel__auth-callout input-panel__auth-callout--on'
    : 'input-panel__auth-callout';

  return (
    <div className={className}>
      <span className="input-panel__auth-icon" aria-hidden="true">
        <SafetyCertificateOutlined />
      </span>
      <div className="input-panel__auth-copy">
        <Typography.Text strong>使用 LLM 分析</Typography.Text>
        <Typography.Text type="secondary" className="input-panel__hint">
          {subject}将发送给第三方
        </Typography.Text>
      </div>
      <Switch
        checked={checked}
        onChange={onChange}
        disabled={disabled}
        aria-label={`使用 LLM 分析，${subject}将发送给第三方`}
      />
    </div>
  );
}
