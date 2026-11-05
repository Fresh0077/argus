import {
  CopyOutlined,
  DownloadOutlined,
  ReloadOutlined,
} from '@ant-design/icons';
import {
  Alert,
  App as AntdApp,
  Button,
  Descriptions,
  Modal,
  Space,
  Spin,
  Typography,
} from 'antd';
import type { RepairSuggestion } from '../types/repair';
import RepairDiffView from './RepairDiffView';

interface RepairSuggestionModalProps {
  open: boolean;
  findingTitle: string;
  filename: string | null;
  loading: boolean;
  error: string | null;
  suggestion: RepairSuggestion | null;
  onClose: () => void;
  onRetry: () => void;
}

/** 下载文件名只做展示用途；后端已保证原始文件名校验过路径字符。 */
function suggestedFileName(filename: string | null): string {
  const base = filename?.trim() || 'argus-fixed.txt';
  const dot = base.lastIndexOf('.');
  if (dot > 0) {
    return `${base.slice(0, dot)}.fixed${base.slice(dot)}`;
  }
  return `${base}.fixed.txt`;
}

async function copyText(text: string): Promise<boolean> {
  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      // 部分环境禁用了 Clipboard API，退回旧方案。
    }
  }

  const textarea = document.createElement('textarea');
  textarea.value = text;
  textarea.setAttribute('readonly', '');
  textarea.style.position = 'fixed';
  textarea.style.opacity = '0';
  document.body.appendChild(textarea);
  textarea.select();
  const copied = document.execCommand('copy');
  document.body.removeChild(textarea);
  return copied;
}

/**
 * 候选修复建议弹窗。
 *
 * 只展示后端返回的内容；复制与下载都必须由用户主动点击，
 * 不会修改原始文件，也不会执行修复后的代码。
 */
export default function RepairSuggestionModal({
  open,
  findingTitle,
  filename,
  loading,
  error,
  suggestion,
  onClose,
  onRetry,
}: RepairSuggestionModalProps) {
  const { message } = AntdApp.useApp();

  const handleCopy = async () => {
    if (!suggestion) {
      return;
    }
    const copied = await copyText(suggestion.fixed_code);
    if (copied) {
      message.success('已复制候选修复代码。请先审查再使用。');
    } else {
      message.error('复制失败，请手动选中代码复制。');
    }
  };

  const handleDownload = () => {
    if (!suggestion) {
      return;
    }
    const blob = new Blob([suggestion.fixed_code], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = suggestedFileName(filename);
    document.body.appendChild(anchor);
    anchor.click();
    document.body.removeChild(anchor);
    URL.revokeObjectURL(url);
    message.success('已下载候选补丁。原文件没有被修改。');
  };

  const body = loading ? (
    <div className="repair-modal__loading" role="status" aria-live="polite">
      <Spin />
      <Typography.Text type="secondary">正在请求模型生成候选补丁…</Typography.Text>
    </div>
  ) : error ? (
    <Alert
      type="error"
      showIcon
      message="无法生成修复建议"
      description={error}
      action={
        <Button size="small" icon={<ReloadOutlined />} onClick={onRetry}>
          重试
        </Button>
      }
    />
  ) : suggestion ? (
    <Space direction="vertical" size="middle" className="repair-modal__body">
      <Alert
        type="warning"
        showIcon
        message="这是候选补丁，未经编译、执行或测试"
        description={suggestion.disclaimer}
      />

      <Descriptions
        size="small"
        bordered
        column={{ xs: 1, sm: 2 }}
        items={[
          { key: 'finding', label: '关联发现', children: findingTitle },
          {
            key: 'excerpt',
            label: '待替换行',
            children: `第 ${suggestion.excerpt_line_start}–${suggestion.excerpt_line_end} 行`,
          },
          {
            key: 'context',
            label: '发送给模型的上下文',
            children: `第 ${suggestion.context_line_start}–${suggestion.context_line_end} 行`,
          },
        ]}
      />

      <section className="detail-section">
        <Typography.Text strong>修复思路</Typography.Text>
        <Typography.Paragraph className="pre-wrap">{suggestion.repair_idea}</Typography.Paragraph>
      </section>

      <section className="detail-section">
        <Typography.Text strong>差异预览</Typography.Text>
        <RepairDiffView diff={suggestion.diff} />
      </section>

      <section className="detail-section">
        <Typography.Text strong>解释</Typography.Text>
        <Typography.Paragraph className="pre-wrap">{suggestion.explanation}</Typography.Paragraph>
      </section>

      <section className="detail-section">
        <Typography.Text strong>可能的兼容性影响</Typography.Text>
        <Typography.Paragraph className="pre-wrap">
          {suggestion.compatibility_impact}
        </Typography.Paragraph>
      </section>

      <section className="detail-section">
        <Typography.Text strong>未能确认的前提</Typography.Text>
        {suggestion.unconfirmed_premises.length > 0 ? (
          <ul className="repair-modal__premises">
            {suggestion.unconfirmed_premises.map((premise) => (
              <li key={premise}>{premise}</li>
            ))}
          </ul>
        ) : (
          <Typography.Paragraph type="secondary">
            模型未列出未确认前提。这不代表修复没有风险，仍需人工核对。
          </Typography.Paragraph>
        )}
      </section>

      <Typography.Paragraph type="secondary" className="repair-modal__note">
        复制或下载都不会修改原文件，也不会执行修复后的代码。请在你的环境中审查并重新测试。
      </Typography.Paragraph>
    </Space>
  ) : null;

  return (
    <Modal
      title="候选修复建议"
      open={open}
      width={920}
      onCancel={onClose}
      footer={[
        <Button key="close" onClick={onClose}>
          关闭
        </Button>,
        <Button
          key="copy"
          icon={<CopyOutlined />}
          disabled={!suggestion || loading}
          onClick={() => {
            void handleCopy();
          }}
        >
          复制修复代码
        </Button>,
        <Button
          key="download"
          type="primary"
          icon={<DownloadOutlined />}
          disabled={!suggestion || loading}
          onClick={handleDownload}
        >
          下载为新文件
        </Button>,
      ]}
    >
      {body}
    </Modal>
  );
}
