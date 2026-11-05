import { DownloadOutlined } from '@ant-design/icons';
import { App as AntdApp, Button, Space } from 'antd';
import { useEffect, useRef, useState } from 'react';
import { ApiError, downloadReport } from '../services/apiClient';
import type { ReportFormat } from '../types/report';

const FORMAT_LABELS: Record<ReportFormat, string> = {
  json: 'JSON',
  markdown: 'Markdown',
};

const FORMAT_EXTENSIONS: Record<ReportFormat, string> = {
  json: 'json',
  markdown: 'md',
};

/**
 * 从本地扫描历史导出报告。
 *
 * 报告由后端生成，前端只负责触发下载；任何错误都以提示展示，
 * 不会把错误 JSON 当作文件保存。
 */
export default function ReportExportButtons({ scanId }: { scanId: string }) {
  const { message } = AntdApp.useApp();
  const [loading, setLoading] = useState<ReportFormat | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  useEffect(
    () => () => {
      abortRef.current?.abort();
      abortRef.current = null;
    },
    [],
  );

  const handleExport = async (format: ReportFormat) => {
    if (loading) {
      return;
    }

    const controller = new AbortController();
    abortRef.current = controller;
    setLoading(format);

    try {
      const blob = await downloadReport(scanId, format, { signal: controller.signal });
      if (abortRef.current !== controller) {
        return;
      }

      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = `argus-report-${scanId}.${FORMAT_EXTENSIONS[format]}`;
      document.body.appendChild(anchor);
      anchor.click();
      document.body.removeChild(anchor);
      URL.revokeObjectURL(url);
      message.success(`已导出 ${FORMAT_LABELS[format]} 报告。`);
    } catch (error) {
      if (error instanceof ApiError && error.kind === 'aborted') {
        return;
      }
      message.error(
        error instanceof ApiError ? error.message : '导出报告失败，请稍后重试。',
      );
    } finally {
      if (abortRef.current === controller) {
        abortRef.current = null;
        setLoading(null);
      }
    }
  };

  return (
    <Space wrap size="small" className="report-export">
      <Button
        size="small"
        icon={<DownloadOutlined />}
        loading={loading === 'json'}
        disabled={loading !== null && loading !== 'json'}
        title="从本地扫描历史生成，不含完整源代码"
        onClick={() => {
          void handleExport('json');
        }}
      >
        导出 JSON
      </Button>
      <Button
        size="small"
        icon={<DownloadOutlined />}
        loading={loading === 'markdown'}
        disabled={loading !== null && loading !== 'markdown'}
        title="从本地扫描历史生成，不含完整源代码"
        onClick={() => {
          void handleExport('markdown');
        }}
      >
        导出 Markdown
      </Button>
    </Space>
  );
}
