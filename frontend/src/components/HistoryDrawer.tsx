import {
  ArrowLeftOutlined,
  DeleteOutlined,
  EyeOutlined,
  HistoryOutlined,
  ReloadOutlined,
} from '@ant-design/icons';
import {
  Alert,
  App as AntdApp,
  Button,
  Descriptions,
  Drawer,
  Empty,
  Popconfirm,
  Space,
  Spin,
  Table,
  Tag,
  Typography,
} from 'antd';
import type { DescriptionsProps, TableProps } from 'antd';
import { useCallback, useEffect, useRef, useState } from 'react';
import {
  SEVERITY_ORDER,
  languageLabel,
  scanStatusMeta,
  severityMeta,
} from '../constants/labels';
import {
  ApiError,
  deleteHistory,
  getHistory,
  listHistory,
} from '../services/apiClient';
import type { HistoryDetail, HistoryItem } from '../types/history';
import { formatDateTime, formatDuration } from '../utils/format';
import AnalyzerStatusList from './AnalyzerStatusList';
import FindingExplorer from './FindingExplorer';
import ReportExportButtons from './ReportExportButtons';
import SeverityStats from './SeverityStats';

const PAGE_SIZE = 10;

function historyErrorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    // 后端返回的 message 已是面向用户的安全文案；
    // 网络不可达等错误也由 ApiError 统一转换。
    return error.message;
  }
  return '读取扫描历史失败，请稍后重试。';
}

/** 列表中的发现数量，附各等级的非零计数。 */
function FindingCount({ item }: { item: HistoryItem }) {
  if (item.total_findings === 0) {
    return <Typography.Text type="secondary">0 条</Typography.Text>;
  }

  return (
    <Space size={[4, 4]} wrap>
      <Typography.Text>{item.total_findings} 条</Typography.Text>
      {SEVERITY_ORDER.filter((severity) => item.severity_counts[severity] > 0).map(
        (severity) => {
          const meta = severityMeta(severity);
          return (
            <Tag key={severity} color={meta.color}>
              {meta.label} {item.severity_counts[severity]}
            </Tag>
          );
        },
      )}
    </Space>
  );
}

/**
 * 扫描历史：从顶部入口打开的抽屉。
 *
 * 列表只显示元数据；点击“详情”才请求完整结果。
 * 所有内容都来自后端，不在前端拼接或推测任何扫描结论。
 */
export default function HistoryDrawer() {
  const { message } = AntdApp.useApp();

  const [open, setOpen] = useState(false);
  const [items, setItems] = useState<HistoryItem[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [enabled, setEnabled] = useState(true);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [detail, setDetail] = useState<HistoryDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);

  const listRequestRef = useRef<AbortController | null>(null);
  const detailRequestRef = useRef<AbortController | null>(null);

  useEffect(
    () => () => {
      listRequestRef.current?.abort();
      detailRequestRef.current?.abort();
    },
    [],
  );

  const loadPage = useCallback(async (targetPage: number) => {
    listRequestRef.current?.abort();
    const controller = new AbortController();
    listRequestRef.current = controller;

    setLoading(true);
    setError(null);
    try {
      const response = await listHistory({
        page: targetPage,
        pageSize: PAGE_SIZE,
        signal: controller.signal,
      });
      if (listRequestRef.current !== controller) {
        return;
      }
      setEnabled(response.enabled);
      setItems(response.items);
      setTotal(response.total);
      setPage(response.page);
    } catch (requestError) {
      if (requestError instanceof ApiError && requestError.kind === 'aborted') {
        return;
      }
      if (listRequestRef.current === controller) {
        setError(historyErrorMessage(requestError));
      }
    } finally {
      if (listRequestRef.current === controller) {
        setLoading(false);
      }
    }
  }, []);

  const handleOpen = () => {
    detailRequestRef.current?.abort();
    detailRequestRef.current = null;
    setOpen(true);
    setDetail(null);
    setDetailError(null);
    void loadPage(1);
  };

  const handleClose = () => {
    listRequestRef.current?.abort();
    detailRequestRef.current?.abort();
    listRequestRef.current = null;
    detailRequestRef.current = null;
    setOpen(false);
    setDetail(null);
    setDetailError(null);
  };

  const handleView = async (item: HistoryItem) => {
    detailRequestRef.current?.abort();
    const controller = new AbortController();
    detailRequestRef.current = controller;

    setDetail(null);
    setDetailError(null);
    setDetailLoading(true);
    try {
      const response = await getHistory(item.scan_id, { signal: controller.signal });
      if (detailRequestRef.current === controller) {
        setDetail(response);
      }
    } catch (requestError) {
      if (requestError instanceof ApiError && requestError.kind === 'aborted') {
        return;
      }
      if (detailRequestRef.current === controller) {
        setDetailError(historyErrorMessage(requestError));
      }
    } finally {
      if (detailRequestRef.current === controller) {
        setDetailLoading(false);
      }
    }
  };

  const handleDelete = async (item: HistoryItem) => {
    try {
      await deleteHistory(item.scan_id);
      message.success('已删除该条扫描历史。');
      if (detail?.scan_id === item.scan_id) {
        setDetail(null);
      }
      // 删掉当前页最后一条时回到上一页，避免停在空白页。
      const nextPage = items.length === 1 && page > 1 ? page - 1 : page;
      await loadPage(nextPage);
    } catch (requestError) {
      message.error(historyErrorMessage(requestError));
    }
  };

  const columns: TableProps<HistoryItem>['columns'] = [
    {
      title: '扫描时间',
      dataIndex: 'created_at',
      width: 176,
      render: (value: string) => formatDateTime(value),
    },
    {
      title: '文件 / 语言',
      key: 'source',
      render: (_value, item) => (
        <Space direction="vertical" size={0}>
          <Typography.Text ellipsis style={{ maxWidth: 220 }}>
            {item.filename ?? '未提供文件名'}
          </Typography.Text>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            {languageLabel(item.language)}
          </Typography.Text>
        </Space>
      ),
    },
    {
      title: '状态',
      dataIndex: 'status',
      width: 100,
      render: (value: string) => {
        const meta = scanStatusMeta(value);
        return <Tag color={meta.color}>{meta.label}</Tag>;
      },
    },
    {
      title: '候选发现',
      dataIndex: 'total_findings',
      width: 200,
      render: (_value, item) => <FindingCount item={item} />,
    },
    {
      title: '操作',
      key: 'actions',
      width: 150,
      render: (_value, item) => (
        <Space size={0}>
          <Button
            size="small"
            type="link"
            icon={<EyeOutlined />}
            onClick={() => {
              void handleView(item);
            }}
          >
            详情
          </Button>
          <Popconfirm
            title="删除这条扫描历史？"
            description="删除后无法通过界面恢复。"
            okText="删除"
            cancelText="取消"
            okButtonProps={{ danger: true }}
            onConfirm={() => handleDelete(item)}
          >
            <Button size="small" type="link" danger icon={<DeleteOutlined />}>
              删除
            </Button>
          </Popconfirm>
        </Space>
      ),
    },
  ];

  const renderDetail = (record: HistoryDetail) => {
    const statusMeta = scanStatusMeta(record.status);
    const itemsForDescriptions: DescriptionsProps['items'] = [
      {
        key: 'created_at',
        label: '扫描时间',
        children: formatDateTime(record.created_at),
      },
      {
        key: 'scan_id',
        label: '扫描编号',
        children: (
          <Typography.Text code copyable={{ text: record.scan_id }}>
            {record.scan_id}
          </Typography.Text>
        ),
      },
      {
        key: 'filename',
        label: '文件名',
        children: record.filename ?? '未提供',
      },
      {
        key: 'language',
        label: '识别语言',
        children: languageLabel(record.language),
      },
      {
        key: 'status',
        label: '扫描状态',
        children: <Tag color={statusMeta.color}>{statusMeta.label}</Tag>,
      },
      {
        key: 'duration',
        label: '总耗时',
        children: formatDuration(record.duration_ms),
      },
      {
        key: 'findings',
        label: '候选发现',
        children: `${record.total_findings} 条`,
      },
      {
        key: 'encoding',
        label: '源文件解码',
        children: record.source_encoding ?? '未发生解码转换（JSON 提交）',
      },
    ];

    return (
      <Space direction="vertical" size="middle" className="history-detail">
        <Alert
          type="info"
          showIcon
          message="历史只保存结果，不保存完整源代码"
          description="记录包含扫描元数据、摘要、候选发现（含最小必要证据片段）与分析器状态。原始源代码没有写入数据库，因此这里无法展示完整文件或重新扫描。报告也不包含完整源代码。"
        />
        <ReportExportButtons scanId={record.scan_id} />
        <Descriptions items={itemsForDescriptions} size="small" bordered column={{ xs: 1, sm: 2 }} />
        <SeverityStats counts={record.severity_counts} />
        {record.analyzer_status.length > 0 ? (
          <section className="detail-section">
            <Typography.Text strong>分析器状态</Typography.Text>
            <AnalyzerStatusList statuses={record.analyzer_status} />
          </section>
        ) : null}
        {record.findings.length > 0 ? (
          <FindingExplorer
            findings={record.findings}
            repairUnavailableReason="扫描历史只保存结果，不保存完整源代码，因此无法为该记录生成候选补丁。请重新提交代码扫描后再生成。"
          />
        ) : (
          <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="该次扫描没有记录到候选发现">
            <Typography.Paragraph type="secondary" className="history-detail__empty-hint">
              没有发现不代表代码安全。请结合上面的分析器状态判断：被跳过或失败的分析器不会产生结果。
            </Typography.Paragraph>
          </Empty>
        )}
        <Typography.Paragraph type="secondary" className="history-detail__note">
          该结果是扫描当时的快照，不会随后续规则调整而更新。
        </Typography.Paragraph>
      </Space>
    );
  };

  const body = detail ? (
    renderDetail(detail)
  ) : detailLoading ? (
    <div className="history-loading" role="status" aria-live="polite">
      <Spin />
      <Typography.Text type="secondary">正在读取历史详情…</Typography.Text>
    </div>
  ) : detailError ? (
    <Alert
      type="error"
      showIcon
      message="无法读取历史详情"
      description={detailError}
      action={
        <Button size="small" onClick={() => setDetailError(null)}>
          返回列表
        </Button>
      }
    />
  ) : (
    <>
      {!enabled ? (
        <Alert
          type="warning"
          showIcon
          message="扫描历史功能未启用"
          description="服务端配置 HISTORY_ENABLED=false，因此不会记录新的扫描，也无法读取或删除历史。扫描功能本身不受影响。"
        />
      ) : null}
      {error ? (
        <Alert
          type="error"
          showIcon
          message="无法读取扫描历史"
          description={error}
          action={
            <Button size="small" onClick={() => void loadPage(page)}>
              重试
            </Button>
          }
        />
      ) : enabled ? (
        <Table<HistoryItem>
          rowKey="scan_id"
          size="small"
          loading={loading}
          columns={columns}
          dataSource={items}
          scroll={{ x: 760 }}
          pagination={{
            current: page,
            pageSize: PAGE_SIZE,
            total,
            showSizeChanger: false,
            showTotal: (count) => `共 ${count} 条`,
            onChange: (nextPage) => {
              void loadPage(nextPage);
            },
          }}
          locale={{
            emptyText: (
              <Empty
                image={Empty.PRESENTED_IMAGE_SIMPLE}
                description="还没有扫描历史。完成一次扫描后，这里会出现记录。"
              />
            ),
          }}
        />
      ) : null}
    </>
  );

  return (
    <>
      <Button ghost icon={<HistoryOutlined />} onClick={handleOpen}>
        扫描历史
      </Button>
      <Drawer
        title={detail ? '历史详情' : '扫描历史'}
        open={open}
        width="min(1080px, 96vw)"
        onClose={handleClose}
        extra={
          detail ? (
            <Button
              icon={<ArrowLeftOutlined />}
              onClick={() => {
                setDetail(null);
                setDetailError(null);
              }}
            >
              返回列表
            </Button>
          ) : (
            <Button
              icon={<ReloadOutlined />}
              onClick={() => void loadPage(page)}
              disabled={!enabled || loading}
            >
              刷新
            </Button>
          )
        }
      >
        {body}
      </Drawer>
    </>
  );
}
