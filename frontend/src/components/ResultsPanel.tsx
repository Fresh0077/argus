import { Alert, Button, Card, Empty, Spin, Typography } from 'antd';
import type { RepairContext } from '../types/repair';
import type { ScanResponse } from '../types/scan';
import type { RequestedAnalyzers, ScanErrorInfo } from '../types/ui';
import ReportExportButtons from './ReportExportButtons';
import ScanResultView from './ScanResultView';

interface ResultsPanelProps {
  result: ScanResponse | null;
  loading: boolean;
  error: ScanErrorInfo | null;
  requestedAnalyzers: RequestedAnalyzers;
  repairContext?: RepairContext | null;
  repairUnavailableReason?: string;
  onRetry?: () => void;
}

/** 结果区容器：只渲染后端真实返回的数据，并区分空、加载、失败与结果四种状态。 */
export default function ResultsPanel({
  result,
  loading,
  error,
  requestedAnalyzers,
  repairContext,
  repairUnavailableReason,
  onRetry,
}: ResultsPanelProps) {
  return (
    <Card
      className="panel-card"
      title="扫描结果"
      aria-busy={loading}
      extra={result ? <ReportExportButtons scanId={result.scan_id} /> : null}
    >
      {loading ? (
        <div className="results-loading" role="status" aria-live="polite">
          <Spin size="large" />
          <Typography.Text strong>正在分析代码…</Typography.Text>
          <Typography.Text type="secondary" className="results-loading__hint">
            特征提取通常很快；启用 LLM 时耗时取决于第三方服务商的响应速度。
          </Typography.Text>
        </div>
      ) : error ? (
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
            onRetry ? (
              <Button size="small" onClick={onRetry}>
                重试
              </Button>
            ) : undefined
          }
        />
      ) : result ? (
        <ScanResultView
          key={result.scan_id}
          result={result}
          requested={requestedAnalyzers}
          repairContext={repairContext}
          repairUnavailableReason={repairUnavailableReason}
        />
      ) : (
        <div className="results-empty">
          <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="尚未执行扫描" />
        </div>
      )}
    </Card>
  );
}
