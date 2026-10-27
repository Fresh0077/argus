import { Alert, Button, Card, Empty, Spin, Typography } from 'antd';
import type { ScanResponse } from '../types/scan';
import type { RequestedAnalyzers, ScanErrorInfo } from '../types/ui';
import ScanResultView from './ScanResultView';

interface ResultsPanelProps {
  result: ScanResponse | null;
  loading: boolean;
  error: ScanErrorInfo | null;
  requestedAnalyzers: RequestedAnalyzers;
  onRetry?: () => void;
}

/** 结果区容器：只渲染后端真实返回的数据，并区分空、加载、失败与结果四种状态。 */
export default function ResultsPanel({
  result,
  loading,
  error,
  requestedAnalyzers,
  onRetry,
}: ResultsPanelProps) {
  return (
    <Card className="panel-card" title="扫描结果">
      {loading ? (
        <div className="results-loading">
          <Spin size="large" />
          <Typography.Text strong>正在分析代码…</Typography.Text>
          <Typography.Text type="secondary" className="results-loading__hint">
            规则与特征分析通常很快；启用 LLM 时耗时取决于第三方服务商的响应速度。
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
        <ScanResultView key={result.scan_id} result={result} requested={requestedAnalyzers} />
      ) : (
        <div className="results-empty">
          <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="尚未执行扫描" />
          <Typography.Paragraph type="secondary" className="results-empty__hint">
            结果区只展示后端真实返回的扫描数据，不使用演示或伪造数据。输入代码或选择文件并点击
            “开始扫描”后，这里会显示扫描摘要、严重程度统计与候选发现列表。
          </Typography.Paragraph>
        </div>
      )}
    </Card>
  );
}
