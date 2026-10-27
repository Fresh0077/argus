import { Alert, Button, Card, Empty, Skeleton, Typography } from 'antd';
import type { ScanResponse } from '../types/scan';
import ScanResultView from './ScanResultView';

interface ResultsPanelProps {
  result: ScanResponse | null;
  loading: boolean;
  error: string | null;
  onRetry?: () => void;
}

/**
 * 结果区容器。
 *
 * 只渲染后端真实返回的数据；本阶段没有发起请求，因此固定显示空状态。
 * 单独抽出容器便于联调阶段接入加载、失败与重试状态。
 */
export default function ResultsPanel({ result, loading, error, onRetry }: ResultsPanelProps) {
  return (
    <Card className="panel-card" title="扫描结果">
      {loading ? (
        <Skeleton active paragraph={{ rows: 10 }} />
      ) : error ? (
        <Alert
          type="error"
          showIcon
          message="扫描失败"
          description={error}
          action={
            onRetry ? (
              <Button size="small" onClick={onRetry}>
                重试
              </Button>
            ) : undefined
          }
        />
      ) : result ? (
        <ScanResultView key={result.scan_id} result={result} />
      ) : (
        <div className="results-empty">
          <Empty
            image={Empty.PRESENTED_IMAGE_SIMPLE}
            description="尚未执行扫描"
          />
          <Typography.Paragraph type="secondary" className="results-empty__hint">
            结果区只展示后端真实返回的扫描数据，不使用演示或伪造数据。
            输入代码并点击“开始扫描”后，这里会显示扫描摘要、严重程度统计与候选发现列表。
          </Typography.Paragraph>
        </div>
      )}
    </Card>
  );
}
