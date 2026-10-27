import { ApiOutlined, SafetyCertificateOutlined } from '@ant-design/icons';
import { Tag, Tooltip } from 'antd';

/**
 * 顶部品牌栏。
 *
 * 服务状态在联调阶段接入真实健康检查；本阶段如实显示“未连接”，
 * 不伪造“在线”状态。
 */
export default function AppHeader() {
  return (
    <header className="app-header">
      <div className="app-header__inner">
        <div className="app-header__brand">
          <span className="app-header__mark" aria-hidden="true">
            <SafetyCertificateOutlined />
          </span>
          <div>
            <h1 className="app-header__title">ARGUS</h1>
            <p className="app-header__subtitle">智能代码安全分析平台 · 辅助检测，不替代人工复核</p>
          </div>
        </div>
        <Tooltip title="后端连通性检查将在前后端联调阶段接入">
          <Tag className="app-header__status" icon={<ApiOutlined />}>
            服务状态：未连接
          </Tag>
        </Tooltip>
      </div>
    </header>
  );
}
