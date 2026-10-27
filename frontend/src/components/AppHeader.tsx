import {
  CheckCircleOutlined,
  CloseCircleOutlined,
  SafetyCertificateOutlined,
  SyncOutlined,
} from '@ant-design/icons';
import { Tag, Tooltip } from 'antd';
import { useEffect, useState } from 'react';
import { ApiError, checkHealth } from '../services/apiClient';
import type { HealthResponse } from '../types/scan';

type ServiceState = 'checking' | 'online' | 'offline';

/** 顶部品牌栏。服务状态来自后端健康检查，不伪造在线状态。 */
export default function AppHeader() {
  const [serviceState, setServiceState] = useState<ServiceState>('checking');
  const [health, setHealth] = useState<HealthResponse | null>(null);

  useEffect(() => {
    const controller = new AbortController();

    checkHealth({ signal: controller.signal })
      .then((response) => {
        setHealth(response);
        setServiceState('online');
      })
      .catch((error: unknown) => {
        if (error instanceof ApiError && error.kind === 'aborted') {
          return;
        }
        setServiceState('offline');
      });

    return () => controller.abort();
  }, []);

  const statusView =
    serviceState === 'online'
      ? {
          label: `服务状态：在线${health ? ` · v${health.version}` : ''}`,
          icon: <CheckCircleOutlined />,
          tooltip: `后端健康检查通过（环境：${health?.environment ?? '未知'}）。该状态只表示 Web 服务可用，不代表规则、Semgrep 或 LLM 均已就绪。`,
        }
      : serviceState === 'offline'
        ? {
            label: '服务状态：不可达',
            icon: <CloseCircleOutlined />,
            tooltip:
              '无法连接后端。请确认后端已启动（默认 http://127.0.0.1:8000），刷新页面可重新检查。',
          }
        : {
            label: '服务状态：检查中',
            icon: <SyncOutlined spin />,
            tooltip: '正在检查后端健康状态',
          };

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
        <Tooltip title={statusView.tooltip}>
          <Tag className="app-header__status" icon={statusView.icon}>
            {statusView.label}
          </Tag>
        </Tooltip>
      </div>
    </header>
  );
}
