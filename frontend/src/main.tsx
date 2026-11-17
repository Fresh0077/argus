import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App as AntdApp, ConfigProvider } from 'antd';
import zhCN from 'antd/locale/zh_CN';
import 'antd/dist/reset.css';
import './styles/global.css';
import App from './App';

const rootElement = document.getElementById('root');
if (!rootElement) {
  throw new Error('页面缺少 #root 挂载点');
}

createRoot(rootElement).render(
  <StrictMode>
    <ConfigProvider
      locale={zhCN}
      theme={{
        token: {
          colorPrimary: '#1668dc',
          colorInfo: '#1668dc',
          colorBgLayout: '#f3f5f9',
          colorBorderSecondary: '#e3e8ef',
          colorText: '#16202e',
          colorTextSecondary: '#5b6b7f',
          borderRadius: 8,
          fontSize: 14,
          fontFamily:
            'system-ui, -apple-system, "Segoe UI", "Microsoft YaHei", "PingFang SC", sans-serif',
        },
        components: {
          Card: {
            headerFontSize: 16,
            headerHeight: 56,
            headerPadding: 20,
            bodyPadding: 20,
          },
          Button: {
            fontWeight: 500,
            defaultShadow: 'none',
            primaryShadow: 'none',
            dangerShadow: 'none',
          },
          Tabs: {
            titleFontSize: 14,
            horizontalItemPadding: '10px 0',
          },
          Table: {
            headerBg: '#f8fafc',
            headerColor: '#16202e',
            headerSplitColor: '#e3e8ef',
          },
          Tag: {
            defaultBg: '#f6f8fa',
            defaultColor: '#16202e',
          },
        },
      }}
    >
      <AntdApp>
        <App />
      </AntdApp>
    </ConfigProvider>
  </StrictMode>,
);
