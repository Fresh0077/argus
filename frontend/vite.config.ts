import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// 开发期把 /api 转发给本机后端，前端因此可以使用相对路径请求，
// 不必依赖 CORS。生产部署时由反向代理承担同样的转发职责。
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
      },
    },
  },
});
