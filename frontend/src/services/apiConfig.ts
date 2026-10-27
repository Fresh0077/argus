/**
 * API 基地址读取。
 *
 * 本阶段只建立配置入口，不发起请求；扫描与上传调用在联调阶段接入。
 * 只允许公开配置：模型密钥必须留在后端环境变量中。
 */
const configuredBaseUrl = import.meta.env.VITE_API_BASE_URL?.trim() ?? '';

/** 去掉末尾斜杠，避免与 `/api/v1/...` 拼接时出现双斜杠。 */
export const API_BASE_URL = configuredBaseUrl.replace(/\/+$/, '');

/** 拼接 API 路径；基地址为空时返回相对路径，交给 Vite 代理转发。 */
export function apiUrl(path: string): string {
  const normalizedPath = path.startsWith('/') ? path : `/${path}`;
  return `${API_BASE_URL}${normalizedPath}`;
}
