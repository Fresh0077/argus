import type {
  AnalysisOptions,
  ApiErrorBody,
  ErrorDetail,
  HealthResponse,
  ScanRequest,
  ScanResponse,
} from '../types/scan';
import { apiUrl } from './apiConfig';

/**
 * 统一 API 客户端。
 *
 * 所有请求都从这里发出，组件不直接调用 `fetch`。这里只做三件事：
 * 拼接地址、把网络与 HTTP 失败收敛成结构化错误、解析 JSON。
 * 不读取、不保存任何密钥。
 */

export type ApiErrorKind = 'http' | 'network' | 'timeout' | 'aborted' | 'invalid_response';

interface ApiErrorOptions {
  status?: number;
  code?: string;
  details?: ErrorDetail[];
}

export class ApiError extends Error {
  readonly kind: ApiErrorKind;
  readonly status: number | undefined;
  readonly code: string | undefined;
  readonly details: ErrorDetail[];

  constructor(kind: ApiErrorKind, message: string, options: ApiErrorOptions = {}) {
    super(message);
    this.name = 'ApiError';
    this.kind = kind;
    this.status = options.status;
    this.code = options.code;
    this.details = options.details ?? [];
  }
}

/** 后端扫描本身有总时限，前端留出余量后再超时。 */
const DEFAULT_TIMEOUT_MS = 90_000;

const BACKEND_UNREACHABLE_MESSAGE =
  '无法连接后端分析服务。请确认后端已启动（默认 http://127.0.0.1:8000），开发模式下还需确认 Vite 代理目标一致。';

interface RequestOptions {
  method: 'GET' | 'POST';
  body?: BodyInit;
  headers?: Record<string, string>;
  signal?: AbortSignal;
  timeoutMs?: number;
}

interface LinkedController {
  signal: AbortSignal;
  timedOut: () => boolean;
  cleanup: () => void;
}

/** 把调用方的取消信号与前端超时合并到一个 AbortController。 */
function createLinkedController(
  callerSignal: AbortSignal | undefined,
  timeoutMs: number,
): LinkedController {
  const controller = new AbortController();
  let timedOut = false;

  const timeoutId = window.setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeoutMs);

  const handleCallerAbort = () => controller.abort();
  if (callerSignal) {
    if (callerSignal.aborted) {
      controller.abort();
    } else {
      callerSignal.addEventListener('abort', handleCallerAbort, { once: true });
    }
  }

  return {
    signal: controller.signal,
    timedOut: () => timedOut,
    cleanup: () => {
      window.clearTimeout(timeoutId);
      callerSignal?.removeEventListener('abort', handleCallerAbort);
    },
  };
}

function isErrorBody(value: unknown): value is ApiErrorBody {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const error = (value as { error?: unknown }).error;
  if (typeof error !== 'object' || error === null) {
    return false;
  }
  const { code, message } = error as { code?: unknown; message?: unknown };
  return typeof code === 'string' && typeof message === 'string';
}

function mapRequestFailure(
  error: unknown,
  callerSignal: AbortSignal | undefined,
  timedOut: boolean,
): ApiError {
  if (error instanceof ApiError) {
    return error;
  }
  if (timedOut) {
    return new ApiError(
      'timeout',
      '请求超时。后端分析可能耗时较长，请稍后重试或缩小输入。',
    );
  }
  if (callerSignal?.aborted) {
    return new ApiError('aborted', '请求已取消。');
  }
  if (error instanceof DOMException && error.name === 'AbortError') {
    return new ApiError('aborted', '请求已取消。');
  }
  return new ApiError('network', BACKEND_UNREACHABLE_MESSAGE);
}

async function requestJson<T>(path: string, options: RequestOptions): Promise<T> {
  const linked = createLinkedController(options.signal, options.timeoutMs ?? DEFAULT_TIMEOUT_MS);

  try {
    let response: Response;
    try {
      response = await fetch(apiUrl(path), {
        method: options.method,
        headers: { Accept: 'application/json', ...options.headers },
        body: options.body,
        signal: linked.signal,
      });
    } catch (error) {
      throw mapRequestFailure(error, options.signal, linked.timedOut());
    }

    let text: string;
    try {
      text = await response.text();
    } catch (error) {
      throw mapRequestFailure(error, options.signal, linked.timedOut());
    }

    let payload: unknown;
    if (text) {
      try {
        payload = JSON.parse(text) as unknown;
      } catch {
        payload = undefined;
      }
    }

    if (!response.ok) {
      const body = isErrorBody(payload) ? payload.error : undefined;
      // Vite 等开发代理连接不上后端时会返回不带错误信封的 5xx。
      // 若沿用“后端返回错误”会让用户误以为扫描逻辑出错，这里按不可达处理。
      if (!body && response.status >= 500) {
        throw new ApiError('network', BACKEND_UNREACHABLE_MESSAGE, {
          status: response.status,
        });
      }
      const details = body && Array.isArray(body.details) ? body.details : [];
      throw new ApiError(
        'http',
        body?.message ?? `后端返回错误（HTTP ${response.status}）。`,
        { status: response.status, code: body?.code, details },
      );
    }

    if (payload === undefined) {
      throw new ApiError('invalid_response', '后端返回了无法解析的响应。', {
        status: response.status,
      });
    }

    return payload as T;
  } finally {
    linked.cleanup();
  }
}

/** 探测后端是否可达；失败不代表扫描功能一定不可用，仅用于顶部状态展示。 */
export async function checkHealth(options: { signal?: AbortSignal } = {}): Promise<HealthResponse> {
  return requestJson<HealthResponse>('/api/v1/health', {
    method: 'GET',
    signal: options.signal,
    timeoutMs: 10_000,
  });
}

export async function scanCode(
  request: ScanRequest,
  options: { signal?: AbortSignal } = {},
): Promise<ScanResponse> {
  return requestJson<ScanResponse>('/api/v1/scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(request),
    signal: options.signal,
  });
}

interface UploadScanOptions {
  analysisOptions: AnalysisOptions;
  language?: string;
  signal?: AbortSignal;
}

export async function scanUpload(
  file: File,
  options: UploadScanOptions,
): Promise<ScanResponse> {
  const formData = new FormData();
  formData.append('file', file, file.name);
  formData.append('enable_llm', String(options.analysisOptions.enable_llm));
  formData.append('enable_semgrep', String(options.analysisOptions.enable_semgrep));
  if (options.language) {
    formData.append('language', options.language);
  }

  // 不要手动设置 Content-Type：浏览器需要自行生成 multipart boundary。
  return requestJson<ScanResponse>('/api/v1/scan/upload', {
    method: 'POST',
    body: formData,
    signal: options.signal,
  });
}
