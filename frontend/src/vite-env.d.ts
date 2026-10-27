/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** 后端 API 的公开基地址；留空时使用 Vite 开发代理。 */
  readonly VITE_API_BASE_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
