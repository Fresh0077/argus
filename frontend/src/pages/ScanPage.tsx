import { App as AntdApp, Col, Row } from 'antd';
import type { UploadFile } from 'antd';
import { useEffect, useRef, useState } from 'react';
import CodeInputPanel from '../components/CodeInputPanel';
import ResultsPanel from '../components/ResultsPanel';
import { ApiError, scanCode, scanUpload } from '../services/apiClient';
import { toScanErrorInfo } from '../services/scanErrors';
import type { RepairContext } from '../types/repair';
import type { ScanResponse } from '../types/scan';
import type { InputMode, RequestedAnalyzers, ScanErrorInfo } from '../types/ui';

type ScanState =
  | { status: 'idle' }
  | { status: 'loading' }
  | {
      status: 'success';
      result: ScanResponse;
      requested: RequestedAnalyzers;
      repairContext: RepairContext | null;
      repairUnavailableReason?: string;
    }
  | { status: 'error'; error: ScanErrorInfo };

/**
 * 为当前结果准备生成候选补丁所需的源代码。
 *
 * - 粘贴模式：直接使用提交扫描的那份文本；
 * - 上传模式：读取原始 File 的文本。只有后端按 UTF-8 解码时，
 *   浏览器读出的文本才与扫描时的源码一致；其他编码会导致行号或字符偏移，
 *   因此宁可禁用修复，也不发送可能错位的代码。
 */
async function buildRepairContext(
  response: ScanResponse,
  mode: InputMode,
  submittedSource: string,
  file: File | undefined,
): Promise<{ context: RepairContext | null; reason?: string }> {
  if (mode === 'paste') {
    return {
      context: {
        sourceCode: submittedSource,
        language: response.detected_language,
        filename: null,
      },
    };
  }

  if (!file) {
    return { context: null, reason: '找不到原始上传文件，无法生成候选补丁。' };
  }

  const encoding = response.source_encoding;
  if (encoding && !encoding.toLowerCase().startsWith('utf-8')) {
    return {
      context: null,
      reason: `后端使用 ${encoding} 解码该文件，浏览器无法可靠还原文本，暂不支持为该结果生成候选补丁。`,
    };
  }

  try {
    const text = await file.text();
    return {
      context: {
        sourceCode: text,
        language: response.detected_language,
        filename: file.name,
      },
    };
  } catch {
    return { context: null, reason: '无法读取上传文件的文本内容，暂不支持生成候选补丁。' };
  }
}

/**
 * 主工作区：管理输入与扫描请求状态。
 *
 * 所有扫描结果都来自后端；同一时间只允许一个请求，切换输入或重新扫描会取消旧请求。
 */
export default function ScanPage() {
  const { message } = AntdApp.useApp();

  const [inputMode, setInputMode] = useState<InputMode>('paste');
  const [sourceCode, setSourceCode] = useState('');
  const [language, setLanguage] = useState<string | undefined>(undefined);
  const [fileList, setFileList] = useState<UploadFile[]>([]);
  const [enableSemgrep, setEnableSemgrep] = useState(false);
  const [enableLlm, setEnableLlm] = useState(false);
  const [scanState, setScanState] = useState<ScanState>({ status: 'idle' });

  const abortRef = useRef<AbortController | null>(null);
  const mountedRef = useRef(true);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      abortRef.current?.abort();
      abortRef.current = null;
    };
  }, []);

  const scanning = scanState.status === 'loading';
  const canScan = inputMode === 'paste' ? sourceCode.trim().length > 0 : fileList.length > 0;

  const result = scanState.status === 'success' ? scanState.result : null;
  const error = scanState.status === 'error' ? scanState.error : null;
  const repairContext = scanState.status === 'success' ? scanState.repairContext : null;
  const repairUnavailableReason =
    scanState.status === 'success' ? scanState.repairUnavailableReason : undefined;
  const requestedAnalyzers: RequestedAnalyzers =
    scanState.status === 'success' ? scanState.requested : { llm: enableLlm, semgrep: enableSemgrep };

  /** 输入变化后旧结果不再对应当前代码，清掉以免误读。 */
  const invalidateResult = () => {
    setScanState((current) => (current.status === 'loading' ? current : { status: 'idle' }));
  };

  const handleInputModeChange = (mode: InputMode) => {
    if (scanning || mode === inputMode) {
      return;
    }
    if (mode === 'paste') {
      setFileList([]);
    } else {
      setSourceCode('');
    }
    setInputMode(mode);
    invalidateResult();
  };

  const handleSourceCodeChange = (value: string) => {
    setSourceCode(value);
    invalidateResult();
  };

  const handleFileListChange = (files: UploadFile[]) => {
    setFileList(files);
    invalidateResult();
  };

  const handleLanguageChange = (value: string | undefined) => {
    setLanguage(value);
    invalidateResult();
  };

  const handleEnableSemgrepChange = (enabled: boolean) => {
    setEnableSemgrep(enabled);
    invalidateResult();
  };

  const handleEnableLlmChange = (enabled: boolean) => {
    setEnableLlm(enabled);
    invalidateResult();
  };

  const handleScan = async () => {
    // 用 ref 而不是组件状态做第一道去重，避免极短时间内重复点击。
    if (abortRef.current) {
      return;
    }
    if (!canScan) {
      message.warning('请先输入代码或选择文件。');
      return;
    }

    const file = inputMode === 'upload' ? fileList[0]?.originFileObj : undefined;
    if (inputMode === 'upload' && !file) {
      message.warning('无法读取所选文件，请重新选择。');
      return;
    }

    const controller = new AbortController();
    abortRef.current = controller;
    setScanState({ status: 'loading' });

    const requested: RequestedAnalyzers = { llm: enableLlm, semgrep: enableSemgrep };
    const analysisOptions = { enable_llm: requested.llm, enable_semgrep: requested.semgrep };
    // 记录本次真正提交的内容，避免修复建议误用用户之后修改的文本。
    const submittedSource = sourceCode;
    const mode = inputMode;

    try {
      let response: ScanResponse;
      if (mode === 'upload' && file) {
        response = await scanUpload(file, {
          analysisOptions,
          language,
          signal: controller.signal,
        });
      } else {
        response = await scanCode(
          {
            source_code: submittedSource,
            language: language ?? null,
            analysis_options: analysisOptions,
          },
          { signal: controller.signal },
        );
      }

      if (!mountedRef.current || abortRef.current !== controller) {
        return;
      }

      const repair = await buildRepairContext(response, mode, submittedSource, file);
      if (!mountedRef.current || abortRef.current !== controller) {
        return;
      }

      setScanState({
        status: 'success',
        result: response,
        requested,
        repairContext: repair.context,
        repairUnavailableReason: repair.reason,
      });
    } catch (requestError) {
      if (!mountedRef.current || abortRef.current !== controller) {
        return;
      }
      if (requestError instanceof ApiError && requestError.kind === 'aborted') {
        return;
      }
      setScanState({ status: 'error', error: toScanErrorInfo(requestError) });
    } finally {
      if (abortRef.current === controller) {
        abortRef.current = null;
      }
    }
  };

  const handleCancel = () => {
    if (!abortRef.current) {
      return;
    }
    abortRef.current.abort();
    abortRef.current = null;
    setScanState({ status: 'idle' });
    message.info('已取消本次扫描。');
  };

  const handleClear = () => {
    abortRef.current?.abort();
    abortRef.current = null;
    setInputMode('paste');
    setSourceCode('');
    setFileList([]);
    setLanguage(undefined);
    setEnableSemgrep(false);
    setEnableLlm(false);
    setScanState({ status: 'idle' });
  };

  return (
    <Row gutter={[20, 20]} className="scan-page">
      <Col xs={24} xl={10}>
        <CodeInputPanel
          inputMode={inputMode}
          onInputModeChange={handleInputModeChange}
          sourceCode={sourceCode}
          onSourceCodeChange={handleSourceCodeChange}
          language={language}
          onLanguageChange={handleLanguageChange}
          fileList={fileList}
          onFileListChange={handleFileListChange}
          enableSemgrep={enableSemgrep}
          onEnableSemgrepChange={handleEnableSemgrepChange}
          enableLlm={enableLlm}
          onEnableLlmChange={handleEnableLlmChange}
          canScan={canScan}
          scanning={scanning}
          onScan={() => {
            void handleScan();
          }}
          onCancel={handleCancel}
          onClear={handleClear}
        />
      </Col>
      <Col xs={24} xl={14}>
        <ResultsPanel
          result={result}
          loading={scanning}
          error={error}
          requestedAnalyzers={requestedAnalyzers}
          repairContext={repairContext}
          repairUnavailableReason={repairUnavailableReason}
          onRetry={() => {
            void handleScan();
          }}
        />
      </Col>
    </Row>
  );
}
