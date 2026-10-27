import { App as AntdApp, Col, Row } from 'antd';
import type { UploadFile } from 'antd';
import { useEffect, useRef, useState } from 'react';
import CodeInputPanel from '../components/CodeInputPanel';
import ResultsPanel from '../components/ResultsPanel';
import { ApiError, scanCode, scanUpload } from '../services/apiClient';
import { toScanErrorInfo } from '../services/scanErrors';
import type { ScanResponse } from '../types/scan';
import type { InputMode, RequestedAnalyzers, ScanErrorInfo } from '../types/ui';

type ScanState =
  | { status: 'idle' }
  | { status: 'loading' }
  | { status: 'success'; result: ScanResponse; requested: RequestedAnalyzers }
  | { status: 'error'; error: ScanErrorInfo };

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

    try {
      let response: ScanResponse;
      if (inputMode === 'upload' && file) {
        response = await scanUpload(file, {
          analysisOptions,
          language,
          signal: controller.signal,
        });
      } else {
        response = await scanCode(
          {
            source_code: sourceCode,
            language: language ?? null,
            analysis_options: analysisOptions,
          },
          { signal: controller.signal },
        );
      }

      if (!mountedRef.current || abortRef.current !== controller) {
        return;
      }
      setScanState({ status: 'success', result: response, requested });
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
          onRetry={() => {
            void handleScan();
          }}
        />
      </Col>
    </Row>
  );
}
