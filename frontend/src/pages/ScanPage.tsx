import { App as AntdApp, Col, Row } from 'antd';
import type { UploadFile } from 'antd';
import { useState } from 'react';
import CodeInputPanel from '../components/CodeInputPanel';
import ResultsPanel from '../components/ResultsPanel';
import type { ScanResponse } from '../types/scan';

/**
 * 主工作区。
 *
 * 本阶段只搭建页面骨架与输入状态，不调用后端：
 * 点击扫描会明确提示“联调阶段接入”，不会伪造任何扫描结果。
 */
export default function ScanPage() {
  const { message } = AntdApp.useApp();

  const [sourceCode, setSourceCode] = useState('');
  const [language, setLanguage] = useState<string | undefined>(undefined);
  const [fileList, setFileList] = useState<UploadFile[]>([]);
  const [enableSemgrep, setEnableSemgrep] = useState(false);
  const [enableLlm, setEnableLlm] = useState(false);

  // 联调阶段由真实请求结果替换；在此之前结果区保持空状态。
  const result: ScanResponse | null = null;
  const loading = false;
  const error: string | null = null;

  const canScan = sourceCode.trim().length > 0 || fileList.length > 0;

  const handleScan = () => {
    message.info('扫描接口将在前后端联调阶段接入，当前版本不会发送请求。');
  };

  const handleClear = () => {
    setSourceCode('');
    setFileList([]);
    setLanguage(undefined);
  };

  return (
    <Row gutter={[20, 20]} className="scan-page">
      <Col xs={24} xl={10}>
        <CodeInputPanel
          sourceCode={sourceCode}
          onSourceCodeChange={setSourceCode}
          language={language}
          onLanguageChange={setLanguage}
          fileList={fileList}
          onFileListChange={setFileList}
          enableSemgrep={enableSemgrep}
          onEnableSemgrepChange={setEnableSemgrep}
          enableLlm={enableLlm}
          onEnableLlmChange={setEnableLlm}
          canScan={canScan}
          scanning={loading}
          onScan={handleScan}
          onClear={handleClear}
        />
      </Col>
      <Col xs={24} xl={14}>
        <ResultsPanel result={result} loading={loading} error={error} />
      </Col>
    </Row>
  );
}
