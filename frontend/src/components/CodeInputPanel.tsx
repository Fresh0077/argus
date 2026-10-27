import { ClearOutlined, InboxOutlined, ScanOutlined } from '@ant-design/icons';
import { Alert, Button, Card, Input, Select, Space, Switch, Typography, Upload } from 'antd';
import type { UploadFile, UploadProps } from 'antd';

const { TextArea } = Input;
const { Dragger } = Upload;

const LANGUAGE_OPTIONS = [
  { value: 'python', label: 'Python' },
  { value: 'javascript', label: 'JavaScript' },
  { value: 'typescript', label: 'TypeScript' },
  { value: 'java', label: 'Java' },
  { value: 'php', label: 'PHP' },
  { value: 'go', label: 'Go' },
  { value: 'ruby', label: 'Ruby' },
  { value: 'html', label: 'HTML' },
  { value: 'vue', label: 'Vue' },
];

/** 与后端默认白名单一致的展示提示；真正的校验仍由后端完成。 */
const ACCEPTED_EXTENSIONS = '.py,.js,.jsx,.ts,.tsx,.php,.java,.go,.rb,.html,.vue';

interface CodeInputPanelProps {
  sourceCode: string;
  onSourceCodeChange: (value: string) => void;
  language: string | undefined;
  onLanguageChange: (value: string | undefined) => void;
  fileList: UploadFile[];
  onFileListChange: (files: UploadFile[]) => void;
  enableSemgrep: boolean;
  onEnableSemgrepChange: (enabled: boolean) => void;
  enableLlm: boolean;
  onEnableLlmChange: (enabled: boolean) => void;
  canScan: boolean;
  scanning: boolean;
  onScan: () => void;
  onClear: () => void;
}

/**
 * 代码输入区：粘贴文本、选择语言、选择文件与可选分析开关。
 *
 * 本阶段只管理界面状态，不发送请求；扫描行为在联调阶段接入。
 */
export default function CodeInputPanel({
  sourceCode,
  onSourceCodeChange,
  language,
  onLanguageChange,
  fileList,
  onFileListChange,
  enableSemgrep,
  onEnableSemgrepChange,
  enableLlm,
  onEnableLlmChange,
  canScan,
  scanning,
  onScan,
  onClear,
}: CodeInputPanelProps) {
  const beforeUpload: UploadProps['beforeUpload'] = () => false;

  const handleUploadChange: UploadProps['onChange'] = ({ fileList: nextFileList }) => {
    onFileListChange(nextFileList.slice(-1));
  };

  return (
    <Card
      className="panel-card"
      title="输入待分析代码"
      extra={
        <Typography.Text type="secondary" className="panel-card__extra">
          支持粘贴或上传单个文件
        </Typography.Text>
      }
    >
      <Space direction="vertical" size="middle" className="input-panel">
        <TextArea
          className="code-textarea"
          value={sourceCode}
          onChange={(event) => onSourceCodeChange(event.target.value)}
          placeholder="在此粘贴待分析的源代码，例如 Python、JavaScript、Java、PHP、Go 等。"
          autoSize={{ minRows: 12, maxRows: 26 }}
          spellCheck={false}
          aria-label="待分析源代码"
        />
        <div className="input-panel__meta">
          <Typography.Text type="secondary">
            当前 {sourceCode.length.toLocaleString('zh-CN')} 字符
          </Typography.Text>
          <Typography.Text type="secondary">单次提交上限由后端配置决定</Typography.Text>
        </div>

        <div className="input-panel__grid">
          <div className="input-panel__field">
            <Typography.Text strong>语言</Typography.Text>
            <Select
              className="input-panel__select"
              value={language}
              onChange={onLanguageChange}
              options={LANGUAGE_OPTIONS}
              placeholder="自动识别"
              allowClear
              aria-label="选择代码语言"
            />
          </div>

          <div className="input-panel__field">
            <Typography.Text strong>可选分析器</Typography.Text>
            <div className="input-panel__switch-row">
              <div>
                <Typography.Text>Semgrep</Typography.Text>
                <Typography.Text type="secondary" className="input-panel__hint">
                  需后端已安装
                </Typography.Text>
              </div>
              <Switch checked={enableSemgrep} onChange={onEnableSemgrepChange} aria-label="启用 Semgrep" />
            </div>
            <div className="input-panel__switch-row">
              <div>
                <Typography.Text>LLM 语义分析</Typography.Text>
                <Typography.Text type="secondary" className="input-panel__hint">
                  代码会发送到第三方
                </Typography.Text>
              </div>
              <Switch checked={enableLlm} onChange={onEnableLlmChange} aria-label="启用 LLM 分析" />
            </div>
          </div>
        </div>

        <Dragger
          accept={ACCEPTED_EXTENSIONS}
          maxCount={1}
          multiple={false}
          fileList={fileList}
          beforeUpload={beforeUpload}
          onChange={handleUploadChange}
          className="upload-dragger"
        >
          <p className="ant-upload-drag-icon">
            <InboxOutlined />
          </p>
          <p className="ant-upload-text">点击或拖拽文件到此处</p>
          <p className="ant-upload-hint">
            依据扩展名判断类型，文件只在内存中处理，不落盘、不执行。
          </p>
        </Dragger>

        <Alert
          type="warning"
          showIcon
          message="启用 LLM 分析会把代码发送给第三方服务商"
          description="请勿提交包含密钥、个人信息或其他敏感内容的代码。不开启该选项时，代码只在本机完成规则与特征分析。"
        />

        <Space wrap>
          <Button
            type="primary"
            size="large"
            icon={<ScanOutlined />}
            onClick={onScan}
            disabled={!canScan || scanning}
            loading={scanning}
          >
            开始扫描
          </Button>
          <Button size="large" icon={<ClearOutlined />} onClick={onClear}>
            清空
          </Button>
        </Space>
      </Space>
    </Card>
  );
}
