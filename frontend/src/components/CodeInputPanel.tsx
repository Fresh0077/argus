import {
  ClearOutlined,
  InboxOutlined,
  SafetyCertificateOutlined,
  ScanOutlined,
  StopOutlined,
} from '@ant-design/icons';
import {
  Alert,
  Button,
  Card,
  Input,
  Select,
  Space,
  Switch,
  Tabs,
  Typography,
  Upload,
} from 'antd';
import type { UploadFile, UploadProps } from 'antd';
import type { InputMode } from '../types/ui';

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

/**
 * 仅用于文件选择器的展示过滤；真正的类型、大小与编码校验都在后端完成，
 * 因此这里不重复维护一份“权威”上限。
 */
const ACCEPTED_EXTENSIONS = '.py,.js,.jsx,.ts,.tsx,.php,.java,.go,.rb,.html,.vue';

interface CodeInputPanelProps {
  inputMode: InputMode;
  onInputModeChange: (mode: InputMode) => void;
  sourceCode: string;
  onSourceCodeChange: (value: string) => void;
  language: string | undefined;
  onLanguageChange: (value: string | undefined) => void;
  fileList: UploadFile[];
  onFileListChange: (files: UploadFile[]) => void;
  enableLlm: boolean;
  onEnableLlmChange: (enabled: boolean) => void;
  canScan: boolean;
  scanning: boolean;
  onScan: () => void;
  onCancel: () => void;
  onClear: () => void;
}

/** 代码输入区：粘贴文本或上传文件，并提供语言与可选分析配置。 */
export default function CodeInputPanel({
  inputMode,
  onInputModeChange,
  sourceCode,
  onSourceCodeChange,
  language,
  onLanguageChange,
  fileList,
  onFileListChange,
  enableLlm,
  onEnableLlmChange,
  canScan,
  scanning,
  onScan,
  onCancel,
  onClear,
}: CodeInputPanelProps) {
  const beforeUpload: UploadProps['beforeUpload'] = () => false;

  const handleUploadChange: UploadProps['onChange'] = ({ fileList: nextFileList }) => {
    onFileListChange(nextFileList.slice(-1));
  };

  const handleTabChange = (activeKey: string) => {
    if (activeKey === 'paste' || activeKey === 'upload') {
      onInputModeChange(activeKey);
    }
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
        <Tabs
          className="input-panel__tabs"
          activeKey={inputMode}
          onChange={handleTabChange}
          items={[
            {
              key: 'paste',
              label: '粘贴代码',
              disabled: scanning,
              children: (
                <Space direction="vertical" size="small" className="input-panel__tab-body">
                  <TextArea
                    className="code-textarea"
                    value={sourceCode}
                    onChange={(event) => onSourceCodeChange(event.target.value)}
                    placeholder="在此粘贴待分析的源代码，例如 Python、JavaScript、Java、PHP、Go 等。"
                    autoSize={{ minRows: 12, maxRows: 26 }}
                    spellCheck={false}
                    disabled={scanning}
                    aria-label="待分析源代码"
                  />
                  <div className="input-panel__meta">
                    <Typography.Text type="secondary">
                      当前 {sourceCode.length.toLocaleString('zh-CN')} 字符
                    </Typography.Text>
                    <Typography.Text type="secondary">单次提交上限由后端配置决定</Typography.Text>
                  </div>
                </Space>
              ),
            },
            {
              key: 'upload',
              label: '上传文件',
              disabled: scanning,
              children: (
                <Space direction="vertical" size="small" className="input-panel__tab-body">
                  <Dragger
                    accept={ACCEPTED_EXTENSIONS}
                    maxCount={1}
                    multiple={false}
                    fileList={fileList}
                    beforeUpload={beforeUpload}
                    onChange={handleUploadChange}
                    disabled={scanning}
                    className="upload-dragger"
                  >
                    <p className="ant-upload-drag-icon">
                      <InboxOutlined />
                    </p>
                    <p className="ant-upload-text">点击或拖拽文件到此处</p>
                  </Dragger>
                  <Typography.Text type="secondary" className="input-panel__hint">
                    支持的文件类型、大小与编码由后端校验；上传后会自动识别语言。
                  </Typography.Text>
                </Space>
              ),
            },
          ]}
        />

        <div className="input-panel__field input-panel__language">
          <Typography.Text strong>语言</Typography.Text>
          <Select
            className="input-panel__select"
            value={language}
            onChange={onLanguageChange}
            options={LANGUAGE_OPTIONS}
            placeholder="自动识别"
            allowClear
            disabled={scanning}
            aria-label="选择代码语言"
          />
          <Typography.Text type="secondary" className="input-panel__hint">
            {inputMode === 'upload' ? '留空时按文件扩展名推断' : '留空时由后端自动识别'}
          </Typography.Text>
        </div>

        <div
          className={
            enableLlm
              ? 'input-panel__auth-callout input-panel__auth-callout--on'
              : 'input-panel__auth-callout'
          }
        >
          <span className="input-panel__auth-icon" aria-hidden="true">
            <SafetyCertificateOutlined />
          </span>
          <div className="input-panel__auth-copy">
            <Typography.Text strong>使用 LLM 分析</Typography.Text>
            <Typography.Text type="secondary" className="input-panel__hint">
              代码将发送给第三方
            </Typography.Text>
          </div>
          <Switch
            checked={enableLlm}
            onChange={onEnableLlmChange}
            disabled={scanning}
            aria-label="使用 LLM 分析，代码将发送给第三方"
          />
        </div>

        {enableLlm ? (
          <Alert
            type="warning"
            showIcon
            message="代码将发送给第三方 LLM 服务商"
            description="请勿提交包含密钥、个人信息或其他敏感内容的代码。不开启该选项时，代码只在本机完成特征提取。"
          />
        ) : null}

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
          {scanning ? (
            <Button size="large" icon={<StopOutlined />} onClick={onCancel}>
              取消
            </Button>
          ) : null}
          <Button size="large" icon={<ClearOutlined />} onClick={onClear} disabled={scanning}>
            清空
          </Button>
        </Space>
        {!canScan && !scanning ? (
          <Typography.Text type="secondary" className="input-panel__hint">
            请输入代码或选择文件后再开始扫描。
          </Typography.Text>
        ) : null}
      </Space>
    </Card>
  );
}
