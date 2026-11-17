import { Descriptions, Empty, Space, Tag, Typography } from 'antd';
import { languageLabel } from '../constants/labels';
import type { FeatureExtractionResult, LanguageSource } from '../types/scan';

const LANGUAGE_SOURCE_LABELS: Record<LanguageSource, string> = {
  explicit: '调用方指定',
  extension: '文件扩展名',
  heuristic: '内容特征',
  none: '未识别',
};

/**
 * 本地特征提取结果。
 *
 * 特征不判定安全性，但它是未授权 LLM 时唯一的分析输出，
 * 也是 LLM 分析时使用的上下文，因此单独展示而不是只显示一行摘要。
 */
export default function CodeFeaturesPanel({
  features,
}: {
  features: FeatureExtractionResult | null;
}) {
  if (!features) {
    return (
      <section className="code-features">
        <header className="code-features__header">
          <Typography.Title level={5}>代码特征</Typography.Title>
        </header>
        <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="未执行特征提取" />
      </section>
    );
  }

  const imports = features.structure.imports;
  const shownImports = imports.slice(0, 12);
  const hiddenImportCount = features.structure.import_count - shownImports.length;

  return (
    <section className="code-features">
      <header className="code-features__header">
        <Typography.Title level={5}>代码特征</Typography.Title>
        <Tag color="default">本地提取 · 不判定安全性</Tag>
      </header>
      <Space direction="vertical" size="middle" className="code-features__body">
        <Descriptions
          size="small"
          column={{ xs: 1, sm: 2, lg: 3 }}
          items={[
            {
              key: 'language',
              label: '识别语言',
              children: languageLabel(features.language),
            },
            {
              key: 'source',
              label: '判断依据',
              children: `${LANGUAGE_SOURCE_LABELS[features.language_source] ?? features.language_source}（${features.language_evidence}）`,
            },
            {
              key: 'lines',
              label: '代码行数',
              children: `${features.stats.total_lines} 行（非空 ${features.stats.non_blank_lines}）`,
            },
            {
              key: 'chars',
              label: '字符数',
              children: features.stats.total_chars.toLocaleString('zh-CN'),
            },
            {
              key: 'maxLine',
              label: '最长行',
              children: `${features.stats.max_line_length} 字符`,
            },
            {
              key: 'structure',
              label: '函数 / 类',
              children: `约 ${features.structure.function_count} / ${features.structure.class_count}`,
            },
          ]}
        />

        <div>
          <Typography.Text strong>导入模块</Typography.Text>
          <div className="code-features__imports">
            {shownImports.length > 0 ? (
              <Space wrap size={[6, 6]}>
                {shownImports.map((name) => (
                  <Tag key={name}>{name}</Tag>
                ))}
                {hiddenImportCount > 0 ? <Tag>另有 {hiddenImportCount} 项</Tag> : null}
              </Space>
            ) : (
              <Typography.Text type="secondary">未识别到导入</Typography.Text>
            )}
          </div>
        </div>

        {features.notes.length > 0 ? (
          <ul className="code-features__notes">
            {features.notes.map((note) => (
              <li key={note}>
                <Typography.Text type="secondary">{note}</Typography.Text>
              </li>
            ))}
          </ul>
        ) : null}
      </Space>
    </section>
  );
}
