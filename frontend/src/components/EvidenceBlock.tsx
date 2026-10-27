import { Button, Space, Typography } from 'antd';
import { useState } from 'react';
import { formatLineRange } from '../utils/format';

const PREVIEW_CHARS = 220;
const PREVIEW_LINES = 12;

/**
 * 代码证据块。
 *
 * 长证据默认限制高度并在内部滚动，避免把详情页无限拉长；
 * “展开”只改变可视高度，不截断或改写证据内容。
 */
export default function EvidenceBlock({
  evidence,
  lineStart,
  lineEnd,
}: {
  evidence: string;
  lineStart: number | null;
  lineEnd: number | null;
}) {
  const [expanded, setExpanded] = useState(false);
  const location = formatLineRange(lineStart, lineEnd);

  if (!evidence) {
    return (
      <section className="detail-section">
        <Space align="center" wrap>
          <Typography.Text strong>代码证据</Typography.Text>
          <Typography.Text type="secondary">{location}</Typography.Text>
        </Space>
        <Typography.Text type="secondary">（本次发现没有可展示的证据片段）</Typography.Text>
      </section>
    );
  }

  const lineCount = evidence.split(/\r?\n/).length;
  const collapsible = evidence.length > PREVIEW_CHARS || lineCount > PREVIEW_LINES;
  const blockClassName = collapsible
    ? expanded
      ? 'evidence-block evidence-block--expanded'
      : 'evidence-block evidence-block--collapsed'
    : 'evidence-block';

  return (
    <section className="detail-section">
      <Space align="center" wrap>
        <Typography.Text strong>代码证据</Typography.Text>
        <Typography.Text type="secondary">{location}</Typography.Text>
      </Space>
      <pre
        className={blockClassName}
        tabIndex={0}
        role="region"
        aria-label={`代码证据，${location}`}
      >
        {evidence}
      </pre>
      {collapsible ? (
        <div className="evidence-block__actions">
          <Button
            type="link"
            size="small"
            onClick={() => setExpanded((current) => !current)}
            aria-expanded={expanded}
          >
            {expanded
              ? '收起代码证据'
              : lineCount > 1
                ? `展开全部代码证据（共 ${lineCount} 行）`
                : '展开全部代码证据'}
          </Button>
          <Typography.Text type="secondary">证据较长，默认限制高度，可滚动查看。</Typography.Text>
        </div>
      ) : null}
    </section>
  );
}
