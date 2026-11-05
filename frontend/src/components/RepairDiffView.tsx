import { Typography } from 'antd';

type DiffLineKind = 'file' | 'hunk' | 'added' | 'removed' | 'context';

function classify(line: string): DiffLineKind {
  if (line.startsWith('--- ') || line.startsWith('+++ ')) {
    return 'file';
  }
  if (line.startsWith('@@')) {
    return 'hunk';
  }
  if (line.startsWith('+')) {
    return 'added';
  }
  if (line.startsWith('-')) {
    return 'removed';
  }
  return 'context';
}

/**
 * 渲染后端计算的 unified diff。
 *
 * 只做展示与着色，不解析、不执行补丁；内容全部由 React 转义。
 */
export default function RepairDiffView({ diff }: { diff: string }) {
  if (!diff.trim()) {
    return (
      <Typography.Text type="secondary">
        模型没有返回与原始代码不同的内容，请谨慎对待。
      </Typography.Text>
    );
  }

  return (
    <pre className="repair-diff" aria-label="修复差异">
      {diff.split('\n').map((line, index) => {
        const kind = classify(line);
        return (
          <div key={`${index}-${kind}`} className={`repair-diff__line repair-diff__line--${kind}`}>
            {line || ' '}
          </div>
        );
      })}
    </pre>
  );
}
