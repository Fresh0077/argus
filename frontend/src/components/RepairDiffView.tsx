import { Typography } from 'antd';

type DiffLineKind = 'file' | 'hunk' | 'added' | 'removed' | 'context';

interface DiffLine {
  kind: DiffLineKind;
  oldNumber: number | null;
  newNumber: number | null;
  text: string;
}

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
 * 把 unified diff 拆成带旧/新行号的展示行。
 *
 * 行号来自 hunk 头；新增行只有新行号，删除行只有旧行号，
 * 这样不会把 diff 的物理行号误当成源码行号。
 */
function withLineNumbers(diff: string): DiffLine[] {
  let oldNumber = 0;
  let newNumber = 0;

  return diff.split('\n').map((line) => {
    const kind = classify(line);

    if (kind === 'hunk') {
      const match = line.match(/^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
      if (match) {
        oldNumber = Number(match[1]);
        newNumber = Number(match[2]);
      }
      return { kind, oldNumber: null, newNumber: null, text: line };
    }

    if (kind === 'file' || line.startsWith('\\ No newline')) {
      return { kind, oldNumber: null, newNumber: null, text: line };
    }

    if (kind === 'added') {
      const current = newNumber;
      newNumber += 1;
      return { kind, oldNumber: null, newNumber: current, text: line };
    }

    if (kind === 'removed') {
      const current = oldNumber;
      oldNumber += 1;
      return { kind, oldNumber: current, newNumber: null, text: line };
    }

    const currentOld = oldNumber;
    const currentNew = newNumber;
    oldNumber += 1;
    newNumber += 1;
    return { kind, oldNumber: currentOld, newNumber: currentNew, text: line };
  });
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
      {withLineNumbers(diff).map((line, index) => (
        <div
          key={`${index}-${line.kind}`}
          className={`repair-diff__line repair-diff__line--${line.kind}`}
        >
          <span className="repair-diff__lineno" aria-hidden="true">
            {line.oldNumber ?? ''}
          </span>
          <span className="repair-diff__lineno" aria-hidden="true">
            {line.newNumber ?? ''}
          </span>
          <span className="repair-diff__code">{line.text || ' '}</span>
        </div>
      ))}
    </pre>
  );
}
