import { RightOutlined } from '@ant-design/icons';
import { List, Tag, Typography } from 'antd';
import {
  severityMeta,
  sourceMeta,
  vulnerabilityTypeLabel,
} from '../constants/labels';
import type { Finding } from '../types/scan';
import { formatLineRange } from '../utils/format';

interface FindingListProps {
  findings: Finding[];
  selectedId: string | null;
  onSelect: (id: string) => void;
}

/** 候选发现列表。点击一项在右侧查看详情。 */
export default function FindingList({ findings, selectedId, onSelect }: FindingListProps) {
  return (
    <List
      className="finding-list"
      dataSource={findings}
      rowKey="id"
      bordered
      renderItem={(finding) => {
        const severity = severityMeta(finding.severity);
        const source = sourceMeta(finding.source);
        const isSelected = finding.id === selectedId;

        return (
          <List.Item
            className={isSelected ? 'finding-item finding-item--active' : 'finding-item'}
            role="button"
            tabIndex={0}
            aria-pressed={isSelected}
            aria-label={`${severity.label}，${finding.title}，来源 ${source.label}，${formatLineRange(finding.line_start, finding.line_end)}`}
            onClick={() => onSelect(finding.id)}
            onKeyDown={(event) => {
              if (event.key === 'Enter' || event.key === ' ') {
                event.preventDefault();
                onSelect(finding.id);
              }
            }}
          >
            <div className="finding-item__main">
              <div className="finding-item__title-row">
                <Tag color={severity.color}>{severity.label}</Tag>
                <Typography.Text strong>{finding.title}</Typography.Text>
              </div>
              <div className="finding-item__meta">
                <span>{source.label}</span>
                <span aria-hidden="true">·</span>
                <span>{formatLineRange(finding.line_start, finding.line_end)}</span>
                <span aria-hidden="true">·</span>
                <span>{vulnerabilityTypeLabel(finding.vulnerability_type)}</span>
              </div>
            </div>
            <RightOutlined className="finding-item__arrow" />
          </List.Item>
        );
      }}
    />
  );
}
