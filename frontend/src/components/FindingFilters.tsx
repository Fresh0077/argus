import { FilterOutlined, InfoCircleOutlined } from '@ant-design/icons';
import { Button, Popover, Select, Tag, Tooltip, Typography } from 'antd';
import { hasActiveFilters } from '../utils/findings';
import type { FindingFilterState } from '../types/ui';

export interface FilterOption {
  value: string;
  label: string;
}

interface FilterFieldProps {
  label: string;
  ariaLabel: string;
  options: FilterOption[];
  value: string[];
  onChange: (values: string[]) => void;
}

function FilterField({ label, ariaLabel, options, value, onChange }: FilterFieldProps) {
  return (
    <div className="finding-filters__field">
      <Typography.Text strong>{label}</Typography.Text>
      <Select
        mode="multiple"
        allowClear
        showSearch
        optionFilterProp="label"
        maxTagCount="responsive"
        aria-label={ariaLabel}
        placeholder="全部"
        options={options}
        value={value}
        onChange={(values) => onChange(values ?? [])}
      />
    </div>
  );
}

interface FindingFiltersProps {
  value: FindingFilterState;
  onChange: (next: FindingFilterState) => void;
  onReset: () => void;
  severityOptions: FilterOption[];
  typeOptions: FilterOption[];
  shown: number;
  total: number;
}

/** 发现列表筛选栏。筛选条件收进 Popover，避免占用过多纵向空间。 */
export default function FindingFilters({
  value,
  onChange,
  onReset,
  severityOptions,
  typeOptions,
  shown,
  total,
}: FindingFiltersProps) {
  const severityLabels = new Map(
    severityOptions.map((option) => [option.value, option.label]),
  );
  const typeLabels = new Map(typeOptions.map((option) => [option.value, option.label]));

  const activeTags = [
    ...value.severities.map((severity) => ({
      key: `severity-${severity}`,
      label: severityLabels.get(severity) ?? severity,
      onClose: () =>
        onChange({
          ...value,
          severities: value.severities.filter((item) => item !== severity),
        }),
    })),
    ...value.types.map((type) => ({
      key: `type-${type}`,
      label: typeLabels.get(type) ?? type,
      onClose: () =>
        onChange({ ...value, types: value.types.filter((item) => item !== type) }),
    })),
  ];

  const activeCount = activeTags.length;

  const filterPanel = (
    <div className="finding-filters__popover">
      <FilterField
        label="严重程度"
        ariaLabel="按严重程度筛选"
        options={severityOptions}
        value={value.severities}
        onChange={(severities) => onChange({ ...value, severities })}
      />
      <FilterField
        label="漏洞类型"
        ariaLabel="按漏洞类型筛选"
        options={typeOptions}
        value={value.types}
        onChange={(types) => onChange({ ...value, types })}
      />
      <Button onClick={onReset} disabled={!hasActiveFilters(value)} block>
        清除筛选
      </Button>
    </div>
  );

  return (
    <section className="finding-filters" aria-label="候选发现筛选">
      <div className="finding-filters__bar">
        <Popover
          trigger="click"
          placement="bottomLeft"
          title="筛选候选发现"
          content={filterPanel}
        >
          <Button icon={<FilterOutlined />}>
            筛选{activeCount > 0 ? `（${activeCount}）` : ''}
          </Button>
        </Popover>

        <div className="finding-filters__tags">
          {activeTags.map((tag) => (
            <Tag
              key={tag.key}
              closable
              onClose={(event) => {
                event.preventDefault();
                tag.onClose();
              }}
            >
              {tag.label}
            </Tag>
          ))}
        </div>

        <div className="finding-filters__meta">
          <Typography.Text type="secondary" aria-live="polite">
            显示 {shown} / 共 {total} 条
          </Typography.Text>
          <Tooltip title="默认排序：严重程度从高到低；同等级按行号升序，未能定位行号的排在最后。">
            <Typography.Text type="secondary" className="finding-filters__sort-hint">
              <InfoCircleOutlined /> 排序说明
            </Typography.Text>
          </Tooltip>
        </div>
      </div>
    </section>
  );
}
