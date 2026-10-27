import { Button, Select, Typography } from 'antd';
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
  sourceOptions: FilterOption[];
  shown: number;
  total: number;
}

/** 发现列表筛选栏。筛选与排序都在本地基于当前响应完成。 */
export default function FindingFilters({
  value,
  onChange,
  onReset,
  severityOptions,
  typeOptions,
  sourceOptions,
  shown,
  total,
}: FindingFiltersProps) {
  return (
    <section className="finding-filters" aria-label="候选发现筛选">
      <div className="finding-filters__fields">
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
        <FilterField
          label="分析来源"
          ariaLabel="按分析来源筛选"
          options={sourceOptions}
          value={value.sources}
          onChange={(sources) => onChange({ ...value, sources })}
        />
        <Button
          className="finding-filters__reset"
          onClick={onReset}
          disabled={!hasActiveFilters(value)}
        >
          重置筛选
        </Button>
      </div>

      <div className="finding-filters__meta">
        <Typography.Text type="secondary" aria-live="polite">
          显示 {shown} / 共 {total} 条
        </Typography.Text>
        <Typography.Text type="secondary">
          默认排序：严重程度从高到低；同等级按行号升序，未能定位行号的排在最后。
        </Typography.Text>
      </div>
    </section>
  );
}
