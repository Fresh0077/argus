import { Col, Row } from 'antd';
import { SEVERITY_ORDER, severityMeta } from '../constants/labels';
import type { SeverityCounts } from '../types/scan';

/**
 * 按严重程度统计的发现数量。
 *
 * 每个统计块同时显示中文等级文字与数字，颜色只是辅助，不是唯一标识。
 */
export default function SeverityStats({ counts }: { counts: SeverityCounts }) {
  const total = counts.critical + counts.high + counts.medium + counts.low + counts.info;

  // 零发现时整排 0 没有信息量，直接不占位；空状态由结果区单独说明。
  if (total === 0) {
    return null;
  }

  return (
    <Row
      gutter={[12, 12]}
      className="severity-stats"
      role="group"
      aria-label="按严重程度统计的候选发现数量"
    >
      {SEVERITY_ORDER.map((severity) => {
        const meta = severityMeta(severity);
        return (
          <Col xs={12} sm={8} lg={4} key={severity}>
            <div className="severity-tile" style={{ borderTopColor: meta.color }}>
              <span className="severity-tile__label">{meta.label}</span>
              <span className="severity-tile__value" style={{ color: meta.color }}>
                {counts[severity]}
              </span>
            </div>
          </Col>
        );
      })}
      <Col xs={12} sm={8} lg={4}>
        <div className="severity-tile severity-tile--total">
          <span className="severity-tile__label">合计</span>
          <span className="severity-tile__value">{total}</span>
        </div>
      </Col>
    </Row>
  );
}
