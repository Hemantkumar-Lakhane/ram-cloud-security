import React, { useState } from 'react';
import type { EDASummary } from '../../types';

interface InteractiveServiceDistributionProps {
  eda?: EDASummary | null;
  height?: number;
}

interface ItemData {
  name: string;
  fullName: string;
  count: number;
  pct: number;
}

export const InteractiveServiceDistribution: React.FC<InteractiveServiceDistributionProps> = ({
  eda,
  height = 240,
}) => {
  const [metricMode, setMetricMode] = useState<'services' | 'apis'>('services');
  const [hoveredItem, setHoveredItem] = useState<ItemData | null>(null);

  const total = eda?.total_records || 2900;

  const data: ItemData[] = metricMode === 'services'
    ? Object.entries(eda?.top_services || {
        'ec2.amazonaws.com': 892,
        'ssm.amazonaws.com': 488,
        'iam.amazonaws.com': 398,
        's3.amazonaws.com': 271,
        'kms.amazonaws.com': 240,
        'secretsmanager.amazonaws.com': 233,
        'rds.amazonaws.com': 150,
        'sts.amazonaws.com': 64,
      }).slice(0, 8).map(([name, count]) => ({
        name: name.replace('.amazonaws.com', ''),
        fullName: name,
        count,
        pct: (count / total) * 100,
      }))
    : Object.entries(eda?.top_apis || {
        'Decrypt': 178,
        'DescribeRouteTables': 163,
        'GetUser': 130,
        'DescribeParameters': 122,
        'ListTagsForResource': 88,
        'GetParameter': 82,
        'DeleteParameter': 78,
        'PutParameter': 67,
      }).slice(0, 8).map(([name, count]) => ({
        name,
        fullName: name,
        count,
        pct: (count / total) * 100,
      }));

  const maxCount = Math.max(...data.map(d => d.count), 1);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', width: '100%' }}>
      {/* Mode Selector */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ display: 'flex', gap: '6px' }}>
          <button
            className={`btn btn-sm ${metricMode === 'services' ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setMetricMode('services')}
            style={{ fontSize: '11px', height: '24px' }}
          >
            Top AWS Services
          </button>
          <button
            className={`btn btn-sm ${metricMode === 'apis' ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setMetricMode('apis')}
            style={{ fontSize: '11px', height: '24px' }}
          >
            Top API Operations
          </button>
        </div>
        <span style={{ fontSize: '11px', color: '#64748b' }}>
          {metricMode === 'services' ? '29 Total Services' : '260 Distinct API Names'}
        </span>
      </div>

      {/* Horizontal Bar Chart */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', minHeight: `${height}px`, justifyContent: 'space-between' }}>
        {data.map((item) => {
          const isHovered = hoveredItem?.name === item.name;
          const barPct = (item.count / maxCount) * 100;

          return (
            <div
              key={item.name}
              onMouseEnter={() => setHoveredItem(item)}
              onMouseLeave={() => setHoveredItem(null)}
              style={{
                display: 'grid',
                gridTemplateColumns: '120px 1fr 65px',
                alignItems: 'center',
                gap: '8px',
                cursor: 'pointer',
              }}
            >
              {/* Label */}
              <span style={{ fontSize: '11px', fontWeight: 600, color: '#0f172a', whiteSpace: 'nowrap', textOverflow: 'ellipsis', overflow: 'hidden' }}>
                <code>{item.name}</code>
              </span>

              {/* Bar track & fill */}
              <div style={{ height: '18px', background: '#f1f5f9', borderRadius: '3px', overflow: 'hidden', position: 'relative' }}>
                <div
                  style={{
                    height: '100%',
                    width: `${barPct}%`,
                    background: isHovered ? '#1d4ed8' : '#3b82f6',
                    borderRadius: '3px',
                    transition: 'all 0.2s ease',
                  }}
                />
              </div>

              {/* Metric count */}
              <span style={{ fontSize: '11px', fontWeight: 600, color: '#475569', textAlign: 'right' }}>
                {item.count} <span style={{ fontSize: '10px', color: '#94a3b8' }}>({item.pct.toFixed(1)}%)</span>
              </span>
            </div>
          );
        })}
      </div>

      {/* Hover Status */}
      {hoveredItem && (
        <div style={{ background: '#f8fafc', padding: '6px 10px', borderRadius: '4px', border: '1px solid #e2e8f0', fontSize: '11px', color: '#334155' }}>
          <strong>{hoveredItem.fullName}:</strong> {hoveredItem.count} observed events across capture window ({hoveredItem.pct.toFixed(2)}% of total telemetry volume).
        </div>
      )}
    </div>
  );
};
