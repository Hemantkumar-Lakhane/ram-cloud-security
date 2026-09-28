import React, { useState } from 'react';
import type { EDASummary } from '../../types';

interface InteractiveTierDonutProps {
  eda?: EDASummary | null;
  size?: number;
  onSelectTier?: (tierKey: string) => void;
}

interface TierSlice {
  key: string;
  name: string;
  count: number;
  pct: number;
  color: string;
  description: string;
}

export const InteractiveTierDonut: React.FC<InteractiveTierDonutProps> = ({
  eda,
  size = 230,
  onSelectTier,
}) => {
  const [hoveredSlice, setHoveredSlice] = useState<TierSlice | null>(null);

  const total = eda?.total_records || 2900;
  const tiers: TierSlice[] = [
    {
      key: 'pure_detonation',
      name: 'Pure Detonation',
      count: eda?.four_tier_breakdown.pure_detonation.count || 214,
      pct: eda?.four_tier_breakdown.pure_detonation.pct || 7.38,
      color: '#dc2626',
      description: 'Adversarial API calls executed directly by Stratus Red Team attack techniques (Tier 1)',
    },
    {
      key: 'stratus_warmup_cleanup',
      name: 'Warmup & Cleanup',
      count: eda?.four_tier_breakdown.stratus_warmup_cleanup.count || 932,
      pct: eda?.four_tier_breakdown.stratus_warmup_cleanup.pct || 32.14,
      color: '#ea580c',
      description: 'Stratus Go runner provisioning/teardown of target cloud prerequisites (Tier 2)',
    },
    {
      key: 'operator_terraform',
      name: 'Operator Terraform',
      count: eda?.four_tier_breakdown.operator_terraform.count || 1006,
      pct: eda?.four_tier_breakdown.operator_terraform.pct || 34.69,
      color: '#2563eb',
      description: 'Admin/Terraform infrastructure management and environment initialization (Tier 3)',
    },
    {
      key: 'aws_background_internal',
      name: 'AWS Background',
      count: eda?.four_tier_breakdown.aws_background_internal.count || 748,
      pct: eda?.four_tier_breakdown.aws_background_internal.pct || 25.79,
      color: '#94a3b8',
      description: 'Internal AWS service-to-service calls & automated control-plane telemetry (Tier 4)',
    },
  ];

  // SVG calculations for donut chart
  const radius = 68;
  const strokeWidth = 26;
  const center = size / 2;
  const circumference = 2 * Math.PI * radius;

  let accumulatedPercent = 0;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', width: '100%' }}>
      <div style={{ position: 'relative', width: `${size}px`, height: `${size}px` }}>
        <svg viewBox={`0 0 ${size} ${size}`} style={{ width: '100%', height: '100%', transform: 'rotate(-90deg)' }}>
          {tiers.map((slice) => {
            const strokeDasharray = `${(slice.pct / 100) * circumference} ${circumference}`;
            const strokeDashoffset = -((accumulatedPercent / 100) * circumference);
            accumulatedPercent += slice.pct;

            const isHovered = hoveredSlice?.key === slice.key;

            return (
              <circle
                key={slice.key}
                cx={center}
                cy={center}
                r={radius}
                fill="transparent"
                stroke={slice.color}
                strokeWidth={isHovered ? strokeWidth + 4 : strokeWidth}
                strokeDasharray={strokeDasharray}
                strokeDashoffset={strokeDashoffset}
                style={{
                  cursor: 'pointer',
                  transition: 'stroke-width 0.2s ease, opacity 0.2s ease',
                  opacity: hoveredSlice && !isHovered ? 0.45 : 1,
                }}
                onMouseEnter={() => setHoveredSlice(slice)}
                onMouseLeave={() => setHoveredSlice(null)}
                onClick={() => onSelectTier?.(slice.key)}
              />
            );
          })}
        </svg>

        {/* Dynamic Center Metric Readout */}
        <div
          style={{
            position: 'absolute',
            top: 0,
            left: 0,
            width: '100%',
            height: '100%',
            display: 'flex',
            flexDirection: 'column',
            justifyContent: 'center',
            alignItems: 'center',
            pointerEvents: 'none',
            textAlign: 'center',
            padding: '10px',
          }}
        >
          {hoveredSlice ? (
            <>
              <span style={{ fontSize: '11px', fontWeight: 600, color: hoveredSlice.color, textTransform: 'uppercase' }}>
                {hoveredSlice.name}
              </span>
              <span style={{ fontSize: '18px', fontWeight: 800, color: '#0f172a' }}>
                {hoveredSlice.pct.toFixed(1)}%
              </span>
              <span style={{ fontSize: '11px', color: '#64748b' }}>
                {hoveredSlice.count.toLocaleString()} calls
              </span>
            </>
          ) : (
            <>
              <span style={{ fontSize: '10px', fontWeight: 600, color: '#64748b', textTransform: 'uppercase' }}>
                Total Capture
              </span>
              <span style={{ fontSize: '18px', fontWeight: 800, color: '#0f172a' }}>
                {total.toLocaleString()}
              </span>
              <span style={{ fontSize: '10px', color: '#94a3b8' }}>
                4 Audited Tiers
              </span>
            </>
          )}
        </div>
      </div>

      {/* Interactive Legend Bar */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '8px', width: '100%', marginTop: '12px' }}>
        {tiers.map((slice) => {
          const isHovered = hoveredSlice?.key === slice.key;
          return (
            <div
              key={slice.key}
              onMouseEnter={() => setHoveredSlice(slice)}
              onMouseLeave={() => setHoveredSlice(null)}
              onClick={() => onSelectTier?.(slice.key)}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                padding: '6px 8px',
                borderRadius: '4px',
                background: isHovered ? '#f1f5f9' : '#f8fafc',
                border: `1px solid ${isHovered ? slice.color : '#e2e8f0'}`,
                cursor: 'pointer',
                transition: 'all 0.15s ease',
              }}
            >
              <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: slice.color, flexShrink: 0 }} />
              <div style={{ display: 'flex', flexDirection: 'column', overflow: 'hidden', flex: 1 }}>
                <span style={{ fontSize: '11px', fontWeight: 600, color: '#0f172a', whiteSpace: 'nowrap', textOverflow: 'ellipsis', overflow: 'hidden' }}>
                  {slice.name}
                </span>
                <span style={{ fontSize: '10px', color: '#64748b' }}>
                  {slice.count} ({slice.pct}%)
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
