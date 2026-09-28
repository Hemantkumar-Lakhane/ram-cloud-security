import React, { useState, useMemo } from 'react';
import type { ThreatRun } from '../../types';

interface InteractiveThreatTimelineProps {
  runs: ThreatRun[];
  onSelectRun?: (run: ThreatRun) => void;
  height?: number;
}

export const InteractiveThreatTimeline: React.FC<InteractiveThreatTimelineProps> = ({
  runs = [],
  onSelectRun,
  height = 140,
}) => {
  const [filterMode, setFilterMode] = useState<'ALL' | 'DETECTED' | 'MISSED'>('ALL');
  const [hoveredRun, setHoveredRun] = useState<ThreatRun | null>(null);

  // Time bounds across the 83 runs
  const timeBounds = useMemo(() => {
    if (!runs.length) return { start: 0, end: 1 };
    const timestamps = runs.map(r => new Date(r.first_seen).getTime());
    return {
      start: Math.min(...timestamps),
      end: Math.max(...timestamps),
    };
  }, [runs]);

  const filteredRuns = useMemo(() => {
    return runs.filter(r => {
      if (filterMode === 'DETECTED') return r.detected_by_baseline_a;
      if (filterMode === 'MISSED') return !r.detected_by_baseline_a;
      return true;
    });
  }, [runs, filterMode]);

  const svgWidth = 700;
  const padding = { top: 25, right: 30, bottom: 30, left: 30 };
  const chartWidth = svgWidth - padding.left - padding.right;

  const getX = (timestampStr: string) => {
    const t = new Date(timestampStr).getTime();
    const duration = timeBounds.end - timeBounds.start || 1;
    return padding.left + ((t - timeBounds.start) / duration) * chartWidth;
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', width: '100%' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ display: 'flex', gap: '6px' }}>
          <button
            className={`btn btn-sm ${filterMode === 'ALL' ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setFilterMode('ALL')}
            style={{ fontSize: '11px', height: '24px' }}
          >
            All 83 Emulation Runs
          </button>
          <button
            className={`btn btn-sm ${filterMode === 'DETECTED' ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setFilterMode('DETECTED')}
            style={{ fontSize: '11px', height: '24px', color: filterMode === 'DETECTED' ? '#fff' : '#16a34a' }}
          >
            ● Detected by Baseline A (17)
          </button>
          <button
            className={`btn btn-sm ${filterMode === 'MISSED' ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setFilterMode('MISSED')}
            style={{ fontSize: '11px', height: '24px', color: filterMode === 'MISSED' ? '#fff' : '#ea580c' }}
          >
            ● Undetected / Stealth (66)
          </button>
        </div>
        <span style={{ fontSize: '11px', color: '#64748b' }}>
          Chronological Test Execution Timeline
        </span>
      </div>

      <svg
        viewBox={`0 0 ${svgWidth} ${height}`}
        style={{ width: '100%', height: `${height}px`, background: '#ffffff', borderRadius: '4px', border: '1px solid #e2e8f0' }}
      >
        {/* Baseline Axis */}
        <line
          x1={padding.left}
          y1={height / 2}
          x2={svgWidth - padding.right}
          y2={height / 2}
          stroke="#cbd5e1"
          strokeWidth="2"
        />

        {/* Start / End Time Labels */}
        <text x={padding.left} y={height - 8} fontSize="10" fill="#64748b" fontFamily="sans-serif">
          11:42 UTC
        </text>
        <text x={svgWidth - padding.right} y={height - 8} textAnchor="end" fontSize="10" fill="#64748b" fontFamily="sans-serif">
          12:37 UTC
        </text>

        {/* Emulation Run Nodes */}
        {filteredRuns.map((r, i) => {
          const x = getX(r.first_seen);
          // Alternate y slightly to prevent visual clutter
          const y = height / 2 + (i % 2 === 0 ? -12 : 12);
          const isDetected = r.detected_by_baseline_a;
          const isHovered = hoveredRun?.detonation_uuid === r.detonation_uuid;

          return (
            <g
              key={r.detonation_uuid}
              style={{ cursor: 'pointer' }}
              onMouseEnter={() => setHoveredRun(r)}
              onMouseLeave={() => setHoveredRun(null)}
              onClick={() => onSelectRun?.(r)}
            >
              <line
                x1={x}
                y1={height / 2}
                x2={x}
                y2={y}
                stroke={isDetected ? '#16a34a' : '#ea580c'}
                strokeWidth={isHovered ? 2 : 1}
                opacity={0.7}
              />
              <circle
                cx={x}
                cy={y}
                r={isHovered ? 6 : (isDetected ? 4.5 : 3.5)}
                fill={isDetected ? '#16a34a' : '#ea580c'}
                stroke="#ffffff"
                strokeWidth="1.5"
                style={{ transition: 'all 0.15s ease' }}
              />
            </g>
          );
        })}
      </svg>

      {/* Hover Card */}
      {hoveredRun && (
        <div style={{ background: '#f8fafc', padding: '8px 12px', borderRadius: '4px', border: '1px solid #cbd5e1', fontSize: '11px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <strong>Emulation Run:</strong> <code>{hoveredRun.detonation_uuid}</code> ({hoveredRun.event_count} events)
            <div style={{ color: '#64748b', fontSize: '10px' }}>
              Target Services: {hoveredRun.services.join(', ')} | APIs: {hoveredRun.apis.join(', ')}
            </div>
          </div>
          <div>
            {hoveredRun.detected_by_baseline_a ? (
              <span className="badge badge-active" style={{ fontSize: '11px' }}>
                Detected ({hoveredRun.findings_count} Rule Alerts)
              </span>
            ) : (
              <span className="badge badge-high" style={{ fontSize: '11px' }}>
                Missed by Rule Baseline
              </span>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
