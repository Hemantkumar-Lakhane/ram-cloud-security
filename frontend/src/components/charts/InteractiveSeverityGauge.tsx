import React from 'react';
import type { SecurityFinding } from '../../types';

interface InteractiveSeverityGaugeProps {
  findings: SecurityFinding[];
  onSelectSeverity?: (severity: string) => void;
  activeSeverity?: string;
}

export const InteractiveSeverityGauge: React.FC<InteractiveSeverityGaugeProps> = ({
  findings = [],
  onSelectSeverity,
  activeSeverity = 'ALL',
}) => {
  const counts = {
    CRITICAL: findings.filter(f => f.severity === 'CRITICAL').length,
    HIGH: findings.filter(f => f.severity === 'HIGH').length,
    MEDIUM: findings.filter(f => f.severity === 'MEDIUM').length,
    LOW: findings.filter(f => f.severity === 'LOW').length,
  };

  const total = findings.length || 1;

  const severities = [
    { key: 'CRITICAL', label: 'Critical', count: counts.CRITICAL, color: '#dc2626', bg: '#fef2f2', border: '#f87171' },
    { key: 'HIGH', label: 'High', count: counts.HIGH, color: '#ea580c', bg: '#fff7ed', border: '#fdba74' },
    { key: 'MEDIUM', label: 'Medium', count: counts.MEDIUM, color: '#ca8a04', bg: '#fefce8', border: '#fde047' },
    { key: 'LOW', label: 'Low', count: counts.LOW, color: '#2563eb', bg: '#eff6ff', border: '#93c5fd' },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', width: '100%' }}>
      {/* Progress Bar Stack */}
      <div style={{ display: 'flex', height: '10px', borderRadius: '4px', overflow: 'hidden', background: '#f1f5f9' }}>
        {severities.map(s => {
          const pct = (s.count / total) * 100;
          if (pct === 0) return null;
          return (
            <div
              key={s.key}
              style={{
                width: `${pct}%`,
                background: s.color,
                transition: 'width 0.2s ease',
              }}
              title={`${s.label}: ${s.count} (${pct.toFixed(1)}%)`}
            />
          );
        })}
      </div>

      {/* Clickable Severity Filter Pills */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '6px' }}>
        {severities.map(s => {
          const isSelected = activeSeverity === s.key;
          return (
            <button
              key={s.key}
              onClick={() => onSelectSeverity?.(isSelected ? 'ALL' : s.key)}
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '4px 8px',
                borderRadius: '4px',
                border: `1px solid ${isSelected ? s.color : '#e2e8f0'}`,
                background: isSelected ? s.bg : '#ffffff',
                cursor: 'pointer',
                transition: 'all 0.15s ease',
              }}
            >
              <span style={{ fontSize: '11px', fontWeight: 600, color: s.color }}>
                {s.label}
              </span>
              <span style={{ fontSize: '12px', fontWeight: 700, color: '#0f172a' }}>
                {s.count}
              </span>
            </button>
          );
        })}
      </div>
    </div>
  );
};
