import React from 'react';
import type { SeverityLevel, OperationalState, ActivityTier } from '../types';

export const SeverityBadge: React.FC<{ severity: SeverityLevel }> = ({ severity }) => {
  const glyphs: Record<SeverityLevel, string> = {
    CRITICAL: '◆',
    HIGH: '▲',
    MEDIUM: '●',
    LOW: '■',
    INFO: '○',
  };

  const className = `badge badge-${severity.toLowerCase()}`;

  return (
    <span className={className}>
      <span>{glyphs[severity] || '●'}</span>
      <span>{severity}</span>
    </span>
  );
};

export const StateBadge: React.FC<{ state: OperationalState }> = ({ state }) => {
  let className = 'badge badge-info';
  if (state === 'Active') className = 'badge badge-active';
  else if (state === 'Not Evaluated') className = 'badge badge-not-evaluated';
  else if (state === 'Not Connected') className = 'badge badge-not-connected';
  else if (state === 'Coming Soon') className = 'badge badge-coming-soon';

  return <span className={className}>{state}</span>;
};

export const ProvenancePill: React.FC<{ tier: ActivityTier | string }> = ({ tier }) => {
  let colorStyle = { backgroundColor: '#f3f4f6', color: '#4b5563', border: '1px solid #d1d5db' };
  
  if (tier.includes('Pure Detonation')) {
    colorStyle = { backgroundColor: '#fef2f2', color: '#991b1b', border: '1px solid #f87171' };
  } else if (tier.includes('Warmup')) {
    colorStyle = { backgroundColor: '#fff7ed', color: '#9a3412', border: '1px solid #fdba74' };
  } else if (tier.includes('Operator')) {
    colorStyle = { backgroundColor: '#eff6ff', color: '#1e40af', border: '1px solid #93c5fd' };
  } else if (tier.includes('Background')) {
    colorStyle = { backgroundColor: '#f9fafb', color: '#4b5563', border: '1px solid #e5e7eb' };
  }

  return (
    <span style={{ ...colorStyle, display: 'inline-flex', padding: '2px 8px', borderRadius: '4px', fontSize: '11px', fontWeight: 600 }}>
      {tier}
    </span>
  );
};

export const FutureStateBanner: React.FC<{
  title: string;
  phase: string;
  description: string;
  requiredInput?: string;
}> = ({ title, phase, description, requiredInput }) => {
  return (
    <div style={{
      backgroundColor: '#f8fafc',
      border: '1px dashed #cbd5e1',
      borderRadius: '6px',
      padding: '20px',
      display: 'flex',
      flexDirection: 'column',
      gap: '8px'
    }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <h3 style={{ fontSize: '14px', fontWeight: 600, color: '#1e293b' }}>{title}</h3>
        <span className="badge badge-not-evaluated">{phase}</span>
      </div>
      <p style={{ fontSize: '13px', color: '#64748b' }}>{description}</p>
      {requiredInput && (
        <div style={{ marginTop: '8px', fontSize: '12px', color: '#475569', backgroundColor: '#ffffff', padding: '8px 12px', borderRadius: '4px', border: '1px solid #e2e8f0' }}>
          <strong>Required Input Pipeline:</strong> <code>{requiredInput}</code>
        </div>
      )}
    </div>
  );
};
