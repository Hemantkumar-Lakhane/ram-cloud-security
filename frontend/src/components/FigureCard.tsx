import React, { useState } from 'react';
import { Maximize2, Minimize2, Info } from 'lucide-react';

export const FigureCard: React.FC<{
  figureNumber: string;
  title: string;
  imageSrc: string;
  fieldsUsed: string[];
  calculationFormula: string;
  securityTakeaway: string;
}> = ({
  figureNumber,
  title,
  imageSrc,
  fieldsUsed,
  calculationFormula,
  securityTakeaway,
}) => {
  const [expanded, setExpanded] = useState(false);
  const [showMeta, setShowMeta] = useState(false);

  return (
    <div className="card" style={{ display: 'flex', flexDirection: 'column' }}>
      <div className="card-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span className="badge badge-info" style={{ fontWeight: 700 }}>{figureNumber}</span>
          <span style={{ fontSize: '13px', fontWeight: 600, color: '#1e293b' }}>{title}</span>
        </div>
        <div style={{ display: 'flex', gap: '6px' }}>
          <button
            className="btn btn-secondary btn-sm"
            onClick={() => setShowMeta(!showMeta)}
            title="Toggle Metadata"
          >
            <Info size={13} />
          </button>
          <button
            className="btn btn-secondary btn-sm"
            onClick={() => setExpanded(!expanded)}
            title="Expand Figure"
          >
            {expanded ? <Minimize2 size={13} /> : <Maximize2 size={13} />}
          </button>
        </div>
      </div>

      <div style={{ padding: '12px', background: '#f8fafc', display: 'flex', justifyContent: 'center' }}>
        <img
          src={imageSrc}
          alt={title}
          style={{
            maxWidth: '100%',
            height: expanded ? 'auto' : '260px',
            objectFit: 'contain',
            borderRadius: '4px',
            border: '1px solid #e2e8f0',
            background: '#ffffff'
          }}
        />
      </div>

      {showMeta && (
        <div style={{ padding: '12px 16px', background: '#ffffff', borderTop: '1px solid #e2e8f0', fontSize: '12px', display: 'flex', flexDirection: 'column', gap: '6px' }}>
          <div>
            <strong style={{ color: '#475569' }}>Raw Fields Used:</strong>{' '}
            <code>{fieldsUsed.join(', ')}</code>
          </div>
          <div>
            <strong style={{ color: '#475569' }}>Aggregation Logic:</strong>{' '}
            <span style={{ color: '#334155' }}>{calculationFormula}</span>
          </div>
          <div>
            <strong style={{ color: '#475569' }}>Security Takeaway:</strong>{' '}
            <span style={{ color: '#0f172a' }}>{securityTakeaway}</span>
          </div>
        </div>
      )}
    </div>
  );
};
