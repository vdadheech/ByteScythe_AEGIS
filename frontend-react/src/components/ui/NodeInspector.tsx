/**
 * AEGIS Active Attribution Engine - Node Inspector Panel
 * 
 * Detailed threat attribution display for a selected node.
 * 
 * DISPLAYS:
 * ---------
 * 1. C2 Confidence Score (0-100%)
 * 2. Threat Level (LOW/ELEVATED/HIGH/CRITICAL)
 * 3. Signal Breakdown:
 *    - Graph anomaly contribution
 *    - Temporal anomaly contribution
 *    - Header anomaly contribution
 *    - Behavioral anomaly contribution
 * 4. Primary Indicators (human-readable reasons)
 * 5. Recommended Actions
 * 6. Raw metrics for analysts
 */

import React from 'react';
import type { 
  NodeDetailsResponse, 
  SignalBreakdown,
  ThreatLevel,
} from '../../types';

// Icons as SVG for no external dependencies
const CloseIcon = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <line x1="18" y1="6" x2="6" y2="18" />
    <line x1="6" y1="6" x2="18" y2="18" />
  </svg>
);

const AlertIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
    <path d="M12 2L1 21h22L12 2zm0 3.5L19.5 19h-15L12 5.5zM11 10v4h2v-4h-2zm0 6v2h2v-2h-2z"/>
  </svg>
);

const CheckIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <polyline points="20 6 9 17 4 12" />
  </svg>
);

const THREAT_COLORS: Record<ThreatLevel, string> = {
  critical: '#ff1744',
  high: '#ff9100',
  elevated: '#ffea00',
  low: '#00e676',
};

const THREAT_BG: Record<ThreatLevel, string> = {
  critical: 'rgba(255, 23, 68, 0.15)',
  high: 'rgba(255, 145, 0, 0.15)',
  elevated: 'rgba(255, 234, 0, 0.15)',
  low: 'rgba(0, 230, 118, 0.15)',
};

interface NodeInspectorProps {
  nodeDetails: NodeDetailsResponse | null;
  isLoading?: boolean;
  onClose?: () => void;
  onQuarantine?: (nodeId: string) => void;
}

const SignalBar: React.FC<{ signal: SignalBreakdown }> = ({ signal }) => {
  const percentage = Math.min(100, signal.raw_score * 100);
  
  // Color based on contribution level
  const getColor = (score: number) => {
    if (score > 0.7) return '#ff1744';
    if (score > 0.4) return '#ff9100';
    if (score > 0.2) return '#ffea00';
    return '#00e676';
  };
  
  return (
    <div style={{ marginBottom: '12px' }}>
      <div style={{ 
        display: 'flex', 
        justifyContent: 'space-between',
        marginBottom: '4px',
      }}>
        <span style={{ 
          color: '#fff', 
          fontSize: '12px',
          textTransform: 'capitalize',
        }}>
          {signal.name}
          <span style={{ color: '#666', marginLeft: '6px' }}>
            (weight: {(signal.weight * 100).toFixed(0)}%)
          </span>
        </span>
        <span style={{ 
          color: getColor(signal.raw_score),
          fontSize: '12px',
          fontWeight: 'bold',
        }}>
          {(signal.raw_score * 100).toFixed(1)}%
        </span>
      </div>
      
      {/* Progress bar */}
      <div style={{
        height: '6px',
        background: 'rgba(255, 255, 255, 0.1)',
        borderRadius: '3px',
        overflow: 'hidden',
      }}>
        <div style={{
          width: `${percentage}%`,
          height: '100%',
          background: getColor(signal.raw_score),
          borderRadius: '3px',
          transition: 'width 0.3s ease',
        }} />
      </div>
      
      {/* Reason */}
      <div style={{
        color: '#888',
        fontSize: '10px',
        marginTop: '4px',
      }}>
        {signal.reason}
      </div>
    </div>
  );
};

const MetricCard: React.FC<{
  label: string;
  value: string | number;
  subValue?: string;
  color?: string;
}> = ({ label, value, subValue, color = '#fff' }) => (
  <div style={{
    background: 'rgba(255, 255, 255, 0.05)',
    borderRadius: '6px',
    padding: '10px',
    textAlign: 'center',
  }}>
    <div style={{ color: '#888', fontSize: '10px', textTransform: 'uppercase' }}>
      {label}
    </div>
    <div style={{ color, fontSize: '18px', fontWeight: 'bold', marginTop: '4px' }}>
      {value}
    </div>
    {subValue && (
      <div style={{ color: '#666', fontSize: '10px', marginTop: '2px' }}>
        {subValue}
      </div>
    )}
  </div>
);

export const NodeInspector: React.FC<NodeInspectorProps> = ({
  nodeDetails,
  isLoading = false,
  onClose,
  onQuarantine,
}) => {
  if (isLoading) {
    return (
      <div style={{
        background: 'linear-gradient(135deg, #1a1a2e 0%, #16213e 100%)',
        borderRadius: '8px',
        padding: '24px',
        color: '#888',
        textAlign: 'center',
      }}>
        <div className="loading-spinner" />
        Loading node details...
      </div>
    );
  }

  if (!nodeDetails) {
    return (
      <div style={{
        background: 'linear-gradient(135deg, #1a1a2e 0%, #16213e 100%)',
        borderRadius: '8px',
        padding: '24px',
        color: '#888',
        textAlign: 'center',
      }}>
        Select a node to view details
      </div>
    );
  }

  const { attribution, timing, headers, graph, nodeId } = nodeDetails;
  const threatLevel = attribution.threat_level;
  const threatColor = THREAT_COLORS[threatLevel];
  const threatBg = THREAT_BG[threatLevel];

  return (
    <div style={{
      background: 'linear-gradient(135deg, #1a1a2e 0%, #16213e 100%)',
      borderRadius: '8px',
      border: `1px solid ${threatColor}33`,
      overflow: 'hidden',
    }}>
      {/* Header */}
      <div style={{
        background: threatBg,
        padding: '16px',
        borderBottom: `1px solid ${threatColor}33`,
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'flex-start',
      }}>
        <div>
          <div style={{ 
            color: '#fff', 
            fontSize: '16px', 
            fontWeight: 'bold',
            fontFamily: 'monospace',
          }}>
            {nodeId}
          </div>
          <div style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '6px',
            marginTop: '6px',
            padding: '4px 10px',
            background: threatColor,
            borderRadius: '4px',
            color: threatLevel === 'elevated' ? '#000' : '#fff',
            fontSize: '11px',
            fontWeight: 'bold',
            textTransform: 'uppercase',
          }}>
            <AlertIcon />
            {threatLevel} THREAT
          </div>
        </div>
        
        {/* Close button */}
        {onClose && (
          <button
            onClick={onClose}
            style={{
              background: 'none',
              border: 'none',
              color: '#888',
              cursor: 'pointer',
              padding: '4px',
            }}
          >
            <CloseIcon />
          </button>
        )}
      </div>

      {/* Main Score */}
      <div style={{
        padding: '20px',
        textAlign: 'center',
        borderBottom: '1px solid rgba(255, 255, 255, 0.1)',
      }}>
        <div style={{
          fontSize: '48px',
          fontWeight: 'bold',
          color: threatColor,
          lineHeight: 1,
        }}>
          {Math.round(attribution.c2_confidence)}%
        </div>
        <div style={{
          color: '#888',
          fontSize: '12px',
          marginTop: '4px',
        }}>
          C2 Confidence Score
        </div>
        <div style={{
          color: '#666',
          fontSize: '10px',
          marginTop: '4px',
        }}>
          Data quality: {(attribution.data_quality * 100).toFixed(0)}%
        </div>
      </div>

      {/* Signal Breakdown */}
      <div style={{ padding: '16px' }}>
        <h4 style={{ 
          color: '#fff', 
          fontSize: '12px', 
          textTransform: 'uppercase',
          marginBottom: '12px',
          letterSpacing: '0.5px',
        }}>
          Signal Analysis
        </h4>
        
        {attribution.signals.map((signal) => (
          <SignalBar key={signal.name} signal={signal} />
        ))}
      </div>

      {/* Primary Indicators */}
      {attribution.primary_indicators.length > 0 && (
        <div style={{
          padding: '16px',
          borderTop: '1px solid rgba(255, 255, 255, 0.1)',
        }}>
          <h4 style={{ 
            color: '#fff', 
            fontSize: '12px', 
            textTransform: 'uppercase',
            marginBottom: '12px',
            letterSpacing: '0.5px',
          }}>
            Detection Reasons
          </h4>
          
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {attribution.primary_indicators.map((indicator, i) => (
              <div
                key={i}
                style={{
                  display: 'flex',
                  alignItems: 'flex-start',
                  gap: '8px',
                  padding: '8px',
                  background: 'rgba(255, 145, 0, 0.1)',
                  borderRadius: '4px',
                  borderLeft: '3px solid #ff9100',
                }}
              >
                <AlertIcon />
                <span style={{ color: '#fff', fontSize: '12px' }}>
                  {indicator}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Metrics Grid */}
      <div style={{
        padding: '16px',
        borderTop: '1px solid rgba(255, 255, 255, 0.1)',
      }}>
        <h4 style={{ 
          color: '#fff', 
          fontSize: '12px', 
          textTransform: 'uppercase',
          marginBottom: '12px',
          letterSpacing: '0.5px',
        }}>
          Raw Metrics
        </h4>
        
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(3, 1fr)',
          gap: '8px',
        }}>
          {timing?.profile && (
            <>
              <MetricCard
                label="Jitter"
                value={`${(timing.profile.jitter * 100).toFixed(1)}%`}
                subValue={timing.profile.jitter < 0.15 ? 'Low (automated)' : 'Normal'}
                color={timing.profile.jitter < 0.15 ? '#ff9100' : '#00e676'}
              />
              <MetricCard
                label="Interval"
                value={`${Math.round(timing.profile.dominant_interval_ms)}ms`}
                subValue={`${(timing.profile.interval_consistency * 100).toFixed(0)}% consistent`}
              />
              <MetricCard
                label="Requests"
                value={timing.profile.request_count}
              />
            </>
          )}
          
          {graph && (
            <>
              <MetricCard
                label="Centrality"
                value={`${(graph.degree_centrality * 100).toFixed(1)}%`}
                color={graph.is_hub ? '#ff9100' : '#fff'}
              />
              <MetricCard
                label="Connections"
                value={graph.in_degree + graph.out_degree}
                subValue={`In: ${graph.in_degree} / Out: ${graph.out_degree}`}
              />
              <MetricCard
                label="Community"
                value={`#${graph.community_id}`}
                subValue={graph.is_bridge ? 'Bridge node' : undefined}
              />
            </>
          )}
          
          {headers && (
            <>
              <MetricCard
                label="Fingerprints"
                value={Object.keys(headers.fingerprints_seen).length}
                subValue={headers.is_consistent ? 'Consistent' : 'Varying'}
              />
              <MetricCard
                label="User Agents"
                value={Object.keys(headers.user_agents_seen).length}
              />
              <MetricCard
                label="Suspicious"
                value={`${headers.suspicious_count}/${headers.total_requests}`}
                color={headers.suspicious_count > 0 ? '#ff9100' : '#00e676'}
              />
            </>
          )}
        </div>
      </div>

      {/* Recommended Actions */}
      <div style={{
        padding: '16px',
        borderTop: '1px solid rgba(255, 255, 255, 0.1)',
      }}>
        <h4 style={{ 
          color: '#fff', 
          fontSize: '12px', 
          textTransform: 'uppercase',
          marginBottom: '12px',
          letterSpacing: '0.5px',
        }}>
          Recommended Actions
        </h4>
        
        <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
          {attribution.recommended_actions.map((action, i) => (
            <div
              key={i}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                padding: '6px 8px',
                background: 'rgba(255, 255, 255, 0.05)',
                borderRadius: '4px',
              }}
            >
              <CheckIcon />
              <span style={{ color: '#fff', fontSize: '12px' }}>
                {action}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Action Buttons */}
      {threatLevel !== 'low' && onQuarantine && (
        <div style={{
          padding: '16px',
          borderTop: '1px solid rgba(255, 255, 255, 0.1)',
        }}>
          <button
            onClick={() => onQuarantine(nodeId)}
            style={{
              width: '100%',
              padding: '12px',
              background: threatLevel === 'critical' ? '#ff1744' : 'rgba(255, 23, 68, 0.2)',
              border: '1px solid #ff1744',
              borderRadius: '6px',
              color: '#fff',
              fontWeight: 'bold',
              fontSize: '14px',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '8px',
            }}
          >
            <AlertIcon />
            {threatLevel === 'critical' ? 'QUARANTINE IMMEDIATELY' : 'Quarantine Node'}
          </button>
        </div>
      )}
    </div>
  );
};

export default NodeInspector;
