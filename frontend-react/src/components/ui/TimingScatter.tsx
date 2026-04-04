/**
 * AEGIS Active Attribution Engine - Timing Scatter Plot
 * 
 * Visualizes request inter-arrival times to detect beaconing behavior.
 * 
 * VISUALIZATION LOGIC:
 * --------------------
 * X-axis: Timestamp of request
 * Y-axis: Time since previous request (delta in ms)
 * 
 * HUMAN TRAFFIC PATTERN:
 * - Points scattered across wide Y range
 * - No consistent horizontal bands
 * - High variance in delta values
 * 
 * BEACON PATTERN (C2 Signature):
 * - Points cluster in horizontal bands
 * - Band position = beacon interval
 * - Tight bands = pure beacon
 * - Slightly fuzzy bands = jittered beacon
 * 
 * Color Coding:
 * - Red: Detected beacon
 * - Green: Human/normal
 */

import React, { useMemo, useState, useCallback } from 'react';
import {
  ScatterChart,
  Scatter,
  XAxis,
  YAxis,
  ZAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  ReferenceLine,
} from 'recharts';
import type { TimingPoint, TimingProfile } from '../../types';

interface TimingScatterProps {
  points: TimingPoint[];
  profiles: TimingProfile[];
  onNodeSelect?: (nodeId: string) => void;
  height?: number;
  showBeaconsOnly?: boolean;
}

// Format timestamp for display
const formatTime = (timestamp: number): string => {
  const date = new Date(timestamp);
  return date.toLocaleTimeString('en-US', { 
    hour: '2-digit', 
    minute: '2-digit',
    second: '2-digit',
  });
};

// Format delta for display
const formatDelta = (delta: number): string => {
  if (delta < 1000) {
    return `${Math.round(delta)}ms`;
  } else if (delta < 60000) {
    return `${(delta / 1000).toFixed(1)}s`;
  } else {
    return `${(delta / 60000).toFixed(1)}m`;
  }
};

// Custom tooltip
const CustomTooltip: React.FC<{
  active?: boolean;
  payload?: Array<{ payload: TimingPoint & { profile?: TimingProfile } }>;
}> = ({ active, payload }) => {
  if (!active || !payload?.length) return null;
  
  const data = payload[0].payload;
  
  return (
    <div style={{
      background: 'rgba(0, 0, 0, 0.9)',
      border: `1px solid ${data.isBeacon ? '#ff1744' : '#00e676'}`,
      borderRadius: '6px',
      padding: '10px',
      maxWidth: '220px',
    }}>
      <div style={{ 
        fontWeight: 'bold', 
        color: data.isBeacon ? '#ff1744' : '#00e676',
        marginBottom: '6px',
      }}>
        {data.node}
      </div>
      <div style={{ color: '#fff', fontSize: '12px' }}>
        <div>Time: {formatTime(data.x)}</div>
        <div>Delta: {formatDelta(data.y)}</div>
      </div>
      {data.isBeacon && (
        <div style={{ 
          marginTop: '6px', 
          paddingTop: '6px', 
          borderTop: '1px solid #333',
          color: '#ff9100',
          fontSize: '11px',
        }}>
          ⚠️ Beacon pattern detected
        </div>
      )}
    </div>
  );
};

export const TimingScatter: React.FC<TimingScatterProps> = ({
  points,
  profiles,
  onNodeSelect,
  height = 400,
  showBeaconsOnly = false,
}) => {
  const [selectedNode, setSelectedNode] = useState<string | null>(null);

  // Split points into beacon and human
  const { beaconPoints, humanPoints, filteredPoints } = useMemo(() => {
    const beaconNodeIds = new Set(
      profiles.filter(p => p.is_beacon).map(p => p.node_id)
    );
    
    const beacon = points.filter(p => beaconNodeIds.has(p.node) || p.isBeacon);
    const human = points.filter(p => !beaconNodeIds.has(p.node) && !p.isBeacon);
    
    return {
      beaconPoints: beacon,
      humanPoints: human,
      filteredPoints: showBeaconsOnly ? beacon : points,
    };
  }, [points, profiles, showBeaconsOnly]);

  // Find dominant intervals for reference lines
  const dominantIntervals = useMemo(() => {
    return profiles
      .filter(p => p.is_beacon && p.interval_consistency > 0.3)
      .map(p => ({
        interval: p.dominant_interval_ms,
        nodeId: p.node_id,
        consistency: p.interval_consistency,
      }))
      .sort((a, b) => b.consistency - a.consistency)
      .slice(0, 3);  // Top 3 dominant intervals
  }, [profiles]);

  // Calculate Y axis domain
  const yDomain = useMemo(() => {
    if (filteredPoints.length === 0) return [0, 1000];
    
    const deltas = filteredPoints.map(p => p.y);
    const max = Math.max(...deltas);
    const p95 = deltas.sort((a, b) => a - b)[Math.floor(deltas.length * 0.95)] || max;
    
    return [0, Math.min(max, p95 * 1.5)];
  }, [filteredPoints]);

  // Handle point click
  const handleClick = useCallback((data: TimingPoint) => {
    setSelectedNode(data.node);
    if (onNodeSelect) {
      onNodeSelect(data.node);
    }
  }, [onNodeSelect]);

  // Beacon statistics
  const stats = useMemo(() => ({
    totalPoints: points.length,
    beaconPoints: beaconPoints.length,
    beaconNodes: profiles.filter(p => p.is_beacon).length,
    totalNodes: profiles.length,
  }), [points.length, beaconPoints.length, profiles]);

  return (
    <div style={{
      background: 'linear-gradient(135deg, #0a0a0f 0%, #1a1a2e 100%)',
      borderRadius: '8px',
      padding: '16px',
    }}>
      {/* Header */}
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        marginBottom: '16px',
      }}>
        <div>
          <h3 style={{ color: '#fff', margin: 0, fontSize: '16px' }}>
            Timing Pattern Analysis
          </h3>
          <p style={{ color: '#888', margin: '4px 0 0', fontSize: '12px' }}>
            Inter-arrival time distribution • Red = Beacon pattern detected
          </p>
        </div>
        
        {/* Stats */}
        <div style={{
          display: 'flex',
          gap: '16px',
          fontSize: '12px',
        }}>
          <div style={{ textAlign: 'center' }}>
            <div style={{ color: '#ff1744', fontSize: '20px', fontWeight: 'bold' }}>
              {stats.beaconNodes}
            </div>
            <div style={{ color: '#888' }}>Beacon Nodes</div>
          </div>
          <div style={{ textAlign: 'center' }}>
            <div style={{ color: '#00e676', fontSize: '20px', fontWeight: 'bold' }}>
              {stats.totalNodes - stats.beaconNodes}
            </div>
            <div style={{ color: '#888' }}>Normal Nodes</div>
          </div>
        </div>
      </div>

      {/* Chart */}
      <ResponsiveContainer width="100%" height={height}>
        <ScatterChart margin={{ top: 20, right: 20, bottom: 20, left: 60 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#333" />
          
          <XAxis 
            dataKey="x" 
            type="number"
            domain={['dataMin', 'dataMax']}
            tickFormatter={formatTime}
            stroke="#666"
            tick={{ fill: '#888', fontSize: 10 }}
            label={{ 
              value: 'Time', 
              position: 'bottom', 
              fill: '#888',
              fontSize: 12,
            }}
          />
          
          <YAxis 
            dataKey="y"
            type="number"
            domain={yDomain}
            tickFormatter={formatDelta}
            stroke="#666"
            tick={{ fill: '#888', fontSize: 10 }}
            label={{ 
              value: 'Inter-arrival Delta', 
              angle: -90, 
              position: 'insideLeft',
              fill: '#888',
              fontSize: 12,
            }}
          />
          
          <ZAxis range={[20, 200]} />
          
          <Tooltip content={<CustomTooltip />} />
          
          <Legend 
            wrapperStyle={{ paddingTop: '10px' }}
            formatter={(value) => (
              <span style={{ color: '#888', fontSize: '12px' }}>{value}</span>
            )}
          />
          
          {/* Reference lines for dominant beacon intervals */}
          {dominantIntervals.map((interval, i) => (
            <ReferenceLine
              key={`interval-${i}`}
              y={interval.interval}
              stroke="#ff9100"
              strokeDasharray="5 5"
              strokeOpacity={0.5}
              label={{
                value: `${formatDelta(interval.interval)}`,
                position: 'right',
                fill: '#ff9100',
                fontSize: 10,
              }}
            />
          ))}
          
          {/* Human traffic points */}
          {!showBeaconsOnly && (
            <Scatter
              name="Normal Traffic"
              data={humanPoints}
              fill="#00e676"
              fillOpacity={0.6}
              onClick={(data) => handleClick(data as unknown as TimingPoint)}
            />
          )}
          
          {/* Beacon points (rendered on top) */}
          <Scatter
            name="Beacon Pattern"
            data={beaconPoints}
            fill="#ff1744"
            fillOpacity={0.8}
            onClick={(data) => handleClick(data as unknown as TimingPoint)}
          />
        </ScatterChart>
      </ResponsiveContainer>

      {/* Beacon profiles list */}
      {profiles.filter(p => p.is_beacon).length > 0 && (
        <div style={{
          marginTop: '16px',
          padding: '12px',
          background: 'rgba(255, 23, 68, 0.1)',
          borderRadius: '6px',
          border: '1px solid rgba(255, 23, 68, 0.3)',
        }}>
          <div style={{ 
            color: '#ff1744', 
            fontWeight: 'bold', 
            fontSize: '12px',
            marginBottom: '8px',
          }}>
            ⚠️ Detected Beacon Patterns
          </div>
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))',
            gap: '8px',
          }}>
            {profiles.filter(p => p.is_beacon).slice(0, 6).map(profile => (
              <div
                key={profile.node_id}
                onClick={() => onNodeSelect?.(profile.node_id)}
                style={{
                  background: selectedNode === profile.node_id 
                    ? 'rgba(255, 23, 68, 0.3)' 
                    : 'rgba(0, 0, 0, 0.3)',
                  padding: '8px',
                  borderRadius: '4px',
                  cursor: 'pointer',
                  border: selectedNode === profile.node_id 
                    ? '1px solid #ff1744' 
                    : '1px solid transparent',
                }}
              >
                <div style={{ color: '#fff', fontSize: '11px', fontWeight: 'bold' }}>
                  {profile.node_id}
                </div>
                <div style={{ color: '#ff9100', fontSize: '10px' }}>
                  Interval: {formatDelta(profile.dominant_interval_ms)}
                </div>
                <div style={{ color: '#888', fontSize: '10px' }}>
                  Jitter: {(profile.jitter * 100).toFixed(1)}% • 
                  Confidence: {(profile.beacon_score * 100).toFixed(0)}%
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default TimingScatter;
