/**
 * AEGIS Beaconing Scatter Plot
 * 
 * Visualizes temporal patterns to detect C2 beaconing.
 * Human traffic = random scatter, C2 beacon = horizontal line.
 */

import { useMemo } from 'react';
import {
  ScatterChart,
  Scatter,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  ReferenceLine,
} from 'recharts';
import { useThreatStore } from './useThreatStore';
import type { TimingPoint } from './types';

// Format time for axis
function formatTime(timestamp: number): string {
  const date = new Date(timestamp);
  return `${date.getHours().toString().padStart(2, '0')}:${date.getMinutes().toString().padStart(2, '0')}`;
}

// Custom tooltip
function CustomTooltip({ active, payload }: { active?: boolean; payload?: Array<{ payload: TimingPoint }> }) {
  if (!active || !payload?.length) return null;
  
  const point = payload[0].payload;
  return (
    <div className="bg-gray-900/95 backdrop-blur-sm border border-gray-700/50 rounded-lg px-4 py-3 shadow-xl">
      <div className="text-gray-400 text-xs mb-1">
        {new Date(point.timestamp).toLocaleTimeString()}
      </div>
      <div className="text-white font-semibold">
        Delta: <span className="text-cyan-400">{point.delta.toFixed(0)}ms</span>
      </div>
    </div>
  );
}

export function BeaconingScatter() {
  const { getSelectedNode, selectedNodeId } = useThreatStore();
  const selectedNode = getSelectedNode();

  // Prepare scatter data
  const scatterData = useMemo(() => {
    if (!selectedNode) return [];
    return selectedNode.timingData.map(point => ({
      ...point,
      x: point.timestamp,
      y: point.delta,
    }));
  }, [selectedNode]);

  // Calculate statistics
  const stats = useMemo(() => {
    if (!scatterData.length) return null;
    
    const deltas = scatterData.map(p => p.delta);
    const mean = deltas.reduce((a, b) => a + b, 0) / deltas.length;
    const variance = deltas.reduce((sum, d) => sum + Math.pow(d - mean, 2), 0) / deltas.length;
    const stdDev = Math.sqrt(variance);
    const jitter = stdDev / mean;
    
    return { mean, stdDev, jitter, min: Math.min(...deltas), max: Math.max(...deltas) };
  }, [scatterData]);

  // Determine if this looks like a beacon
  const isBeacon = stats && stats.jitter < 0.3;
  
  // Color based on pattern
  const dotColor = isBeacon ? '#EF4444' : '#3B82F6';

  if (!selectedNodeId) {
    return (
      <div className="h-full flex flex-col items-center justify-center bg-gray-900/30 rounded-2xl border border-gray-800/50">
        <div className="text-gray-500 text-lg mb-2">📊 Timing Analysis</div>
        <div className="text-gray-600 text-sm">Click a node to view timing pattern</div>
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col bg-gray-900/30 rounded-2xl border border-gray-800/50 p-4">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div>
          <h3 className="text-white font-semibold">Timing Pattern</h3>
          <div className="text-gray-400 text-sm">{selectedNode?.ip || 'Unknown'}</div>
        </div>
        
        {stats && (
          <div className={`px-3 py-1.5 rounded-full text-sm font-medium ${
            isBeacon 
              ? 'bg-red-500/20 text-red-400 border border-red-500/30' 
              : 'bg-blue-500/20 text-blue-400 border border-blue-500/30'
          }`}>
            {isBeacon ? '🎯 BEACON DETECTED' : '👤 Human Pattern'}
          </div>
        )}
      </div>

      {/* Stats bar */}
      {stats && (
        <div className="grid grid-cols-4 gap-3 mb-4">
          <div className="bg-gray-800/50 rounded-lg p-2 text-center">
            <div className="text-gray-500 text-xs">Mean</div>
            <div className="text-white font-semibold">{stats.mean.toFixed(0)}ms</div>
          </div>
          <div className="bg-gray-800/50 rounded-lg p-2 text-center">
            <div className="text-gray-500 text-xs">Std Dev</div>
            <div className="text-white font-semibold">{stats.stdDev.toFixed(0)}ms</div>
          </div>
          <div className="bg-gray-800/50 rounded-lg p-2 text-center">
            <div className="text-gray-500 text-xs">Jitter</div>
            <div className={`font-semibold ${stats.jitter < 0.15 ? 'text-red-400' : stats.jitter < 0.3 ? 'text-orange-400' : 'text-green-400'}`}>
              {(stats.jitter * 100).toFixed(1)}%
            </div>
          </div>
          <div className="bg-gray-800/50 rounded-lg p-2 text-center">
            <div className="text-gray-500 text-xs">Samples</div>
            <div className="text-white font-semibold">{scatterData.length}</div>
          </div>
        </div>
      )}

      {/* Chart */}
      <div className="flex-1 min-h-0">
        <ResponsiveContainer width="100%" height="100%">
          <ScatterChart margin={{ top: 10, right: 10, bottom: 30, left: 50 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#374151" opacity={0.5} />
            
            <XAxis
              dataKey="x"
              type="number"
              domain={['dataMin', 'dataMax']}
              tickFormatter={formatTime}
              stroke="#6B7280"
              tick={{ fill: '#9CA3AF', fontSize: 11 }}
              label={{ value: 'Time', position: 'bottom', fill: '#6B7280', fontSize: 12 }}
            />
            
            <YAxis
              dataKey="y"
              type="number"
              domain={[0, 'auto']}
              stroke="#6B7280"
              tick={{ fill: '#9CA3AF', fontSize: 11 }}
              label={{ value: 'Inter-arrival (ms)', angle: -90, position: 'insideLeft', fill: '#6B7280', fontSize: 12 }}
            />
            
            {/* Reference line for mean (beacon baseline) */}
            {stats && isBeacon && (
              <ReferenceLine
                y={stats.mean}
                stroke="#EF4444"
                strokeDasharray="5 5"
                strokeWidth={2}
                label={{ value: `Beacon: ${stats.mean.toFixed(0)}ms`, fill: '#EF4444', fontSize: 11 }}
              />
            )}
            
            <Tooltip content={<CustomTooltip />} />
            
            <Scatter
              name="Timing"
              data={scatterData}
              fill={dotColor}
              fillOpacity={0.7}
              shape="circle"
            />
          </ScatterChart>
        </ResponsiveContainer>
      </div>

      {/* Pattern explanation */}
      {isBeacon && (
        <div className="mt-3 p-3 bg-red-500/10 border border-red-500/30 rounded-lg">
          <div className="text-red-400 text-sm font-medium flex items-center gap-2">
            <span>⚠️</span>
            <span>Rigid timing indicates automated C2 communication</span>
          </div>
        </div>
      )}
    </div>
  );
}
