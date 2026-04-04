/**
 * AEGIS Global Controls
 * 
 * Time range selector and confidence threshold filter.
 * Updates graph + scatter plot in real-time.
 */

import { useState } from 'react';
import { motion } from 'framer-motion';
import { Clock, Filter, Activity, AlertTriangle, Shield, Zap } from 'lucide-react';
import { useThreatStore, useThreatStats } from './useThreatStore';

interface GlobalControlsProps {
  onGenerateData?: () => void;
  onClear?: () => void;
  isStreaming?: boolean;
}

export function GlobalControls({ onGenerateData, onClear, isStreaming }: GlobalControlsProps) {
  const { confidenceThreshold, setConfidenceThreshold, setTimeRange } = useThreatStore();
  const stats = useThreatStats();
  const [selectedTimeRange, setSelectedTimeRange] = useState<string>('1h');

  const timeRanges = [
    { label: '15m', value: 15 * 60 * 1000 },
    { label: '30m', value: 30 * 60 * 1000 },
    { label: '1h', value: 60 * 60 * 1000 },
    { label: '6h', value: 6 * 60 * 60 * 1000 },
    { label: '24h', value: 24 * 60 * 60 * 1000 },
  ];

  const handleTimeRangeChange = (label: string, value: number) => {
    setSelectedTimeRange(label);
    const now = Date.now();
    setTimeRange({ start: now - value, end: now });
  };

  return (
    <div className="bg-gray-900/50 backdrop-blur-sm border border-gray-800/50 rounded-2xl p-4">
      <div className="flex flex-wrap items-center justify-between gap-4">
        {/* Left: Stats */}
        <div className="flex items-center gap-6">
          {/* Total Nodes */}
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-cyan-500/20 flex items-center justify-center">
              <Activity className="w-5 h-5 text-cyan-400" />
            </div>
            <div>
              <div className="text-gray-500 text-xs uppercase tracking-wider">Total Nodes</div>
              <div className="text-white font-bold text-xl">{stats.total.toLocaleString()}</div>
            </div>
          </div>

          {/* Critical */}
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-red-500/20 flex items-center justify-center">
              <AlertTriangle className="w-5 h-5 text-red-400" />
            </div>
            <div>
              <div className="text-gray-500 text-xs uppercase tracking-wider">Critical</div>
              <div className="text-red-400 font-bold text-xl">{stats.critical}</div>
            </div>
          </div>

          {/* Elevated */}
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-orange-500/20 flex items-center justify-center">
              <Shield className="w-5 h-5 text-orange-400" />
            </div>
            <div>
              <div className="text-gray-500 text-xs uppercase tracking-wider">Elevated</div>
              <div className="text-orange-400 font-bold text-xl">{stats.elevated}</div>
            </div>
          </div>

          {/* Streaming indicator */}
          {isStreaming && (
            <div className="flex items-center gap-2 px-3 py-1.5 bg-green-500/20 rounded-lg border border-green-500/30">
              <motion.div
                className="w-2 h-2 rounded-full bg-green-400"
                animate={{ opacity: [1, 0.3, 1] }}
                transition={{ duration: 1.5, repeat: Infinity }}
              />
              <span className="text-green-400 text-sm font-medium">Live Streaming</span>
            </div>
          )}
        </div>

        {/* Right: Controls */}
        <div className="flex items-center gap-4">
          {/* Time Range */}
          <div className="flex items-center gap-2">
            <Clock className="w-4 h-4 text-gray-500" />
            <div className="flex bg-gray-800/50 rounded-lg p-1">
              {timeRanges.map(({ label, value }) => (
                <button
                  key={label}
                  onClick={() => handleTimeRangeChange(label, value)}
                  className={`px-3 py-1.5 text-sm font-medium rounded-md transition-colors ${
                    selectedTimeRange === label
                      ? 'bg-cyan-500 text-white'
                      : 'text-gray-400 hover:text-white hover:bg-gray-700/50'
                  }`}
                >
                  {label}
                </button>
              ))}
            </div>
          </div>

          {/* Confidence Threshold Slider */}
          <div className="flex items-center gap-3">
            <Filter className="w-4 h-4 text-gray-500" />
            <div className="flex items-center gap-3">
              <span className="text-gray-400 text-sm">Min Confidence:</span>
              <input
                type="range"
                min={0}
                max={100}
                value={confidenceThreshold}
                onChange={(e) => setConfidenceThreshold(Number(e.target.value))}
                className="w-32 h-2 bg-gray-700 rounded-lg appearance-none cursor-pointer accent-cyan-500"
              />
              <span className={`text-sm font-bold w-12 ${
                confidenceThreshold >= 80 ? 'text-red-400' : 
                confidenceThreshold >= 50 ? 'text-orange-400' : 'text-cyan-400'
              }`}>
                {confidenceThreshold}%
              </span>
            </div>
          </div>

          {/* Action Buttons */}
          <div className="flex items-center gap-2">
            {onGenerateData && (
              <button
                onClick={onGenerateData}
                className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg font-medium text-sm transition-colors"
              >
                <Zap className="w-4 h-4" />
                Generate Data
              </button>
            )}
            {onClear && (
              <button
                onClick={onClear}
                className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-gray-300 rounded-lg font-medium text-sm transition-colors"
              >
                Clear
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
