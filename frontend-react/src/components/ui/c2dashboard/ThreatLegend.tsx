/**
 * AEGIS Threat Legend
 * 
 * Mini legend showing node color meanings.
 */

import { motion } from 'framer-motion';
import { NODE_COLORS } from './types';

export function ThreatLegend() {
  const items = [
    { status: 'normal', label: 'Normal', color: NODE_COLORS.normal, threshold: '<30%' },
    { status: 'suspicious', label: 'Suspicious', color: NODE_COLORS.suspicious, threshold: '30-50%' },
    { status: 'elevated', label: 'Elevated', color: NODE_COLORS.elevated, threshold: '50-80%' },
    { status: 'critical', label: 'Critical', color: NODE_COLORS.critical, threshold: '80-90%' },
    { status: 'controller', label: 'Controller', color: NODE_COLORS.controller, threshold: '>90%' },
  ];

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className="absolute top-4 right-4 bg-gray-900/90 backdrop-blur-sm rounded-xl p-4 border border-gray-700/50 shadow-xl pointer-events-none z-10"
    >
      <div className="text-gray-400 text-xs uppercase tracking-wider mb-3 font-medium">
        Threat Level
      </div>
      <div className="space-y-2">
        {items.map(({ status, label, color, threshold }) => (
          <div key={status} className="flex items-center gap-3">
            <div
              className="w-3 h-3 rounded-full"
              style={{ backgroundColor: color }}
            />
            <span className="text-gray-300 text-sm flex-1">{label}</span>
            <span className="text-gray-500 text-xs">{threshold}</span>
          </div>
        ))}
      </div>
    </motion.div>
  );
}
