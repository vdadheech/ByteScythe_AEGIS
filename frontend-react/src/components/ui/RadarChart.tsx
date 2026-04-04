/**
 * AEGIS Active Attribution Engine — XAI Radar Chart
 * 
 * Canvas-rendered radar/spider chart showing 5 C2 detection signal axes:
 * - Timing Entropy
 * - Header Sequence Deviation  
 * - Graph Influence
 * - Behavioral Anomaly
 * - HTTP Method Ratio
 * 
 * Cyber-aesthetic: neon-line radar with dark background, glowing active areas.
 */

import React, { useEffect, useRef, useMemo } from 'react';
import type { RadarAxis } from '../../types';

interface RadarChartProps {
  data: RadarAxis[];
  width?: number;
  height?: number;
  color?: string;
  showLabels?: boolean;
}

// Neon color palette
const NEON_CYAN = '#00e5ff';
const NEON_FILL = 'rgba(0, 229, 255, 0.15)';
const GRID_COLOR = 'rgba(255, 255, 255, 0.08)';
const LABEL_COLOR = 'rgba(255, 255, 255, 0.7)';
const AXIS_COLOR = 'rgba(255, 255, 255, 0.12)';
const DOT_GLOW = 'rgba(0, 229, 255, 0.6)';

export const RadarChart: React.FC<RadarChartProps> = ({
  data,
  width = 320,
  height = 320,
  color = NEON_CYAN,
  showLabels = true,
}) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  const axes = useMemo(() => data.length, [data]);
  const centerX = width / 2;
  const centerY = height / 2;
  const radius = Math.min(centerX, centerY) - 50;

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas || axes < 3) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    // HiDPI scaling
    const dpr = window.devicePixelRatio || 1;
    canvas.width = width * dpr;
    canvas.height = height * dpr;
    ctx.scale(dpr, dpr);

    // Clear
    ctx.clearRect(0, 0, width, height);

    const angleStep = (2 * Math.PI) / axes;
    const levels = 5; // Concentric grid levels

    // ── Draw concentric grid ──
    for (let l = 1; l <= levels; l++) {
      const r = (radius * l) / levels;
      ctx.beginPath();
      for (let i = 0; i <= axes; i++) {
        const angle = i * angleStep - Math.PI / 2;
        const x = centerX + r * Math.cos(angle);
        const y = centerY + r * Math.sin(angle);
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      }
      ctx.closePath();
      ctx.strokeStyle = GRID_COLOR;
      ctx.lineWidth = 1;
      ctx.stroke();
    }

    // ── Draw axis lines ──
    for (let i = 0; i < axes; i++) {
      const angle = i * angleStep - Math.PI / 2;
      ctx.beginPath();
      ctx.moveTo(centerX, centerY);
      ctx.lineTo(
        centerX + radius * Math.cos(angle),
        centerY + radius * Math.sin(angle)
      );
      ctx.strokeStyle = AXIS_COLOR;
      ctx.lineWidth = 1;
      ctx.stroke();
    }

    // ── Draw data polygon (filled) ──
    ctx.beginPath();
    for (let i = 0; i < axes; i++) {
      const angle = i * angleStep - Math.PI / 2;
      const value = Math.min(1, Math.max(0, data[i]?.value || 0));
      const r = radius * value;
      const x = centerX + r * Math.cos(angle);
      const y = centerY + r * Math.sin(angle);
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    }
    ctx.closePath();

    // Glow fill
    ctx.fillStyle = NEON_FILL;
    ctx.fill();

    // Neon stroke
    ctx.strokeStyle = color;
    ctx.lineWidth = 2;
    ctx.shadowColor = color;
    ctx.shadowBlur = 8;
    ctx.stroke();
    ctx.shadowBlur = 0;

    // ── Draw data points ──
    for (let i = 0; i < axes; i++) {
      const angle = i * angleStep - Math.PI / 2;
      const value = Math.min(1, Math.max(0, data[i]?.value || 0));
      const r = radius * value;
      const x = centerX + r * Math.cos(angle);
      const y = centerY + r * Math.sin(angle);

      // Outer glow
      ctx.beginPath();
      ctx.arc(x, y, 6, 0, 2 * Math.PI);
      ctx.fillStyle = DOT_GLOW;
      ctx.fill();

      // Inner dot
      ctx.beginPath();
      ctx.arc(x, y, 3, 0, 2 * Math.PI);
      ctx.fillStyle = color;
      ctx.fill();
    }

    // ── Draw labels ──
    if (showLabels) {
      ctx.font = '11px Inter, system-ui, sans-serif';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';

      for (let i = 0; i < axes; i++) {
        const angle = i * angleStep - Math.PI / 2;
        const labelR = radius + 30;
        let x = centerX + labelR * Math.cos(angle);
        let y = centerY + labelR * Math.sin(angle);

        // Adjust text alignment based on position
        if (Math.cos(angle) > 0.1) ctx.textAlign = 'left';
        else if (Math.cos(angle) < -0.1) ctx.textAlign = 'right';
        else ctx.textAlign = 'center';

        const label = data[i]?.axis || `Signal ${i + 1}`;
        const value = data[i]?.value || 0;

        // Label
        ctx.fillStyle = LABEL_COLOR;
        ctx.fillText(label, x, y - 8);

        // Value
        ctx.fillStyle = value > 0.7 ? '#ff1744' : value > 0.4 ? '#ffea00' : '#00e676';
        ctx.font = 'bold 12px Inter, system-ui, sans-serif';
        ctx.fillText(`${(value * 100).toFixed(0)}%`, x, y + 8);
        ctx.font = '11px Inter, system-ui, sans-serif';
      }
    }

    // ── Draw center score ──
    const avgScore = data.reduce((sum, d) => sum + (d.value || 0), 0) / axes;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.font = 'bold 22px Inter, system-ui, sans-serif';
    ctx.fillStyle = avgScore > 0.7 ? '#ff1744' : avgScore > 0.4 ? '#ffea00' : '#00e676';
    ctx.shadowColor = ctx.fillStyle;
    ctx.shadowBlur = 12;
    ctx.fillText(`${(avgScore * 100).toFixed(0)}`, centerX, centerY - 6);
    ctx.shadowBlur = 0;
    ctx.font = '10px Inter, system-ui, sans-serif';
    ctx.fillStyle = 'rgba(255,255,255,0.4)';
    ctx.fillText('C2 SCORE', centerX, centerY + 12);

  }, [data, width, height, color, axes, centerX, centerY, radius, showLabels]);

  return (
    <div style={{
      position: 'relative',
      width,
      height,
      background: 'linear-gradient(135deg, rgba(10,10,15,0.95) 0%, rgba(20,20,35,0.95) 100%)',
      borderRadius: 12,
      border: '1px solid rgba(255,255,255,0.06)',
      padding: 0,
    }}>
      {/* Title */}
      <div style={{
        position: 'absolute',
        top: 8,
        left: 12,
        fontSize: 10,
        textTransform: 'uppercase',
        letterSpacing: '1.5px',
        color: 'rgba(255,255,255,0.3)',
        fontWeight: 600,
      }}>
        Attribution Radar
      </div>

      <canvas
        ref={canvasRef}
        style={{ width, height }}
        width={width}
        height={height}
      />
    </div>
  );
};

export default RadarChart;
