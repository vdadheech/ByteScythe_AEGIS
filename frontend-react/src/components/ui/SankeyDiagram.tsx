/**
 * AEGIS Active Attribution Engine — Sankey Diagram
 * 
 * D3-powered Sankey diagram for "Golden Image" contrast.
 * Visualises header-order transition flows:
 *   - Legitimate sequences (green/teal)
 *   - Shadow sequences (red/orange)
 * 
 * Data comes from the Markov Transition Matrix API.
 */

import React, { useEffect, useRef, useMemo } from 'react';
import * as d3 from 'd3';
import type { SankeyData as SankeyDataType } from '../../types';

interface SankeyDiagramProps {
  data: SankeyDataType;
  width?: number;
  height?: number;
}

// Color scheme
const LEGITIMATE_COLOR = '#00e5ff'; // Cyan for legitimate flows
const SHADOW_COLOR = '#ff1744';      // Red for shadow flows
const NODE_COLOR = '#37474f';
const BG_COLOR = 'rgba(10, 10, 15, 0.95)';
const TEXT_COLOR = 'rgba(255,255,255,0.7)';

/**
 * Simple Sankey layout engine (no d3-sankey dependency).
 * Positions nodes in columns and calculates link paths.
 */
function computeSankeyLayout(
  data: SankeyDataType,
  width: number,
  height: number,
  padding: number = 60,
) {
  if (!data.nodes.length || !data.links.length) {
    return { nodes: [], links: [] };
  }

  // Assign depth (column) via BFS from source nodes
  const nodeDepths: number[] = new Array(data.nodes.length).fill(-1);
  const nodeOutLinks: number[][] = Array.from({ length: data.nodes.length }, () => []);
  const nodeInLinks: number[][] = Array.from({ length: data.nodes.length }, () => []);

  data.links.forEach((link, i) => {
    nodeOutLinks[link.source].push(i);
    nodeInLinks[link.target].push(i);
  });

  // Find source nodes (no incoming links)
  const sourceNodes = data.nodes
    .map((_, i) => i)
    .filter(i => nodeInLinks[i].length === 0);

  // BFS to assign depths
  const queue = sourceNodes.map(i => ({ node: i, depth: 0 }));
  const visited = new Set<number>();

  if (queue.length === 0 && data.nodes.length > 0) {
    // All nodes have incoming links — start from node 0
    queue.push({ node: 0, depth: 0 });
  }

  while (queue.length > 0) {
    const { node, depth } = queue.shift()!;
    if (visited.has(node)) continue;
    visited.add(node);
    nodeDepths[node] = depth;

    for (const linkIdx of nodeOutLinks[node]) {
      const targetNode = data.links[linkIdx].target;
      if (!visited.has(targetNode)) {
        queue.push({ node: targetNode, depth: depth + 1 });
      }
    }
  }

  // Assign remaining unvisited nodes
  const maxDepth = Math.max(...nodeDepths.filter(d => d >= 0), 0);
  nodeDepths.forEach((d, i) => {
    if (d < 0) nodeDepths[i] = maxDepth + 1;
  });

  const finalMaxDepth = Math.max(...nodeDepths);
  const columnWidth = (width - 2 * padding) / Math.max(finalMaxDepth, 1);

  // Group nodes by depth
  const columns: number[][] = [];
  for (let d = 0; d <= finalMaxDepth; d++) {
    columns.push(data.nodes.map((_, i) => i).filter(i => nodeDepths[i] === d));
  }

  // Calculate node positions
  const nodeHeight = 24;
  const nodeGap = 8;
  const nodePositions: { x: number; y: number; w: number; h: number }[] = [];

  columns.forEach((col, colIdx) => {
    const totalH = col.length * nodeHeight + (col.length - 1) * nodeGap;
    const startY = (height - totalH) / 2;

    col.forEach((nodeIdx, rowIdx) => {
      nodePositions[nodeIdx] = {
        x: padding + colIdx * columnWidth,
        y: startY + rowIdx * (nodeHeight + nodeGap),
        w: Math.min(columnWidth * 0.6, 120),
        h: nodeHeight,
      };
    });
  });

  // Calculate link paths
  const layoutLinks = data.links.map((link) => {
    const src = nodePositions[link.source];
    const tgt = nodePositions[link.target];

    if (!src || !tgt) return null;

    const thickness = Math.max(2, Math.min(12, link.value / 10));

    return {
      source: link.source,
      target: link.target,
      value: link.value,
      category: link.category,
      thickness,
      path: {
        x0: src.x + src.w,
        y0: src.y + src.h / 2,
        x1: tgt.x,
        y1: tgt.y + tgt.h / 2,
      },
    };
  }).filter(Boolean);

  return {
    nodes: data.nodes.map((n, i) => ({
      ...n,
      index: i,
      ...nodePositions[i],
    })),
    links: layoutLinks as NonNullable<typeof layoutLinks[number]>[],
  };
}

export const SankeyDiagram: React.FC<SankeyDiagramProps> = ({
  data,
  width = 700,
  height = 400,
}) => {
  const svgRef = useRef<SVGSVGElement>(null);

  const layout = useMemo(() => computeSankeyLayout(data, width, height), [data, width, height]);

  useEffect(() => {
    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    if (!layout.nodes.length) return;

    const defs = svg.append('defs');

    // Glow filter
    const glow = defs.append('filter').attr('id', 'sankey-glow');
    glow.append('feGaussianBlur').attr('stdDeviation', '3').attr('result', 'blur');
    glow.append('feMerge')
      .selectAll('feMergeNode')
      .data(['blur', 'SourceGraphic'])
      .enter()
      .append('feMergeNode')
      .attr('in', d => d);

    // Draw links
    const linkGroup = svg.append('g').attr('class', 'links');

    layout.links.forEach(link => {
      const { x0, y0, x1, y1 } = link.path;
      const midX = (x0 + x1) / 2;
      const color = link.category === 'legitimate' ? LEGITIMATE_COLOR : SHADOW_COLOR;

      // Link path (cubic bezier)
      linkGroup.append('path')
        .attr('d', `M${x0},${y0} C${midX},${y0} ${midX},${y1} ${x1},${y1}`)
        .attr('fill', 'none')
        .attr('stroke', color)
        .attr('stroke-width', link.thickness)
        .attr('opacity', 0.4)
        .attr('filter', 'url(#sankey-glow)')
        .on('mouseover', function () {
          d3.select(this).attr('opacity', 0.8).attr('stroke-width', link.thickness + 2);
        })
        .on('mouseout', function () {
          d3.select(this).attr('opacity', 0.4).attr('stroke-width', link.thickness);
        });
    });

    // Draw nodes
    const nodeGroup = svg.append('g').attr('class', 'nodes');

    layout.nodes.forEach(node => {
      if (!node.x && node.x !== 0) return;

      const g = nodeGroup.append('g')
        .attr('transform', `translate(${node.x}, ${node.y})`);

      // Node rect
      g.append('rect')
        .attr('width', node.w)
        .attr('height', node.h)
        .attr('rx', 4)
        .attr('fill', NODE_COLOR)
        .attr('stroke', 'rgba(255,255,255,0.1)')
        .attr('stroke-width', 1);

      // Node label
      g.append('text')
        .attr('x', node.w / 2)
        .attr('y', node.h / 2)
        .attr('text-anchor', 'middle')
        .attr('dominant-baseline', 'central')
        .attr('fill', TEXT_COLOR)
        .attr('font-size', '10px')
        .attr('font-family', 'Inter, system-ui, sans-serif')
        .text(node.name.length > 15 ? node.name.slice(0, 14) + '…' : node.name);
    });

    // Legend
    const legend = svg.append('g')
      .attr('transform', `translate(${width - 180}, 15)`);

    [
      { label: 'Legitimate Sequence', color: LEGITIMATE_COLOR },
      { label: 'Shadow Sequence', color: SHADOW_COLOR },
    ].forEach(({ label, color }, i) => {
      const g = legend.append('g').attr('transform', `translate(0, ${i * 20})`);
      g.append('rect')
        .attr('width', 14)
        .attr('height', 3)
        .attr('rx', 1.5)
        .attr('fill', color)
        .attr('opacity', 0.7)
        .attr('y', 5);
      g.append('text')
        .attr('x', 20)
        .attr('y', 10)
        .attr('fill', 'rgba(255,255,255,0.5)')
        .attr('font-size', '10px')
        .attr('font-family', 'Inter, system-ui, sans-serif')
        .text(label);
    });

  }, [layout, width, height]);

  return (
    <div style={{
      background: `linear-gradient(135deg, ${BG_COLOR} 0%, rgba(20,20,35,0.95) 100%)`,
      borderRadius: 12,
      border: '1px solid rgba(255,255,255,0.06)',
      overflow: 'hidden',
      position: 'relative',
    }}>
      {/* Title */}
      <div style={{
        padding: '10px 14px 0',
        fontSize: 10,
        textTransform: 'uppercase',
        letterSpacing: '1.5px',
        color: 'rgba(255,255,255,0.3)',
        fontWeight: 600,
      }}>
        Golden Image Contrast — Header Sequence Flows
      </div>

      <svg
        ref={svgRef}
        width={width}
        height={height}
        style={{ display: 'block' }}
      />

      {/* Empty state */}
      {(!data.nodes.length || !data.links.length) && (
        <div style={{
          position: 'absolute',
          top: '50%',
          left: '50%',
          transform: 'translate(-50%, -50%)',
          color: 'rgba(255,255,255,0.3)',
          fontSize: 13,
          textAlign: 'center',
        }}>
          No baseline data available.<br />
          Waiting for traffic analysis…
        </div>
      )}
    </div>
  );
};

export default SankeyDiagram;
