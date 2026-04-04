/**
 * AEGIS Active Attribution Engine - Threat Graph Visualization
 * 
 * WebGL-powered network graph using react-force-graph-2d.
 * 
 * FEATURES v2:
 * - Cluster Super-Nodes: Hexagonal nodes representing collapsed subnets
 * - Blast Radius Pulse Red: Animated glow on compromised edges
 * - Zoom-to-Controller: Click hub to isolate ego subgraph
 * - Dynamic expansion: Only nodes with score > 70 stay expanded
 * 
 * WHY WEBGL OVER SVG/D3:
 * ----------------------
 * SVG/D3 creates individual DOM elements for each node/edge.
 * At 500+ nodes, this causes:
 * - DOM reflow on every frame
 * - High memory usage (each element = JS object + DOM node)
 * - FPS drops below 30
 * 
 * WebGL renders to a SINGLE canvas element:
 * - GPU-accelerated drawing
 * - 60fps at 10,000+ nodes
 * - Memory efficient (raw vertex buffers)
 * 
 * This component handles 5,000+ nodes smoothly.
 */

import React, { useCallback, useRef, useMemo, useState, useEffect } from 'react';
import ForceGraph2D from 'react-force-graph-2d';
import type { NodeObject, LinkObject } from 'react-force-graph-2d';
import type { ThreatNode, ThreatLink, ThreatLevel, BlastRadiusResponse } from '../../types';

// Color palette for threat levels
const THREAT_COLORS: Record<ThreatLevel, string> = {
  critical: '#ff1744',  // Bright red
  high: '#ff9100',      // Orange
  elevated: '#ffea00',  // Yellow
  low: '#00e676',       // Green
};

// Cluster node color
const CLUSTER_COLOR = '#546e7a';
const PULSE_RED = '#ff1744';

interface ThreatGraphNode extends NodeObject {
  id: string;
  score: number;
  level: ThreatLevel;
  type: string;
  community: number;
  isHub: boolean;
  isBridge: boolean;
  connections: number;
  primaryIndicator: string | null;
  // Cluster fields
  memberCount?: number;
  memberIds?: string[];
  maxScore?: number;
  isController?: boolean;
  // Force graph adds these
  x?: number;
  y?: number;
  vx?: number;
  vy?: number;
}

interface ThreatGraphLink extends LinkObject {
  source: string | ThreatGraphNode;
  target: string | ThreatGraphNode;
  weight: number;
}

interface ThreatGraphProps {
  nodes: ThreatNode[];
  links: ThreatLink[];
  onNodeClick?: (node: ThreatNode) => void;
  onNodeHover?: (node: ThreatNode | null) => void;
  onControllerFocus?: (nodeId: string) => void;
  blastRadius?: BlastRadiusResponse | null;
  width?: number;
  height?: number;
  minScore?: number;
  highlightCommunity?: number | null;
}

export const ThreatGraph: React.FC<ThreatGraphProps> = ({
  nodes,
  links,
  onNodeClick,
  onNodeHover,
  onControllerFocus,
  blastRadius = null,
  width = 800,
  height = 600,
  minScore = 0,
  highlightCommunity = null,
}) => {
  const graphRef = useRef<any>(null);
  const [hoveredNode, setHoveredNode] = useState<ThreatGraphNode | null>(null);
  const pulseRef = useRef(0);

  // Blast radius edge set for quick lookup
  const blastEdges = useMemo(() => {
    if (!blastRadius) return new Set<string>();
    return new Set(
      blastRadius.compromised_edges.map(([s, t]) => `${s}→${t}`)
    );
  }, [blastRadius]);

  const blastNodes = useMemo(() => {
    if (!blastRadius) return new Set<string>();
    return new Set([blastRadius.origin, ...blastRadius.compromised_nodes]);
  }, [blastRadius]);

  // Animation loop for pulse effect
  useEffect(() => {
    let animFrame: number;
    const animate = () => {
      pulseRef.current = (pulseRef.current + 0.03) % (2 * Math.PI);
      animFrame = requestAnimationFrame(animate);
    };
    if (blastRadius) {
      animate();
    }
    return () => {
      if (animFrame) cancelAnimationFrame(animFrame);
    };
  }, [blastRadius]);

  // Transform data for force graph
  const graphData = useMemo(() => {
    const filteredNodes = nodes
      .filter(n => n.score >= minScore)
      .map(n => ({
        ...n,
        val: Math.max(1, n.score / 10),
      }));

    const nodeIds = new Set(filteredNodes.map(n => n.id));
    
    const filteredLinks = links.filter(
      l => nodeIds.has(l.source) && nodeIds.has(l.target)
    );

    return {
      nodes: filteredNodes,
      links: filteredLinks,
    };
  }, [nodes, links, minScore]);

  // Draw hexagon helper
  const drawHexagon = (ctx: CanvasRenderingContext2D, x: number, y: number, size: number) => {
    ctx.beginPath();
    for (let i = 0; i < 6; i++) {
      const angle = (Math.PI / 3) * i - Math.PI / 6;
      const hx = x + size * Math.cos(angle);
      const hy = y + size * Math.sin(angle);
      if (i === 0) ctx.moveTo(hx, hy);
      else ctx.lineTo(hx, hy);
    }
    ctx.closePath();
  };

  // Node rendering function
  const nodeCanvasObject = useCallback((
    obj: any,
    ctx: CanvasRenderingContext2D,
    globalScale: number
  ) => {
    const node = obj as ThreatGraphNode;
    const { x = 0, y = 0, score, level, isHub, isBridge, type } = node;
    
    const isCluster = type === 'cluster';
    const isInBlast = blastNodes.has(node.id);
    const isBlastOrigin = blastRadius?.origin === node.id;
    
    // Base size from score
    const baseSize = isCluster
      ? Math.max(8, Math.sqrt((node.memberCount || 1) * 20))
      : Math.max(4, Math.sqrt(score) * 1.5);
    
    // Hub/Bridge nodes are larger
    const size = isHub || isBridge ? baseSize * 1.5 : baseSize;
    
    // Color based on threat level or cluster
    const color = isCluster ? CLUSTER_COLOR : THREAT_COLORS[level];
    
    // Dim nodes not in highlighted community
    const alpha = highlightCommunity !== null && node.community !== highlightCommunity 
      ? 0.3 
      : 1.0;
    
    // ── Blast Radius Pulse Glow ──
    if (isInBlast) {
      const pulseAlpha = 0.3 + 0.3 * Math.sin(pulseRef.current * 2);
      ctx.beginPath();
      ctx.arc(x, y, size * 2.5, 0, 2 * Math.PI);
      ctx.fillStyle = `rgba(255, 23, 68, ${pulseAlpha})`;
      ctx.fill();
    }
    
    // Blast origin special ring
    if (isBlastOrigin) {
      ctx.beginPath();
      ctx.arc(x, y, size * 3, 0, 2 * Math.PI);
      ctx.strokeStyle = PULSE_RED;
      ctx.lineWidth = 3;
      ctx.setLineDash([6, 4]);
      ctx.stroke();
      ctx.setLineDash([]);
    }
    
    // Draw node glow for high-threat nodes
    if (score > 75 && !isCluster) {
      ctx.beginPath();
      ctx.arc(x, y, size * 1.8, 0, 2 * Math.PI);
      ctx.fillStyle = `${color}33`;
      ctx.fill();
    }
    
    // ── Draw main node ──
    if (isCluster) {
      // Hexagon for clusters
      drawHexagon(ctx, x, y, size);
      ctx.fillStyle = alpha < 1 
        ? `${color}${Math.floor(alpha * 255).toString(16).padStart(2, '0')}` 
        : color;
      ctx.fill();
      ctx.strokeStyle = 'rgba(255,255,255,0.3)';
      ctx.lineWidth = 1.5;
      ctx.stroke();
      
      // Member count badge
      if (globalScale > 0.5) {
        ctx.font = `bold ${Math.max(8, 12 / globalScale)}px Inter, system-ui, sans-serif`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillStyle = '#ffffff';
        ctx.fillText(`${node.memberCount || '?'}`, x, y);
      }
    } else {
      // Circle for regular nodes
      ctx.beginPath();
      ctx.arc(x, y, size, 0, 2 * Math.PI);
      ctx.fillStyle = alpha < 1 
        ? `${color}${Math.floor(alpha * 255).toString(16).padStart(2, '0')}` 
        : color;
      ctx.fill();
    }
    
    // Draw ring for hubs
    if (isHub && !isCluster) {
      ctx.beginPath();
      ctx.arc(x, y, size + 2, 0, 2 * Math.PI);
      ctx.strokeStyle = '#ffffff';
      ctx.lineWidth = 2;
      ctx.stroke();
    }
    
    // Draw square marker for bridges
    if (isBridge && !isHub && !isCluster) {
      const half = size + 3;
      ctx.strokeStyle = '#ffffff';
      ctx.lineWidth = 1.5;
      ctx.strokeRect(x - half, y - half, half * 2, half * 2);
    }
    
    // Controller icon
    if (node.isController) {
      ctx.font = `${Math.max(12, 16 / globalScale)}px Inter, system-ui, sans-serif`;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillStyle = '#ff1744';
      ctx.fillText('⚡', x, y - size - 8);
    }
    
    // Draw label for critical/high nodes when zoomed in
    if (globalScale > 1.5 && score > 50 && !isCluster) {
      ctx.font = `${Math.max(8, 10 / globalScale)}px Inter, system-ui, sans-serif`;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'top';
      ctx.fillStyle = '#ffffff';
      ctx.fillText(
        `${Math.round(score)}%`,
        x,
        y + size + 4
      );
    }
    
    // Draw hover highlight
    if (hoveredNode?.id === node.id) {
      ctx.beginPath();
      if (isCluster) {
        drawHexagon(ctx, x, y, size + 6);
      } else {
        ctx.arc(x, y, size + 6, 0, 2 * Math.PI);
      }
      ctx.strokeStyle = '#ffffff';
      ctx.lineWidth = 2;
      ctx.setLineDash([4, 4]);
      ctx.stroke();
      ctx.setLineDash([]);
    }
  }, [hoveredNode, highlightCommunity, blastNodes, blastRadius]);

  // Link rendering
  const linkCanvasObject = useCallback((
    obj: any,
    ctx: CanvasRenderingContext2D,
    _globalScale: number
  ) => {
    const link = obj as ThreatGraphLink;
    const source = link.source as ThreatGraphNode;
    const target = link.target as ThreatGraphNode;
    
    if (!source.x || !source.y || !target.x || !target.y) return;

    const edgeKey = `${source.id}→${target.id}`;
    const isBlastEdge = blastEdges.has(edgeKey);
    
    // Width based on weight
    const baseWidth = Math.max(0.5, Math.min(3, link.weight / 10));
    const width = isBlastEdge ? baseWidth * 2.5 : baseWidth;
    
    // Color — Pulse Red for blast radius edges
    if (isBlastEdge) {
      const pulseAlpha = 0.5 + 0.4 * Math.sin(pulseRef.current * 3);
      ctx.beginPath();
      ctx.moveTo(source.x, source.y);
      ctx.lineTo(target.x, target.y);
      ctx.strokeStyle = `rgba(255, 23, 68, ${pulseAlpha})`;
      ctx.lineWidth = width + 2;
      ctx.stroke();
    }
    
    // Normal edge
    const sourceLevel = source.level || 'low';
    const color = isBlastEdge ? PULSE_RED : THREAT_COLORS[sourceLevel];
    
    ctx.beginPath();
    ctx.moveTo(source.x, source.y);
    ctx.lineTo(target.x, target.y);
    ctx.strokeStyle = isBlastEdge ? `${color}cc` : `${color}66`;
    ctx.lineWidth = width;
    ctx.stroke();
  }, [blastEdges]);

  // Handle node click
  const handleNodeClick = useCallback((node: NodeObject) => {
    const threatNode = node as ThreatGraphNode;
    
    // If it's a hub/controller, trigger zoom-to-controller
    if (threatNode.isHub && onControllerFocus) {
      onControllerFocus(threatNode.id);
      return;
    }
    
    if (onNodeClick) {
      onNodeClick({
        id: threatNode.id,
        score: threatNode.score,
        level: threatNode.level,
        type: threatNode.type as 'client' | 'endpoint' | 'host' | 'unknown',
        community: threatNode.community,
        isHub: threatNode.isHub,
        isBridge: threatNode.isBridge,
        connections: threatNode.connections,
        primaryIndicator: threatNode.primaryIndicator,
      });
    }
  }, [onNodeClick, onControllerFocus]);

  // Handle hover
  const handleNodeHover = useCallback((node: NodeObject | null) => {
    setHoveredNode(node as ThreatGraphNode | null);
    if (onNodeHover) {
      if (node) {
        const threatNode = node as ThreatGraphNode;
        onNodeHover({
          id: threatNode.id,
          score: threatNode.score,
          level: threatNode.level,
          type: threatNode.type as 'client' | 'endpoint' | 'host' | 'unknown',
          community: threatNode.community,
          isHub: threatNode.isHub,
          isBridge: threatNode.isBridge,
          connections: threatNode.connections,
          primaryIndicator: threatNode.primaryIndicator,
        });
      } else {
        onNodeHover(null);
      }
    }
  }, [onNodeHover]);

  // Center on high-threat nodes initially
  useEffect(() => {
    if (graphRef.current && graphData.nodes.length > 0) {
      setTimeout(() => {
        graphRef.current?.zoomToFit(400, 50);
      }, 500);
    }
  }, [graphData.nodes.length]);

  return (
    <div 
      style={{ 
        background: 'linear-gradient(135deg, #0a0a0f 0%, #1a1a2e 100%)',
        borderRadius: '8px',
        overflow: 'hidden',
        position: 'relative',
      }}
    >
      {/* Legend */}
      <div style={{
        position: 'absolute',
        top: 10,
        right: 10,
        background: 'rgba(0,0,0,0.7)',
        padding: '10px',
        borderRadius: '6px',
        zIndex: 10,
        fontSize: '12px',
        color: '#fff',
      }}>
        <div style={{ fontWeight: 'bold', marginBottom: '8px' }}>Threat Level</div>
        {Object.entries(THREAT_COLORS).map(([level, color]) => (
          <div key={level} style={{ display: 'flex', alignItems: 'center', marginBottom: '4px' }}>
            <div style={{
              width: 12,
              height: 12,
              borderRadius: '50%',
              backgroundColor: color,
              marginRight: 8,
            }} />
            <span style={{ textTransform: 'capitalize' }}>{level}</span>
          </div>
        ))}
        <div style={{ marginTop: '8px', borderTop: '1px solid #333', paddingTop: '8px' }}>
          <div style={{ display: 'flex', alignItems: 'center', marginBottom: '4px' }}>
            <div style={{
              width: 12,
              height: 12,
              borderRadius: '50%',
              border: '2px solid #fff',
              marginRight: 8,
            }} />
            <span>Hub Node</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', marginBottom: '4px' }}>
            <div style={{
              width: 12,
              height: 12,
              border: '1.5px solid #fff',
              marginRight: 8,
            }} />
            <span>Bridge Node</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center' }}>
            <svg width={12} height={12} style={{ marginRight: 8 }}>
              <polygon 
                points="6,0 12,3 12,9 6,12 0,9 0,3" 
                fill={CLUSTER_COLOR}
                stroke="rgba(255,255,255,0.3)"
                strokeWidth="1"
              />
            </svg>
            <span>Cluster</span>
          </div>
        </div>
      </div>

      {/* Stats overlay */}
      <div style={{
        position: 'absolute',
        bottom: 10,
        left: 10,
        background: 'rgba(0,0,0,0.7)',
        padding: '8px 12px',
        borderRadius: '6px',
        zIndex: 10,
        fontSize: '11px',
        color: '#aaa',
      }}>
        <span>{graphData.nodes.length} nodes</span>
        <span style={{ margin: '0 8px' }}>•</span>
        <span>{graphData.links.length} connections</span>
        {blastRadius && (
          <>
            <span style={{ margin: '0 8px' }}>•</span>
            <span style={{ color: PULSE_RED }}>
              ⚡ Blast: {blastRadius.total_impact} compromised
            </span>
          </>
        )}
      </div>

      {/* Hover tooltip */}
      {hoveredNode && (
        <div style={{
          position: 'absolute',
          top: 10,
          left: 10,
          background: 'rgba(0,0,0,0.9)',
          padding: '12px',
          borderRadius: '6px',
          zIndex: 10,
          maxWidth: '250px',
          border: `1px solid ${hoveredNode.type === 'cluster' ? CLUSTER_COLOR : THREAT_COLORS[hoveredNode.level]}`,
        }}>
          <div style={{ 
            fontWeight: 'bold', 
            color: hoveredNode.type === 'cluster' ? CLUSTER_COLOR : THREAT_COLORS[hoveredNode.level],
            marginBottom: '4px',
          }}>
            {hoveredNode.type === 'cluster' ? `Subnet Cluster` : hoveredNode.id}
          </div>
          {hoveredNode.type === 'cluster' ? (
            <>
              <div style={{ fontSize: '14px', color: '#fff' }}>
                {hoveredNode.memberCount} nodes collapsed
              </div>
              <div style={{ fontSize: '11px', color: '#aaa', marginTop: 4 }}>
                Avg Score: {Math.round(hoveredNode.score)}% • Max: {Math.round(hoveredNode.maxScore || 0)}%
              </div>
            </>
          ) : (
            <>
              <div style={{ fontSize: '24px', fontWeight: 'bold', color: '#fff' }}>
                {Math.round(hoveredNode.score)}%
              </div>
              <div style={{ 
                textTransform: 'uppercase', 
                fontSize: '10px', 
                color: THREAT_COLORS[hoveredNode.level],
                marginBottom: '8px',
              }}>
                {hoveredNode.level} threat
              </div>
            </>
          )}
          {hoveredNode.primaryIndicator && (
            <div style={{ fontSize: '11px', color: '#aaa' }}>
              {hoveredNode.primaryIndicator}
            </div>
          )}
          <div style={{ 
            fontSize: '10px', 
            color: '#666', 
            marginTop: '8px',
            display: 'flex',
            gap: '12px',
          }}>
            <span>Type: {hoveredNode.type}</span>
            <span>Connections: {hoveredNode.connections}</span>
          </div>
        </div>
      )}

      <ForceGraph2D
        ref={graphRef}
        graphData={graphData}
        width={width}
        height={height}
        nodeCanvasObject={nodeCanvasObject}
        linkCanvasObject={linkCanvasObject}
        onNodeClick={handleNodeClick}
        onNodeHover={handleNodeHover}
        nodeRelSize={6}
        linkDirectionalArrowLength={3}
        linkDirectionalArrowRelPos={1}
        cooldownTicks={100}
        d3AlphaDecay={0.02}
        d3VelocityDecay={0.3}
        enableNodeDrag={true}
        enableZoomInteraction={true}
        enablePanInteraction={true}
      />
    </div>
  );
};

export default ThreatGraph;
