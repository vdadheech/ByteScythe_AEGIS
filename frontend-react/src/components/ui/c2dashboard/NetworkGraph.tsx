/**
 * AEGIS Network Attack Graph - WebGL Force-Directed Visualization
 * 
 * Performance-optimized for 10,000+ nodes using Canvas/WebGL rendering.
 * Features: dynamic node sizing, confidence-based coloring, glow effects.
 */

import { useCallback, useEffect, useRef, useMemo } from 'react';
import ForceGraph2D from 'react-force-graph-2d';
import { useThreatStore } from './useThreatStore';
import type { ThreatNode, ThreatLink } from './types';
import { NODE_COLORS } from './types';

// Define our own types since react-force-graph-2d doesn't export them
type NodeObject = Record<string, any>;
type LinkObject = Record<string, any>;

interface NetworkGraphProps {
  width?: number;
  height?: number;
  onReady?: () => void;
}

// Glow effect configuration
const GLOW_COLORS = {
  critical: 'rgba(239, 68, 68, 0.6)',
  controller: 'rgba(220, 38, 38, 0.8)',
};

export function NetworkGraph({ width = 800, height = 600, onReady }: NetworkGraphProps) {
  const graphRef = useRef<any>(null);
  const animationRef = useRef<number>(0);
  
  // Subscribe to raw state and compute filtered data in useMemo
  const nodesMap = useThreatStore(state => state.nodes);
  const allLinks = useThreatStore(state => state.links);
  const selectNode = useThreatStore(state => state.selectNode);
  const hoverNode = useThreatStore(state => state.hoverNode);
  const selectedNodeId = useThreatStore(state => state.selectedNodeId);
  const hoveredNodeId = useThreatStore(state => state.hoveredNodeId);
  const confidenceThreshold = useThreatStore(state => state.confidenceThreshold);
  const totalNodes = useThreatStore(state => state.totalNodes);
  
  // Filter nodes and links in useMemo (reacts to state changes)
  const nodes = useMemo(() => {
    return Array.from(nodesMap.values()).filter(n => n.confidence >= confidenceThreshold);
  }, [nodesMap, confidenceThreshold]);
  
  const links = useMemo(() => {
    const nodeIds = new Set(nodes.map(n => n.id));
    return allLinks.filter(link => {
      const sourceId = typeof link.source === 'string' ? link.source : link.source.id;
      const targetId = typeof link.target === 'string' ? link.target : link.target.id;
      return nodeIds.has(sourceId) && nodeIds.has(targetId);
    });
  }, [allLinks, nodes]);

  // Memoize graph data for performance - now depends on actual data
  const graphData = useMemo(() => {
    console.log('[NetworkGraph] Updating graph data:', nodes.length, 'nodes', links.length, 'links');
    return {
      nodes: nodes.map(n => ({ ...n })),
      links: links.map(l => ({
        ...l,
        source: typeof l.source === 'string' ? l.source : l.source.id,
        target: typeof l.target === 'string' ? l.target : l.target.id,
      })),
    };
  }, [nodes, links, confidenceThreshold, totalNodes]);

  // Animation frame for pulsing high-threat nodes
  useEffect(() => {
    const animate = () => {
      animationRef.current = requestAnimationFrame(animate);
    };
    animate();
    return () => cancelAnimationFrame(animationRef.current);
  }, []);

  // Initial zoom to fit
  useEffect(() => {
    if (graphRef.current && graphData.nodes.length > 0) {
      setTimeout(() => {
        graphRef.current?.zoomToFit(400, 50);
        onReady?.();
      }, 500);
    }
  }, [graphData.nodes.length, onReady]);

  // Custom node rendering with glow effects
  const paintNode = useCallback((node: NodeObject, ctx: CanvasRenderingContext2D, globalScale: number) => {
    const threatNode = node as unknown as ThreatNode;
    const { confidence, centrality, status, id } = threatNode;
    
    // Calculate node size based on centrality (min 4, max 16)
    const baseSize = 4 + centrality * 12;
    const size = baseSize / Math.sqrt(globalScale);
    
    const x = node.x ?? 0;
    const y = node.y ?? 0;
    
    // Glow effect for high-threat nodes
    if (confidence >= 80) {
      const glowColor = status === 'controller' ? GLOW_COLORS.controller : GLOW_COLORS.critical;
      const pulse = Math.sin(Date.now() / 300) * 0.3 + 0.7;
      
      ctx.beginPath();
      ctx.arc(x, y, size * 2.5 * pulse, 0, 2 * Math.PI);
      ctx.fillStyle = glowColor;
      ctx.fill();
      
      ctx.beginPath();
      ctx.arc(x, y, size * 1.8 * pulse, 0, 2 * Math.PI);
      ctx.fillStyle = status === 'controller' ? 'rgba(220, 38, 38, 0.4)' : 'rgba(239, 68, 68, 0.3)';
      ctx.fill();
    }
    
    // Selection ring
    if (id === selectedNodeId) {
      ctx.beginPath();
      ctx.arc(x, y, size + 4, 0, 2 * Math.PI);
      ctx.strokeStyle = '#FBBF24';
      ctx.lineWidth = 2;
      ctx.stroke();
    }
    
    // Hover ring
    if (id === hoveredNodeId && id !== selectedNodeId) {
      ctx.beginPath();
      ctx.arc(x, y, size + 3, 0, 2 * Math.PI);
      ctx.strokeStyle = 'rgba(255, 255, 255, 0.5)';
      ctx.lineWidth = 1.5;
      ctx.stroke();
    }
    
    // Main node circle
    ctx.beginPath();
    ctx.arc(x, y, size, 0, 2 * Math.PI);
    ctx.fillStyle = NODE_COLORS[status];
    ctx.fill();
    
    // Inner highlight for controllers
    if (status === 'controller') {
      ctx.beginPath();
      ctx.arc(x, y, size * 0.4, 0, 2 * Math.PI);
      ctx.fillStyle = '#FEF3C7';
      ctx.fill();
    }
  }, [selectedNodeId, hoveredNodeId]);

  // Pointer area for click/hover detection
  const paintNodePointerArea = useCallback((node: NodeObject, color: string, ctx: CanvasRenderingContext2D, globalScale: number) => {
    const threatNode = node as unknown as ThreatNode;
    const baseSize = 4 + threatNode.centrality * 12;
    const size = baseSize / Math.sqrt(globalScale);
    
    // Add 12px of visual screen-space padding to make clicking extremely easy
    const hitPadding = 12 / globalScale; 
    
    ctx.fillStyle = color;
    ctx.beginPath();
    ctx.arc(node.x ?? 0, node.y ?? 0, size + hitPadding, 0, 2 * Math.PI);
    ctx.fill();
  }, []);

  // Link styling
  const getLinkColor = useCallback((link: LinkObject) => {
    const threatLink = link as unknown as ThreatLink;
    switch (threatLink.type) {
      case 'c2': return 'rgba(239, 68, 68, 0.6)';
      case 'lateral': return 'rgba(249, 115, 22, 0.4)';
      default: return 'rgba(59, 130, 246, 0.15)';
    }
  }, []);

  const getLinkWidth = useCallback((link: LinkObject) => {
    const threatLink = link as unknown as ThreatLink;
    return threatLink.type === 'c2' ? 2 : threatLink.type === 'lateral' ? 1.5 : 0.5;
  }, []);

  // Node click handler
  const handleNodeClick = useCallback((node: NodeObject) => {
    const threatNode = node as unknown as ThreatNode;
    selectNode(threatNode.id);
  }, [selectNode]);

  // Node hover handlers
  const handleNodeHover = useCallback((node: NodeObject | null) => {
    if (node) {
      const threatNode = node as unknown as ThreatNode;
      hoverNode(threatNode.id);
    } else {
      hoverNode(null);
    }
  }, [hoverNode]);

  // Tooltip content
  const getNodeLabel = useCallback((node: NodeObject) => {
    const n = node as unknown as ThreatNode;
    return `
      <div style="background: rgba(17, 24, 39, 0.95); padding: 12px 16px; border-radius: 8px; border: 1px solid rgba(75, 85, 99, 0.5); max-width: 280px;">
        <div style="font-weight: 600; color: #F9FAFB; margin-bottom: 6px;">${n.ip}</div>
        <div style="display: flex; justify-content: space-between; margin-bottom: 4px;">
          <span style="color: #9CA3AF;">Status:</span>
          <span style="color: ${NODE_COLORS[n.status]}; font-weight: 500; text-transform: uppercase;">${n.status}</span>
        </div>
        <div style="display: flex; justify-content: space-between; margin-bottom: 4px;">
          <span style="color: #9CA3AF;">C2 Confidence:</span>
          <span style="color: ${n.confidence >= 80 ? '#EF4444' : n.confidence >= 50 ? '#F97316' : '#3B82F6'}; font-weight: 600;">${n.confidence.toFixed(1)}%</span>
        </div>
        <div style="display: flex; justify-content: space-between;">
          <span style="color: #9CA3AF;">Connections:</span>
          <span style="color: #F9FAFB;">${n.connections}</span>
        </div>
        ${n.beaconInterval ? `
        <div style="display: flex; justify-content: space-between; margin-top: 4px;">
          <span style="color: #9CA3AF;">Beacon:</span>
          <span style="color: #FBBF24;">${n.beaconInterval}ms</span>
        </div>
        ` : ''}
      </div>
    `;
  }, []);

  return (
    <div style={{
      position: 'relative',
      width: '100%',
      height: '100%',
      background: 'rgba(17, 24, 39, 0.5)',
      borderRadius: '16px',
      overflow: 'hidden',
    }}>
      {/* Graph Canvas */}
      <ForceGraph2D
        ref={graphRef}
        graphData={graphData}
        width={width}
        height={height}
        
        // Performance optimizations
        nodeRelSize={6}
        nodeCanvasObject={paintNode}
        nodePointerAreaPaint={paintNodePointerArea}
        nodeCanvasObjectMode={() => 'replace'}
        
        // Links
        linkColor={getLinkColor}
        linkWidth={getLinkWidth}
        linkDirectionalParticles={2}
        linkDirectionalParticleWidth={(link) => {
          const threatLink = link as unknown as ThreatLink;
          return threatLink.type === 'c2' ? 3 : 0;
        }}
        linkDirectionalParticleSpeed={0.005}
        linkDirectionalParticleColor={() => '#EF4444'}
        
        // Interactions
        onNodeClick={handleNodeClick}
        onNodeHover={handleNodeHover}
        nodeLabel={getNodeLabel}
        
        // Physics - tuned for botnet visualization
        d3AlphaDecay={0.02}
        d3VelocityDecay={0.3}
        cooldownTicks={100}
        warmupTicks={50}
        
        // Background
        backgroundColor="transparent"
        
        // Enable zoom/pan
        enableZoomInteraction={true}
        enablePanInteraction={true}
        enableNodeDrag={true}
      />
      
      {/* Node count indicator */}
      <div style={{
        position: 'absolute',
        bottom: '16px',
        left: '16px',
        background: 'rgba(17, 24, 39, 0.8)',
        backdropFilter: 'blur(4px)',
        padding: '8px 12px',
        borderRadius: '8px',
        border: '1px solid rgba(55, 65, 81, 0.5)',
      }}>
        <span style={{ color: '#9ca3af', fontSize: '14px' }}>Nodes: </span>
        <span style={{ color: 'white', fontWeight: '600' }}>{graphData.nodes.length.toLocaleString()}</span>
      </div>
    </div>
  );
}
