/**
 * AEGIS C2 Detection Dashboard
 * 
 * Enterprise-grade threat intelligence dashboard with:
 * - WebGL-powered network graph (10K+ nodes @ 60fps)
 * - Real-time beaconing detection visualization
 * - Explainable C2 attribution
 * - Actionable kill switch controls
 * 
 * Designed for hackathon final presentation.
 * 
 * Layout: Bento Grid
 * ┌─────────────────────────────────────────────────────┐
 * │                 GLOBAL CONTROLS                     │
 * ├──────────────────────────┬──────────────────────────┤
 * │                          │   BEACONING SCATTER      │
 * │    NETWORK GRAPH         ├──────────────────────────┤
 * │    (60% width)           │   NODE INSPECTOR         │
 * │                          │   (40% width)            │
 * └──────────────────────────┴──────────────────────────┘
 */

import { useEffect, useCallback, useRef, useState } from 'react';
import { motion } from 'framer-motion';
import { NetworkGraph } from './NetworkGraph';
import { BeaconingScatter } from './BeaconingScatter';
import { NodeInspector } from './NodeInspector';
import { GlobalControls } from './GlobalControls';
import { KillSwitchModal } from './KillSwitchModal';
import { ThreatLegend } from './ThreatLegend';
import { useThreatStore } from './useThreatStore';
import { generateMockData, generateLargeDataset } from './mockDataGenerator';

interface C2DashboardProps {
  /** Initial data scale multiplier */
  scale?: number;
  /** Enable streaming simulation */
  streaming?: boolean;
  /** Large dataset mode (10K+ nodes) */
  largeDataset?: boolean;
}

export function C2Dashboard({ 
  scale = 1, 
  streaming = false,
  largeDataset = false,
}: C2DashboardProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [dimensions, setDimensions] = useState({ width: 800, height: 600 });
  
  const { 
    setNodes, 
    setLinks, 
    reset,
    isStreaming,
    setStreaming,
    addNode,
  } = useThreatStore();

  // Responsive sizing
  useEffect(() => {
    const updateDimensions = () => {
      if (containerRef.current) {
        const rect = containerRef.current.getBoundingClientRect();
        // Graph takes 60% of container width
        setDimensions({
          width: rect.width * 0.6 - 16,
          height: rect.height - 32,
        });
      }
    };

    updateDimensions();
    window.addEventListener('resize', updateDimensions);
    return () => window.removeEventListener('resize', updateDimensions);
  }, []);

  // Generate initial data
  const generateData = useCallback(() => {
    reset();
    
    const data = largeDataset 
      ? generateLargeDataset(10000)
      : generateMockData(scale);
    
    setNodes(data.nodes);
    setLinks(data.links);
    
    console.log(`[AEGIS] Generated ${data.nodes.length} nodes, ${data.links.length} links`);
  }, [largeDataset, scale, reset, setNodes, setLinks]);

  // Stream data simulation
  const startStreaming = useCallback(() => {
    if (isStreaming) return;
    
    setStreaming(true);
    const data = generateMockData(0.5);
    let index = 0;
    
    const interval = setInterval(() => {
      if (index < data.nodes.length) {
        addNode(data.nodes[index]);
        index++;
      } else {
        clearInterval(interval);
        setStreaming(false);
      }
    }, 100);

    return () => clearInterval(interval);
  }, [isStreaming, setStreaming, addNode]);

  // Load initial data
  useEffect(() => {
    generateData();
    
    if (streaming) {
      const cleanup = startStreaming();
      return cleanup;
    }
  }, []);

  return (
    <div className="h-screen w-full bg-gray-950 text-white overflow-hidden">
      {/* Background gradient */}
      <div className="absolute inset-0 bg-gradient-to-br from-gray-900 via-gray-950 to-black" />
      
      {/* Grid pattern overlay */}
      <div 
        className="absolute inset-0 opacity-[0.03]"
        style={{
          backgroundImage: `
            linear-gradient(rgba(255,255,255,.1) 1px, transparent 1px),
            linear-gradient(90deg, rgba(255,255,255,.1) 1px, transparent 1px)
          `,
          backgroundSize: '50px 50px',
        }}
      />
      
      {/* Main content */}
      <div className="relative h-full flex flex-col p-4 gap-4">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          className="flex items-center justify-between"
        >
          <div className="flex items-center gap-4">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center">
              <span className="text-xl">🛡️</span>
            </div>
            <div>
              <h1 className="text-2xl font-bold bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent">
                AEGIS Active Attribution Engine
              </h1>
              <p className="text-gray-500 text-sm">Real-time C2 Infrastructure Detection</p>
            </div>
          </div>
          
          <div className="flex items-center gap-2">
            <span className="text-gray-500 text-sm">v2.0</span>
            <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
            <span className="text-green-400 text-sm">Online</span>
          </div>
        </motion.div>

        {/* Global Controls */}
        <motion.div
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
        >
          <GlobalControls
            onGenerateData={generateData}
            onClear={reset}
            isStreaming={isStreaming}
          />
        </motion.div>

        {/* Main Bento Grid */}
        <div 
          ref={containerRef}
          className="flex-1 grid grid-cols-5 gap-4 min-h-0"
        >
          {/* Network Graph (3/5 = 60%) */}
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: 0.2 }}
            className="col-span-3 relative"
          >
            <NetworkGraph
              width={dimensions.width}
              height={dimensions.height}
            />
            <ThreatLegend />
          </motion.div>

          {/* Right Panel (2/5 = 40%) */}
          <div className="col-span-2 flex flex-col gap-4 min-h-0">
            {/* Beaconing Scatter (top) */}
            <motion.div
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 0.3 }}
              className="h-[45%] min-h-0"
            >
              <BeaconingScatter />
            </motion.div>

            {/* Node Inspector (bottom) */}
            <motion.div
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 0.4 }}
              className="flex-1 min-h-0"
            >
              <NodeInspector />
            </motion.div>
          </div>
        </div>

        {/* Footer */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.5 }}
          className="flex items-center justify-between text-gray-600 text-xs"
        >
          <span>© 2024 AEGIS Security • Enterprise Threat Intelligence</span>
          <span>WebGL Rendering • 60fps @ 10K+ nodes</span>
        </motion.div>
      </div>

      {/* Kill Switch Modal */}
      <KillSwitchModal />
    </div>
  );
}
