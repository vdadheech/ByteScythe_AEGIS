/**
 * AEGIS Active Attribution Engine - React Hook
 * 
 * Provides state management and data fetching for the threat dashboard.
 */

import { useState, useEffect, useCallback, useRef } from 'react';
import {
  fetchActiveThreats,
  fetchNodeDetails,
  fetchTimingData,
  fetchThreatSummary,
} from '../api/endpoints';
import type {
  ThreatNode,
  ThreatLink,
  ThreatGraphMetadata,
  NodeDetailsResponse,
  TimingPoint,
  TimingProfile,
  ThreatSummary,
} from '../types';

interface UseAttributionEngineOptions {
  autoRefresh?: boolean;
  refreshInterval?: number;  // ms
  minScore?: number;
  maxNodes?: number;
}

interface UseAttributionEngineResult {
  // Threat Graph
  nodes: ThreatNode[];
  links: ThreatLink[];
  metadata: ThreatGraphMetadata | null;
  
  // Timing Data
  timingPoints: TimingPoint[];
  timingProfiles: TimingProfile[];
  
  // Summary
  summary: ThreatSummary | null;
  
  // Selected Node
  selectedNode: NodeDetailsResponse | null;
  selectNode: (nodeId: string | null) => void;
  
  // Loading/Error States
  isLoading: boolean;
  isNodeLoading: boolean;
  error: string | null;
  
  // Actions
  refresh: () => Promise<void>;
  setMinScore: (score: number) => void;
}

export function useAttributionEngine(
  options: UseAttributionEngineOptions = {}
): UseAttributionEngineResult {
  const {
    autoRefresh = true,
    refreshInterval = 10000,
    minScore: initialMinScore = 50,
    maxNodes = 500,
  } = options;

  // State
  const [nodes, setNodes] = useState<ThreatNode[]>([]);
  const [links, setLinks] = useState<ThreatLink[]>([]);
  const [metadata, setMetadata] = useState<ThreatGraphMetadata | null>(null);
  
  const [timingPoints, setTimingPoints] = useState<TimingPoint[]>([]);
  const [timingProfiles, setTimingProfiles] = useState<TimingProfile[]>([]);
  
  const [summary, setSummary] = useState<ThreatSummary | null>(null);
  
  const [selectedNode, setSelectedNode] = useState<NodeDetailsResponse | null>(null);
  
  const [isLoading, setIsLoading] = useState(true);
  const [isNodeLoading, setIsNodeLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [minScore, setMinScore] = useState(initialMinScore);
  
  // Refs for cleanup
  const refreshTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const abortControllerRef = useRef<AbortController | null>(null);

  // Fetch all data
  const refresh = useCallback(async () => {
    // Cancel any pending requests
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }
    abortControllerRef.current = new AbortController();
    
    try {
      // Parallel fetch for performance
      const [threatData, timingData, summaryData] = await Promise.all([
        fetchActiveThreats({ minScore, maxNodes }),
        fetchTimingData({ maxPoints: 500 }),
        fetchThreatSummary(),
      ]);
      
      setNodes(threatData.nodes);
      setLinks(threatData.links);
      setMetadata(threatData.metadata);
      
      setTimingPoints(timingData.points);
      setTimingProfiles(timingData.profiles);
      
      setSummary(summaryData);
      
      setError(null);
    } catch (err) {
      if (err instanceof Error && err.name === 'AbortError') {
        return;  // Cancelled, ignore
      }
      console.error('Failed to fetch attribution data:', err);
      setError(err instanceof Error ? err.message : 'Failed to fetch data');
    } finally {
      setIsLoading(false);
    }
  }, [minScore, maxNodes]);

  // Select a node for detailed view
  const selectNode = useCallback(async (nodeId: string | null) => {
    if (!nodeId) {
      setSelectedNode(null);
      return;
    }
    
    setIsNodeLoading(true);
    try {
      const details = await fetchNodeDetails(nodeId);
      setSelectedNode(details);
    } catch (err) {
      console.error('Failed to fetch node details:', err);
      setSelectedNode(null);
    } finally {
      setIsNodeLoading(false);
    }
  }, []);

  // Initial load
  useEffect(() => {
    refresh();
  }, [refresh]);

  // Auto-refresh
  useEffect(() => {
    if (!autoRefresh) return;
    
    refreshTimerRef.current = setInterval(refresh, refreshInterval);
    
    return () => {
      if (refreshTimerRef.current) {
        clearInterval(refreshTimerRef.current);
      }
    };
  }, [autoRefresh, refreshInterval, refresh]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
      if (refreshTimerRef.current) {
        clearInterval(refreshTimerRef.current);
      }
    };
  }, []);

  return {
    nodes,
    links,
    metadata,
    timingPoints,
    timingProfiles,
    summary,
    selectedNode,
    selectNode,
    isLoading,
    isNodeLoading,
    error,
    refresh,
    setMinScore,
  };
}

export default useAttributionEngine;
