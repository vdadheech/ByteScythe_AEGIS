import { fetchWithRetry, postJson } from './client';
import type {
  AssetsResponse,
  SchemaLog,
  CityMapResponse,
  HeatmapResponse,
  ThreatGraphResponse,
  NodeDetailsResponse,
  TimingDataResponse,
  ThreatSummary,
  Community,
  StarTopology,
  BlastRadiusResponse,
  SankeyData,
  ZoomResponse,
  BaselineResponse,
  ShadowController,
  IngestionStats,
} from '../types';

export function fetchAssets(): Promise<AssetsResponse> {
  return fetchWithRetry<AssetsResponse>('/assets');
}

export function fetchSchemaLogs(): Promise<SchemaLog> {
  return fetchWithRetry<SchemaLog>('/schema-logs');
}

export function fetchCityMap(): Promise<CityMapResponse> {
  return fetchWithRetry<CityMapResponse>('/city-map');
}

export function fetchHeatmap(): Promise<HeatmapResponse> {
  return fetchWithRetry<HeatmapResponse>('/heatmap');
}

export function quarantineNode(
  nodeId: number
): Promise<{ message: string; node_id: number }> {
  return postJson<{ message: string; node_id: number }>(
    `/nodes/${nodeId}/quarantine`
  );
}


/* ═══════════════════════════════════════
   ACTIVE ATTRIBUTION ENGINE ENDPOINTS
   ═══════════════════════════════════════ */

export function fetchActiveThreats(params?: {
  minScore?: number;
  maxNodes?: number;
  includeLinks?: boolean;
  communityFilter?: number;
}): Promise<ThreatGraphResponse> {
  const searchParams = new URLSearchParams();
  
  if (params?.minScore !== undefined) {
    searchParams.set('min_score', params.minScore.toString());
  }
  if (params?.maxNodes !== undefined) {
    searchParams.set('max_nodes', params.maxNodes.toString());
  }
  if (params?.includeLinks !== undefined) {
    searchParams.set('include_links', params.includeLinks.toString());
  }
  if (params?.communityFilter !== undefined) {
    searchParams.set('community_filter', params.communityFilter.toString());
  }
  
  const query = searchParams.toString();
  return fetchWithRetry<ThreatGraphResponse>(
    `/v1/graph/active-threats${query ? `?${query}` : ''}`
  );
}

export function fetchNodeDetails(nodeId: string): Promise<NodeDetailsResponse> {
  return fetchWithRetry<NodeDetailsResponse>(
    `/v1/graph/node/${encodeURIComponent(nodeId)}`
  );
}

export function fetchTimingData(params?: {
  maxPoints?: number;
  nodeFilter?: string;
}): Promise<TimingDataResponse> {
  const searchParams = new URLSearchParams();
  
  if (params?.maxPoints !== undefined) {
    searchParams.set('max_points', params.maxPoints.toString());
  }
  if (params?.nodeFilter !== undefined) {
    searchParams.set('node_filter', params.nodeFilter);
  }
  
  const query = searchParams.toString();
  return fetchWithRetry<TimingDataResponse>(
    `/v1/graph/timing${query ? `?${query}` : ''}`
  );
}

export function fetchThreatSummary(): Promise<ThreatSummary> {
  return fetchWithRetry<ThreatSummary>('/v1/graph/summary');
}

export function fetchCommunities(minSize?: number): Promise<{ communities: Community[] }> {
  const query = minSize !== undefined ? `?min_size=${minSize}` : '';
  return fetchWithRetry<{ communities: Community[] }>(
    `/v1/graph/communities${query}`
  );
}

export function fetchStarTopologies(): Promise<{ starTopologies: StarTopology[]; count: number }> {
  return fetchWithRetry<{ starTopologies: StarTopology[]; count: number }>(
    '/v1/graph/star-topologies'
  );
}

export function fetchPipelineStats(): Promise<{
  running: boolean;
  workers: number;
  queue_size: number;
  processed_count: number;
  error_count: number;
  cache_size: number;
}> {
  return fetchWithRetry('/v1/graph/pipeline/stats');
}


/* ═══════════════════════════════════════
   ATTRIBUTION ENGINE v2 — NEW ENDPOINTS
   ═══════════════════════════════════════ */

/** BFS blast-radius from a C2 node */
export function fetchBlastRadius(nodeId: string): Promise<BlastRadiusResponse> {
  return fetchWithRetry<BlastRadiusResponse>(
    `/v1/graph/blast-radius/${encodeURIComponent(nodeId)}`
  );
}

/** Zoom to controller (1-hop ego graph) */
export function fetchZoomToController(nodeId: string): Promise<ZoomResponse> {
  return fetchWithRetry<ZoomResponse>(
    `/v1/graph/zoom/${encodeURIComponent(nodeId)}`
  );
}

/** Golden Image baseline data */
export function fetchBaseline(): Promise<BaselineResponse> {
  return fetchWithRetry<BaselineResponse>('/v1/graph/baseline');
}

/** Sankey diagram: legitimate vs shadow header sequences */
export function fetchSankeyData(): Promise<SankeyData> {
  return fetchWithRetry<SankeyData>('/v1/graph/sankey');
}

/** Shadow Controller detection */
export function fetchShadowControllers(threshold?: number): Promise<{
  shadow_controllers: ShadowController[];
  count: number;
}> {
  const query = threshold !== undefined ? `?threshold=${threshold}` : '';
  return fetchWithRetry(`/v1/graph/shadow-controllers${query}`);
}

/** AsyncLogTailer ingestion stats */
export function fetchIngestionStats(): Promise<IngestionStats> {
  return fetchWithRetry<IngestionStats>('/v1/graph/ingestion/stats');
}

