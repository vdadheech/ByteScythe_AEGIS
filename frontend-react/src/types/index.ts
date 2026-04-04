/* ═══════════════════════════════════════
   AEGIS — Shared TypeScript Interfaces
   ═══════════════════════════════════════ */

export interface Asset {
  node_id: number;
  hardware_serial: string;
  threat_score: number;
  status_color?: string;
  is_quarantined?: number;
}

export interface NodeData {
  node_id: number;
  node_serial: string;
  location: string;
  http_status: number;
  response_time: number;
  status_color: string;
  spoof_flag: number;
  ddos_flag: number;
  malware_flag: number;
  is_quarantined: number;
  hardware_serial?: string;
  threat_score?: number;
}

export interface SchemaLog {
  logs: string[];
}

export interface HeatmapPoint {
  log_id: number;
  response_time_ms: number;
}

export interface HeatmapResponse {
  heatmap: HeatmapPoint[];
}

export interface CityMapNode {
  node_serial: string;
  node_id: number;
  location: string;
  http_status: number;
  response_time: number;
  status_color: string;
  spoof_flag: number;
  ddos_flag: number;
  malware_flag: number;
  is_quarantined: number;
}

export interface CityMapResponse {
  nodes: CityMapNode[];
}

export interface AssetsResponse {
  assets: Asset[];
}

export interface GraphNode {
  id: string;
  original_data: CityMapNode;
  x?: number;
  y?: number;
  fx?: number | null;
  fy?: number | null;
}

export interface GraphLink {
  source: string | GraphNode;
  target: string | GraphNode;
}

export type WebSocketEvent =
  | { event: 'log'; log_id: number; response_time_ms: number }
  | { event: 'schema_change'; log_id: number; version: number; active_column: string }
  | { event: 'stream_complete' };


/* ═══════════════════════════════════════
   ACTIVE ATTRIBUTION ENGINE TYPES
   ═══════════════════════════════════════ */

export type ThreatLevel = 'low' | 'elevated' | 'high' | 'critical';

export interface ThreatNode {
  id: string;
  score: number;
  level: ThreatLevel;
  type: 'client' | 'endpoint' | 'host' | 'unknown';
  community: number;
  isHub: boolean;
  isBridge: boolean;
  connections: number;
  primaryIndicator: string | null;
}

export interface ThreatLink {
  source: string;
  target: string;
  weight: number;
}

export interface ThreatGraphMetadata {
  totalNodes: number;
  totalEdges: number;
  filteredNodes: number;
  filteredEdges: number;
  minScoreFilter: number;
  computedAt: number;
  processingTimeMs: number;
}

export interface ThreatGraphResponse {
  nodes: ThreatNode[];
  links: ThreatLink[];
  metadata: ThreatGraphMetadata;
}

export interface SignalBreakdown {
  name: string;
  raw_score: number;
  weight: number;
  weighted_score: number;
  reason: string;
}

export interface AttributionResult {
  node_id: string;
  c2_confidence: number;
  threat_level: ThreatLevel;
  signals: SignalBreakdown[];
  primary_indicators: string[];
  recommended_actions: string[];
  data_quality: number;
}

export interface TimingPoint {
  x: number;  // timestamp
  y: number;  // delta_ms
  node: string;
  isBeacon: boolean;
}

export interface TimingProfile {
  node_id: string;
  request_count: number;
  mean_delta_ms: number;
  std_delta_ms: number;
  jitter: number;
  dominant_interval_ms: number;
  interval_consistency: number;
  beacon_score: number;
  is_beacon: boolean;
  pattern_type: 'human' | 'beacon' | 'jittered_beacon' | 'burst' | 'semi_automated';
}

export interface TimingDataResponse {
  points: TimingPoint[];
  profiles: TimingProfile[];
  summary: {
    totalPoints: number;
    totalProfiles: number;
    beaconNodes: number;
    avgDeltaMs: number;
  };
}

export interface HeaderProfile {
  node_id: string;
  fingerprints_seen: Record<string, number>;
  user_agents_seen: Record<string, number>;
  total_requests: number;
  suspicious_count: number;
  header_anomaly_score: number;
  primary_fingerprint: string | null;
  is_consistent: boolean;
}

export interface NodeDetailsResponse {
  nodeId: string;
  attribution: AttributionResult;
  timing: {
    points: TimingPoint[];
    profile: TimingProfile | null;
  };
  headers: HeaderProfile | null;
  graph: {
    node_id: string;
    degree_centrality: number;
    in_degree: number;
    out_degree: number;
    betweenness: number;
    closeness: number;
    community_id: number;
    is_hub: boolean;
    is_bridge: boolean;
    anomaly_score: number;
  } | null;
}

export interface ThreatSummary {
  total_nodes: number;
  critical_count: number;
  high_count: number;
  elevated_count: number;
  top_threats: AttributionResult[];
  computed_at: number;
  engines: {
    graph: { nodes: number; edges: number };
    temporal: { trackedNodes: number };
    headers: {
      total_fingerprints: number;
      browser_fingerprints: number;
      suspicious_fingerprints: number;
      total_nodes: number;
      suspicious_nodes: number;
    };
  };
}

export interface Community {
  id: number;
  nodes: string[];
  size: number;
  avgScore: number;
  hubCount: number;
}

export interface StarTopology {
  controller: string;
  victim_count: number;
  interconnect_ratio: number;
  confidence: number;
}


/* ═══════════════════════════════════════
   ATTRIBUTION ENGINE v2 — NEW TYPES
   ═══════════════════════════════════════ */

/** XAI Radar chart axis */
export interface RadarAxis {
  axis: string;
  value: number;
  weight: number;
}

/** Transparent attribution metadata (XAI) */
export interface AttributionMetadataResponse {
  score_weights: Record<string, number>;
  signal_contributions: Record<string, number>;
  timing_entropy: number;
  header_sequence_likelihood: number;
  graph_centrality_score: number;
  method_ratio_score: number;
  behavioral_score: number;
  radar_chart_data: RadarAxis[];
}

/** BFS Blast Radius result */
export interface BlastRadiusResponse {
  origin: string;
  origin_score: number;
  compromised_nodes: string[];
  compromised_edges: [string, string][];
  depth: number;
  total_impact: number;
}

/** Cluster super-node (auto-collapsed low-score nodes) */
export interface ClusterNode {
  id: string;
  score: number;
  maxScore: number;
  type: 'cluster';
  community: number;
  isHub: boolean;
  isBridge: boolean;
  connections: number;
  memberCount: number;
  memberIds: string[];
  primaryIndicator: string;
}

/** Sankey diagram node */
export interface SankeyNode {
  name: string;
  category: string;
}

/** Sankey diagram link */
export interface SankeyLink {
  source: number;
  target: number;
  value: number;
  category: 'legitimate' | 'shadow';
}

/** Sankey diagram data for Golden Image contrast */
export interface SankeyData {
  nodes: SankeyNode[];
  links: SankeyLink[];
}

/** Shadow Controller detection result */
export interface ShadowController {
  node_id: string;
  request_count: number;
  jitter: number;
  timing_entropy_normalized: number;
  shadow_controller_score: number;
  pattern_type: string;
}

/** Zoom-to-controller ego graph response */
export interface ZoomResponse {
  nodes: (ThreatNode & { isController?: boolean })[];
  links: ThreatLink[];
  metadata: {
    controllerId: string;
    neighborCount: number;
    egoNodeCount: number;
  };
}

/** Baseline / Golden Image response */
export interface BaselineResponse {
  header_transition_matrix: Record<string, Record<string, number>>;
  fingerprint_stats: Record<string, number>;
  avg_timing_entropy: number;
  computed_at: number;
}

/** AsyncLogTailer ingestion stats */
export interface IngestionStats {
  running: boolean;
  window_size: number;
  window_capacity: number;
  total_ingested: number;
  error_count: number;
  ingest_rate_per_sec: number;
  uptime_seconds: number;
}
