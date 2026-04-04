"""
AEGIS Active Attribution Engine — Pydantic V2 Core Models

Central model definitions for zero-latency schema validation.
All engine modules import from here to ensure a single source of truth.

Uses Pydantic V2 semantics:
- model_dump() instead of .dict()
- ConfigDict instead of class Config
- Field validators with @field_validator
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, ConfigDict, Field, field_validator


# ═══════════════════════════════════════
#  ENUMS
# ═══════════════════════════════════════

class ThreatLevel(str, Enum):
    LOW = "low"
    ELEVATED = "elevated"
    HIGH = "high"
    CRITICAL = "critical"


class PatternType(str, Enum):
    HUMAN = "human"
    BEACON = "beacon"
    JITTERED_BEACON = "jittered_beacon"
    SEMI_AUTOMATED = "semi_automated"
    BURST = "burst"
    SHADOW_CONTROLLER = "shadow_controller"


# ═══════════════════════════════════════
#  INGESTION
# ═══════════════════════════════════════

class IngestRecord(BaseModel):
    """Incoming telemetry record — validated at ingestion boundary."""
    model_config = ConfigDict(strict=False)

    node_id: str
    timestamp: float
    source_ip: str = ""
    target_endpoint: str = "/api/default"
    http_method: str = "GET"
    http_response_code: int = 200
    response_time_ms: float = 0.0
    user_agent: str = ""
    headers: Optional[Dict[str, str]] = None
    header_order: Optional[List[str]] = None

    @field_validator("http_method", mode="before")
    @classmethod
    def uppercase_method(cls, v: str) -> str:
        return v.upper() if isinstance(v, str) else "GET"


# ═══════════════════════════════════════
#  HEADER FINGERPRINTING
# ═══════════════════════════════════════

class HeaderFingerprintModel(BaseModel):
    """Fingerprint derived from HTTP headers."""
    model_config = ConfigDict(strict=False)

    hash: str
    header_order: List[str]
    user_agent: str = ""
    claimed_browser: Optional[str] = None
    detected_client: Optional[str] = None
    is_browser: bool = False
    is_suspicious: bool = False
    anomaly_reasons: List[str] = Field(default_factory=list)
    confidence: float = 0.0
    sequence_likelihood: float = 1.0  # Markov chain score


class NodeHeaderProfileModel(BaseModel):
    """Aggregated header profile for a node."""
    model_config = ConfigDict(strict=False)

    node_id: str
    fingerprints_seen: Dict[str, int] = Field(default_factory=dict)
    user_agents_seen: Dict[str, int] = Field(default_factory=dict)
    total_requests: int = 0
    suspicious_count: int = 0
    header_anomaly_score: float = 0.0
    primary_fingerprint: Optional[str] = None
    is_consistent: bool = True
    avg_sequence_likelihood: float = 1.0  # Mean Markov score across requests


# ═══════════════════════════════════════
#  TEMPORAL FINGERPRINTING
# ═══════════════════════════════════════

class TimingProfileModel(BaseModel):
    """Timing characteristics for a single node/IP."""
    model_config = ConfigDict(strict=False)

    node_id: str
    request_count: int = 0
    mean_delta_ms: float = 0.0
    std_delta_ms: float = 0.0
    min_delta_ms: float = 0.0
    max_delta_ms: float = 0.0
    jitter: float = 0.0
    dominant_interval_ms: float = 0.0
    interval_consistency: float = 0.0
    beacon_score: float = 0.0
    is_beacon: bool = False
    pattern_type: PatternType = PatternType.HUMAN

    # Shannon Entropy additions
    timing_entropy: float = 0.0             # Raw Shannon entropy
    timing_entropy_normalized: float = 0.0  # Normalized to [0, 1]
    shadow_controller_score: float = 0.0    # Composite shadow-controller detection


# ═══════════════════════════════════════
#  GRAPH ANALYTICS
# ═══════════════════════════════════════

class NodeMetricsModel(BaseModel):
    """Container for graph-derived metrics per node."""
    model_config = ConfigDict(strict=False)

    node_id: str
    degree_centrality: float = 0.0
    in_degree: int = 0
    out_degree: int = 0
    betweenness: float = 0.0
    closeness: float = 0.0
    community_id: int = 0
    is_hub: bool = False
    is_bridge: bool = False
    anomaly_score: float = 0.0


class ClusterNode(BaseModel):
    """Super-node representing a collapsed subnet cluster."""
    model_config = ConfigDict(strict=False)

    id: str                    # e.g. "cluster_3"
    member_count: int = 0
    avg_score: float = 0.0
    max_score: float = 0.0
    community_id: int = 0
    member_ids: List[str] = Field(default_factory=list)
    node_type: str = "cluster"


class BlastRadiusResult(BaseModel):
    """BFS blast-radius output from a high-confidence C2 node."""
    model_config = ConfigDict(strict=False)

    origin: str
    origin_score: float = 0.0
    compromised_nodes: List[str] = Field(default_factory=list)
    compromised_edges: List[List[str]] = Field(default_factory=list)  # [[src, tgt], ...]
    depth: int = 0
    total_impact: int = 0


class GraphSnapshotModel(BaseModel):
    """Immutable snapshot of graph state."""
    model_config = ConfigDict(strict=False)

    node_count: int = 0
    edge_count: int = 0
    communities: int = 0
    hub_nodes: List[str] = Field(default_factory=list)
    bridge_nodes: List[str] = Field(default_factory=list)
    computed_at: float = 0.0


# ═══════════════════════════════════════
#  ATTRIBUTION — XAI
# ═══════════════════════════════════════

class RadarAxis(BaseModel):
    """Single axis of the XAI radar chart."""
    axis: str
    value: float = 0.0
    weight: float = 0.0


class AttributionMetadata(BaseModel):
    """Transparent, explainable attribution metadata (XAI)."""
    model_config = ConfigDict(strict=False)

    score_weights: Dict[str, float] = Field(default_factory=lambda: {
        "timing_entropy": 0.30,
        "header_sequence_deviation": 0.25,
        "graph_influence": 0.20,
        "behavioral": 0.15,
        "method_ratio": 0.10,
    })
    signal_contributions: Dict[str, float] = Field(default_factory=dict)
    timing_entropy: float = 0.0
    header_sequence_likelihood: float = 1.0
    graph_centrality_score: float = 0.0
    method_ratio_score: float = 0.0
    behavioral_score: float = 0.0
    radar_chart_data: List[RadarAxis] = Field(default_factory=list)


class SignalBreakdownModel(BaseModel):
    """Individual signal contribution to the final score."""
    model_config = ConfigDict(strict=False)

    name: str
    raw_score: float = 0.0
    weight: float = 0.0
    weighted_score: float = 0.0
    reason: str = ""
    details: Dict[str, Any] = Field(default_factory=dict)


class AttributionResultModel(BaseModel):
    """Complete C2 attribution result for a node."""
    model_config = ConfigDict(strict=False)

    node_id: str
    c2_confidence: float = 0.0
    threat_level: ThreatLevel = ThreatLevel.LOW
    signals: List[SignalBreakdownModel] = Field(default_factory=list)
    primary_indicators: List[str] = Field(default_factory=list)
    recommended_actions: List[str] = Field(default_factory=list)
    computed_at: float = 0.0
    data_quality: float = 0.0
    metadata: AttributionMetadata = Field(default_factory=AttributionMetadata)


# ═══════════════════════════════════════
#  GOLDEN IMAGE BASELINE
# ═══════════════════════════════════════

class BaselineFingerprint(BaseModel):
    """'Golden Image' — fingerprint computed from first 10% of traffic."""
    model_config = ConfigDict(strict=False)

    sample_size: int = 0
    total_traffic: int = 0
    sample_percentage: float = 0.10
    header_transition_matrix: Dict[str, Dict[str, float]] = Field(default_factory=dict)
    dominant_sequences: List[List[str]] = Field(default_factory=list)
    avg_timing_entropy: float = 0.0
    method_distribution: Dict[str, float] = Field(default_factory=dict)  # {"GET": 0.7, "POST": 0.2, ...}
    computed_at: float = 0.0


# ═══════════════════════════════════════
#  SANKEY DIAGRAM DATA
# ═══════════════════════════════════════

class SankeyNode(BaseModel):
    name: str
    category: str = "legitimate"  # "legitimate" | "shadow"


class SankeyLink(BaseModel):
    source: int  # index into nodes list
    target: int
    value: float = 1.0
    category: str = "legitimate"


class SankeyData(BaseModel):
    """Sankey diagram data for Golden Image contrast visualisation."""
    model_config = ConfigDict(strict=False)

    nodes: List[SankeyNode] = Field(default_factory=list)
    links: List[SankeyLink] = Field(default_factory=list)
