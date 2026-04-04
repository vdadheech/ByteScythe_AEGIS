"""
AEGIS Active Attribution Engine - API Schemas

Pydantic V2 request/response schemas for all API endpoints.
"""

from pydantic import BaseModel, ConfigDict, Field
from typing import Any, Dict, List, Optional


class BlastRadiusResponse(BaseModel):
    model_config = ConfigDict(strict=False)
    origin: str
    origin_score: float = 0.0
    compromised_nodes: List[str] = Field(default_factory=list)
    compromised_edges: List[List[str]] = Field(default_factory=list)
    depth: int = 0
    total_impact: int = 0


class RadarAxisResponse(BaseModel):
    axis: str
    value: float = 0.0
    weight: float = 0.0


class AttributionMetadataResponse(BaseModel):
    model_config = ConfigDict(strict=False)
    score_weights: Dict[str, float] = Field(default_factory=dict)
    signal_contributions: Dict[str, float] = Field(default_factory=dict)
    timing_entropy: float = 0.0
    header_sequence_likelihood: float = 1.0
    graph_centrality_score: float = 0.0
    method_ratio_score: float = 0.0
    behavioral_score: float = 0.0
    radar_chart_data: List[RadarAxisResponse] = Field(default_factory=list)


class BaselineResponse(BaseModel):
    model_config = ConfigDict(strict=False)
    sample_size: int = 0
    total_traffic: int = 0
    sample_percentage: float = 0.10
    header_transition_matrix: Dict[str, Dict[str, float]] = Field(default_factory=dict)
    avg_timing_entropy: float = 0.0
    method_distribution: Dict[str, float] = Field(default_factory=dict)
    computed_at: float = 0.0


class SankeyNodeResponse(BaseModel):
    name: str
    category: str = "legitimate"


class SankeyLinkResponse(BaseModel):
    source: int
    target: int
    value: float = 1.0
    category: str = "legitimate"


class SankeyResponse(BaseModel):
    model_config = ConfigDict(strict=False)
    nodes: List[SankeyNodeResponse] = Field(default_factory=list)
    links: List[SankeyLinkResponse] = Field(default_factory=list)


class IngestionStatsResponse(BaseModel):
    model_config = ConfigDict(strict=False)
    running: bool = False
    window_size: int = 0
    window_capacity: int = 50000
    total_ingested: int = 0
    error_count: int = 0
    ingest_rate_per_sec: float = 0.0
    uptime_seconds: float = 0.0
