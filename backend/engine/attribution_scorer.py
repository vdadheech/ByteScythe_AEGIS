"""
AEGIS Active Attribution Engine - C2 Attribution Scorer

This module implements the core C2 confidence scoring algorithm that
combines multiple detection signals into a unified threat score.

SCORING ARCHITECTURE (v2 — 5-Signal Model):
--------------------------------------------
The AttributionScorer aggregates five orthogonal detection vectors:

1. TIMING ENTROPY (weight: 0.30)
   - Shannon Entropy of inter-arrival times
   - Shadow Controller detection (periodic + jitter)
   - Beaconing behavior (fixed intervals)

2. HEADER SEQUENCE DEVIATION (weight: 0.25)
   - Markov Chain transition-probability scoring
   - Non-browser fingerprints
   - User-Agent spoofing detection

3. GRAPH INFLUENCE (weight: 0.20)
   - High centrality in network topology
   - Bridge nodes between communities
   - Star topology detection (controller → victims)

4. BEHAVIORAL ANOMALY (weight: 0.15)
   - Request volume patterns
   - Endpoint targeting patterns
   - Error rate anomalies

5. HTTP METHOD RATIO (weight: 0.10)
   - C2 beacons overwhelmingly use a single HTTP method
   - Normal browsing: ~70% GET, ~20% POST, ~10% other
   - >95% single method → high score

WHY THESE WEIGHTS?
-----------------
- Timing (0.30): Strongest C2 indicator. Entropy catches what CV misses.
- Headers (0.25): Markov chains detect spoofed/obfuscated agents.
- Graph (0.20): Topology reveals infrastructure at scale.
- Behavioral (0.15): Contextual signal, supports primary vectors.
- Method Ratio (0.10): Simple but effective secondary signal.

XAI TRANSPARENCY:
-----------------
Every score includes an AttributionMetadata object with:
- score_weights: {timing_entropy: 0.30, ...}
- signal_contributions: actual weighted contribution per signal
- radar_chart_data: [{axis: "Timing Entropy", value: 0.87}, ...]

SCORING FORMULA:
---------------
C2_Score = Σ(weight_i × signal_i) × confidence_multiplier

Where:
- signal_i ∈ [0, 1] for each detection vector
- confidence_multiplier adjusts for data quality
- Final score ∈ [0, 100]

THREAT LEVELS:
-------------
- 0-25:   LOW       - Normal traffic, no indicators
- 26-50:  ELEVATED  - Some indicators, monitoring recommended
- 51-75:  HIGH      - Multiple strong indicators, investigation required
- 76-100: CRITICAL  - High-confidence C2 activity, immediate action needed
"""

from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
import logging
import time
import math

from backend.engine.graph_engine import GraphAnalyticsEngine, NodeMetrics, get_graph_engine
from backend.engine.temporal_engine import TemporalFingerprintEngine, TimingProfile, get_temporal_engine
from backend.engine.header_fingerprint import HeaderFingerprintEngine, NodeHeaderProfile, get_header_engine

logger = logging.getLogger(__name__)


class ThreatLevel(Enum):
    LOW = "low"
    ELEVATED = "elevated"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class SignalBreakdown:
    """Individual signal contribution to the final score."""
    name: str
    raw_score: float
    weight: float
    weighted_score: float
    reason: str
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RadarAxis:
    """Single axis of the XAI radar chart."""
    axis: str
    value: float = 0.0
    weight: float = 0.0


@dataclass
class AttributionMetadata:
    """Transparent, explainable attribution metadata (XAI)."""
    score_weights: Dict[str, float] = field(default_factory=lambda: {
        "timing_entropy": 0.30,
        "header_sequence_deviation": 0.25,
        "graph_influence": 0.20,
        "behavioral": 0.15,
        "method_ratio": 0.10,
    })
    signal_contributions: Dict[str, float] = field(default_factory=dict)
    timing_entropy: float = 0.0
    header_sequence_likelihood: float = 1.0
    graph_centrality_score: float = 0.0
    method_ratio_score: float = 0.0
    behavioral_score: float = 0.0
    radar_chart_data: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'score_weights': self.score_weights,
            'signal_contributions': {k: round(v, 4) for k, v in self.signal_contributions.items()},
            'timing_entropy': round(self.timing_entropy, 4),
            'header_sequence_likelihood': round(self.header_sequence_likelihood, 6),
            'graph_centrality_score': round(self.graph_centrality_score, 4),
            'method_ratio_score': round(self.method_ratio_score, 4),
            'behavioral_score': round(self.behavioral_score, 4),
            'radar_chart_data': self.radar_chart_data,
        }


@dataclass
class AttributionResult:
    """Complete C2 attribution result for a node."""
    node_id: str
    c2_confidence: float          # 0-100
    threat_level: ThreatLevel
    signals: List[SignalBreakdown]
    primary_indicators: List[str]
    recommended_actions: List[str]
    computed_at: float
    data_quality: float           # Confidence in the result
    metadata: AttributionMetadata = field(default_factory=AttributionMetadata)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'node_id': self.node_id,
            'c2_confidence': round(self.c2_confidence, 1),
            'threat_level': self.threat_level.value,
            'signals': [
                {
                    'name': s.name,
                    'raw_score': round(s.raw_score, 3),
                    'weight': s.weight,
                    'weighted_score': round(s.weighted_score, 3),
                    'reason': s.reason
                }
                for s in self.signals
            ],
            'primary_indicators': self.primary_indicators,
            'recommended_actions': self.recommended_actions,
            'data_quality': round(self.data_quality, 2),
            'metadata': self.metadata.to_dict(),
        }


class AttributionScorer:
    """
    Enterprise-grade C2 attribution scoring engine.
    
    Combines five detection signals with calibrated weights
    to produce a confidence score for C2 activity.
    
    Usage:
        scorer = AttributionScorer()
        result = scorer.score_node("192.168.1.100")
        print(f"C2 Confidence: {result.c2_confidence}%")
    """
    
    # Signal weights (must sum to 1.0) — 5-signal model
    WEIGHT_TIMING = 0.30
    WEIGHT_HEADER = 0.25
    WEIGHT_GRAPH = 0.20
    WEIGHT_BEHAVIORAL = 0.15
    WEIGHT_METHOD = 0.10
    
    # Threat level thresholds
    THRESHOLD_ELEVATED = 25
    THRESHOLD_HIGH = 50
    THRESHOLD_CRITICAL = 75
    
    def __init__(
        self,
        graph_engine: Optional[GraphAnalyticsEngine] = None,
        temporal_engine: Optional[TemporalFingerprintEngine] = None,
        header_engine: Optional[HeaderFingerprintEngine] = None
    ):
        self.graph_engine = graph_engine or get_graph_engine()
        self.temporal_engine = temporal_engine or get_temporal_engine()
        self.header_engine = header_engine or get_header_engine()
    
    def score_node(self, node_id: str) -> AttributionResult:
        """
        Compute C2 confidence score for a specific node.
        
        Aggregates all five signals and produces a weighted score
        with full XAI metadata.
        """
        signals = []
        indicators = []
        
        # 1. TIMING / ENTROPY SIGNAL
        temporal_signal = self._compute_temporal_signal(node_id)
        signals.append(temporal_signal)
        if temporal_signal.raw_score > 0.5:
            indicators.extend(self._temporal_indicators(temporal_signal))
        
        # 2. HEADER SEQUENCE SIGNAL
        header_signal = self._compute_header_signal(node_id)
        signals.append(header_signal)
        if header_signal.raw_score > 0.3:
            indicators.extend(self._header_indicators(header_signal))
        
        # 3. GRAPH SIGNAL
        graph_signal = self._compute_graph_signal(node_id)
        signals.append(graph_signal)
        if graph_signal.raw_score > 0.5:
            indicators.extend(self._graph_indicators(graph_signal))
        
        # 4. BEHAVIORAL SIGNAL
        behavioral_signal = self._compute_behavioral_signal(node_id)
        signals.append(behavioral_signal)
        if behavioral_signal.raw_score > 0.5:
            indicators.extend(self._behavioral_indicators(behavioral_signal))
        
        # 5. METHOD RATIO SIGNAL
        method_signal = self._compute_method_ratio_signal(node_id)
        signals.append(method_signal)
        if method_signal.raw_score > 0.5:
            indicators.append(f"HTTP method anomaly: {method_signal.reason}")
        
        # Calculate final score
        raw_score = sum(s.weighted_score for s in signals)
        
        # Apply data quality multiplier
        data_quality = self._compute_data_quality(node_id, signals)
        
        # Scale to 0-100 with quality adjustment
        c2_confidence = min(100, raw_score * 100 * data_quality)
        
        # Determine threat level
        threat_level = self._determine_threat_level(c2_confidence)
        
        # Generate recommended actions
        actions = self._recommend_actions(threat_level, signals, indicators)
        
        # Build XAI metadata
        metadata = self._build_metadata(signals, temporal_signal, header_signal, graph_signal, behavioral_signal, method_signal)
        
        return AttributionResult(
            node_id=node_id,
            c2_confidence=c2_confidence,
            threat_level=threat_level,
            signals=signals,
            primary_indicators=indicators[:5],
            recommended_actions=actions,
            computed_at=time.time(),
            data_quality=data_quality,
            metadata=metadata,
        )
    
    def _build_metadata(
        self,
        signals: List[SignalBreakdown],
        temporal: SignalBreakdown,
        header: SignalBreakdown,
        graph: SignalBreakdown,
        behavioral: SignalBreakdown,
        method: SignalBreakdown,
    ) -> AttributionMetadata:
        """Build transparent XAI metadata with radar chart data."""
        contributions = {s.name: s.weighted_score for s in signals}
        
        timing_entropy = temporal.details.get('timing_entropy', 0.0)
        header_likelihood = header.details.get('avg_sequence_likelihood', 1.0)
        graph_centrality = graph.details.get('centrality', 0.0)
        method_score = method.raw_score
        behavioral_val = behavioral.raw_score
        
        radar_data = [
            {"axis": "Timing Entropy", "value": round(temporal.raw_score, 3), "weight": self.WEIGHT_TIMING},
            {"axis": "Header Sequence", "value": round(header.raw_score, 3), "weight": self.WEIGHT_HEADER},
            {"axis": "Graph Influence", "value": round(graph.raw_score, 3), "weight": self.WEIGHT_GRAPH},
            {"axis": "Behavioral", "value": round(behavioral_val, 3), "weight": self.WEIGHT_BEHAVIORAL},
            {"axis": "Method Ratio", "value": round(method_score, 3), "weight": self.WEIGHT_METHOD},
        ]
        
        return AttributionMetadata(
            signal_contributions=contributions,
            timing_entropy=timing_entropy,
            header_sequence_likelihood=header_likelihood,
            graph_centrality_score=graph_centrality,
            method_ratio_score=method_score,
            behavioral_score=behavioral_val,
            radar_chart_data=radar_data,
        )
    
    def _compute_graph_signal(self, node_id: str) -> SignalBreakdown:
        """Extract C2 signal from graph topology."""
        metrics = self.graph_engine.compute_metrics()
        node_metrics = metrics.get(node_id)
        
        if not node_metrics:
            return SignalBreakdown(
                name="graph",
                raw_score=0.0,
                weight=self.WEIGHT_GRAPH,
                weighted_score=0.0,
                reason="No graph data available"
            )
        
        score = node_metrics.anomaly_score
        
        reasons = []
        if node_metrics.is_hub:
            reasons.append("Hub node (high connectivity)")
        if node_metrics.is_bridge:
            reasons.append("Bridge node (community connector)")
        if node_metrics.degree_centrality > 0.3:
            reasons.append(f"High centrality ({node_metrics.degree_centrality:.2f})")
        
        reason = "; ".join(reasons) if reasons else "Normal graph position"
        
        return SignalBreakdown(
            name="graph",
            raw_score=score,
            weight=self.WEIGHT_GRAPH,
            weighted_score=score * self.WEIGHT_GRAPH,
            reason=reason,
            details={
                'centrality': node_metrics.degree_centrality,
                'betweenness': node_metrics.betweenness,
                'community_id': node_metrics.community_id,
                'is_hub': node_metrics.is_hub,
                'is_bridge': node_metrics.is_bridge
            }
        )
    
    def _compute_temporal_signal(self, node_id: str) -> SignalBreakdown:
        """Extract C2 signal from timing patterns including Shannon Entropy."""
        profile = self.temporal_engine.analyze_node(node_id)
        
        if not profile:
            return SignalBreakdown(
                name="temporal",
                raw_score=0.0,
                weight=self.WEIGHT_TIMING,
                weighted_score=0.0,
                reason="Insufficient timing data"
            )
        
        # Combine beacon score with shadow controller score for maximum detection
        score = max(profile.beacon_score, profile.shadow_controller_score)
        
        reasons = []
        if profile.pattern_type == 'shadow_controller':
            reasons.append(f"⚠ Shadow Controller detected (entropy: {profile.timing_entropy_normalized:.3f}, jitter: {profile.jitter:.3f})")
        elif profile.is_beacon:
            reasons.append(f"Beacon pattern detected ({profile.pattern_type})")
        if profile.jitter < 0.15:
            reasons.append(f"Low timing jitter ({profile.jitter:.3f})")
        if profile.interval_consistency > 0.5:
            reasons.append(f"High interval consistency ({profile.interval_consistency:.1%})")
        if profile.timing_entropy_normalized < 0.3:
            reasons.append(f"Low timing entropy ({profile.timing_entropy_normalized:.3f}) — automated")
        
        reason = "; ".join(reasons) if reasons else "Normal timing variance"
        
        return SignalBreakdown(
            name="temporal",
            raw_score=score,
            weight=self.WEIGHT_TIMING,
            weighted_score=score * self.WEIGHT_TIMING,
            reason=reason,
            details={
                'mean_delta_ms': profile.mean_delta_ms,
                'jitter': profile.jitter,
                'dominant_interval_ms': profile.dominant_interval_ms,
                'consistency': profile.interval_consistency,
                'pattern_type': profile.pattern_type,
                'is_beacon': profile.is_beacon,
                'timing_entropy': profile.timing_entropy,
                'timing_entropy_normalized': profile.timing_entropy_normalized,
                'shadow_controller_score': profile.shadow_controller_score,
            }
        )
    
    def _compute_header_signal(self, node_id: str) -> SignalBreakdown:
        """Extract C2 signal from header fingerprints including Markov scoring."""
        profile = self.header_engine.get_node_profile(node_id)
        
        if not profile:
            return SignalBreakdown(
                name="header",
                raw_score=0.0,
                weight=self.WEIGHT_HEADER,
                weighted_score=0.0,
                reason="No header data available"
            )
        
        # Combine anomaly score with Markov deviation
        markov_penalty = max(0, 1.0 - profile.avg_sequence_likelihood)
        score = max(profile.header_anomaly_score, markov_penalty * 0.8)
        
        reasons = []
        if profile.suspicious_count > 0:
            ratio = profile.suspicious_count / profile.total_requests
            reasons.append(f"Suspicious headers ({ratio:.1%} of requests)")
        if not profile.is_consistent:
            reasons.append("Inconsistent fingerprints")
        if len(profile.fingerprints_seen) == 1 and profile.total_requests > 10:
            reasons.append("Single fingerprint (bot-like consistency)")
        if profile.avg_sequence_likelihood < 0.3:
            reasons.append(f"Header sequence deviation (likelihood: {profile.avg_sequence_likelihood:.4f})")
        
        reason = "; ".join(reasons) if reasons else "Normal header patterns"
        
        return SignalBreakdown(
            name="header",
            raw_score=score,
            weight=self.WEIGHT_HEADER,
            weighted_score=score * self.WEIGHT_HEADER,
            reason=reason,
            details={
                'fingerprints_seen': len(profile.fingerprints_seen),
                'user_agents_seen': len(profile.user_agents_seen),
                'suspicious_count': profile.suspicious_count,
                'total_requests': profile.total_requests,
                'avg_sequence_likelihood': profile.avg_sequence_likelihood,
            }
        )
    
    def _compute_behavioral_signal(self, node_id: str) -> SignalBreakdown:
        """Extract C2 signal from behavioral patterns."""
        graph_metrics = self.graph_engine.compute_metrics().get(node_id)
        timing_profile = self.temporal_engine.analyze_node(node_id)
        
        score = 0.0
        reasons = []
        
        # High request volume
        if graph_metrics:
            request_count = graph_metrics.out_degree
            if request_count > 100:
                score += 0.3
                reasons.append(f"High request volume ({request_count})")
        
        # Request timing patterns
        if timing_profile:
            if timing_profile.request_count > 50 and timing_profile.jitter < 0.2:
                score += 0.4
                reasons.append("Sustained automated activity")
        
        score = min(1.0, score)
        
        reason = "; ".join(reasons) if reasons else "Normal behavior patterns"
        
        return SignalBreakdown(
            name="behavioral",
            raw_score=score,
            weight=self.WEIGHT_BEHAVIORAL,
            weighted_score=score * self.WEIGHT_BEHAVIORAL,
            reason=reason
        )
    
    def _compute_method_ratio_signal(self, node_id: str) -> SignalBreakdown:
        """
        Extract C2 signal from HTTP method distribution.
        
        C2 beacons overwhelmingly use GET or POST exclusively.
        Normal browsing has a healthy mix of methods.
        
        Scoring:
        - >99% single method → 0.95
        - >95% single method → 0.80
        - >90% single method → 0.50
        - Balanced distribution → 0.0
        """
        method_dist = self.graph_engine.get_method_distribution(node_id)
        
        if not method_dist:
            return SignalBreakdown(
                name="method_ratio",
                raw_score=0.0,
                weight=self.WEIGHT_METHOD,
                weighted_score=0.0,
                reason="No method data available"
            )
        
        total = sum(method_dist.values())
        if total == 0:
            return SignalBreakdown(
                name="method_ratio",
                raw_score=0.0,
                weight=self.WEIGHT_METHOD,
                weighted_score=0.0,
                reason="No requests recorded"
            )
        
        # Find dominant method
        dominant_method = max(method_dist, key=method_dist.get)
        dominant_ratio = method_dist[dominant_method] / total
        
        # Score based on how skewed the distribution is
        if dominant_ratio >= 0.99:
            score = 0.95
        elif dominant_ratio >= 0.95:
            score = 0.80
        elif dominant_ratio >= 0.90:
            score = 0.50
        elif dominant_ratio >= 0.80:
            score = 0.20
        else:
            score = 0.0
        
        # Build reason
        method_str = ", ".join(f"{m}: {c}" for m, c in sorted(method_dist.items(), key=lambda x: -x[1]))
        if score > 0.5:
            reason = f"Skewed to {dominant_method} ({dominant_ratio:.1%}): [{method_str}]"
        else:
            reason = f"Normal method mix: [{method_str}]"
        
        return SignalBreakdown(
            name="method_ratio",
            raw_score=score,
            weight=self.WEIGHT_METHOD,
            weighted_score=score * self.WEIGHT_METHOD,
            reason=reason,
            details={
                'method_distribution': method_dist,
                'dominant_method': dominant_method,
                'dominant_ratio': dominant_ratio,
            }
        )
    
    def _compute_data_quality(
        self, 
        node_id: str, 
        signals: List[SignalBreakdown]
    ) -> float:
        """
        Compute confidence multiplier based on data availability.
        """
        available_signals = sum(1 for s in signals if s.raw_score > 0 or 'No' not in s.reason)
        total_signals = len(signals)
        
        base_quality = available_signals / total_signals
        high_conf_bonus = sum(0.08 for s in signals if s.raw_score > 0.7)
        
        return min(1.0, base_quality + high_conf_bonus)
    
    def _determine_threat_level(self, score: float) -> ThreatLevel:
        """Map numeric score to threat level."""
        if score >= self.THRESHOLD_CRITICAL:
            return ThreatLevel.CRITICAL
        elif score >= self.THRESHOLD_HIGH:
            return ThreatLevel.HIGH
        elif score >= self.THRESHOLD_ELEVATED:
            return ThreatLevel.ELEVATED
        else:
            return ThreatLevel.LOW
    
    def _graph_indicators(self, signal: SignalBreakdown) -> List[str]:
        indicators = []
        details = signal.details
        if details.get('is_hub'):
            indicators.append("Network hub position")
        if details.get('is_bridge'):
            indicators.append("Community bridge position")
        if details.get('centrality', 0) > 0.5:
            indicators.append("Abnormally high network centrality")
        return indicators
    
    def _temporal_indicators(self, signal: SignalBreakdown) -> List[str]:
        indicators = []
        details = signal.details
        
        if details.get('pattern_type') == 'shadow_controller':
            indicators.append("⚠ Shadow Controller: periodic C2 with deliberate jitter evasion")
        elif details.get('is_beacon'):
            pattern = details.get('pattern_type', 'beacon')
            interval = details.get('dominant_interval_ms', 0)
            indicators.append(f"Beacon pattern: {pattern} @ {interval:.0f}ms")
        
        jitter = details.get('jitter', 1.0)
        if jitter < 0.1:
            indicators.append("Rigid timing (automation signature)")
        elif jitter < 0.2:
            indicators.append("Low-jitter timing (possible automation)")
        
        entropy = details.get('timing_entropy_normalized', 1.0)
        if entropy < 0.3:
            indicators.append(f"Low timing entropy ({entropy:.3f})")
        
        return indicators
    
    def _header_indicators(self, signal: SignalBreakdown) -> List[str]:
        indicators = []
        details = signal.details
        if details.get('suspicious_count', 0) > 0:
            indicators.append("Non-browser HTTP fingerprint")
        if details.get('fingerprints_seen', 0) == 1:
            indicators.append("Single consistent fingerprint (bot-like)")
        if details.get('avg_sequence_likelihood', 1.0) < 0.3:
            indicators.append("Header sequence deviates from baseline (Markov chain)")
        return indicators
    
    def _behavioral_indicators(self, signal: SignalBreakdown) -> List[str]:
        return [r.strip() for r in signal.reason.split(";") if r.strip() and "Normal" not in r]
    
    def _recommend_actions(
        self,
        threat_level: ThreatLevel,
        signals: List[SignalBreakdown],
        indicators: List[str]
    ) -> List[str]:
        actions = []
        
        if threat_level == ThreatLevel.CRITICAL:
            actions.append("IMMEDIATE: Isolate node from network")
            actions.append("Capture full packet traces")
            actions.append("Escalate to incident response team")
            actions.append("Check for lateral movement from this node")
        elif threat_level == ThreatLevel.HIGH:
            actions.append("Increase monitoring on this node")
            actions.append("Review all connections to/from node")
            actions.append("Verify legitimate business purpose")
            actions.append("Consider temporary quarantine")
        elif threat_level == ThreatLevel.ELEVATED:
            actions.append("Flag for analyst review")
            actions.append("Monitor for escalation")
            actions.append("Collect additional telemetry")
        else:
            actions.append("Continue standard monitoring")
        
        return actions
    
    def score_all_nodes(self, min_score: float = 0.0) -> List[AttributionResult]:
        """Score all known nodes. Returns nodes with score >= min_score."""
        node_ids = set()
        
        for node_id in self.graph_engine.compute_metrics().keys():
            node_ids.add(node_id)
        
        for node_id in self.temporal_engine._timestamps.keys():
            node_ids.add(node_id)
        
        for node_id in self.header_engine._node_profiles.keys():
            node_ids.add(node_id)
        
        results = []
        for node_id in node_ids:
            result = self.score_node(node_id)
            if result.c2_confidence >= min_score:
                results.append(result)
        
        results.sort(key=lambda r: r.c2_confidence, reverse=True)
        return results
    
    def get_threat_summary(self) -> Dict[str, Any]:
        """Get summary of all threats across the network."""
        all_results = self.score_all_nodes(min_score=0)
        
        critical = [r for r in all_results if r.threat_level == ThreatLevel.CRITICAL]
        high = [r for r in all_results if r.threat_level == ThreatLevel.HIGH]
        elevated = [r for r in all_results if r.threat_level == ThreatLevel.ELEVATED]
        
        return {
            'total_nodes': len(all_results),
            'critical_count': len(critical),
            'high_count': len(high),
            'elevated_count': len(elevated),
            'top_threats': [r.to_dict() for r in all_results[:10]],
            'computed_at': time.time()
        }


# Singleton instance
_scorer: Optional[AttributionScorer] = None


def get_attribution_scorer() -> AttributionScorer:
    """Get or create the singleton scorer instance."""
    global _scorer
    if _scorer is None:
        _scorer = AttributionScorer()
    return _scorer


def reset_attribution_scorer() -> None:
    """Reset the scorer (for testing)."""
    global _scorer
    _scorer = None
