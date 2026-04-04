"""Quick smoke test of all new Attribution Engine features."""
import numpy as np

# 1. Test Shannon Entropy + Shadow Controller
from backend.engine.temporal_engine import TemporalFingerprintEngine

engine = TemporalFingerprintEngine()
# Simulate periodic bot traffic
for i in range(100):
    engine.record_request("bot_1", 1000 + i * 300)
# Simulate jittered shadow controller
for i in range(100):
    jitter = np.random.normal(0, 30)
    engine.record_request("shadow_1", 1000 + i * 300 + jitter)
# Simulate human traffic
for i in range(100):
    engine.record_request("human_1", 1000 + np.random.exponential(5000))

p1 = engine.analyze_node("bot_1")
p2 = engine.analyze_node("shadow_1")
p3 = engine.analyze_node("human_1")

print(f"Bot: pattern={p1.pattern_type}, entropy={p1.timing_entropy_normalized:.3f}, shadow={p1.shadow_controller_score:.3f}")
print(f"Shadow: pattern={p2.pattern_type}, entropy={p2.timing_entropy_normalized:.3f}, shadow={p2.shadow_controller_score:.3f}")
print(f"Human: pattern={p3.pattern_type}, entropy={p3.timing_entropy_normalized:.3f}, shadow={p3.shadow_controller_score:.3f}")
print()

# 2. Test Markov Chain
from backend.engine.header_fingerprint import HeaderFingerprintEngine

eng = HeaderFingerprintEngine()
fp = eng.analyze_request(
    "test_node",
    {"User-Agent": "python-requests/2.31.0", "Accept": "*/*", "Connection": "keep-alive"},
    ["user-agent", "accept", "connection"],
)
print(f"Header: suspicious={fp.is_suspicious}, likelihood={fp.sequence_likelihood:.4f}")
print(f"  Reasons: {fp.anomaly_reasons}")
print()

# 3. Test Graph + Blast Radius
from backend.engine.graph_engine import GraphAnalyticsEngine

g = GraphAnalyticsEngine()
for i in range(20):
    g.add_interaction(f"10.0.0.{i}", "/api/data", 1000 + i * 100, {"http_method": "GET"})
    g.add_interaction("10.0.0.99", f"/api/endpoint_{i}", 1000 + i * 100, {"http_method": "POST"})

blast = g.compute_blast_radius("10.0.0.99")
ti = blast["total_impact"]
d = blast["depth"]
print(f"Blast radius: origin=10.0.0.99, impact={ti}, depth={d}")

viz = g.get_graph_for_visualization(enable_clustering=True)
fn = viz["metadata"]["filteredNodes"]
fe = viz["metadata"]["filteredEdges"]
cc = viz["metadata"]["clusterCount"]
print(f"Viz: {fn} nodes, {fe} edges, {cc} clusters")
print()

# 4. Test Method Ratio
md = g.get_method_distribution("10.0.0.99")
print(f"10.0.0.99 method dist: {md}")
print()

# 5. Test Attribution Scorer
from backend.engine.attribution_scorer import AttributionScorer

scorer = AttributionScorer(graph_engine=g, temporal_engine=engine)
result = scorer.score_node("10.0.0.99")
print(f"Attribution: C2={result.c2_confidence:.1f}%, level={result.threat_level.value}")
axes = [f"{d['axis']}={d['value']}" for d in result.metadata.radar_chart_data]
print(f"Radar: {axes}")
print()

# 6. Test Pydantic V2 Models
from backend.engine.models import IngestRecord as IR, AttributionMetadata, BlastRadiusResult

record = IR(node_id="test", timestamp=12345.0, http_method="get")
assert record.http_method == "GET", "method not uppercased"
print(f"Pydantic V2: IngestRecord validated OK, method={record.http_method}")

meta = AttributionMetadata()
print(f"AttributionMetadata defaults: weights={meta.score_weights}")

blast_m = BlastRadiusResult(origin="10.0.0.1", depth=3, total_impact=12)
print(f"BlastRadiusResult: {blast_m.model_dump()}")
print()

print("=" * 50)
print("ALL SMOKE TESTS PASSED")
print("=" * 50)
