"""
AEGIS Active Attribution Engine - Graph API Routes

This module exposes the graph analytics and attribution engine via REST API.

ENDPOINT DESIGN PRINCIPLES:
--------------------------
1. PAYLOAD MINIMIZATION: Only return suspicious nodes (score > threshold)
2. PAGINATION: Support large datasets without memory explosion
3. CACHING: Use ETags and Cache-Control for repeat requests
4. STREAMING: WebSocket for real-time threat updates

KEY ENDPOINTS:
-------------
GET  /api/v1/graph/active-threats  - Main threat graph endpoint
GET  /api/v1/graph/node/{id}       - Detailed node analysis
GET  /api/v1/graph/timing          - Timing scatter data
GET  /api/v1/graph/summary         - Aggregate threat summary
WS   /ws/v1/threats                - Real-time threat stream
"""

from fastapi import APIRouter, Query, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
from typing import Optional, List
import asyncio
import json
import logging
import time

from backend.engine.graph_engine import get_graph_engine
from backend.engine.temporal_engine import get_temporal_engine
from backend.engine.header_fingerprint import get_header_engine
from backend.engine.attribution_scorer import get_attribution_scorer, ThreatLevel
from backend.engine.ingestion import get_log_tailer
from backend.services.async_pipeline import (
    get_processing_pipeline, 
    ProcessingTask, 
    TaskPriority,
    compute_attribution_async
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/graph", tags=["Graph Analytics"])


@router.get("/active-threats")
async def get_active_threats(
    min_score: float = Query(50.0, ge=0, le=100, description="Minimum C2 confidence score"),
    max_nodes: int = Query(500, ge=1, le=2000, description="Maximum nodes to return"),
    include_links: bool = Query(True, description="Include graph edges"),
    community_filter: Optional[int] = Query(None, description="Filter by community ID")
):
    """
    Returns suspicious nodes with C2 confidence score > threshold.
    
    This is the PRIMARY endpoint for the threat visualization dashboard.
    
    Response format optimized for react-force-graph:
    ```json
    {
        "nodes": [
            {"id": "192.168.1.100", "score": 87, "level": "critical", ...}
        ],
        "links": [
            {"source": "192.168.1.100", "target": "/api/beacon", "weight": 42}
        ],
        "metadata": {
            "totalNodes": 1500,
            "filteredNodes": 23,
            "computedAt": 1712345678.123
        }
    }
    ```
    
    PAYLOAD MINIMIZATION STRATEGY:
    - Only includes nodes with score >= min_score
    - Links only between filtered nodes
    - Metadata summarizes what was filtered out
    """
    start_time = time.time()
    
    try:
        # Get graph data
        graph_engine = get_graph_engine()
        graph_data = graph_engine.get_graph_for_visualization(
            max_nodes=max_nodes,
            min_score=min_score / 100  # Convert to 0-1 scale
        )
        
        # Get attribution scores for visible nodes
        scorer = get_attribution_scorer()
        
        # Enhance nodes with attribution data
        enhanced_nodes = []
        for node in graph_data['nodes']:
            node_id = node['id']
            
            # Get detailed attribution
            attribution = scorer.score_node(node_id)
            
            # Determine threat level
            level = attribution.threat_level.value
            
            enhanced_node = {
                'id': node_id,
                'score': round(attribution.c2_confidence, 1),
                'level': level,
                'type': node.get('type', 'unknown'),
                'community': node.get('community', 0),
                'isHub': node.get('isHub', False),
                'isBridge': node.get('isBridge', False),
                'connections': node.get('connections', 0),
                'primaryIndicator': attribution.primary_indicators[0] if attribution.primary_indicators else None
            }
            
            # Apply community filter
            if community_filter is not None and enhanced_node['community'] != community_filter:
                continue
            
            enhanced_nodes.append(enhanced_node)
        
        # Filter and limit
        enhanced_nodes.sort(key=lambda n: n['score'], reverse=True)
        enhanced_nodes = enhanced_nodes[:max_nodes]
        
        # Filter links to only include visible nodes
        visible_ids = {n['id'] for n in enhanced_nodes}
        filtered_links = []
        
        if include_links:
            for link in graph_data.get('links', []):
                if link['source'] in visible_ids and link['target'] in visible_ids:
                    filtered_links.append(link)
        
        processing_time = (time.time() - start_time) * 1000
        
        return {
            'nodes': enhanced_nodes,
            'links': filtered_links,
            'metadata': {
                'totalNodes': graph_data['metadata']['totalNodes'],
                'totalEdges': graph_data['metadata']['totalEdges'],
                'filteredNodes': len(enhanced_nodes),
                'filteredEdges': len(filtered_links),
                'minScoreFilter': min_score,
                'computedAt': time.time(),
                'processingTimeMs': round(processing_time, 2)
            }
        }
        
    except Exception as e:
        logger.error(f"Error in get_active_threats: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/node/{node_id}")
async def get_node_details(node_id: str):
    """
    Get detailed analysis for a specific node.
    
    Returns full attribution breakdown with:
    - C2 confidence score and level
    - Signal breakdown (graph, temporal, header, behavioral)
    - Primary indicators
    - Recommended actions
    - Raw timing data for visualization
    """
    try:
        scorer = get_attribution_scorer()
        attribution = scorer.score_node(node_id)
        
        # Get timing data for this node
        temporal = get_temporal_engine()
        timing_data = temporal.get_timing_data_for_visualization(
            node_id=node_id,
            max_points=200
        )
        
        # Get header profile
        headers = get_header_engine()
        header_profile = headers.get_node_profile(node_id)
        
        # Get graph metrics
        graph = get_graph_engine()
        graph_metrics = graph.compute_metrics().get(node_id)
        
        return {
            'nodeId': node_id,
            'attribution': attribution.to_dict(),
            'timing': {
                'points': timing_data['points'],
                'profile': timing_data['profiles'][0] if timing_data['profiles'] else None
            },
            'headers': header_profile.to_dict() if header_profile else None,
            'graph': graph_metrics.to_dict() if graph_metrics else None
        }
        
    except Exception as e:
        logger.error(f"Error getting node details for {node_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/timing")
async def get_timing_scatter(
    max_points: int = Query(500, ge=1, le=2000),
    node_filter: Optional[str] = Query(None, description="Filter to specific node")
):
    """
    Get timing data for scatter plot visualization.
    
    Returns:
    ```json
    {
        "points": [
            {"x": 1712345678000, "y": 305, "node": "192.168.1.100", "isBeacon": true}
        ],
        "profiles": [
            {"nodeId": "...", "beaconScore": 0.87, "patternType": "beacon"}
        ],
        "summary": {
            "totalPoints": 500,
            "beaconNodes": 5,
            "avgDeltaMs": 320
        }
    }
    ```
    
    Visualization shows:
    - X axis: Timestamp
    - Y axis: Inter-arrival delta (ms)
    - Color: Red = beacon, Green = human
    
    Human traffic appears scattered; beacons form horizontal bands.
    """
    try:
        temporal = get_temporal_engine()
        
        data = temporal.get_timing_data_for_visualization(
            node_id=node_filter,
            max_points=max_points
        )
        
        # Compute summary stats
        beacon_nodes = [p for p in data['profiles'] if p.get('is_beacon')]
        
        deltas = [p['y'] for p in data['points']]
        avg_delta = sum(deltas) / len(deltas) if deltas else 0
        
        return {
            'points': data['points'],
            'profiles': data['profiles'],
            'summary': {
                'totalPoints': len(data['points']),
                'totalProfiles': len(data['profiles']),
                'beaconNodes': len(beacon_nodes),
                'avgDeltaMs': round(avg_delta, 2)
            }
        }
        
    except Exception as e:
        logger.error(f"Error getting timing data: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/summary")
async def get_threat_summary():
    """
    Get aggregate threat summary for dashboard widgets.
    
    Returns counts by threat level and top threats.
    """
    try:
        scorer = get_attribution_scorer()
        summary = scorer.get_threat_summary()
        
        # Add engine stats
        graph = get_graph_engine()
        temporal = get_temporal_engine()
        headers = get_header_engine()
        
        return {
            **summary,
            'engines': {
                'graph': {
                    'nodes': len(graph.graph),
                    'edges': graph.graph.number_of_edges()
                },
                'temporal': {
                    'trackedNodes': len(temporal._timestamps)
                },
                'headers': headers.get_fingerprint_stats()
            }
        }
        
    except Exception as e:
        logger.error(f"Error getting threat summary: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/communities")
async def get_communities(
    min_size: int = Query(2, ge=1, description="Minimum community size")
):
    """
    Get detected communities/clusters.
    
    Useful for identifying botnet groups.
    """
    try:
        graph = get_graph_engine()
        metrics = graph.compute_metrics()
        
        # Group nodes by community
        communities = {}
        for node_id, m in metrics.items():
            cid = m.community_id
            if cid not in communities:
                communities[cid] = {
                    'id': cid,
                    'nodes': [],
                    'totalScore': 0,
                    'hubCount': 0
                }
            communities[cid]['nodes'].append(node_id)
            communities[cid]['totalScore'] += m.anomaly_score
            if m.is_hub:
                communities[cid]['hubCount'] += 1
        
        # Filter by size and compute average scores
        filtered = []
        for c in communities.values():
            if len(c['nodes']) >= min_size:
                c['size'] = len(c['nodes'])
                c['avgScore'] = round(c['totalScore'] / c['size'] * 100, 1)
                del c['totalScore']
                filtered.append(c)
        
        # Sort by average score
        filtered.sort(key=lambda c: c['avgScore'], reverse=True)
        
        return {'communities': filtered}
        
    except Exception as e:
        logger.error(f"Error getting communities: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/star-topologies")
async def detect_star_topologies():
    """
    Detect star topology patterns characteristic of C2.
    
    A star topology indicates:
    - One central controller
    - Multiple victim endpoints
    - Low interconnection between victims
    """
    try:
        graph = get_graph_engine()
        stars = graph.detect_star_topology()
        
        return {
            'starTopologies': stars,
            'count': len(stars)
        }
        
    except Exception as e:
        logger.error(f"Error detecting star topologies: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/pipeline/stats")
async def get_pipeline_stats():
    """Get async processing pipeline statistics."""
    try:
        pipeline = get_processing_pipeline()
        return pipeline.get_stats()
    except Exception as e:
        logger.error(f"Error getting pipeline stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/blast-radius/{node_id}")
async def get_blast_radius(node_id: str):
    """
    BFS blast-radius traversal from a high-confidence C2 node.
    
    Returns all compromised downstream nodes and edges.
    Frontend renders compromised edges in animated "Pulse Red".
    """
    try:
        graph = get_graph_engine()
        result = graph.compute_blast_radius(node_id)
        return result
    except Exception as e:
        logger.error(f"Error computing blast radius for {node_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/zoom/{node_id}")
async def zoom_to_controller(node_id: str):
    """
    Zoom-to-Controller: isolate a node and its 1-hop neighbors.
    Returns the ego subgraph for focused analysis.
    """
    try:
        graph = get_graph_engine()
        return graph.zoom_to_controller(node_id)
    except Exception as e:
        logger.error(f"Error in zoom-to-controller for {node_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/baseline")
async def get_baseline():
    """
    Returns the 'Golden Image' baseline fingerprint data.
    Built from the Markov transition matrix of known-good browser traffic.
    """
    try:
        headers = get_header_engine()
        matrix = headers.get_markov_matrix()
        stats = headers.get_fingerprint_stats()
        
        temporal = get_temporal_engine()
        profiles = temporal.analyze_all_nodes()
        entropies = [p.timing_entropy_normalized for p in profiles.values() if p.timing_entropy_normalized > 0]
        avg_entropy = sum(entropies) / len(entropies) if entropies else 0.0
        
        return {
            'header_transition_matrix': matrix,
            'fingerprint_stats': stats,
            'avg_timing_entropy': round(avg_entropy, 4),
            'computed_at': time.time(),
        }
    except Exception as e:
        logger.error(f"Error getting baseline: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/sankey")
async def get_sankey_data():
    """
    Returns Sankey diagram data: legitimate vs shadow sequence flows.
    
    Nodes represent header names, links represent transitions.
    Legitimate flows (matching baseline) are green;
    Shadow flows (deviating from baseline) are red.
    """
    try:
        headers = get_header_engine()
        matrix = headers.get_markov_matrix()
        
        if not matrix:
            return {'nodes': [], 'links': []}
        
        # Build Sankey nodes from unique headers
        header_set = set()
        for src, transitions in matrix.items():
            header_set.add(src)
            header_set.update(transitions.keys())
        
        header_list = sorted(header_set)
        header_idx = {h: i for i, h in enumerate(header_list)}
        
        nodes = []
        for h in header_list:
            nodes.append({"name": h, "category": "header"})
        
        # Build links from transition matrix
        links = []
        for src, transitions in matrix.items():
            for tgt, prob in transitions.items():
                if prob > 0.01:  # Filter noise
                    category = "legitimate" if prob > 0.3 else "shadow"
                    links.append({
                        "source": header_idx[src],
                        "target": header_idx[tgt],
                        "value": round(prob * 100, 2),
                        "category": category,
                    })
        
        return {'nodes': nodes, 'links': links}
    except Exception as e:
        logger.error(f"Error getting sankey data: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/shadow-controllers")
async def get_shadow_controllers(
    threshold: float = Query(0.5, ge=0, le=1, description="Minimum shadow controller score")
):
    """
    Detect Shadow Controllers: periodic C2 with deliberate jitter evasion.
    These are the most dangerous — periodic traffic + ~10% random jitter.
    """
    try:
        temporal = get_temporal_engine()
        controllers = temporal.get_shadow_controllers(threshold=threshold)
        return {
            'shadow_controllers': [c.to_dict() for c in controllers],
            'count': len(controllers),
        }
    except Exception as e:
        logger.error(f"Error getting shadow controllers: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/ingestion/stats")
async def get_ingestion_stats():
    """Get AsyncLogTailer ingestion statistics."""
    try:
        tailer = get_log_tailer()
        return tailer.get_stats()
    except Exception as e:
        logger.error(f"Error getting ingestion stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# WebSocket for real-time threat updates

class ThreatStreamManager:
    """Manages WebSocket connections for threat streaming."""
    
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self._broadcast_task: Optional[asyncio.Task] = None
    
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"Threat stream client connected. Total: {len(self.active_connections)}")
    
    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        logger.info(f"Threat stream client disconnected. Total: {len(self.active_connections)}")
    
    async def broadcast(self, message: dict):
        """Broadcast message to all connected clients."""
        if not self.active_connections:
            return
        
        json_msg = json.dumps(message)
        disconnected = []
        
        for connection in self.active_connections:
            try:
                await connection.send_text(json_msg)
            except Exception:
                disconnected.append(connection)
        
        for conn in disconnected:
            self.disconnect(conn)


threat_stream = ThreatStreamManager()


@router.websocket("/ws/threats")
async def websocket_threat_stream(websocket: WebSocket):
    """
    Real-time threat stream via WebSocket.
    
    Sends threat updates as they are computed:
    ```json
    {
        "event": "threat_update",
        "node": {"id": "...", "score": 85, ...},
        "timestamp": 1712345678.123
    }
    ```
    """
    await threat_stream.connect(websocket)
    
    try:
        while True:
            # Keep connection alive
            # In production, this would receive and process client messages
            data = await websocket.receive_text()
            
            # Echo acknowledgment
            await websocket.send_text(json.dumps({
                "event": "ack",
                "received": data
            }))
            
    except WebSocketDisconnect:
        threat_stream.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        threat_stream.disconnect(websocket)
