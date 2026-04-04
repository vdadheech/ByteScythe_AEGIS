"""
AEGIS Active Attribution Engine - Ingestion Layer

This module handles data ingestion from two paths:

1. COLD START (CSV):
   - load_all_data() reads static CSVs for initial database seeding
   - clean_system_logs() validates and deduplicates

2. HOT PATH (AsyncLogTailer):
   - Simulates a socket-based stream using asyncio
   - Maintains a sliding window deque(maxlen=50,000) of recent requests
   - Feeds all three engines (graph, temporal, header) simultaneously
   - Ensures the Graph Engine only processes "hot" data

ARCHITECTURE:
   CSV/Socket → AsyncLogTailer → deque(50k) → [Graph, Temporal, Header] engines
"""

import pandas as pd
import asyncio
import logging
import time
from pathlib import Path
from collections import deque
from typing import Optional, List, Dict, Any, Callable, AsyncGenerator
import sqlite3

from pydantic import BaseModel, ConfigDict, Field, field_validator

from backend.engine.graph_engine import get_graph_engine
from backend.engine.temporal_engine import get_temporal_engine
from backend.engine.header_fingerprint import get_header_engine

# Set up professional logging to track our data pipeline
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)


# ═══════════════════════════════════════
#  Pydantic V2 Ingestion Schema
# ═══════════════════════════════════════

class IngestRecord(BaseModel):
    """Incoming telemetry record — validated at ingestion boundary with zero-latency."""
    model_config = ConfigDict(strict=False)

    node_id: str
    timestamp: float = Field(default_factory=lambda: time.time() * 1000)
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
#  CSV Cold-Start Functions (Original)
# ═══════════════════════════════════════

def clean_system_logs(df: pd.DataFrame) -> pd.DataFrame:
    initial_rows = len(df)
    
    required_columns = ['log_id', 'node_id', 'http_response_code']
    missing_cols = [col for col in required_columns if col not in df.columns]
    if missing_cols:
        raise ValueError(f"CRITICAL ERROR: System logs are missing essential columns: {missing_cols}")

    for col in required_columns:
        df[col] = pd.to_numeric(df[col], errors='coerce')

    df = df.dropna(subset=required_columns)

    df['log_id'] = df['log_id'].astype(int)
    df['node_id'] = df['node_id'].astype(int)
    df['http_response_code'] = df['http_response_code'].astype(int)

    df = df.sort_values(by='log_id', ascending=True)

    # Deduplication with warning
    duplicates = df.duplicated(subset=['log_id']).sum()
    if duplicates > 0:
        logger.warning(f"Dropped {duplicates} duplicate log entries.")
        
    df = df.drop_duplicates(subset=['log_id'], keep='first')
    df = df.reset_index(drop=True)

    final_rows = len(df)
    fatal_errors = initial_rows - final_rows - duplicates
    logger.info(f"System Logs cleaned: Processed {initial_rows} rows. Dropped {fatal_errors} corrupted rows and {duplicates} duplicates. Final count: {final_rows}.")
    
    return df

def load_all_data(data_dir: str = "data") -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    base_path = Path(data_dir)
    logs_path = base_path / "system_logs.csv"
    registry_path = base_path / "node_registry.csv"
    schema_path = base_path / "schema_config.csv"

    for path in [logs_path, registry_path, schema_path]:
        if not path.exists():
            raise FileNotFoundError(f"PIPELINE HALTED: Could not find required intelligence asset at {path.absolute()}")

    logger.info("Ingesting raw CSV files...")
    try:
        raw_logs = pd.read_csv(logs_path)
        registry = pd.read_csv(registry_path)
        schemas = pd.read_csv(schema_path)
    except (pd.errors.ParserError, pd.errors.EmptyDataError, OSError) as e:
        raise RuntimeError(f"Failed to read CSV files. Error: {str(e)}")

    clean_logs = clean_system_logs(raw_logs)
    return clean_logs, registry, schemas


# ═══════════════════════════════════════
#  AsyncLogTailer — Hot Path Ingestion
# ═══════════════════════════════════════

class AsyncLogTailer:
    """
    Async ingestion engine that simulates a socket-based stream.
    
    Maintains a sliding window deque of the last 50,000 requests,
    ensuring the Graph Engine only processes "hot" data.
    
    Usage:
        tailer = AsyncLogTailer()
        await tailer.start()
        
        # Ingest a single record
        await tailer.ingest({"node_id": "10", "timestamp": 1234567890000, ...})
        
        # Simulate tailing a CSV file
        async for record in tailer.tail_csv("data/system_logs.csv"):
            pass  # records are auto-ingested
    """
    
    WINDOW_SIZE = 50_000
    
    def __init__(self, window_size: int = WINDOW_SIZE):
        self._window: deque = deque(maxlen=window_size)
        self._running: bool = False
        self._ingest_count: int = 0
        self._error_count: int = 0
        self._start_time: float = 0.0
        self._callbacks: List[Callable] = []
    
    async def start(self) -> None:
        """Start the tailer."""
        self._running = True
        self._start_time = time.time()
        logger.info(f"AsyncLogTailer started (window: {self._window.maxlen})")
    
    async def stop(self) -> None:
        """Stop the tailer."""
        self._running = False
        logger.info(f"AsyncLogTailer stopped. Ingested: {self._ingest_count}, Errors: {self._error_count}")
    
    def on_ingest(self, callback: Callable) -> None:
        """Register a callback for each ingested record."""
        self._callbacks.append(callback)
    
    async def ingest(self, raw_record: Dict[str, Any]) -> Optional[IngestRecord]:
        """
        Ingest a single record with Pydantic V2 validation.
        
        Pushes validated record to the sliding window deque and
        feeds all three detection engines simultaneously.
        """
        try:
            # Validate with Pydantic V2 (zero-latency schema validation)
            record = IngestRecord(**raw_record)
        except Exception as e:
            self._error_count += 1
            logger.debug(f"Ingestion validation error: {e}")
            return None
        
        # Push to sliding window
        self._window.append(record)
        self._ingest_count += 1
        
        # ── Feed all three engines simultaneously ──
        
        # 1. Graph Engine
        graph = get_graph_engine()
        graph.add_interaction(
            source_ip=record.source_ip or str(record.node_id),
            target_endpoint=record.target_endpoint,
            timestamp=record.timestamp,
            metadata={"http_method": record.http_method},
        )
        
        # 2. Temporal Engine
        temporal = get_temporal_engine()
        temporal.record_request(
            node_id=record.node_id,
            timestamp_ms=record.timestamp,
        )
        
        # 3. Header Engine (if headers present)
        if record.headers:
            header_engine = get_header_engine()
            header_engine.analyze_request(
                node_id=record.node_id,
                headers=record.headers,
                header_order=record.header_order,
            )
        
        # Fire callbacks
        for cb in self._callbacks:
            try:
                result = cb(record)
                if asyncio.iscoroutine(result):
                    await result
            except Exception:
                pass
        
        return record
    
    async def ingest_batch(self, records: List[Dict[str, Any]]) -> int:
        """Ingest a batch of records. Returns count of successfully ingested."""
        success = 0
        for raw in records:
            result = await self.ingest(raw)
            if result is not None:
                success += 1
            # Yield control periodically
            if success % 100 == 0:
                await asyncio.sleep(0)
        return success
    
    async def tail_csv(
        self,
        csv_path: str,
        poll_interval: float = 0.5,
        batch_size: int = 100,
    ) -> AsyncGenerator[IngestRecord, None]:
        """
        Simulate live file-tailing by reading a CSV and yielding records
        as if they were arriving via a network socket.
        
        Args:
            csv_path: Path to the CSV file
            poll_interval: Seconds between batches (simulates stream pace)
            batch_size: Records per batch
        """
        try:
            df = pd.read_csv(csv_path)
        except Exception as e:
            logger.error(f"Failed to read CSV for tailing: {e}")
            return
        
        logger.info(f"Tailing CSV: {csv_path} ({len(df)} rows, batch_size={batch_size})")
        
        for start_idx in range(0, len(df), batch_size):
            if not self._running:
                break
            
            batch = df.iloc[start_idx:start_idx + batch_size]
            
            for _, row in batch.iterrows():
                raw = {
                    "node_id": str(row.get("node_id", "unknown")),
                    "timestamp": float(row.get("timestamp", time.time() * 1000)),
                    "source_ip": str(row.get("source_ip", f"10.0.0.{row.get('node_id', 0)}")),
                    "target_endpoint": str(row.get("target_endpoint", "/api/telemetry")),
                    "http_method": str(row.get("http_method", "GET")),
                    "http_response_code": int(row.get("http_response_code", 200)),
                    "response_time_ms": float(row.get("response_time_ms", 0)),
                    "user_agent": str(row.get("user_agent", "")),
                }
                
                record = await self.ingest(raw)
                if record:
                    yield record
            
            # Simulate stream pacing
            await asyncio.sleep(poll_interval)
        
        logger.info(f"CSV tailing complete: {self._ingest_count} records ingested")
    
    def get_window(self) -> List[Dict[str, Any]]:
        """Return the current sliding window as a list of dicts."""
        return [r.model_dump() for r in self._window]
    
    def get_window_size(self) -> int:
        """Return current window occupancy."""
        return len(self._window)
    
    def get_stats(self) -> Dict[str, Any]:
        """Return tailer statistics."""
        elapsed = time.time() - self._start_time if self._start_time else 0
        rate = self._ingest_count / elapsed if elapsed > 0 else 0
        
        return {
            "running": self._running,
            "window_size": len(self._window),
            "window_capacity": self._window.maxlen,
            "total_ingested": self._ingest_count,
            "error_count": self._error_count,
            "ingest_rate_per_sec": round(rate, 1),
            "uptime_seconds": round(elapsed, 1),
        }


# ═══════════════════════════════════════
#  Singleton
# ═══════════════════════════════════════

_tailer: Optional[AsyncLogTailer] = None


def get_log_tailer() -> AsyncLogTailer:
    """Get or create the singleton AsyncLogTailer."""
    global _tailer
    if _tailer is None:
        _tailer = AsyncLogTailer()
    return _tailer


def reset_log_tailer() -> None:
    """Reset the tailer (for testing)."""
    global _tailer
    _tailer = None


# ═══════════════════════════════════════
#  Original CLI entrypoint
# ═══════════════════════════════════════

if __name__ == "__main__":
    try:
        # 1. Run the pipeline (loads all 3, cleans the logs)
        logs, nodes, schema = load_all_data(data_dir="data")
        
        # 2. Create a folder for the clean data
        processed_dir = Path("data/processed")
        processed_dir.mkdir(parents=True, exist_ok=True)
        
        # 3. Export ALL artifacts so Phase 2 has everything in one place
        logs.to_csv(processed_dir / "clean_system_logs.csv", index=False)
        nodes.to_csv(processed_dir / "validated_node_registry.csv", index=False)
        schema.to_csv(processed_dir / "validated_schema_config.csv", index=False)
        
        logger.info("SUCCESS: All datasets exported to data/processed/")
        print("\n✅ Phase 1 Complete. All 3 Artifacts generated.")
        
    except (FileNotFoundError, ValueError, RuntimeError, OSError, sqlite3.Error) as e:
        logger.error(str(e))