"""
RAG layer — indexes verified findings into Qdrant for semantic recall.
sentence-transformers is optional; RAG silently skips if not installed.
"""
import os
import uuid
from typing import List

COLLECTION = "vulnerability_kb"
VECTOR_DIM = 384


def _deps():
    """Lazy import — avoids pulling PyTorch into the orchestrator image."""
    from qdrant_client import QdrantClient
    from qdrant_client.models import Distance, VectorParams, PointStruct
    from sentence_transformers import SentenceTransformer
    return QdrantClient, Distance, VectorParams, PointStruct, SentenceTransformer


def index_findings(findings: List[dict], scan_id: str) -> None:
    if not findings:
        return
    try:
        QdrantClient, Distance, VectorParams, PointStruct, SentenceTransformer = _deps()
    except ImportError:
        print("[rag] sentence-transformers not installed — skipping RAG indexing")
        return

    client = QdrantClient(
        host=os.getenv("QDRANT_HOST", "localhost"),
        port=int(os.getenv("QDRANT_PORT", 6333)),
    )

    names = [c.name for c in client.get_collections().collections]
    if COLLECTION not in names:
        client.create_collection(
            collection_name=COLLECTION,
            vectors_config=VectorParams(size=VECTOR_DIM, distance=Distance.COSINE),
        )

    encoder = SentenceTransformer("all-MiniLM-L6-v2")
    points = []
    for f in findings:
        text = " ".join(filter(None, [
            f.get("vulnerability", ""),
            f.get("root_cause", ""),
            f.get("location", ""),
        ]))
        points.append(PointStruct(
            id=str(uuid.uuid4()),
            vector=encoder.encode(text).tolist(),
            payload={**f, "scan_id": scan_id},
        ))

    client.upsert(collection_name=COLLECTION, points=points)
    print(f"[rag] Indexed {len(points)} findings for scan {scan_id}")
