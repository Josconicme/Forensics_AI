# src/storage/evidence_store.py
"""
Evidence storage with integrity verification
"""
import json
import sqlite3
from pathlib import Path
from datetime import datetime
from typing import List, Optional, Dict, Any
import sys
sys.path.append(str(Path(__file__).parent.parent))
from models.evidence import Evidence


class EvidenceStore:
    """Stores evidence with integrity tracking"""
    
    def __init__(self, db_path: str = "./output/evidence_db/forensics.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_database()
    
    def _init_database(self):
        """Initialize database schema"""
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS evidence (
                    evidence_id TEXT PRIMARY KEY,
                    evidence_type TEXT NOT NULL,
                    source_path TEXT NOT NULL,
                    collected_timestamp TEXT NOT NULL,
                    collector_name TEXT NOT NULL,
                    hash_sha256 TEXT NOT NULL,
                    hash_md5 TEXT NOT NULL,
                    data_size INTEGER NOT NULL,
                    metadata TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS evidence_data (
                    evidence_id TEXT PRIMARY KEY,
                    data BLOB NOT NULL,
                    FOREIGN KEY (evidence_id) REFERENCES evidence(evidence_id)
                )
            """)
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_evidence_type 
                ON evidence(evidence_type)
            """)
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_collected_timestamp 
                ON evidence(collected_timestamp)
            """)
    
    def store_evidence(self, evidence: Evidence) -> bool:
        """Store evidence item"""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                # Store metadata
                conn.execute("""
                    INSERT INTO evidence 
                    (evidence_id, evidence_type, source_path, collected_timestamp,
                     collector_name, hash_sha256, hash_md5, data_size, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    evidence.evidence_id,
                    evidence.evidence_type,
                    evidence.source_path,
                    evidence.collected_timestamp.isoformat(),
                    evidence.collector_name,
                    evidence.hash_sha256,
                    evidence.hash_md5,
                    len(evidence.data),
                    json.dumps(evidence.metadata)
                ))
                
                # Store binary data separately
                conn.execute("""
                    INSERT INTO evidence_data (evidence_id, data)
                    VALUES (?, ?)
                """, (evidence.evidence_id, evidence.data))
                
                conn.commit()
                return True
        except Exception as e:
            print(f"Error storing evidence: {e}")
            return False
    
    def get_evidence(self, evidence_id: str) -> Optional[Evidence]:
        """Retrieve evidence by ID"""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                conn.row_factory = sqlite3.Row
                
                # Get metadata
                cursor = conn.execute("""
                    SELECT * FROM evidence WHERE evidence_id = ?
                """, (evidence_id,))
                
                row = cursor.fetchone()
                if not row:
                    return None
                
                # Get binary data
                cursor = conn.execute("""
                    SELECT data FROM evidence_data WHERE evidence_id = ?
                """, (evidence_id,))
                
                data_row = cursor.fetchone()
                if not data_row:
                    return None
                
                # Reconstruct Evidence object
                evidence = Evidence(
                    evidence_id=row['evidence_id'],
                    evidence_type=row['evidence_type'],
                    source_path=row['source_path'],
                    collected_timestamp=datetime.fromisoformat(row['collected_timestamp']),
                    collector_name=row['collector_name'],
                    data=data_row['data'],
                    metadata=json.loads(row['metadata']) if row['metadata'] else {},
                    hash_sha256=row['hash_sha256'],
                    hash_md5=row['hash_md5']
                )
                
                return evidence
        except Exception as e:
            print(f"Error retrieving evidence: {e}")
            return None
    
    def get_all_evidence(self, evidence_type: Optional[str] = None) -> List[Evidence]:
        """Retrieve all evidence, optionally filtered by type"""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                conn.row_factory = sqlite3.Row
                
                if evidence_type:
                    cursor = conn.execute("""
                        SELECT e.*, ed.data 
                        FROM evidence e
                        JOIN evidence_data ed ON e.evidence_id = ed.evidence_id
                        WHERE e.evidence_type = ?
                        ORDER BY e.collected_timestamp DESC
                    """, (evidence_type,))
                else:
                    cursor = conn.execute("""
                        SELECT e.*, ed.data 
                        FROM evidence e
                        JOIN evidence_data ed ON e.evidence_id = ed.evidence_id
                        ORDER BY e.collected_timestamp DESC
                    """)
                
                evidence_list = []
                for row in cursor.fetchall():
                    evidence = Evidence(
                        evidence_id=row['evidence_id'],
                        evidence_type=row['evidence_type'],
                        source_path=row['source_path'],
                        collected_timestamp=datetime.fromisoformat(row['collected_timestamp']),
                        collector_name=row['collector_name'],
                        data=row['data'],
                        metadata=json.loads(row['metadata']) if row['metadata'] else {},
                        hash_sha256=row['hash_sha256'],
                        hash_md5=row['hash_md5']
                    )
                    evidence_list.append(evidence)
                
                return evidence_list
        except Exception as e:
            print(f"Error retrieving all evidence: {e}")
            return []
    
    def verify_integrity(self, evidence_id: str) -> bool:
        """Verify evidence integrity by recomputing hashes"""
        evidence = self.get_evidence(evidence_id)
        if not evidence:
            return False
        
        return evidence.verify_integrity()
    
    def get_evidence_summary(self) -> Dict[str, Any]:
        """Get summary statistics of stored evidence"""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                cursor = conn.execute("""
                    SELECT 
                        COUNT(*) as total_count,
                        SUM(data_size) as total_size,
                        evidence_type,
                        COUNT(*) as type_count
                    FROM evidence
                    GROUP BY evidence_type
                """)
                
                type_counts = {}
                total_count = 0
                total_size = 0
                
                for row in cursor.fetchall():
                    type_counts[row[2]] = row[3]
                    total_count += row[3]
                    total_size += row[1] if row[1] else 0
                
                return {
                    'total_evidence': total_count,
                    'total_size_bytes': total_size,
                    'evidence_by_type': type_counts
                }
        except Exception as e:
            print(f"Error getting evidence summary: {e}")
            return {}
    
    def delete_evidence(self, evidence_id: str) -> bool:
        """Delete evidence (use with caution - chain of custody implications)"""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                conn.execute("DELETE FROM evidence_data WHERE evidence_id = ?", (evidence_id,))
                conn.execute("DELETE FROM evidence WHERE evidence_id = ?", (evidence_id,))
                conn.commit()
                return True
        except Exception as e:
            print(f"Error deleting evidence: {e}")
            return False
    
    def search_evidence(self, search_params: Dict[str, Any]) -> List[Evidence]:
        """Search evidence based on various parameters"""
        try:
            query = """
                SELECT e.*, ed.data 
                FROM evidence e
                JOIN evidence_data ed ON e.evidence_id = ed.evidence_id
                WHERE 1=1
            """
            params = []
            
            if 'evidence_type' in search_params:
                query += " AND e.evidence_type = ?"
                params.append(search_params['evidence_type'])
            
            if 'source_path' in search_params:
                query += " AND e.source_path LIKE ?"
                params.append(f"%{search_params['source_path']}%")
            
            if 'start_date' in search_params:
                query += " AND e.collected_timestamp >= ?"
                params.append(search_params['start_date'])
            
            if 'end_date' in search_params:
                query += " AND e.collected_timestamp <= ?"
                params.append(search_params['end_date'])
            
            query += " ORDER BY e.collected_timestamp DESC"
            
            with sqlite3.connect(str(self.db_path)) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute(query, params)
                
                evidence_list = []
                for row in cursor.fetchall():
                    evidence = Evidence(
                        evidence_id=row['evidence_id'],
                        evidence_type=row['evidence_type'],
                        source_path=row['source_path'],
                        collected_timestamp=datetime.fromisoformat(row['collected_timestamp']),
                        collector_name=row['collector_name'],
                        data=row['data'],
                        metadata=json.loads(row['metadata']) if row['metadata'] else {},
                        hash_sha256=row['hash_sha256'],
                        hash_md5=row['hash_md5']
                    )
                    evidence_list.append(evidence)
                
                return evidence_list
        except Exception as e:
            print(f"Error searching evidence: {e}")
            return []