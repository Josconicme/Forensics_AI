# src/collectors/file_collector.py
"""File artifact collector"""
from pathlib import Path
from datetime import datetime
from typing import Optional
from collectors.base_collector import BaseCollector
from models.evidence import Evidence

class FileCollector(BaseCollector):
    """Collects file artifacts as evidence"""
    
    def __init__(self, evidence_store, custody_manager):
        super().__init__(evidence_store, custody_manager)
        self.collector_name = "FileCollector"
    
    def collect(self, source_path: str) -> Optional[Evidence]:
        """Collect file as evidence"""
        source_path = Path(source_path)
        
        if not source_path.exists():
            print(f"[{self.collector_name}] File not found: {source_path}")
            return None
        
        try:
            with open(source_path, 'rb') as f:
                data = f.read()
            
            evidence = Evidence(
                evidence_id=Evidence.generate_id(),
                evidence_type='file',
                source_path=str(source_path),
                collected_timestamp=datetime.now(),
                collector_name=self.collector_name,
                data=data,
                metadata={'file_size': len(data), 'file_name': source_path.name}
            )
            
            if self.evidence_store.store_evidence(evidence):
                self._log_collection(evidence)
                return evidence
        except Exception as e:
            print(f"[{self.collector_name}] Error: {e}")
        return None
