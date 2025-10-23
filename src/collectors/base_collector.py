# src/collectors/base_collector.py
"""
Base collector interface for evidence collection
"""
from abc import ABC, abstractmethod
from pathlib import Path
from datetime import datetime
from typing import Optional

from chain_of_custody.custody_manager import CustodyManager
from storage.evidence_store import EvidenceStore
from models.evidence import Evidence


class BaseCollector(ABC):
    """Abstract base class for evidence collectors"""
    
    def __init__(self, evidence_store: EvidenceStore, custody_manager: CustodyManager):
        self.evidence_store = evidence_store
        self.custody_manager = custody_manager
    
    @abstractmethod
    def collect(self, source_path: str) -> Optional[Evidence]:
        """
        Collect evidence from source
        
        Args:
            source_path: Path to evidence source
        
        Returns:
            Evidence object if successful, None otherwise
        """
        pass
    
    def _verify_source_exists(self, source_path: str) -> bool:
        """Verify that source path exists"""
        path = Path(source_path)
        if not path.exists():
            print(f"[Collector] Source not found: {source_path}")
            return False
        return True
    
    def _log_collection(self, evidence: Evidence):
        """Log evidence collection to chain of custody"""
        self.custody_manager.log_collection(
            evidence_id=evidence.evidence_id,
            source_path=evidence.source_path,
            collector_name=evidence.collector_name
        )