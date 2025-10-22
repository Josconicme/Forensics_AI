"""
Base collector for evidence ingestion
"""
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List
import uuid
import json
from ..storage.chain_of_custody import CustodyManager
from ..utils.crypto import CryptoUtils


class Evidence:
    """Represents a piece of digital evidence"""
    
    def __init__(
        self,
        evidence_id: str,
        evidence_type: str,
        source_path: str,
        data: bytes,
        metadata: Dict[str, Any],
        collected_at: str
    ):
        self.evidence_id = evidence_id
        self.evidence_type = evidence_type
        self.source_path = source_path
        self.data = data
        self.metadata = metadata
        self.collected_at = collected_at
        self.hash = CryptoUtils.compute_hash(data)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert evidence to dictionary"""
        return {
            "evidence_id": self.evidence_id,
            "evidence_type": self.evidence_type,
            "source_path": self.source_path,
            "hash": self.hash,
            "metadata": self.metadata,
            "collected_at": self.collected_at,
            "size_bytes": len(self.data)
        }


class BaseCollector(ABC):
    """Abstract base class for evidence collectors"""
    
    def __init__(self, custody_manager: CustodyManager, collector_name: str):
        """
        Initialize collector
        
        Args:
            custody_manager: Chain of custody manager
            collector_name: Name of this collector
        """
        self.custody_manager = custody_manager
        self.collector_name = collector_name
        self.collected_evidence: List[Evidence] = []
    
    @abstractmethod
    def collect(self, source_path: Path) -> List[Evidence]:
        """
        Collect evidence from source
        
        Args:
            source_path: Path to evidence source
            
        Returns:
            List of collected evidence items
        """
        pass
    
    @abstractmethod
    def validate(self, data: bytes) -> bool:
        """
        Validate evidence data
        
        Args:
            data: Evidence data to validate
            
        Returns:
            True if valid
        """
        pass
    
    def register_evidence(self, evidence: Evidence) -> Evidence:
        """
        Register evidence in chain of custody
        
        Args:
            evidence: Evidence to register
            
        Returns:
            Registered evidence
        """
        self.custody_manager.register_evidence(
            evidence_id=evidence.evidence_id,
            evidence_data=evidence.data,
            evidence_type=evidence.evidence_type,
            collector=self.collector_name,
            metadata=evidence.metadata
        )
        
        self.collected_evidence.append(evidence)
        return evidence
    
    def create_evidence(
        self,
        evidence_type: str,
        source_path: str,
        data: bytes,
        metadata: Dict[str, Any]
    ) -> Evidence:
        """
        Create evidence object
        
        Args:
            evidence_type: Type of evidence
            source_path: Source path
            data: Evidence data
            metadata: Additional metadata
            
        Returns:
            Evidence object
        """
        evidence_id = str(uuid.uuid4())
        
        evidence = Evidence(
            evidence_id=evidence_id,
            evidence_type=evidence_type,
            source_path=source_path,
            data=data,
            metadata=metadata,
            collected_at=datetime.utcnow().isoformat()
        )
        
        return evidence
    
    def get_collected_evidence(self) -> List[Evidence]:
        """Get all collected evidence"""
        return self.collected_evidence