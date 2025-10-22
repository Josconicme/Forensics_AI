# src/models/evidence.py
"""
Evidence data model with integrity verification
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Any
from enum import Enum
import hashlib
import uuid


class EvidenceType(Enum):
    """Evidence type enumeration"""
    LOG = "log"
    FILE = "file"
    NETWORK = "network"
    MEMORY = "memory"
    REGISTRY = "registry"


@dataclass
class Evidence:
    """Represents a piece of digital evidence"""
    evidence_id: str
    evidence_type: str  # 'log', 'file', 'network', 'memory'
    source_path: str
    collected_timestamp: datetime
    collector_name: str
    data: bytes
    metadata: Dict[str, Any] = field(default_factory=dict)
    hash_sha256: str = ""
    hash_md5: str = ""
    
    def __post_init__(self):
        """Compute hashes if not provided"""
        if not self.hash_sha256 or not self.hash_md5:
            self._compute_hashes()
    
    def _compute_hashes(self):
        """Compute SHA256 and MD5 hashes of evidence data"""
        self.hash_sha256 = hashlib.sha256(self.data).hexdigest()
        self.hash_md5 = hashlib.md5(self.data).hexdigest()
    
    def verify_integrity(self) -> bool:
        """Verify that current data matches stored hashes"""
        current_sha256 = hashlib.sha256(self.data).hexdigest()
        current_md5 = hashlib.md5(self.data).hexdigest()
        
        return (current_sha256 == self.hash_sha256 and 
                current_md5 == self.hash_md5)
    
    @staticmethod
    def generate_id() -> str:
        """Generate unique evidence ID"""
        return f"EVD-{uuid.uuid4().hex[:12].upper()}"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert evidence to dictionary for serialization"""
        return {
            'evidence_id': self.evidence_id,
            'evidence_type': self.evidence_type,
            'source_path': self.source_path,
            'collected_timestamp': self.collected_timestamp.isoformat(),
            'collector_name': self.collector_name,
            'hash_sha256': self.hash_sha256,
            'hash_md5': self.hash_md5,
            'data_size': len(self.data),
            'metadata': self.metadata
        }


@dataclass
class Finding:
    """Represents an analysis finding"""
    finding_id: str
    severity: str  # 'critical', 'high', 'medium', 'low', 'info'
    title: str
    description: str
    evidence_ids: list
    timestamp: datetime
    confidence: float  # 0.0 to 1.0
    indicators: Dict[str, Any] = field(default_factory=dict)
    recommendations: list = field(default_factory=list)
    
    @staticmethod
    def generate_id() -> str:
        """Generate unique finding ID"""
        return f"FND-{uuid.uuid4().hex[:12].upper()}"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary"""
        return {
            'finding_id': self.finding_id,
            'severity': self.severity,
            'title': self.title,
            'description': self.description,
            'evidence_ids': self.evidence_ids,
            'timestamp': self.timestamp.isoformat(),
            'confidence': self.confidence,
            'indicators': self.indicators,
            'recommendations': self.recommendations
        }