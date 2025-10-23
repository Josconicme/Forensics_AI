"""
Chain of Custody Manager - Tracks evidence handling and maintains integrity
"""
import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from utils.crypto import CryptoUtils


@dataclass
class CustodyEvent:
    """Represents a chain of custody event"""
    event_id: str
    evidence_id: str
    timestamp: str
    event_type: str  # collected, analyzed, transferred, accessed
    actor: str
    action: str
    previous_hash: Optional[str]
    current_hash: str
    signature: str
    metadata: Dict[str, Any]


class CustodyManager:
    """Manages chain of custody for forensic evidence"""
    
    def __init__(self, storage_path: Path):
        """
        Initialize custody manager
        
        Args:
            storage_path: Path to store custody logs
        """
        self.storage_path = storage_path
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self.custody_file = self.storage_path / "chain_of_custody.jsonl"
        self.evidence_registry: Dict[str, List[CustodyEvent]] = {}
        self._load_custody_log()
    
    def _load_custody_log(self):
        """Load existing custody log from disk"""
        if self.custody_file.exists():
            with open(self.custody_file, 'r') as f:
                for line in f:
                    if line.strip():
                        event_data = json.loads(line)
                        event = CustodyEvent(**event_data)
                        if event.evidence_id not in self.evidence_registry:
                            self.evidence_registry[event.evidence_id] = []
                        self.evidence_registry[event.evidence_id].append(event)
    
    def register_evidence(
        self,
        evidence_id: str,
        evidence_data: bytes,
        evidence_type: str,
        collector: str,
        metadata: Dict[str, Any]
    ) -> CustodyEvent:
        """
        Register new evidence in chain of custody
        
        Args:
            evidence_id: Unique identifier for evidence
            evidence_data: Raw evidence data
            evidence_type: Type of evidence
            collector: Identity of collector
            metadata: Additional metadata
            
        Returns:
            CustodyEvent for registration
        """
        evidence_hash = CryptoUtils.compute_hash(evidence_data)
        
        event = CustodyEvent(
            event_id=str(uuid.uuid4()),
            evidence_id=evidence_id,
            timestamp=datetime.utcnow().isoformat(),
            event_type="collected",
            actor=collector,
            action=f"Evidence collected: {evidence_type}",
            previous_hash=None,
            current_hash=evidence_hash,
            signature="",
            metadata={
                **metadata,
                "evidence_type": evidence_type,
                "size_bytes": len(evidence_data)
            }
        )
        
        # Create signature
        event.signature = self._sign_event(event)
        
        # Store event
        self._store_event(event)
        
        return event
    
    def record_access(
        self,
        evidence_id: str,
        actor: str,
        action: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> CustodyEvent:
        """
        Record evidence access event
        
        Args:
            evidence_id: Evidence identifier
            actor: Identity of accessor
            action: Action performed
            metadata: Additional metadata
            
        Returns:
            CustodyEvent for access
        """
        # Get last event for this evidence
        previous_event = self._get_last_event(evidence_id)
        previous_hash = previous_event.current_hash if previous_event else None
        
        event = CustodyEvent(
            event_id=str(uuid.uuid4()),
            evidence_id=evidence_id,
            timestamp=datetime.utcnow().isoformat(),
            event_type="accessed",
            actor=actor,
            action=action,
            previous_hash=previous_hash,
            current_hash=previous_hash or "",
            signature="",
            metadata=metadata or {}
        )
        
        event.signature = self._sign_event(event)
        self._store_event(event)
        
        return event
    
    def record_analysis(
        self,
        evidence_id: str,
        analyzer: str,
        findings: Dict[str, Any]
    ) -> CustodyEvent:
        """
        Record evidence analysis
        
        Args:
            evidence_id: Evidence identifier
            analyzer: Identity of analyzer
            findings: Analysis findings
            
        Returns:
            CustodyEvent for analysis
        """
        previous_event = self._get_last_event(evidence_id)
        previous_hash = previous_event.current_hash if previous_event else None
        
        event = CustodyEvent(
            event_id=str(uuid.uuid4()),
            evidence_id=evidence_id,
            timestamp=datetime.utcnow().isoformat(),
            event_type="analyzed",
            actor=analyzer,
            action="Evidence analyzed",
            previous_hash=previous_hash,
            current_hash=previous_hash or "",
            signature="",
            metadata={"findings_summary": findings}
        )
        
        event.signature = self._sign_event(event)
        self._store_event(event)
        
        return event
    
    def verify_integrity(self, evidence_id: str) -> bool:
        """
        Verify integrity of evidence chain
        
        Args:
            evidence_id: Evidence identifier
            
        Returns:
            True if chain is valid
        """
        if evidence_id not in self.evidence_registry:
            return False
        
        events = self.evidence_registry[evidence_id]
        
        for i, event in enumerate(events):
            # Verify signature
            expected_signature = self._sign_event(event, verify=True)
            if event.signature != expected_signature:
                return False
            
            # Verify hash chain
            if i > 0:
                prev_event = events[i - 1]
                if event.previous_hash != prev_event.current_hash:
                    return False
        
        return True
    
    def get_custody_chain(self, evidence_id: str) -> List[Dict[str, Any]]:
        """
        Get complete custody chain for evidence
        
        Args:
            evidence_id: Evidence identifier
            
        Returns:
            List of custody events
        """
        if evidence_id not in self.evidence_registry:
            return []
        
        return [asdict(event) for event in self.evidence_registry[evidence_id]]
    
    def get_summary(self, evidence_id: str) -> Dict[str, Any]:
        """
        Get custody summary for evidence
        
        Args:
            evidence_id: Evidence identifier
            
        Returns:
            Summary of custody chain
        """
        if evidence_id not in self.evidence_registry:
            return {}
        
        events = self.evidence_registry[evidence_id]
        
        return {
            "evidence_id": evidence_id,
            "total_events": len(events),
            "first_collected": events[0].timestamp if events else None,
            "last_accessed": events[-1].timestamp if events else None,
            "collectors": list(set(e.actor for e in events if e.event_type == "collected")),
            "analyzers": list(set(e.actor for e in events if e.event_type == "analyzed")),
            "integrity_verified": self.verify_integrity(evidence_id),
            "custody_chain": [
                {
                    "timestamp": e.timestamp,
                    "actor": e.actor,
                    "action": e.action,
                    "event_type": e.event_type
                }
                for e in events
            ]
        }
    
    def _sign_event(self, event: CustodyEvent, verify: bool = False) -> str:
        """Create signature for custody event"""
        event_dict = asdict(event)
        if verify:
            # Remove signature for verification
            event_dict.pop('signature', None)
        else:
            event_dict['signature'] = ""
        
        return CryptoUtils.create_custody_signature(event_dict)
    
    def _store_event(self, event: CustodyEvent):
        """Store event to disk and memory"""
        # Add to registry
        if event.evidence_id not in self.evidence_registry:
            self.evidence_registry[event.evidence_id] = []
        self.evidence_registry[event.evidence_id].append(event)
        
        # Append to file
        with open(self.custody_file, 'a') as f:
            f.write(json.dumps(asdict(event)) + '\n')
    
    def _get_last_event(self, evidence_id: str) -> Optional[CustodyEvent]:
        """Get last event for evidence"""
        if evidence_id in self.evidence_registry and self.evidence_registry[evidence_id]:
            return self.evidence_registry[evidence_id][-1]
        return None