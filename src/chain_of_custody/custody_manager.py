# src/chain_of_custody/custody_manager.py
"""
Chain of custody management for evidence tracking
"""
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
from utils.crypto import CryptoUtils


class CustodyManager:
    """Manages chain of custody log for evidence"""
    
    def __init__(self, log_path: str = "./output/custody/chain_of_custody.log"):
        """
        Initialize custody manager
        
        Args:
            log_path: Path to chain of custody log file
        """
        self.log_path = Path(log_path)
        self.storage_path = self.log_path.parent
        self.storage_path.mkdir(parents=True, exist_ok=True)
        
        # Initialize log file if it doesn't exist
        if not self.log_path.exists():
            self._init_log_file()
    
    def _init_log_file(self):
        """Initialize empty log file with header"""
        with open(self.log_path, 'w') as f:
            header = {
                'log_initialized': datetime.now().isoformat(),
                'log_version': '1.0',
                'description': 'Chain of Custody Log for Digital Forensics Evidence'
            }
            f.write(json.dumps(header) + '\n')
    
    def log_event(self, event_type: str, evidence_id: str, actor: str, 
                  details: Optional[Dict[str, Any]] = None):
        """
        Log a custody event
        
        Args:
            event_type: Type of event (collection, access, transfer, analysis, etc.)
            evidence_id: Evidence identifier
            actor: Name of person/system performing action
            details: Additional event details
        """
        event = {
            'timestamp': datetime.now().isoformat(),
            'event_type': event_type,
            'evidence_id': evidence_id,
            'actor': actor,
            'details': details or {}
        }
        
        # Append to log file
        with open(self.log_path, 'a') as f:
            f.write(json.dumps(event) + '\n')
    
    def log_collection(self, evidence_id: str, source_path: str, 
                       collector_name: str, hash_sha256: str = None):
        """
        Log evidence collection event
        
        Args:
            evidence_id: Unique evidence identifier
            source_path: Path where evidence was collected from
            collector_name: Name of collector
            hash_sha256: SHA256 hash of evidence
        """
        details = {
            'source_path': source_path,
            'hash_sha256': hash_sha256
        }
        self.log_event('collection', evidence_id, collector_name, details)
    
    def log_access(self, evidence_id: str, accessor: str, purpose: str):
        """
        Log evidence access event
        
        Args:
            evidence_id: Evidence identifier
            accessor: Person/system accessing evidence
            purpose: Purpose of access
        """
        details = {'purpose': purpose}
        self.log_event('access', evidence_id, accessor, details)
    
    def log_analysis(self, evidence_id: str, analyzer: str, analysis_type: str):
        """
        Log evidence analysis event
        
        Args:
            evidence_id: Evidence identifier
            analyzer: Person/system performing analysis
            analysis_type: Type of analysis performed
        """
        details = {'analysis_type': analysis_type}
        self.log_event('analysis', evidence_id, analyzer, details)
    
    def log_transfer(self, evidence_id: str, from_actor: str, to_actor: str, 
                     reason: str):
        """
        Log evidence transfer event
        
        Args:
            evidence_id: Evidence identifier
            from_actor: Current custodian
            to_actor: New custodian
            reason: Reason for transfer
        """
        details = {
            'from': from_actor,
            'to': to_actor,
            'reason': reason
        }
        self.log_event('transfer', evidence_id, from_actor, details)
    
    def log_modification(self, evidence_id: str, modifier: str, 
                        modification_type: str, reason: str):
        """
        Log evidence modification event (should be rare/restricted)
        
        Args:
            evidence_id: Evidence identifier
            modifier: Person/system making modification
            modification_type: Type of modification
            reason: Justification for modification
        """
        details = {
            'modification_type': modification_type,
            'reason': reason,
            'warning': 'Evidence modified - integrity may be compromised'
        }
        self.log_event('modification', evidence_id, modifier, details)
    
    def get_custody_log(self, evidence_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Retrieve custody log entries
        
        Args:
            evidence_id: Optional filter by evidence ID
        
        Returns:
            List of custody log events
        """
        if not self.log_path.exists():
            return []
        
        events = []
        with open(self.log_path, 'r') as f:
            for line in f:
                try:
                    event = json.loads(line.strip())
                    
                    # Skip header line
                    if 'log_initialized' in event:
                        continue
                    
                    # Filter by evidence_id if provided
                    if evidence_id is None or event.get('evidence_id') == evidence_id:
                        events.append(event)
                except json.JSONDecodeError:
                    continue
        
        return events
    
    def verify_custody_chain(self, evidence_id: str) -> bool:
        """
        Verify that custody chain is complete for evidence
        
        Args:
            evidence_id: Evidence identifier
        
        Returns:
            True if chain is complete, False otherwise
        """
        events = self.get_custody_log(evidence_id)
        
        if not events:
            return False
        
        # Check that first event is collection
        if events[0].get('event_type') != 'collection':
            return False
        
        # Check for chronological order
        timestamps = [datetime.fromisoformat(e['timestamp']) for e in events]
        if timestamps != sorted(timestamps):
            return False
        
        return True
    
    def get_custody_summary(self, evidence_id: str) -> Dict[str, Any]:
        """
        Get summary of custody chain for evidence
        
        Args:
            evidence_id: Evidence identifier
        
        Returns:
            Summary dictionary with custody information
        """
        events = self.get_custody_log(evidence_id)
        
        if not events:
            return {'error': 'No custody events found'}
        
        # Count event types
        event_types = {}
        for event in events:
            event_type = event.get('event_type', 'unknown')
            event_types[event_type] = event_types.get(event_type, 0) + 1
        
        # Get actors involved
        actors = set()
        for event in events:
            actor = event.get('actor')
            if actor:
                actors.add(actor)
        
        return {
            'evidence_id': evidence_id,
            'total_events': len(events),
            'event_types': event_types,
            'actors': list(actors),
            'first_event': events[0]['timestamp'],
            'last_event': events[-1]['timestamp'],
            'chain_valid': self.verify_custody_chain(evidence_id)
        }
    
    def export_custody_report(self, output_path: str, evidence_id: Optional[str] = None):
        """
        Export custody log to readable report
        
        Args:
            output_path: Path to output report file
            evidence_id: Optional filter by evidence ID
        """
        events = self.get_custody_log(evidence_id)
        
        with open(output_path, 'w') as f:
            f.write("CHAIN OF CUSTODY REPORT\n")
            f.write("=" * 70 + "\n\n")
            
            if evidence_id:
                f.write(f"Evidence ID: {evidence_id}\n\n")
            
            f.write(f"Total Events: {len(events)}\n")
            f.write(f"Report Generated: {datetime.now().isoformat()}\n\n")
            f.write("=" * 70 + "\n\n")
            
            for i, event in enumerate(events, 1):
                f.write(f"Event #{i}\n")
                f.write(f"  Timestamp: {event['timestamp']}\n")
                f.write(f"  Type: {event['event_type']}\n")
                f.write(f"  Evidence ID: {event.get('evidence_id', 'N/A')}\n")
                f.write(f"  Actor: {event.get('actor', 'N/A')}\n")
                
                if event.get('details'):
                    f.write(f"  Details:\n")
                    for key, value in event['details'].items():
                        f.write(f"    {key}: {value}\n")
                
                f.write("\n")
        
        print(f"[CustodyManager] Custody report exported to {output_path}")