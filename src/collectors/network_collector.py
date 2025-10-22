"""
Network traffic collector for analyzing network captures and logs
"""
from pathlib import Path
from typing import List, Dict, Any
import csv
import json
from .base_collector import BaseCollector, Evidence


class NetworkCollector(BaseCollector):
    """Collects and processes network traffic data"""
    
    def __init__(self, custody_manager, collector_name: str = "NetworkCollector"):
        super().__init__(custody_manager, collector_name)
        self.supported_formats = ['.csv', '.json', '.pcap']
    
    def collect(self, source_path: Path) -> List[Evidence]:
        """
        Collect network traffic data from source
        
        Args:
            source_path: Path to network capture file or directory
            
        Returns:
            List of evidence items
        """
        evidence_list = []
        
        if source_path.is_file():
            evidence = self._collect_file(source_path)
            if evidence:
                evidence_list.append(evidence)
        elif source_path.is_dir():
            for net_file in source_path.rglob('*'):
                if net_file.is_file() and net_file.suffix in self.supported_formats:
                    evidence = self._collect_file(net_file)
                    if evidence:
                        evidence_list.append(evidence)
        
        return evidence_list
    
    def _collect_file(self, file_path: Path) -> Evidence:
        """Collect single network file"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            if not self.validate(data):
                return None
            
            # Extract network metadata
            metadata = self._extract_metadata(file_path, data)
            
            evidence = self.create_evidence(
                evidence_type="network_traffic",
                source_path=str(file_path),
                data=data,
                metadata=metadata
            )
            
            return self.register_evidence(evidence)
            
        except Exception as e:
            print(f"Error collecting network file {file_path}: {e}")
            return None
    
    def validate(self, data: bytes) -> bool:
        """
        Validate network data
        
        Args:
            data: Network data
            
        Returns:
            True if valid
        """
        if len(data) == 0:
            return False
        
        return True
    
    def _extract_metadata(self, file_path: Path, data: bytes) -> Dict[str, Any]:
        """Extract metadata from network file"""
        metadata = {
            "filename": file_path.name,
            "file_size": len(data),
            "capture_format": file_path.suffix[1:],
        }
        
        # Parse based on file type
        if file_path.suffix == '.csv':
            metadata.update(self._parse_csv_metadata(data))
        elif file_path.suffix == '.json':
            metadata.update(self._parse_json_metadata(data))
        elif file_path.suffix == '.pcap':
            metadata.update(self._parse_pcap_metadata(data))
        
        return metadata
    
    def _parse_csv_metadata(self, data: bytes) -> Dict[str, Any]:
        """Parse CSV network data metadata"""
        try:
            content = data.decode('utf-8')
            reader = csv.DictReader(content.splitlines())
            rows = list(reader)
            
            if not rows:
                return {"packet_count": 0}
            
            # Extract connection statistics
            unique_sources = set()
            unique_destinations = set()
            protocols = {}
            ports = {}
            
            for row in rows:
                if 'src_ip' in row or 'source_ip' in row:
                    src = row.get('src_ip') or row.get('source_ip')
                    unique_sources.add(src)
                
                if 'dst_ip' in row or 'dest_ip' in row:
                    dst = row.get('dst_ip') or row.get('dest_ip')
                    unique_destinations.add(dst)
                
                if 'protocol' in row:
                    proto = row['protocol']
                    protocols[proto] = protocols.get(proto, 0) + 1
                
                if 'dst_port' in row or 'dest_port' in row:
                    port = row.get('dst_port') or row.get('dest_port')
                    ports[port] = ports.get(port, 0) + 1
            
            return {
                "packet_count": len(rows),
                "unique_sources": len(unique_sources),
                "unique_destinations": len(unique_destinations),
                "protocols": dict(list(protocols.items())[:10]),  # Top 10
                "top_ports": dict(sorted(ports.items(), key=lambda x: x[1], reverse=True)[:10]),
                "fields": list(rows[0].keys()) if rows else []
            }
        
        except Exception as e:
            return {"parse_error": str(e)}
    
    def _parse_json_metadata(self, data: bytes) -> Dict[str, Any]:
        """Parse JSON network data metadata"""
        try:
            content = json.loads(data.decode('utf-8'))
            
            if isinstance(content, list):
                return {
                    "packet_count": len(content),
                    "data_type": "packet_list"
                }
            elif isinstance(content, dict):
                return {
                    "packet_count": len(content.get('packets', [])),
                    "data_type": "structured",
                    "keys": list(content.keys())
                }
        
        except Exception as e:
            return {"parse_error": str(e)}
    
    def _parse_pcap_metadata(self, data: bytes) -> Dict[str, Any]:
        """Parse PCAP file metadata"""
        # Simplified PCAP parsing - in production, use scapy or dpkt
        metadata = {
            "data_type": "pcap_capture",
            "file_size": len(data)
        }
        
        # Check PCAP magic number
        if data[:4] == b'\xd4\xc3\xb2\xa1':
            metadata["pcap_version"] = "2.4"
        elif data[:4] == b'\xa1\xb2\xc3\xd4':
            metadata["pcap_version"] = "2.4_swapped"
        
        return metadata