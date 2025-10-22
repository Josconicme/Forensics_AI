"""
Log file collector for ingesting system and application logs
"""
from pathlib import Path
from typing import List, Dict, Any
import re
from .base_collector import BaseCollector, Evidence


class LogCollector(BaseCollector):
    """Collects and processes log files"""
    
    def __init__(self, custody_manager, collector_name: str = "LogCollector"):
        super().__init__(custody_manager, collector_name)
        self.supported_formats = ['.log', '.txt']
    
    def collect(self, source_path: Path) -> List[Evidence]:
        """
        Collect log files from source path
        
        Args:
            source_path: Path to log file or directory
            
        Returns:
            List of evidence items
        """
        evidence_list = []
        
        if source_path.is_file():
            evidence = self._collect_file(source_path)
            if evidence:
                evidence_list.append(evidence)
        elif source_path.is_dir():
            for log_file in source_path.rglob('*'):
                if log_file.is_file() and log_file.suffix in self.supported_formats:
                    evidence = self._collect_file(log_file)
                    if evidence:
                        evidence_list.append(evidence)
        
        return evidence_list
    
    def _collect_file(self, file_path: Path) -> Evidence:
        """Collect single log file"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            if not self.validate(data):
                return None
            
            # Parse log metadata
            metadata = self._extract_metadata(file_path, data)
            
            evidence = self.create_evidence(
                evidence_type="log_file",
                source_path=str(file_path),
                data=data,
                metadata=metadata
            )
            
            # Register in chain of custody
            return self.register_evidence(evidence)
            
        except Exception as e:
            print(f"Error collecting log file {file_path}: {e}")
            return None
    
    def validate(self, data: bytes) -> bool:
        """
        Validate log file data
        
        Args:
            data: Log file data
            
        Returns:
            True if valid
        """
        if len(data) == 0:
            return False
        
        # Check if it's text-based
        try:
            data.decode('utf-8')
            return True
        except UnicodeDecodeError:
            # Try other encodings
            try:
                data.decode('latin-1')
                return True
            except:
                return False
    
    def _extract_metadata(self, file_path: Path, data: bytes) -> Dict[str, Any]:
        """Extract metadata from log file"""
        try:
            content = data.decode('utf-8')
        except:
            content = data.decode('latin-1')
        
        lines = content.split('\n')
        
        metadata = {
            "filename": file_path.name,
            "file_size": len(data),
            "line_count": len(lines),
            "log_type": self._detect_log_type(file_path.name, content),
            "encoding": "utf-8",
            "first_line": lines[0][:200] if lines else "",
            "last_line": lines[-1][:200] if lines and lines[-1] else ""
        }
        
        # Extract timestamps if present
        timestamps = self._extract_timestamps(content)
        if timestamps:
            metadata["first_timestamp"] = timestamps[0]
            metadata["last_timestamp"] = timestamps[-1]
            metadata["time_span_seconds"] = self._calculate_timespan(timestamps)
        
        return metadata
    
    def _detect_log_type(self, filename: str, content: str) -> str:
        """Detect type of log file"""
        filename_lower = filename.lower()
        
        if 'auth' in filename_lower or 'security' in filename_lower:
            return 'authentication'
        elif 'apache' in filename_lower or 'access' in filename_lower:
            return 'web_server'
        elif 'error' in filename_lower:
            return 'error'
        elif 'system' in filename_lower or 'syslog' in filename_lower:
            return 'system'
        elif 'firewall' in filename_lower:
            return 'firewall'
        else:
            return 'unknown'
    
    def _extract_timestamps(self, content: str) -> List[str]:
        """Extract timestamps from log content"""
        timestamps = []
        
        # Common timestamp patterns
        patterns = [
            r'\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}',  # 2024-01-01 12:00:00
            r'\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}',   # 01/Jan/2024:12:00:00
            r'\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2}'     # Jan 1 12:00:00
        ]
        
        lines = content.split('\n')[:100]  # Check first 100 lines
        
        for line in lines:
            for pattern in patterns:
                match = re.search(pattern, line)
                if match:
                    timestamps.append(match.group())
                    break
        
        return timestamps
    
    def _calculate_timespan(self, timestamps: List[str]) -> int:
        """Calculate timespan between first and last timestamp"""
        # Simplified - in production, parse timestamps properly
        return len(timestamps)