"""
File metadata collector for analyzing file system artifacts
"""
from pathlib import Path
from typing import List, Dict, Any
import json
import os
from datetime import datetime
from .base_collector import BaseCollector, Evidence


class FileCollector(BaseCollector):
    """Collects file metadata and content for forensic analysis"""
    
    def __init__(self, custody_manager, collector_name: str = "FileCollector"):
        super().__init__(custody_manager, collector_name)
    
    def collect(self, source_path: Path) -> List[Evidence]:
        """
        Collect file metadata from source
        
        Args:
            source_path: Path to file or directory
            
        Returns:
            List of evidence items
        """
        evidence_list = []
        
        if source_path.is_file():
            # If it's a JSON file with metadata, parse it
            if source_path.suffix == '.json':
                evidence = self._collect_metadata_file(source_path)
                if evidence:
                    evidence_list.append(evidence)
            else:
                # Collect individual file
                evidence = self._collect_single_file(source_path)
                if evidence:
                    evidence_list.append(evidence)
        elif source_path.is_dir():
            # Collect all files in directory
            for file_path in source_path.rglob('*'):
                if file_path.is_file():
                    evidence = self._collect_single_file(file_path)
                    if evidence:
                        evidence_list.append(evidence)
        
        return evidence_list
    
    def _collect_metadata_file(self, file_path: Path) -> Evidence:
        """Collect from a JSON metadata file"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            if not self.validate(data):
                return None
            
            # Parse JSON metadata
            metadata_content = json.loads(data.decode('utf-8'))
            
            # Create evidence with the metadata
            metadata = {
                "source_type": "metadata_file",
                "file_count": len(metadata_content.get('files', [])),
                "metadata_file": str(file_path)
            }
            
            evidence = self.create_evidence(
                evidence_type="file_metadata",
                source_path=str(file_path),
                data=data,
                metadata=metadata
            )
            
            return self.register_evidence(evidence)
            
        except Exception as e:
            print(f"Error collecting metadata file {file_path}: {e}")
            return None
    
    def _collect_single_file(self, file_path: Path) -> Evidence:
        """Collect a single file's metadata and content"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            if not self.validate(data):
                return None
            
            # Extract file metadata
            metadata = self._extract_file_metadata(file_path, data)
            
            evidence = self.create_evidence(
                evidence_type="file",
                source_path=str(file_path),
                data=data,
                metadata=metadata
            )
            
            return self.register_evidence(evidence)
            
        except Exception as e:
            print(f"Error collecting file {file_path}: {e}")
            return None
    
    def validate(self, data: bytes) -> bool:
        """
        Validate file data
        
        Args:
            data: File data
            
        Returns:
            True if valid
        """
        # Accept any non-empty file
        return len(data) > 0
    
    def _extract_file_metadata(self, file_path: Path, data: bytes) -> Dict[str, Any]:
        """Extract comprehensive metadata from file"""
        stat_info = os.stat(file_path)
        
        metadata = {
            "filename": file_path.name,
            "file_extension": file_path.suffix,
            "file_size": len(data),
            "created_time": datetime.fromtimestamp(stat_info.st_ctime).isoformat(),
            "modified_time": datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
            "accessed_time": datetime.fromtimestamp(stat_info.st_atime).isoformat(),
            "permissions": oct(stat_info.st_mode)[-3:],
            "inode": stat_info.st_ino,
        }
        
        # Detect file type
        metadata["file_type"] = self._detect_file_type(file_path, data)
        
        # Extract magic bytes
        metadata["magic_bytes"] = data[:16].hex() if len(data) >= 16 else data.hex()
        
        # Check for suspicious indicators
        metadata["suspicious_indicators"] = self._check_suspicious_indicators(file_path, data)
        
        return metadata
    
    def _detect_file_type(self, file_path: Path, data: bytes) -> str:
        """Detect file type from extension and magic bytes"""
        # Check common magic bytes
        magic_bytes = data[:8] if len(data) >= 8 else data
        
        # Common file signatures
        signatures = {
            b'\x50\x4B\x03\x04': 'zip',
            b'\x1F\x8B': 'gzip',
            b'\x25\x50\x44\x46': 'pdf',
            b'\x89\x50\x4E\x47': 'png',
            b'\xFF\xD8\xFF': 'jpeg',
            b'\x4D\x5A': 'executable',
            b'<?xml': 'xml',
            b'#!/': 'script'
        }
        
        for sig, file_type in signatures.items():
            if magic_bytes.startswith(sig):
                return file_type
        
        # Fall back to extension
        ext = file_path.suffix.lower()
        if ext:
            return ext[1:]  # Remove the dot
        
        return 'unknown'
    
    def _check_suspicious_indicators(self, file_path: Path, data: bytes) -> List[str]:
        """Check for suspicious file indicators"""
        indicators = []
        
        filename_lower = file_path.name.lower()
        
        # Suspicious extensions
        suspicious_extensions = ['.exe', '.dll', '.ps1', '.bat', '.cmd', '.vbs', '.js']
        if any(filename_lower.endswith(ext) for ext in suspicious_extensions):
            indicators.append("suspicious_extension")
        
        # Hidden file
        if filename_lower.startswith('.'):
            indicators.append("hidden_file")
        
        # Double extension
        if filename_lower.count('.') > 1:
            indicators.append("double_extension")
        
        # Check for encrypted/packed content
        if len(data) > 1000:
            # High entropy might indicate encryption/packing
            entropy = self._calculate_entropy(data[:1000])
            if entropy > 7.5:
                indicators.append("high_entropy_possible_encryption")
        
        # Suspicious strings in content
        if len(data) < 1000000:  # Only for smaller files
            try:
                content = data.decode('utf-8', errors='ignore').lower()
                suspicious_keywords = ['password', 'confidential', 'secret', 'credential']
                if any(keyword in content for keyword in suspicious_keywords):
                    indicators.append("contains_sensitive_keywords")
            except:
                pass
        
        return indicators
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
        
        entropy = 0.0
        for x in range(256):
            p_x = data.count(x) / len(data)
            if p_x > 0:
                entropy += - p_x * (p_x.bit_length() - 1)
        
        return entropy