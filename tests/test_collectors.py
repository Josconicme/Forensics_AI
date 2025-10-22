"""
Unit tests for evidence collectors
"""
import pytest
import os
import tempfile
import json
from datetime import datetime
from pathlib import Path

from src.collectors.log_collector import LogCollector
from src.collectors.file_collector import FileCollector
from src.collectors.network_collector import NetworkCollector
from src.models.evidence import Evidence, EvidenceType


class TestLogCollector:
    """Test suite for LogCollector"""
    
    @pytest.fixture
    def temp_log_file(self):
        """Create a temporary log file for testing"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log') as f:
            f.write("2024-10-21 10:00:00 auth: Failed password for admin from 192.168.1.100\n")
            f.write("2024-10-21 10:00:05 auth: Failed password for admin from 192.168.1.100\n")
            f.write("2024-10-21 10:00:10 auth: Accepted password for admin from 192.168.1.100\n")
            temp_path = f.name
        
        yield temp_path
        
        # Cleanup
        if os.path.exists(temp_path):
            os.unlink(temp_path)
    
    def test_collect_logs(self, temp_log_file):
        """Test basic log collection"""
        collector = LogCollector()
        evidence_list = collector.collect(temp_log_file)
        
        assert len(evidence_list) > 0
        assert evidence_list[0].evidence_type == EvidenceType.LOG
        assert evidence_list[0].hash is not None
        assert evidence_list[0].source_path == temp_log_file
    
    def test_hash_computation(self, temp_log_file):
        """Test that hash is computed correctly"""
        collector = LogCollector()
        evidence_list = collector.collect(temp_log_file)
        
        # Hash should be consistent for same content
        evidence_list_2 = collector.collect(temp_log_file)
        assert evidence_list[0].hash == evidence_list_2[0].hash
    
    def test_metadata_extraction(self, temp_log_file):
        """Test metadata extraction from logs"""
        collector = LogCollector()
        evidence_list = collector.collect(temp_log_file)
        
        metadata = evidence_list[0].metadata
        assert 'file_size' in metadata
        assert 'line_count' in metadata
        assert metadata['line_count'] == 3


class TestFileCollector:
    """Test suite for FileCollector"""
    
    @pytest.fixture
    def temp_files(self):
        """Create temporary files for testing"""
        temp_dir = tempfile.mkdtemp()
        
        # Create test files
        test_file_1 = os.path.join(temp_dir, "test1.txt")
        test_file_2 = os.path.join(temp_dir, "test2.exe")
        
        with open(test_file_1, 'w') as f:
            f.write("Test content 1")
        
        with open(test_file_2, 'w') as f:
            f.write("MZ")  # PE header signature
        
        yield temp_dir
        
        # Cleanup
        import shutil
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
    
    def test_collect_files(self, temp_files):
        """Test file metadata collection"""
        collector = FileCollector()
        evidence_list = collector.collect(temp_files)
        
        assert len(evidence_list) == 2
        assert all(e.evidence_type == EvidenceType.FILE_METADATA for e in evidence_list)
    
    def test_file_extensions(self, temp_files):
        """Test file extension detection"""
        collector = FileCollector()
        evidence_list = collector.collect(temp_files)
        
        extensions = [e.metadata.get('extension') for e in evidence_list]
        assert '.txt' in extensions
        assert '.exe' in extensions
    
    def test_suspicious_file_detection(self, temp_files):
        """Test detection of suspicious file types"""
        collector = FileCollector()
        evidence_list = collector.collect(temp_files)
        
        # Find the .exe file
        exe_evidence = [e for e in evidence_list if e.metadata.get('extension') == '.exe'][0]
        assert exe_evidence.metadata.get('suspicious', False)


class TestNetworkCollector:
    """Test suite for NetworkCollector"""
    
    @pytest.fixture
    def temp_network_file(self):
        """Create a temporary network log file"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.csv') as f:
            f.write("timestamp,src_ip,dst_ip,src_port,dst_port,protocol,bytes\n")
            f.write("2024-10-21 10:00:00,192.168.1.100,8.8.8.8,54321,443,TCP,1024\n")
            f.write("2024-10-21 10:00:05,192.168.1.100,8.8.8.8,54321,443,TCP,2048\n")
            temp_path = f.name
        
        yield temp_path
        
        # Cleanup
        if os.path.exists(temp_path):
            os.unlink(temp_path)
    
    def test_collect_network_data(self, temp_network_file):
        """Test network data collection"""
        collector = NetworkCollector()
        evidence_list = collector.collect(temp_network_file)
        
        assert len(evidence_list) > 0
        assert evidence_list[0].evidence_type == EvidenceType.NETWORK_TRAFFIC
    
    def test_connection_parsing(self, temp_network_file):
        """Test parsing of network connections"""
        collector = NetworkCollector()
        evidence_list = collector.collect(temp_network_file)
        
        metadata = evidence_list[0].metadata
        assert 'connection_count' in metadata
        assert metadata['connection_count'] == 2
    
    def test_protocol_detection(self, temp_network_file):
        """Test protocol detection"""
        collector = NetworkCollector()
        evidence_list = collector.collect(temp_network_file)
        
        metadata = evidence_list[0].metadata
        assert 'protocols' in metadata
        assert 'TCP' in metadata['protocols']


class TestCollectorIntegration:
    """Integration tests across collectors"""
    
    def test_collector_factory(self):
        """Test that collectors can be instantiated"""
        log_collector = LogCollector()
        file_collector = FileCollector()
        network_collector = NetworkCollector()
        
        assert log_collector is not None
        assert file_collector is not None
        assert network_collector is not None
    
    def test_evidence_consistency(self):
        """Test that all collectors produce consistent Evidence objects"""
        # Create temporary test data
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log') as f:
            f.write("test log\n")
            log_path = f.name
        
        try:
            collector = LogCollector()
            evidence_list = collector.collect(log_path)
            
            for evidence in evidence_list:
                # All evidence should have these fields
                assert evidence.evidence_id is not None
                assert evidence.evidence_type is not None
                assert evidence.hash is not None
                assert evidence.collected_at is not None
                assert evidence.source_path is not None
                assert isinstance(evidence.metadata, dict)
        finally:
            if os.path.exists(log_path):
                os.unlink(log_path)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])