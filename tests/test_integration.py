"""
Integration tests for the complete forensics system
"""
import pytest
import os
import tempfile
import json
from datetime import datetime
from pathlib import Path

from src.collectors.log_collector import LogCollector
from src.storage.evidence_store import EvidenceStore
from src.storage.chain_of_custody import CustodyManager
from src.models.evidence import Evidence, EvidenceType


class TestEndToEndFlow:
    """Test complete evidence flow from collection to storage"""
    
    @pytest.fixture
    def temp_environment(self):
        """Create temporary environment for testing"""
        temp_dir = tempfile.mkdtemp()
        evidence_dir = os.path.join(temp_dir, "evidence")
        custody_db = os.path.join(temp_dir, "custody.db")
        
        os.makedirs(evidence_dir, exist_ok=True)
        
        # Create test log file
        log_file = os.path.join(temp_dir, "test.log")
        with open(log_file, 'w') as f:
            f.write("2024-10-21 10:00:00 auth: Failed password for admin\n")
        
        yield {
            'temp_dir': temp_dir,
            'evidence_dir': evidence_dir,
            'custody_db': custody_db,
            'log_file': log_file
        }
        
        # Cleanup
        import shutil
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
    
    def test_collect_store_verify_flow(self, temp_environment):
        """Test: Collect -> Store -> Verify chain"""
        # Step 1: Collect evidence
        collector = LogCollector()
        evidence_list = collector.collect(temp_environment['log_file'])
        
        assert len(evidence_list) > 0
        evidence = evidence_list[0]
        original_hash = evidence.hash
        
        # Step 2: Store evidence
        store = EvidenceStore(storage_path=temp_environment['evidence_dir'])
        store.store_evidence(evidence)
        
        # Step 3: Retrieve and verify
        retrieved = store.get_evidence(evidence.evidence_id)
        assert retrieved is not None
        assert retrieved.hash == original_hash
        assert retrieved.evidence_id == evidence.evidence_id
    
    def test_chain_of_custody_tracking(self, temp_environment):
        """Test complete chain of custody tracking"""
        # Initialize components
        collector = LogCollector()
        store = EvidenceStore(storage_path=temp_environment['evidence_dir'])
        custody = CustodyManager(db_path=temp_environment['custody_db'])
        
        # Collect evidence
        evidence_list = collector.collect(temp_environment['log_file'])
        evidence = evidence_list[0]
        
        # Record collection in custody
        custody.record_action(
            evidence_id=evidence.evidence_id,
            action="INGESTED",
            agent="LogCollector",
            hash_value=evidence.hash,
            metadata=evidence.metadata
        )
        
        # Store evidence
        store.store_evidence(evidence)
        
        # Record storage
        custody.record_action(
            evidence_id=evidence.evidence_id,
            action="STORED",
            agent="EvidenceStore",
            hash_value=evidence.hash
        )
        
        # Retrieve custody chain
        chain = custody.get_chain(evidence.evidence_id)
        
        assert len(chain) >= 2
        assert chain[0]['action'] == 'INGESTED'
        assert chain[1]['action'] == 'STORED'
        
        # Verify integrity
        assert custody.verify_integrity(evidence.evidence_id)


class TestMultiSourceAnalysis:
    """Test analysis across multiple evidence sources"""
    
    @pytest.fixture
    def multi_source_environment(self):
        """Create environment with multiple evidence types"""
        temp_dir = tempfile.mkdtemp()
        
        # Create log file
        log_file = os.path.join(temp_dir, "auth.log")
        with open(log_file, 'w') as f:
            f.write("2024-10-21 10:00:00 Failed password for admin\n")
            f.write("2024-10-21 10:00:05 Failed password for admin\n")
            f.write("2024-10-21 10:00:10 Accepted password for admin\n")
        
        # Create suspicious file
        exe_file = os.path.join(temp_dir, "malware.exe")
        with open(exe_file, 'wb') as f:
            f.write(b'MZ\x90\x00')  # PE header
        
        # Create network log
        network_file = os.path.join(temp_dir, "network.csv")
        with open(network_file, 'w') as f:
            f.write("timestamp,src_ip,dst_ip,protocol\n")
            f.write("2024-10-21 10:05:00,192.168.1.100,8.8.8.8,TCP\n")
        
        yield {
            'temp_dir': temp_dir,
            'log_file': log_file,
            'exe_file': exe_file,
            'network_file': network_file
        }
        
        # Cleanup
        import shutil
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
    
    def test_multi_collector_integration(self, multi_source_environment):
        """Test collecting from multiple sources"""
        from src.collectors.file_collector import FileCollector
        from src.collectors.network_collector import NetworkCollector
        
        log_collector = LogCollector()
        file_collector = FileCollector()
        network_collector = NetworkCollector()
        
        # Collect from all sources
        log_evidence = log_collector.collect(multi_source_environment['log_file'])
        file_evidence = file_collector.collect(multi_source_environment['temp_dir'])
        network_evidence = network_collector.collect(multi_source_environment['network_file'])
        
        # Verify we got evidence from all sources
        assert len(log_evidence) > 0
        assert len(file_evidence) > 0
        assert len(network_evidence) > 0
        
        # Verify evidence types are correct
        assert log_evidence[0].evidence_type == EvidenceType.LOG
        assert any(e.evidence_type == EvidenceType.FILE_METADATA for e in file_evidence)
        assert network_evidence[0].evidence_type == EvidenceType.NETWORK_TRAFFIC


class TestReportGeneration:
    """Test report generation from analysis"""
    
    def test_report_structure(self):
        """Test that reports contain required sections"""
        from src.reporting.report_generator import ReportGenerator
        
        # Create mock analysis results
        analysis_results = {
            'case_id': 'CASE-2024-001',
            'findings': [
                {
                    'type': 'brute_force',
                    'severity': 'high',
                    'description': 'Multiple failed login attempts detected',
                    'evidence_ids': ['EVD-001']
                }
            ],
            'timeline': [
                {
                    'timestamp': '2024-10-21 10:00:00',
                    'event': 'Brute force attack initiated',
                    'source': 'auth.log'
                }
            ]
        }
        
        generator = ReportGenerator()
        report = generator.generate_report(
            case_id='CASE-2024-001',
            analysis_results=analysis_results,
            evidence_list=[],
            custody_chain=[]
        )
        
        # Verify report structure
        assert 'case_id' in report
        assert 'executive_summary' in report
        assert 'findings' in report
        assert 'timeline' in report
        assert 'recommendations' in report


class TestErrorHandling:
    """Test system behavior under error conditions"""
    
    def test_invalid_evidence_path(self):
        """Test handling of non-existent evidence paths"""
        collector = LogCollector()
        
        # Should handle gracefully
        evidence_list = collector.collect("/non/existent/path.log")
        assert len(evidence_list) == 0
    
    def test_corrupted_evidence(self):
        """Test handling of corrupted evidence"""
        temp_dir = tempfile.mkdtemp()
        
        try:
            # Create evidence store
            store = EvidenceStore(storage_path=temp_dir)
            
            # Create evidence
            evidence = Evidence(
                evidence_id="TEST-001",
                evidence_type=EvidenceType.LOG,
                source_path="/tmp/test.log",
                hash="original_hash",
                collected_at=datetime.now(),
                data="test data",
                metadata={}
            )
            
            # Store it
            store.store_evidence(evidence)
            
            # Manually corrupt the stored file
            evidence_file = os.path.join(temp_dir, "TEST-001.json")
            with open(evidence_file, 'w') as f:
                f.write("corrupted data")
            
            # Try to retrieve - should handle gracefully
            retrieved = store.get_evidence("TEST-001")
            # Depending on implementation, might return None or raise exception
            
        finally:
            import shutil
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)
    
    def test_database_unavailable(self):
        """Test handling when database is unavailable"""
        # Try to create custody manager with invalid path
        custody = CustodyManager(db_path="/invalid/path/custody.db")
        
        # Should initialize but operations may fail gracefully
        assert custody is not None


class TestPerformance:
    """Performance and scalability tests"""
    
    def test_large_log_file_handling(self):
        """Test handling of large log files"""
        temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log')
        
        try:
            # Create a large log file (1000 lines)
            for i in range(1000):
                temp_file.write(f"2024-10-21 10:00:{i:02d} Test log entry {i}\n")
            temp_file.close()
            
            collector = LogCollector()
            evidence_list = collector.collect(temp_file.name)
            
            # Should handle without issues
            assert len(evidence_list) > 0
            assert evidence_list[0].metadata['line_count'] == 1000
            
        finally:
            if os.path.exists(temp_file.name):
                os.unlink(temp_file.name)
    
    def test_concurrent_evidence_storage(self):
        """Test concurrent storage operations"""
        import threading
        
        temp_dir = tempfile.mkdtemp()
        
        try:
            store = EvidenceStore(storage_path=temp_dir)
            
            def store_evidence(evidence_id):
                evidence = Evidence(
                    evidence_id=evidence_id,
                    evidence_type=EvidenceType.LOG,
                    source_path="/tmp/test.log",
                    hash=f"hash_{evidence_id}",
                    collected_at=datetime.now(),
                    data="test data",
                    metadata={}
                )
                store.store_evidence(evidence)
            
            # Create multiple threads
            threads = []
            for i in range(10):
                t = threading.Thread(target=store_evidence, args=(f"EVD-{i:03d}",))
                threads.append(t)
                t.start()
            
            # Wait for all threads
            for t in threads:
                t.join()
            
            # Verify all evidence was stored
            evidence_files = list(Path(temp_dir).glob("EVD-*.json"))
            assert len(evidence_files) == 10
            
        finally:
            import shutil
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])