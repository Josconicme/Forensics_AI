# create_all_collectors.py
"""Create all collector files with correct implementation"""
from pathlib import Path

log_collector = '''# src/collectors/log_collector.py
"""Log file collector"""
from pathlib import Path
from datetime import datetime
from typing import Optional
from collectors.base_collector import BaseCollector
from models.evidence import Evidence

class LogCollector(BaseCollector):
    """Collects log file evidence"""
    
    def __init__(self, evidence_store, custody_manager):
        super().__init__(evidence_store, custody_manager)
        self.collector_name = "LogCollector"
    
    def collect(self, source_path: str) -> Optional[Evidence]:
        """Collect log file as evidence"""
        source_path = Path(source_path)
        
        if not source_path.exists():
            print(f"[{self.collector_name}] File not found: {source_path}")
            return None
        
        try:
            with open(source_path, 'rb') as f:
                data = f.read()
            
            evidence = Evidence(
                evidence_id=Evidence.generate_id(),
                evidence_type='log',
                source_path=str(source_path),
                collected_timestamp=datetime.now(),
                collector_name=self.collector_name,
                data=data,
                metadata={'file_size': len(data)}
            )
            
            if self.evidence_store.store_evidence(evidence):
                self._log_collection(evidence)
                return evidence
        except Exception as e:
            print(f"[{self.collector_name}] Error: {e}")
        return None
'''

file_collector = '''# src/collectors/file_collector.py
"""File artifact collector"""
from pathlib import Path
from datetime import datetime
from typing import Optional
from collectors.base_collector import BaseCollector
from models.evidence import Evidence

class FileCollector(BaseCollector):
    """Collects file artifacts as evidence"""
    
    def __init__(self, evidence_store, custody_manager):
        super().__init__(evidence_store, custody_manager)
        self.collector_name = "FileCollector"
    
    def collect(self, source_path: str) -> Optional[Evidence]:
        """Collect file as evidence"""
        source_path = Path(source_path)
        
        if not source_path.exists():
            print(f"[{self.collector_name}] File not found: {source_path}")
            return None
        
        try:
            with open(source_path, 'rb') as f:
                data = f.read()
            
            evidence = Evidence(
                evidence_id=Evidence.generate_id(),
                evidence_type='file',
                source_path=str(source_path),
                collected_timestamp=datetime.now(),
                collector_name=self.collector_name,
                data=data,
                metadata={'file_size': len(data), 'file_name': source_path.name}
            )
            
            if self.evidence_store.store_evidence(evidence):
                self._log_collection(evidence)
                return evidence
        except Exception as e:
            print(f"[{self.collector_name}] Error: {e}")
        return None
'''

network_collector = '''# src/collectors/network_collector.py
"""Network capture collector"""
from pathlib import Path
from datetime import datetime
from typing import Optional
from collectors.base_collector import BaseCollector
from models.evidence import Evidence

class NetworkCollector(BaseCollector):
    """Collects network capture evidence"""
    
    def __init__(self, evidence_store, custody_manager):
        super().__init__(evidence_store, custody_manager)
        self.collector_name = "NetworkCollector"
    
    def collect(self, source_path: str) -> Optional[Evidence]:
        """Collect network capture as evidence"""
        source_path = Path(source_path)
        
        if not source_path.exists():
            print(f"[{self.collector_name}] File not found: {source_path}")
            return None
        
        try:
            with open(source_path, 'rb') as f:
                data = f.read()
            
            evidence = Evidence(
                evidence_id=Evidence.generate_id(),
                evidence_type='network',
                source_path=str(source_path),
                collected_timestamp=datetime.now(),
                collector_name=self.collector_name,
                data=data,
                metadata={'file_size': len(data)}
            )
            
            if self.evidence_store.store_evidence(evidence):
                self._log_collection(evidence)
                return evidence
        except Exception as e:
            print(f"[{self.collector_name}] Error: {e}")
        return None
'''

def main():
    print("Creating all collector files...")
    
    collectors_dir = Path('src/collectors')
    collectors_dir.mkdir(parents=True, exist_ok=True)
    
    Path('src/collectors/log_collector.py').write_text(log_collector, encoding='utf-8')
    print("✓ Created log_collector.py")
    
    Path('src/collectors/file_collector.py').write_text(file_collector, encoding='utf-8')
    print("✓ Created file_collector.py")
    
    Path('src/collectors/network_collector.py').write_text(network_collector, encoding='utf-8')
    print("✓ Created network_collector.py")
    
    print("\n✓ All collectors created!")
    print("Run: python main.py")

if __name__ == "__main__":
    main()