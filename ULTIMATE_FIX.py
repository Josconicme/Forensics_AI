# ULTIMATE_FIX.py
"""
ONE-SHOT FIX for all import issues
Run this script once to fix everything
"""
import os
import shutil
from pathlib import Path


def empty_all_init_files():
    """Empty all __init__.py files in src"""
    print("Step 1: Emptying all __init__.py files...")
    
    init_files = list(Path('src').rglob('__init__.py'))
    for init_file in init_files:
        with open(init_file, 'w') as f:
            f.write("# Package initialization\n")
    
    print(f"  ✓ Emptied {len(init_files)} __init__.py files")


def fix_all_imports():
    """Fix all relative imports to absolute imports"""
    print("\nStep 2: Fixing all import statements...")
    
    files_to_fix = {
        'src/collectors/base_collector.py': [
            ('from ..storage.chain_of_custody import CustodyManager', 
             'from chain_of_custody.custody_manager import CustodyManager'),
            ('from ..chain_of_custody.custody_manager import CustodyManager',
             'from chain_of_custody.custody_manager import CustodyManager'),
        ],
        'src/collectors/log_collector.py': [
            ('from .base_collector import BaseCollector', 
             'from collectors.base_collector import BaseCollector'),
            ('from ..models.evidence import Evidence',
             'from models.evidence import Evidence'),
        ],
        'src/collectors/file_collector.py': [
            ('from .base_collector import BaseCollector',
             'from collectors.base_collector import BaseCollector'),
            ('from ..models.evidence import Evidence',
             'from models.evidence import Evidence'),
        ],
        'src/collectors/network_collector.py': [
            ('from .base_collector import BaseCollector',
             'from collectors.base_collector import BaseCollector'),
            ('from ..models.evidence import Evidence',
             'from models.evidence import Evidence'),
        ],
        'src/agents/base_agent.py': [
            ('from ..models.evidence import Evidence, Finding',
             'from models.evidence import Evidence, Finding'),
        ],
        'src/agents/file_analysis_agent.py': [
            ('from .base_agent import BaseAgent',
             'from agents.base_agent import BaseAgent'),
            ('from ..models.evidence import Evidence, Finding',
             'from models.evidence import Evidence, Finding'),
        ],
        'src/agents/log_analysis_agent.py': [
            ('from .base_agent import BaseAgent',
             'from agents.base_agent import BaseAgent'),
            ('from ..models.evidence import Evidence, Finding',
             'from models.evidence import Evidence, Finding'),
        ],
        'src/agents/network_analysis_agent.py': [
            ('from .base_agent import BaseAgent',
             'from agents.base_agent import BaseAgent'),
            ('from ..models.evidence import Evidence, Finding',
             'from models.evidence import Evidence, Finding'),
        ],
        'src/agents/correlation_agent.py': [
            ('from .base_agent import BaseAgent',
             'from agents.base_agent import BaseAgent'),
            ('from ..models.evidence import Evidence, Finding',
             'from models.evidence import Evidence, Finding'),
        ],
        'src/storage/evidence_store.py': [
            ('from ..models.evidence import Evidence',
             'from models.evidence import Evidence'),
        ],
        'src/chain_of_custody/custody_manager.py': [
            ('from ..utils.crypto import CryptoUtils',
             'from utils.crypto import CryptoUtils'),
        ],
        'src/analysis/analysis_engine.py': [
            ('from ..agents.file_analysis_agent import FileAnalysisAgent',
             'from agents.file_analysis_agent import FileAnalysisAgent'),
            ('from ..agents.log_analysis_agent import LogAnalysisAgent',
             'from agents.log_analysis_agent import LogAnalysisAgent'),
            ('from ..agents.network_analysis_agent import NetworkAnalysisAgent',
             'from agents.network_analysis_agent import NetworkAnalysisAgent'),
            ('from ..agents.correlation_agent import CorrelationAgent',
             'from agents.correlation_agent import CorrelationAgent'),
            ('from ..models.evidence import Evidence, Finding',
             'from models.evidence import Evidence, Finding'),
            ('from ..storage.evidence_store import EvidenceStore',
             'from storage.evidence_store import EvidenceStore'),
        ],
        'src/reporting/report_generator.py': [
            ('from ..models.evidence import Finding, Evidence',
             'from models.evidence import Finding, Evidence'),
            ('from ..storage.evidence_store import EvidenceStore',
             'from storage.evidence_store import EvidenceStore'),
        ],
    }
    
    fixed_count = 0
    for file_path, replacements in files_to_fix.items():
        path = Path(file_path)
        if not path.exists():
            print(f"  ⚠ Skipping {file_path} (not found)")
            continue
        
        try:
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            original_content = content
            
            for old, new in replacements:
                content = content.replace(old, new)
            
            if content != original_content:
                with open(path, 'w', encoding='utf-8') as f:
                    f.write(content)
                print(f"  ✓ Fixed {file_path}")
                fixed_count += 1
        
        except Exception as e:
            print(f"  ✗ Error fixing {file_path}: {e}")
    
    print(f"\n  ✓ Fixed {fixed_count} files")


def clean_pycache():
    """Remove all __pycache__ directories"""
    print("\nStep 3: Cleaning Python cache...")
    
    removed = 0
    for pycache_dir in Path('.').rglob('__pycache__'):
        try:
            shutil.rmtree(pycache_dir)
            removed += 1
        except Exception as e:
            pass
    
    print(f"  ✓ Removed {removed} __pycache__ directories")


def verify_structure():
    """Verify directory structure"""
    print("\nStep 4: Verifying structure...")
    
    required_files = [
        'src/config.py',
        'src/models/evidence.py',
        'src/storage/evidence_store.py',
        'src/chain_of_custody/custody_manager.py',
        'src/utils/crypto.py',
        'src/collectors/base_collector.py',
        'src/agents/base_agent.py',
        'src/analysis/analysis_engine.py',
        'src/reporting/report_generator.py',
    ]
    
    all_exist = True
    for file_path in required_files:
        if Path(file_path).exists():
            print(f"  ✓ {file_path}")
        else:
            print(f"  ✗ MISSING: {file_path}")
            all_exist = False
    
    return all_exist


def main():
    print("=" * 70)
    print("ULTIMATE FIX - Resolving All Import Issues")
    print("=" * 70)
    print()
    
    # Step 1: Empty init files
    empty_all_init_files()
    
    # Step 2: Fix imports
    fix_all_imports()
    
    # Step 3: Clean cache
    clean_pycache()
    
    # Step 4: Verify
    all_good = verify_structure()
    
    print("\n" + "=" * 70)
    if all_good:
        print("✓ ALL FIXES APPLIED SUCCESSFULLY!")
        print("\nYou can now run: python main.py")
    else:
        print("⚠ Some files are missing. Please check the output above.")
    print("=" * 70)


if __name__ == "__main__":
    main()