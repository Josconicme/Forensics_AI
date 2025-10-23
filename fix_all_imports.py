# fix_all_imports.py
"""
Automatically fix ALL import statements in the forensics codebase
This script converts relative imports to absolute imports
"""
import os
import re
from pathlib import Path


def fix_imports_in_file(file_path: Path) -> bool:
    """Fix imports in a single Python file"""
    if not file_path.exists() or file_path.suffix != '.py':
        return False
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        print(f"  Error reading {file_path}: {e}")
        return False
    
    original_content = content
    
    # Convert relative imports to absolute imports
    # Pattern: from ..something import -> from something import
    # Pattern: from .something import -> from something import
    
    replacements = [
        # Two levels up
        (r'from \.\.models\.evidence import', 'from models.evidence import'),
        (r'from \.\.storage\.evidence_store import', 'from storage.evidence_store import'),
        (r'from \.\.chain_of_custody\.custody_manager import', 'from chain_of_custody.custody_manager import'),
        (r'from \.\.utils\.crypto import', 'from utils.crypto import'),
        (r'from \.\.agents\.', 'from agents.'),
        (r'from \.\.collectors\.', 'from collectors.'),
        (r'from \.\.analysis\.', 'from analysis.'),
        (r'from \.\.reporting\.', 'from reporting.'),
        
        # One level up  
        (r'from \.models\.evidence import', 'from models.evidence import'),
        (r'from \.storage\.evidence_store import', 'from storage.evidence_store import'),
        (r'from \.chain_of_custody\.custody_manager import', 'from chain_of_custody.custody_manager import'),
        (r'from \.utils\.crypto import', 'from utils.crypto import'),
        (r'from \.agents\.', 'from agents.'),
        (r'from \.collectors\.', 'from collectors.'),
        (r'from \.analysis\.', 'from analysis.'),
        (r'from \.reporting\.', 'from reporting.'),
        
        # Same level
        (r'from \.base_agent import', 'from agents.base_agent import'),
        (r'from \.base_collector import', 'from collectors.base_collector import'),
    ]
    
    for pattern, replacement in replacements:
        content = re.sub(pattern, replacement, content)
    
    # Write back if changed
    if content != original_content:
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            return True
        except Exception as e:
            print(f"  Error writing {file_path}: {e}")
            return False
    
    return False


def fix_all_files():
    """Fix imports in all Python files in src directory"""
    print("=" * 70)
    print("FIXING ALL IMPORT STATEMENTS")
    print("=" * 70)
    print()
    
    src_dir = Path('src')
    if not src_dir.exists():
        print("ERROR: 'src' directory not found")
        return
    
    # Find all Python files
    python_files = list(src_dir.rglob('*.py'))
    
    print(f"Found {len(python_files)} Python files\n")
    
    fixed_count = 0
    for file_path in python_files:
        if fix_imports_in_file(file_path):
            print(f"✓ Fixed: {file_path}")
            fixed_count += 1
    
    print(f"\n{'='*70}")
    print(f"✓ Fixed {fixed_count} file(s)")
    print(f"{'='*70}\n")
    
    if fixed_count > 0:
        print("Now cleaning Python cache...")
        clean_pycache()
    
    print("\nYou can now run: python main.py")


def clean_pycache():
    """Remove all __pycache__ directories"""
    import shutil
    
    removed = 0
    for pycache_dir in Path('.').rglob('__pycache__'):
        try:
            shutil.rmtree(pycache_dir)
            removed += 1
        except Exception as e:
            print(f"  Could not remove {pycache_dir}: {e}")
    
    print(f"✓ Removed {removed} __pycache__ directories")


if __name__ == "__main__":
    fix_all_files()