# fix_src_imports.py
"""
Remove all "from src." prefix imports in the codebase
"""
import re
from pathlib import Path


def fix_file(file_path: Path) -> bool:
    """Fix imports in a single file"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        original = content
        
        # Replace "from src.xxx" with "from xxx"
        content = re.sub(r'from src\.([a-zA-Z_][a-zA-Z0-9_.]*)( import)', r'from \1\2', content)
        
        # Replace "import src.xxx" with "import xxx"  
        content = re.sub(r'import src\.([a-zA-Z_][a-zA-Z0-9_.]*)', r'import \1', content)
        
        # Fix specific bad patterns
        replacements = [
            ('from src.config import config', 'from config import Config'),
            ('from agents.base_agent import BaseAgent, Finding', 'from agents.base_agent import BaseAgent\nfrom models.evidence import Finding'),
        ]
        
        for old, new in replacements:
            content = content.replace(old, new)
        
        if content != original:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            return True
        
        return False
    
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
        return False


def main():
    print("=" * 70)
    print("Fixing 'from src.' imports")
    print("=" * 70)
    print()
    
    src_dir = Path('src')
    if not src_dir.exists():
        print("Error: 'src' directory not found")
        return
    
    python_files = list(src_dir.rglob('*.py'))
    fixed_count = 0
    
    for file_path in python_files:
        if fix_file(file_path):
            print(f"✓ Fixed: {file_path}")
            fixed_count += 1
    
    print(f"\n✓ Fixed {fixed_count} files")
    print("\nNow run: python main.py")


if __name__ == "__main__":
    main()