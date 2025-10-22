"""
Script to create all necessary directories for the forensics system.

This ensures the proper directory structure exists before running the application.
"""

import os
from pathlib import Path


def create_directories():
    """Create all necessary directories for the application."""
    
    # Base directory (project root)
    base_dir = Path(__file__).parent.parent
    
    # List of directories to create
    directories = [
        # Data directories
        "mock_data",
        "mock_data/files",
        "mock_data/logs",
        "mock_data/network",
        
        # Output directories
        "output",
        "output/reports",
        "output/exports",
        
        # Storage directories
        "evidence_storage",
        "evidence_backup",
        
        # Database directory
        "data",
        
        # Logging directory
        "logs",
        
        # Configuration directory
        "config",
        
        # Template directory
        "templates",
        
        # Keys directory (for encryption)
        "keys",
        
        # Cache directory
        "cache",
        
        # Test fixtures
        "tests/fixtures",
        
        # Documentation build
        "docs/diagrams",
    ]
    
    print("Creating directory structure...")
    print(f"Base directory: {base_dir}")
    print()
    
    created_count = 0
    existing_count = 0
    
    for directory in directories:
        dir_path = base_dir / directory
        
        if dir_path.exists():
            print(f"  ✓ {directory} (already exists)")
            existing_count += 1
        else:
            try:
                dir_path.mkdir(parents=True, exist_ok=True)
                print(f"  ✓ {directory} (created)")
                created_count += 1
            except Exception as e:
                print(f"  ✗ {directory} (error: {e})")
    
    print()
    print(f"Summary:")
    print(f"  Created: {created_count} directories")
    print(f"  Existing: {existing_count} directories")
    print(f"  Total: {created_count + existing_count} directories")
    print()
    print("Directory structure ready!")
    
    # Create .gitkeep files in empty directories that should be tracked
    gitkeep_dirs = [
        "mock_data",
        "output",
        "logs",
        "templates",
        "tests/fixtures",
    ]
    
    print()
    print("Creating .gitkeep files...")
    
    for directory in gitkeep_dirs:
        gitkeep_path = base_dir / directory / ".gitkeep"
        if not gitkeep_path.exists():
            try:
                gitkeep_path.touch()
                print(f"  ✓ {directory}/.gitkeep")
            except Exception as e:
                print(f"  ✗ {directory}/.gitkeep (error: {e})")
    
    print()
    print("Setup complete!")


if __name__ == "__main__":
    create_directories()