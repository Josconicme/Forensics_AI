"""
Setup script for AI-Powered Digital Forensics System.

This script allows installation via pip and defines package metadata.
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README for long description
readme_file = Path(__file__).parent / "README.md"
if readme_file.exists():
    with open(readme_file, "r", encoding="utf-8") as f:
        long_description = f.read()
else:
    long_description = "AI-Powered Digital Forensics System"

# Read requirements
requirements_file = Path(__file__).parent / "requirements.txt"
if requirements_file.exists():
    with open(requirements_file, "r", encoding="utf-8") as f:
        requirements = [line.strip() for line in f if line.strip() and not line.startswith("#")]
else:
    requirements = []

# Package metadata
setup(
    name="forensics-ai",
    version="1.0.0",
    author="Forensics AI Team",
    author_email="forensics@example.com",
    description="AI-Powered Digital Forensics System for automated security incident investigation",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/forensics-ai",
    project_urls={
        "Bug Tracker": "https://github.com/yourusername/forensics-ai/issues",
        "Documentation": "https://github.com/yourusername/forensics-ai/docs",
        "Source Code": "https://github.com/yourusername/forensics-ai",
    },
    
    # Package configuration
    packages=find_packages(exclude=["tests", "tests.*", "docs", "scripts"]),
    package_dir={"": "."},
    
    # Python version requirement
    python_requires=">=3.9",
    
    # Dependencies
    install_requires=requirements,
    
    # Optional dependencies
    extras_require={
        "dev": [
            "pytest>=8.3.3",
            "pytest-asyncio>=0.24.0",
            "pytest-cov>=5.0.0",
            "black>=24.10.0",
            "flake8>=7.1.1",
            "mypy>=1.13.0",
            "pre-commit>=3.5.0",
        ],
        "docs": [
            "sphinx>=7.0.0",
            "sphinx-rtd-theme>=2.0.0",
            "sphinx-autodoc-typehints>=1.24.0",
        ],
        "analysis": [
            "jupyter>=1.0.0",
            "matplotlib>=3.8.0",
            "seaborn>=0.13.0",
        ],
    },
    
    # Entry points for command-line scripts
    entry_points={
        "console_scripts": [
            "forensics-ai=main:main",
            "forensics-collect=scripts.generate_mock_data:main",
        ],
    },
    
    # Package data
    include_package_data=True,
    package_data={
        "": [
            "config/*.yaml",
            "templates/*.md",
            "templates/*.html",
        ],
    },
    
    # Classifiers
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Science/Research",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "Natural Language :: English",
    ],
    
    # Keywords
    keywords=[
        "forensics",
        "digital-forensics",
        "cybersecurity",
        "incident-response",
        "security-analysis",
        "ai",
        "machine-learning",
        "threat-detection",
        "malware-analysis",
        "security-investigation",
        "evidence-collection",
        "chain-of-custody",
    ],
    
    # License
    license="MIT",
    
    # Additional metadata
    zip_safe=False,
    platforms=["any"],
)