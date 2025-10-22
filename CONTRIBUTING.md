# Contributing to AI-Powered Digital Forensics System

Thank you for your interest in contributing! This guide will help you get started.

## Development Setup

### 1. Fork and Clone

```bash
git clone https://github.com/your-username/forensics-ai.git
cd forensics-ai
```

### 2. Create Development Environment

```bash
python3 -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -r requirements.txt
pip install -e .  # Install in editable mode
```

### 3. Install Development Tools

```bash
pip install pytest pytest-cov black flake8 mypy pre-commit
```

### 4. Set Up Pre-commit Hooks

```bash
pre-commit install
```

## Project Structure

```
forensics-ai/
├── src/               # Main source code
│   ├── agents/        # AI analysis agents
│   ├── collectors/    # Evidence collectors
│   ├── storage/       # Evidence storage
│   ├── analysis/      # Analysis engine
│   └── reporting/     # Report generation
├── tests/             # Test suite
├── docs/              # Documentation
├── scripts/           # Utility scripts
└── mock_data/         # Test data
```

## Development Workflow

### 1. Create a Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b bugfix/issue-number
```

### 2. Make Changes

Follow the coding standards below.

### 3. Write Tests

Every new feature should include tests:

```python
# tests/test_your_feature.py
import pytest
from src.your_module import YourClass

def test_your_feature():
    instance = YourClass()
    result = instance.method()
    assert result == expected_value
```

### 4. Run Tests

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=src --cov-report=html

# Run specific test
pytest tests/test_your_feature.py -v
```

### 5. Format Code

```bash
# Format with black
black src/ tests/

# Check linting
flake8 src/ tests/

# Type checking
mypy src/
```

### 6. Commit Changes

```bash
git add .
git commit -m "feat: add new feature description"
```

**Commit Message Format:**
- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `test:` Test additions/changes
- `refactor:` Code refactoring
- `perf:` Performance improvements
- `chore:` Maintenance tasks

### 7. Push and Create PR

```bash
git push origin feature/your-feature-name
```

Then create a Pull Request on GitHub.

## Coding Standards

### Python Style Guide

Follow PEP 8 with these specifics:

- **Line Length:** 100 characters max
- **Indentation:** 4 spaces (no tabs)
- **Imports:** Organized in three groups (stdlib, third-party, local)
- **Docstrings:** Google style

**Example:**

```python
"""
Module for collecting forensic evidence.

This module provides collectors for different evidence types
including logs, files, and network traffic.
"""

import os
from typing import List, Optional
from datetime import datetime

from src.models.evidence import Evidence, EvidenceType
from src.utils.crypto import compute_hash


class LogCollector:
    """Collects and processes log files for forensic analysis.
    
    Attributes:
        supported_formats: List of supported log file formats
        
    Example:
        >>> collector = LogCollector()
        >>> evidence = collector.collect("/var/log/auth.log")
    """
    
    def __init__(self):
        """Initialize the log collector."""
        self.supported_formats = ['.log', '.txt']
    
    def collect(self, source_path: str) -> List[Evidence]:
        """Collect evidence from a log file.
        
        Args:
            source_path: Path to the log file
            
        Returns:
            List of Evidence objects
            
        Raises:
            FileNotFoundError: If source_path doesn't exist
            PermissionError: If unable to read file
        """
        if not os.path.exists(source_path):
            raise FileNotFoundError(f"Log file not found: {source_path}")
        
        # Implementation here
        pass
```

### Type Hints

Use type hints for all function signatures:

```python
def analyze_logs(
    logs: List[str],
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None
) -> Dict[str, Any]:
    """Analyze log entries within time range."""
    pass
```

### Error Handling

Always handle errors gracefully:

```python
try:
    evidence = collector.collect(path)
except FileNotFoundError:
    logger.error(f"Evidence file not found: {path}")
    return []
except PermissionError:
    logger.error(f"Permission denied: {path}")
    return []
except Exception as e:
    logger.exception(f"Unexpected error: {e}")
    return []
```

### Logging

Use proper logging instead of print():

```python
import logging

logger = logging.getLogger(__name__)

logger.debug("Detailed debugging information")
logger.info("General informational message")
logger.warning("Warning message")
logger.error("Error message")
logger.critical("Critical error message")
```

## Adding New Features

### Adding a New Collector

1. Create file in `src/collectors/`:

```python
# src/collectors/registry_collector.py
from typing import List
from src.collectors.base_collector import BaseCollector
from src.models.evidence import Evidence, EvidenceType

class RegistryCollector(BaseCollector):
    """Collects Windows Registry artifacts."""
    
    def collect(self, source_path: str) -> List[Evidence]:
        """Collect registry evidence."""
        # Implementation
        pass
```

2. Add tests:

```python
# tests/test_registry_collector.py
import pytest
from src.collectors.registry_collector import RegistryCollector

def test_collect_registry():
    collector = RegistryCollector()
    evidence = collector.collect("path/to/registry/hive")
    assert len(evidence) > 0
```

3. Update documentation in `docs/API.md`

### Adding a New AI Agent

1. Create file in `src/agents/`:

```python
# src/agents/memory_analysis_agent.py
from typing import Dict, List
from src.agents.base_agent import BaseAgent
from src.models.evidence import Evidence

class MemoryAnalysisAgent(BaseAgent):
    """Analyzes memory dumps for malicious processes."""
    
    async def analyze(self, evidence: List[Evidence]) -> Dict:
        """Analyze memory evidence."""
        # Implementation
        pass
```

2. Add tests:

```python
# tests/test_memory_agent.py
import pytest
from src.agents.memory_analysis_agent import MemoryAnalysisAgent

@pytest.mark.asyncio
async def test_analyze_memory():
    agent = MemoryAnalysisAgent(mock_llm)
    results = await agent.analyze(memory_evidence)
    assert 'findings' in results
```

## Testing Guidelines

### Test Coverage

Aim for 85%+ code coverage:

```bash
pytest tests/ --cov=src --cov-report=term --cov-report=html
```

### Test Structure

```python
class TestYourFeature:
    """Test suite for YourFeature."""
    
    @pytest.fixture
    def setup_data(self):
        """Setup test data."""
        # Return test data
        pass
    
    def test_basic_functionality(self, setup_data):
        """Test basic functionality."""
        # Test code
        pass
    
    def test_edge_case(self, setup_data):
        """Test edge case handling."""
        # Test code
        pass
    
    def test_error_handling(self):
        """Test error handling."""
        with pytest.raises(ValueError):
            # Code that should raise ValueError
            pass
```

### Async Tests

For async functions:

```python
import pytest

@pytest.mark.asyncio
async def test_async_function():
    result = await async_function()
    assert result is not None
```

### Mock External Services

Mock AI API calls in tests:

```python
from unittest.mock import Mock, AsyncMock

@pytest.fixture
def mock_llm():
    mock = AsyncMock()
    mock.invoke = AsyncMock(return_value=Mock(
        content='{"findings": []}'
    ))
    return mock
```

## Documentation

### Docstrings

All public functions, classes, and modules need docstrings:

```python
def complex_function(param1: str, param2: int) -> Dict[str, Any]:
    """Brief one-line summary.
    
    More detailed description if needed. Explain what the
    function does, any important algorithms, etc.
    
    Args:
        param1: Description of first parameter
        param2: Description of second parameter
        
    Returns:
        Dictionary containing:
            - key1: Description
            - key2: Description
            
    Raises:
        ValueError: When param2 is negative
        
    Example:
        >>> result = complex_function("test", 42)
        >>> print(result['key1'])
        'value'
    """
    pass
```

### Updating Documentation

When adding features, update:
- `README.md` - If user-facing
- `docs/API.md` - API reference
- `docs/ARCHITECTURE.md` - If architectural changes
- `docs/QUICKSTART.md` - If affects setup/usage

## Pull Request Process

### Before Submitting

- [ ] All tests pass: `pytest tests/ -v`
- [ ] Code is formatted: `black src/ tests/`
- [ ] No linting errors: `flake8 src/ tests/`
- [ ] Type checking passes: `mypy src/`
- [ ] Documentation updated
- [ ] CHANGELOG.md updated (if significant)

### PR Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
Describe testing performed

## Checklist
- [ ] Tests pass
- [ ] Code formatted
- [ ] Documentation updated
```

## Reporting Issues

### Bug Reports

Include:
1. Description of the bug
2. Steps to reproduce
3. Expected behavior
4. Actual behavior
5. Environment (OS, Python version)
6. Logs/error messages

### Feature Requests

Include:
1. Description of the feature
2. Use case/motivation
3. Proposed implementation (optional)
4. Alternatives considered

## Code Review Guidelines

### As a Reviewer

- Be respectful and constructive
- Focus on code, not the person
- Explain reasoning behind suggestions
- Approve when ready, request changes if needed

### As an Author

- Be open to feedback
- Respond to all comments
- Make requested changes promptly
- Ask questions if unclear

## Release Process

1. Update version in `src/__init__.py`
2. Update CHANGELOG.md
3. Create release branch
4. Run full test suite
5. Tag release: `git tag v1.x.x`
6. Push tags: `git push --tags`

## Getting Help

- **Documentation:** See `docs/` directory
- **Examples:** Check `tests/` for usage examples
- **Questions:** Open a GitHub Discussion

## Code of Conduct

- Be respectful and inclusive
- Welcome newcomers
- Focus on what's best for the project
- Show empathy towards other community members

Thank you for contributing to making digital forensics more accessible and effective!