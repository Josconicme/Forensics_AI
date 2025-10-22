# API Documentation

Complete reference for the AI-Powered Digital Forensics System components.

## Table of Contents

1. [Evidence Models](#evidence-models)
2. [Collectors](#collectors)
3. [AI Agents](#ai-agents)
4. [Storage](#storage)
5. [Chain of Custody](#chain-of-custody)
6. [Analysis Engine](#analysis-engine)
7. [Report Generator](#report-generator)

---

## Evidence Models

### Evidence Class

Represents a piece of forensic evidence.

```python
from src.models.evidence import Evidence, EvidenceType
from datetime import datetime

evidence = Evidence(
    evidence_id="EVD-001",
    evidence_type=EvidenceType.LOG,
    source_path="/var/log/auth.log",
    hash="sha256:abc123...",
    collected_at=datetime.now(),
    data="log content here",
    metadata={"line_count": 100}
)
```

**Attributes:**
- `evidence_id` (str): Unique identifier
- `evidence_type` (EvidenceType): Type of evidence
- `source_path` (str): Original file path
- `hash` (str): SHA-256 hash of content
- `collected_at` (datetime): Collection timestamp
- `data` (str): Evidence content
- `metadata` (dict): Additional metadata

### EvidenceType Enum

```python
from src.models.evidence import EvidenceType

EvidenceType.LOG               # Log files
EvidenceType.FILE_METADATA     # File system metadata
EvidenceType.NETWORK_TRAFFIC   # Network captures
EvidenceType.MEMORY_DUMP       # Memory dumps
EvidenceType.REGISTRY          # Windows registry
```

---

## Collectors

### Base Collector

All collectors inherit from `BaseCollector`.

```python
from src.collectors.base_collector import BaseCollector

class CustomCollector(BaseCollector):
    def collect(self, source_path: str) -> List[Evidence]:
        # Your collection logic
        pass
```

### Log Collector

Collects and processes log files.

```python
from src.collectors.log_collector import LogCollector

collector = LogCollector()
evidence_list = collector.collect("/var/log/auth.log")
```

**Methods:**
- `collect(source_path: str) -> List[Evidence]`: Collect network data

**Example:**
```python
collector = NetworkCollector()
evidence = collector.collect("/var/log/network.csv")

for item in evidence:
    print(f"Connections: {item.metadata['connection_count']}")
    print(f"Protocols: {item.metadata['protocols']}")
```

---

## AI Agents

### Base Agent

All AI agents inherit from `BaseAgent`.

```python
from src.agents.base_agent import BaseAgent

class CustomAgent(BaseAgent):
    async def analyze(self, evidence: List[Evidence]) -> Dict:
        # Your analysis logic
        pass
```

**Required Methods:**
- `analyze(evidence: List[Evidence]) -> Dict`: Analyze evidence

### Log Analysis Agent

Analyzes system and application logs.

```python
from src.agents.log_analysis_agent import LogAnalysisAgent
from langchain_anthropic import ChatAnthropic

llm = ChatAnthropic(model="claude-sonnet-4-5-20250929")
agent = LogAnalysisAgent(llm)
results = await agent.analyze(log_evidence)
```

**Analysis Capabilities:**
- Brute force attacks
- Privilege escalation
- Suspicious commands
- Authentication anomalies
- Lateral movement indicators

**Return Format:**
```python
{
    "agent_name": "LogAnalysisAgent",
    "findings": [
        {
            "type": "brute_force",
            "severity": "high",
            "description": "Multiple failed login attempts",
            "evidence_ids": ["EVD-001"],
            "timestamp": "2024-10-21 10:00:00"
        }
    ],
    "confidence": 0.95,
    "reasoning": "Detected pattern of failed authentications..."
}
```

**Example:**
```python
import asyncio

async def analyze_logs():
    llm = ChatAnthropic(model="claude-sonnet-4-5-20250929")
    agent = LogAnalysisAgent(llm)
    
    # Load log evidence
    from src.collectors.log_collector import LogCollector
    collector = LogCollector()
    evidence = collector.collect("/var/log/auth.log")
    
    # Analyze
    results = await agent.analyze(evidence)
    
    # Process findings
    for finding in results['findings']:
        if finding['severity'] == 'high':
            print(f"HIGH SEVERITY: {finding['description']}")

asyncio.run(analyze_logs())
```

### File Analysis Agent

Analyzes file system artifacts.

```python
from src.agents.file_analysis_agent import FileAnalysisAgent

agent = FileAnalysisAgent(llm)
results = await agent.analyze(file_evidence)
```

**Analysis Capabilities:**
- Malware detection
- Suspicious file types
- Data exfiltration patterns
- Unauthorized modifications
- File signature analysis

**Example:**
```python
async def analyze_files():
    agent = FileAnalysisAgent(llm)
    
    from src.collectors.file_collector import FileCollector
    collector = FileCollector()
    evidence = collector.collect("/suspicious/directory")
    
    results = await agent.analyze(evidence)
    
    for finding in results['findings']:
        if finding['type'] == 'malware':
            print(f"MALWARE: {finding['file_path']}")
            print(f"Hash: {finding['hash']}")

asyncio.run(analyze_files())
```

### Network Analysis Agent

Analyzes network traffic patterns.

```python
from src.agents.network_analysis_agent import NetworkAnalysisAgent

agent = NetworkAnalysisAgent(llm)
results = await agent.analyze(network_evidence)
```

**Analysis Capabilities:**
- C2 communications
- Port scans
- Data exfiltration
- DNS tunneling
- Beaconing patterns

**Example:**
```python
async def analyze_network():
    agent = NetworkAnalysisAgent(llm)
    
    from src.collectors.network_collector import NetworkCollector
    collector = NetworkCollector()
    evidence = collector.collect("/var/log/network.csv")
    
    results = await agent.analyze(evidence)
    
    for finding in results['findings']:
        if finding['type'] == 'c2_communication':
            print(f"C2 DETECTED: {finding['dst_ip']}")

asyncio.run(analyze_network())
```

### Correlation Agent

Correlates findings across all sources.

```python
from src.agents.correlation_agent import CorrelationAgent

agent = CorrelationAgent(llm)
results = await agent.correlate(all_findings)
```

**Input Format:**
```python
all_findings = {
    'log_findings': [...],
    'file_findings': [...],
    'network_findings': [...]
}
```

**Output Format:**
```python
{
    "timeline": [
        {
            "timestamp": "2024-10-21 10:00:00",
            "event": "Initial access via brute force",
            "source": "auth.log",
            "severity": "high"
        }
    ],
    "attack_chain": "Initial Access -> Execution -> Persistence",
    "iocs": ["203.0.113.45", "malware.exe", "..."]
}
```

---

## Storage

### Evidence Store

Manages evidence storage and retrieval.

```python
from src.storage.evidence_store import EvidenceStore

store = EvidenceStore(storage_path="/path/to/evidence")
```

**Methods:**

#### `store_evidence(evidence: Evidence) -> bool`
Store evidence securely.

```python
store = EvidenceStore()
success = store.store_evidence(evidence)
```

#### `get_evidence(evidence_id: str) -> Optional[Evidence]`
Retrieve stored evidence.

```python
evidence = store.get_evidence("EVD-001")
if evidence:
    print(f"Retrieved: {evidence.evidence_id}")
```

#### `list_evidence() -> List[str]`
List all stored evidence IDs.

```python
all_evidence = store.list_evidence()
print(f"Total evidence items: {len(all_evidence)}")
```

#### `verify_integrity(evidence_id: str) -> bool`
Verify evidence hasn't been tampered with.

```python
is_valid = store.verify_integrity("EVD-001")
if not is_valid:
    print("WARNING: Evidence integrity compromised!")
```

**Example:**
```python
# Store evidence
store = EvidenceStore(storage_path="./evidence_storage")

for item in evidence_list:
    success = store.store_evidence(item)
    if success:
        print(f"✓ Stored: {item.evidence_id}")
    else:
        print(f"✗ Failed: {item.evidence_id}")

# Retrieve and verify
stored = store.get_evidence("EVD-001")
if store.verify_integrity("EVD-001"):
    print("Evidence integrity verified")
```

---

## Chain of Custody

### Custody Manager

Tracks chain of custody for all evidence.

```python
from src.chain_of_custody.custody_manager import CustodyManager

custody = CustodyManager(db_path="./data/custody.db")
```

**Methods:**

#### `record_action(evidence_id, action, agent, hash_value, metadata=None)`
Record a custody event.

```python
custody.record_action(
    evidence_id="EVD-001",
    action="INGESTED",
    agent="LogCollector",
    hash_value="sha256:abc123...",
    metadata={"source": "/var/log/auth.log"}
)
```

**Actions:**
- `INGESTED` - Evidence collected
- `STORED` - Evidence stored
- `ACCESSED` - Evidence retrieved
- `ANALYZED` - Analysis performed
- `EXPORTED` - Included in report

#### `get_chain(evidence_id: str) -> List[Dict]`
Get complete custody chain.

```python
chain = custody.get_chain("EVD-001")
for record in chain:
    print(f"{record['timestamp']}: {record['action']} by {record['agent']}")
```

#### `verify_integrity(evidence_id: str) -> bool`
Verify chain integrity.

```python
if custody.verify_integrity("EVD-001"):
    print("Chain of custody intact")
else:
    print("WARNING: Chain broken!")
```

#### `export_chain(evidence_id: str, format: str = 'json') -> str`
Export chain for legal proceedings.

```python
json_chain = custody.export_chain("EVD-001", format='json')
with open("custody_report.json", 'w') as f:
    f.write(json_chain)
```

**Example:**
```python
custody = CustodyManager()

# Record collection
custody.record_action(
    evidence_id="EVD-001",
    action="INGESTED",
    agent="LogCollector",
    hash_value=evidence.hash
)

# Record storage
custody.record_action(
    evidence_id="EVD-001",
    action="STORED",
    agent="EvidenceStore",
    hash_value=evidence.hash
)

# Verify before analysis
if custody.verify_integrity("EVD-001"):
    # Proceed with analysis
    pass
```

---

## Analysis Engine

### Analysis Engine

Orchestrates multi-agent analysis workflow.

```python
from src.analysis.analysis_engine import AnalysisEngine

engine = AnalysisEngine(
    evidence_store=store,
    custody_manager=custody,
    llm_client=llm
)
```

**Methods:**

#### `async analyze_case(case_id: str, evidence_list: List[Evidence]) -> Dict`
Run complete analysis.

```python
results = await engine.analyze_case(
    case_id="CASE-2024-001",
    evidence_list=all_evidence
)
```

**Return Format:**
```python
{
    "case_id": "CASE-2024-001",
    "timestamp": "2024-10-21T14:30:00Z",
    "log_analysis": {...},
    "file_analysis": {...},
    "network_analysis": {...},
    "correlation": {...},
    "summary": {
        "total_findings": 15,
        "critical": 3,
        "high": 5,
        "medium": 7
    }
}
```

**Example:**
```python
async def run_analysis():
    # Initialize components
    store = EvidenceStore()
    custody = CustodyManager()
    llm = ChatAnthropic(model="claude-sonnet-4-5-20250929")
    
    # Create engine
    engine = AnalysisEngine(store, custody, llm)
    
    # Collect evidence
    from src.collectors.log_collector import LogCollector
    collector = LogCollector()
    evidence = collector.collect("/var/log/auth.log")
    
    # Run analysis
    results = await engine.analyze_case(
        case_id="CASE-2024-001",
        evidence_list=evidence
    )
    
    # Process results
    print(f"Total findings: {results['summary']['total_findings']}")
    print(f"Critical: {results['summary']['critical']}")

asyncio.run(run_analysis())
```

---

## Report Generator

### Report Generator

Generates forensic reports in multiple formats.

```python
from src.reporting.report_generator import ReportGenerator

generator = ReportGenerator()
```

**Methods:**

#### `generate_report(case_id, analysis_results, evidence_list, custody_chain) -> Dict`
Generate comprehensive report.

```python
report = generator.generate_report(
    case_id="CASE-2024-001",
    analysis_results=results,
    evidence_list=all_evidence,
    custody_chain=custody.get_all_chains()
)
```

#### `save_report(report: Dict, output_path: str, format: str = 'markdown')`
Save report to file.

```python
generator.save_report(
    report=report,
    output_path="./output",
    format="markdown"
)
```

**Formats:**
- `markdown` - Human-readable Markdown
- `json` - Structured JSON
- `html` - Web-viewable HTML

**Example:**
```python
# Generate report
generator = ReportGenerator()

report = generator.generate_report(
    case_id="CASE-2024-001",
    analysis_results=analysis_results,
    evidence_list=all_evidence,
    custody_chain=custody_chain
)

# Save in multiple formats
generator.save_report(report, "./output", format="markdown")
generator.save_report(report, "./output", format="json")
generator.save_report(report, "./output", format="html")

print(f"Report saved to ./output/forensic_report_CASE-2024-001.*")
```

---

## Complete Workflow Example

Here's a complete end-to-end workflow:

```python
import asyncio
from datetime import datetime
from langchain_anthropic import ChatAnthropic

from src.collectors.log_collector import LogCollector
from src.collectors.file_collector import FileCollector
from src.collectors.network_collector import NetworkCollector
from src.storage.evidence_store import EvidenceStore
from src.chain_of_custody.custody_manager import CustodyManager
from src.analysis.analysis_engine import AnalysisEngine
from src.reporting.report_generator import ReportGenerator

async def complete_investigation():
    # 1. Initialize components
    case_id = f"CASE-{datetime.now().strftime('%Y-%m-%d-%H%M%S')}"
    store = EvidenceStore(storage_path="./evidence_storage")
    custody = CustodyManager(db_path="./data/custody.db")
    llm = ChatAnthropic(model="claude-sonnet-4-5-20250929")
    
    # 2. Collect evidence
    print("Collecting evidence...")
    log_collector = LogCollector()
    file_collector = FileCollector()
    network_collector = NetworkCollector()
    
    log_evidence = log_collector.collect("./mock_data/system_logs.log")
    file_evidence = file_collector.collect("./mock_data/")
    network_evidence = network_collector.collect("./mock_data/network_traffic.csv")
    
    all_evidence = log_evidence + file_evidence + network_evidence
    print(f"✓ Collected {len(all_evidence)} evidence items")
    
    # 3. Store evidence and record custody
    print("Storing evidence...")
    for evidence in all_evidence:
        store.store_evidence(evidence)
        custody.record_action(
            evidence_id=evidence.evidence_id,
            action="INGESTED",
            agent="Collector",
            hash_value=evidence.hash
        )
    print(f"✓ Stored {len(all_evidence)} items")
    
    # 4. Run analysis
    print("Running AI analysis...")
    engine = AnalysisEngine(store, custody, llm)
    results = await engine.analyze_case(case_id, all_evidence)
    print(f"✓ Analysis complete: {results['summary']['total_findings']} findings")
    
    # 5. Generate report
    print("Generating report...")
    generator = ReportGenerator()
    report = generator.generate_report(
        case_id=case_id,
        analysis_results=results,
        evidence_list=all_evidence,
        custody_chain=[custody.get_chain(e.evidence_id) for e in all_evidence]
    )
    
    generator.save_report(report, "./output", format="markdown")
    generator.save_report(report, "./output", format="json")
    print(f"✓ Report saved to ./output/forensic_report_{case_id}.*")
    
    return report

# Run the investigation
if __name__ == "__main__":
    report = asyncio.run(complete_investigation())
    print("\nInvestigation complete!")
```

---

## Error Handling

All components include error handling:

```python
try:
    evidence = collector.collect("/path/to/logs")
except FileNotFoundError:
    print("Evidence file not found")
except PermissionError:
    print("Permission denied accessing evidence")
except Exception as e:
    print(f"Error collecting evidence: {e}")
```

---

## Configuration

See `src/config.py` for all configuration options:

```python
from src.config import Config

# Access configuration
print(Config.AI_PROVIDER)
print(Config.EVIDENCE_STORAGE_PATH)
print(Config.MAX_PARALLEL_AGENTS)
```

---

## Testing

Test all components:

```python
# Run all tests
pytest tests/ -v

# Test specific component
pytest tests/test_collectors.py -v

# Test with coverage
pytest tests/ --cov=src --cov-report=html
```

---

For more information, see:
- `docs/ARCHITECTURE.md` - System design
- `docs/STRATEGIC_DISCUSSION.md` - Strategic considerations
- `docs/QUICKSTART.md` - Getting started guide Collect logs from file

**Example:**
```python
collector = LogCollector()
evidence = collector.collect("/var/log/system.log")

for item in evidence:
    print(f"Collected: {item.evidence_id}")
    print(f"Lines: {item.metadata['line_count']}")
    print(f"Hash: {item.hash}")
```

### File Collector

Collects file system metadata.

```python
from src.collectors.file_collector import FileCollector

collector = FileCollector()
evidence_list = collector.collect("/path/to/directory")
```

**Methods:**
- `collect(source_path: str) -> List[Evidence]`: Collect file metadata

**Example:**
```python
collector = FileCollector()
evidence = collector.collect("/suspicious/directory")

for item in evidence:
    if item.metadata.get('suspicious'):
        print(f"Suspicious file: {item.source_path}")
```

### Network Collector

Collects network traffic data.

```python
from src.collectors.network_collector import NetworkCollector

collector = NetworkCollector()
evidence_list = collector.collect("/path/to/traffic.csv")
```

**Methods:**
- `collect(source_path: str) -> List[Evidence]`: