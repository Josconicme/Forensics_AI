# AI-Powered Digital Forensics System

An intelligent digital forensics platform that automates evidence collection, analysis, and reporting using AI agents for security incident investigation.

## 🎯 Features

- **Multi-Source Evidence Collection**: Automated ingestion from logs, files, and network captures
- **AI-Powered Analysis**: Specialized agents for pattern detection and threat correlation
- **Chain of Custody**: Cryptographic verification and immutable audit trails
- **Automated Reporting**: Comprehensive forensic reports with timelines and recommendations
- **Evidence Correlation**: Cross-source analysis for incident reconstruction

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Ingestion Layer                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │Log Collector │  │File Collector│  │Net. Collector│     │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘     │
└─────────┼──────────────────┼──────────────────┼─────────────┘
          │                  │                  │
          └──────────────────┼──────────────────┘
                             ▼
          ┌─────────────────────────────────────┐
          │      Evidence Store + Chain of      │
          │           Custody Tracking          │
          └─────────────┬───────────────────────┘
                        ▼
          ┌─────────────────────────────────────┐
          │         AI Agent Layer              │
          │  ┌────────────┐  ┌──────────────┐  │
          │  │Log Analysis│  │File Analysis │  │
          │  └────────────┘  └──────────────┘  │
          │  ┌────────────┐  ┌──────────────┐  │
          │  │Network Anal│  │ Correlation  │  │
          │  └────────────┘  └──────────────┘  │
          └─────────────┬───────────────────────┘
                        ▼
          ┌─────────────────────────────────────┐
          │      Analysis Engine                │
          │   (Orchestrates Multi-Agent         │
          │    Collaboration)                   │
          └─────────────┬───────────────────────┘
                        ▼
          ┌─────────────────────────────────────┐
          │      Report Generator               │
          │   (Executive Summary + Technical)   │
          └─────────────────────────────────────┘
```

## 🚀 Quick Start

### Prerequisites

- Python 3.9+
- Anthropic API key (for Claude) or OpenAI API key

### Installation

1. **Clone the repository**
```bash
git clone <your-repo-url>
cd forensics-ai
```

2. **Create virtual environment**
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

4. **Configure environment**
```bash
cp .env.example .env
# Edit .env and add your API keys
```

### Generate Mock Data

```bash
python scripts/generate_mock_data.py
```

This creates realistic forensic artifacts in `mock_data/`:
- System and application logs
- File metadata with suspicious patterns
- Network traffic captures

### Run Analysis

```bash
python main.py
```

This will:
1. Ingest evidence from mock data sources
2. Run AI-powered analysis using specialized agents
3. Generate a comprehensive forensic report in `output/`

## 📁 Project Structure

```
forensics-ai/
├── docs/
│   ├── ARCHITECTURE.md          # Detailed system design
│   ├── STRATEGIC_DISCUSSION.md  # Answers to strategic questions
│   └── diagrams/                # Architecture diagrams
├── src/
│   ├── agents/                  # AI analysis agents
│   │   ├── base_agent.py
│   │   ├── log_analysis_agent.py
│   │   ├── file_analysis_agent.py
│   │   ├── network_analysis_agent.py
│   │   └── correlation_agent.py
│   ├── collectors/              # Evidence collectors
│   │   ├── base_collector.py
│   │   ├── log_collector.py
│   │   ├── file_collector.py
│   │   └── network_collector.py
│   ├── storage/                 # Evidence storage
│   │   └── evidence_store.py
│   ├── chain_of_custody/        # Audit trail management
│   │   └── custody_manager.py
│   ├── analysis/                # Analysis orchestration
│   │   └── analysis_engine.py
│   ├── reporting/               # Report generation
│   │   └── report_generator.py
│   ├── models/                  # Data models
│   │   └── evidence.py
│   ├── utils/                   # Utilities
│   │   └── crypto.py
│   └── config.py                # Configuration
├── scripts/
│   └── generate_mock_data.py    # Mock data generator
├── tests/                       # Test suite
│   ├── test_collectors.py
│   ├── test_agents.py
│   └── test_integration.py
├── mock_data/                   # Generated mock evidence
├── output/                      # Generated reports
├── .env.example                 # Environment template
├── .gitignore
├── requirements.txt
└── README.md
```

## 🔬 Usage Examples

### Basic Analysis
```bash
python main.py
```

### Custom Evidence Path
```bash
python main.py --evidence-path /path/to/evidence
```

### Generate Report Only
```bash
python main.py --report-only --case-id CASE-2024-001
```

## 🤖 AI Agents

The system uses specialized AI agents for different analysis tasks:

- **Log Analysis Agent**: Detects authentication failures, privilege escalations, suspicious commands
- **File Analysis Agent**: Identifies malware signatures, data exfiltration patterns, unauthorized modifications
- **Network Analysis Agent**: Analyzes traffic patterns, C2 communications, port scans
- **Correlation Agent**: Connects findings across sources to reconstruct attack timelines

## 🔐 Security Features

- **Cryptographic Hashing**: SHA-256 verification for evidence integrity
- **Chain of Custody**: Immutable audit trail with timestamps and agent signatures
- **Evidence Isolation**: Secure storage with access controls
- **PII Protection**: Automatic detection and masking of sensitive data

## 📊 Sample Output

After running the analysis, you'll find in `output/`:

- `forensic_report_CASE-XXX.json` - Structured findings
- `forensic_report_CASE-XXX.md` - Human-readable report
- `timeline_CASE-XXX.json` - Incident timeline
- `chain_of_custody_CASE-XXX.json` - Audit trail

## 🧪 Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov-report=html

# Run specific test
pytest tests/test_agents.py -v
```

## 📖 Documentation

- [Architecture Document](docs/ARCHITECTURE.md) - Detailed system design
- [Strategic Discussion](docs/STRATEGIC_DISCUSSION.md) - Answers to evaluation questions
- [API Documentation](docs/API.md) - Code reference

## 🎯 Design Principles

1. **Evidence Integrity First**: Every operation logged and hashed
2. **AI Transparency**: All agent decisions include reasoning and confidence scores
3. **Modular Architecture**: Easy to extend with new collectors and agents
4. **Legal Compliance**: Built-in chain of custody and audit trails
5. **Human-in-the-Loop**: Findings require analyst validation

## 🔄 Extending the System

### Adding a New Collector

```python
from src.collectors.base_collector import BaseCollector

class CustomCollector(BaseCollector):
    def collect(self, source_path: str) -> List[Evidence]:
        # Your collection logic
        pass
```

### Adding a New Agent

```python
from src.agents.base_agent import BaseAgent

class CustomAgent(BaseAgent):
    async def analyze(self, evidence: List[Evidence]) -> Dict:
        # Your analysis logic
        pass
```

## 🛣️ Roadmap

- [ ] Real-time streaming analysis
- [ ] Memory forensics integration
- [ ] Cloud evidence collection (AWS, Azure, GCP)
- [ ] Advanced ML models for anomaly detection
- [ ] Multi-tenancy support
- [ ] Web-based investigation dashboard

## 📝 License

This project is for educational and demonstration purposes as part of Ibn Sina Corporation's assessment.

## 🤝 Contributing

This is an assessment project. For questions or issues, please contact the development team.

## 👥 Authors

Developed as part of Ibn Sina Corporation's AI-Powered Digital Forensics System assessment.

## 🙏 Acknowledgments

- LangChain for agent orchestration
- Anthropic Claude for AI analysis
- Digital forensics community for best practices