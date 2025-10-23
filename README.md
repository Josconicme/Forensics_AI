# AI-Powered Digital Forensics System

An intelligent digital forensics platform that automates evidence collection, analysis, and reporting using AI agents for security incident investigation.

## Key Features

- **Multi-Source Evidence Collection** - Automated ingestion from logs, files, and network captures
- **AI-Powered Analysis** - Specialized agents for pattern detection and threat correlation
- **Chain of Custody** - Cryptographic verification and immutable audit trails
- **Automated Reporting** - Comprehensive forensic reports with timelines and recommendations
- **Evidence Correlation** - Cross-source analysis for incident reconstruction

## 🏗️ System Architecture
```
┌─────────────────────────────────────────────────────────────┐
│                  Evidence Collection Layer                   │
│   Log Collector  │  File Collector  │  Network Collector    │
└────────────────────────┬─────────────────────────────────────┘
                         ▼
          ┌──────────────────────────────────┐
          │   Evidence Store + Chain of      │
          │      Custody Tracking            │
          └──────────────┬───────────────────┘
                         ▼
          ┌──────────────────────────────────┐
          │      AI Analysis Agents          │
          │  • Log Analysis                  │
          │  • File Analysis                 │
          │  • Network Analysis              │
          │  • Correlation Engine            │
          └──────────────┬───────────────────┘
                         ▼
          ┌──────────────────────────────────┐
          │   Forensic Report Generator      │
          │  (Markdown + JSON + Timeline)    │
          └──────────────────────────────────┘
```

## 🚀 Quick Start

### Prerequisites
- Python 3.9+
- Anthropic API key (for AI analysis)

### Installation
```bash
# Clone repository
git clone git@github.com:Josconicme/Forensics_AI.git
cd Forensics_AI

# Create virtual environment
python -m venv forensics_env
source forensics_env/bin/activate  # Windows: forensics_env\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Add your ANTHROPIC_API_KEY to .env
```

### Generate Mock Data
```bash
python scripts/generate_mock_data.py
```

This creates realistic forensic evidence including:
- Apache and Windows security logs with attack patterns
- Suspicious executables and sensitive data files
- Network traffic captures with malicious activity

## 🔧 Usage - Different Branches

The system has three branches with different execution modes:

### **Branch: `dev`** (Default/Simple Mode/Claude API)
```bash
git checkout dev
python main.py
```
- Runs basic forensic analysis
- Uses default configuration
- Best for quick testing

### **Branch: `master`** (Custom Investigation Mode/OPENAI API)
```bash
git checkout master
python main.py --mock-data --case-name "Test Investigation"
```
- Allows custom case naming
- Enables mock data processing
- Suitable for demonstrations

### **Branch: `dev2`** (Demo Mode/OPENAI API )
```bash
git checkout dev2
python main.py --mode demo
```
- Full demonstration mode
- Runs complete investigation workflow
- Generates comprehensive reports

## 📊 Output

After analysis completes, check `output/` directory:
```
output/
├── reports/
│   ├── forensic_report_YYYYMMDD_HHMMSS.md    # Human-readable report
│   └── forensic_report_YYYYMMDD_HHMMSS.json  # Machine-readable data
├── evidence_db/
│   └── forensics.db                          # Evidence database
└── custody/
    └── chain_of_custody.log                  # Audit trail
```

### Sample Report Findings:
- **131 Total Findings** (45 Critical, 85 High, 1 Medium)
- SQL Injection attacks detected
- Brute force authentication attempts
- Suspicious account creation
- Data exfiltration patterns
- Complete attack chain correlation

## 🤖 AI Agents

| Agent | Purpose | Detection Capabilities |
|-------|---------|----------------------|
| **Log Analysis** | System & application logs | Brute force, privilege escalation, suspicious commands |
| **File Analysis** | Executables & documents | Malware patterns, sensitive data exposure |
| **Network Analysis** | Traffic captures | C2 communications, port scans, data exfiltration |
| **Correlation** | Cross-evidence analysis | Attack chain reconstruction, timeline building |

## 🔐 Security & Compliance

- ✅ **SHA-256 Cryptographic Hashing** - Evidence integrity verification
- ✅ **Immutable Chain of Custody** - Complete audit trail with timestamps
- ✅ **PII Detection & Masking** - Automatic sensitive data protection
- ✅ **Role-Based Access Control** - Secure evidence handling
- ✅ **Legal Admissibility** - Court-ready forensic documentation

## 📁 Project Structure
```
forensics-ai/
├── src/
│   ├── agents/              # AI analysis agents
│   ├── collectors/          # Evidence collectors
│   ├── storage/             # Evidence database
│   ├── chain_of_custody/    # Audit trail
│   ├── analysis/            # Analysis orchestration
│   ├── reporting/           # Report generation
│   └── config.py
├── scripts/
│   └── generate_mock_data.py
├── mock_data/               # Sample evidence
├── output/                  # Generated reports
├── docs/                    # Documentation
│   ├── ARCHITECTURE.md
│   └── STRATEGIC_DISCUSSION.md
├── main.py                  # Entry point
└── requirements.txt
```

## 🧪 Testing
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov-report=html

# Verify setup
python verify_setup.py
```

## 📖 Documentation

- **[Architecture Document](docs/ARCHITECTURE.md)** - System design and workflows
- **[Strategic Discussion](docs/STRATEGIC_DISCUSSION.md)** - Legal compliance, scalability, security
- **[API Reference](docs/API.md)** - Code documentation

## 🎯 Key Design Principles

1. **Evidence Integrity** - Every operation cryptographically verified
2. **AI Transparency** - All decisions include confidence scores and reasoning
3. **Modular Design** - Easy to extend with new collectors and agents
4. **Human Oversight** - Findings require analyst validation
5. **Legal Compliance** - Built-in chain of custody for court admissibility

## 🛠️ Extending the System

### Add a New Evidence Collector
```python
from collectors.base_collector import BaseCollector

class CustomCollector(BaseCollector):
    def collect(self, source_path: str):
        # Your collection logic
        pass
```

### Add a New Analysis Agent
```python
from agents.base_agent import BaseAgent

class CustomAgent(BaseAgent):
    def analyze(self, evidence_list):
        # Your analysis logic
        pass
```

## 🚧 Roadmap

- [ ] Real-time streaming analysis for active threat hunting
- [ ] Memory forensics integration (Volatility)
- [ ] Cloud evidence collection (AWS, Azure, GCP)
- [ ] Advanced ML anomaly detection models
- [ ] Web-based investigation dashboard
- [ ] Multi-tenancy support for enterprise deployments

## ⚠️ Important Notes

- **API Credits**: AI analysis requires Anthropic API credits. System gracefully degrades to pattern-based analysis if API is unavailable.
- **Mock Data**: Always run `generate_mock_data.py` before first execution.
- **Performance**: Analysis of 292 evidence items completes in ~40-45 seconds.

## 📝 Assessment Information

This project was developed as part of Ibn Sina Corporation's AI-Powered Digital Forensics System assessment, demonstrating:
- Multi-agent AI architecture
- Forensic evidence handling
- Automated security analysis
- Legal compliance considerations

## 👥 Author

Developed for Ibn Sina Corporation Technical Assessment

## 🙏 Technologies Used

- **Python 3.9+** - Core language
- **Anthropic Claude** - AI analysis engine
- **SQLite** - Evidence storage
- **Cryptography** - Evidence integrity verification

---

**Ready to investigate?** Run `python main.py --mode demo` to see the system in action! 🔍