# Quick Start Guide - AI-Powered Digital Forensics System

This guide will help you get the system up and running in under 10 minutes.

## Prerequisites

- Python 3.9 or higher
- Git
- API key from Anthropic (Claude) or OpenAI (GPT-4)
- 500 MB free disk space

## Installation Steps

### 1. Clone the Repository

```bash
git clone <your-repo-url>
cd forensics-ai
```

### 2. Quick Setup (Linux/Mac)

```bash
# Make setup script executable
chmod +x scripts/setup.sh

# Run setup
./scripts/setup.sh
```

### 2. Quick Setup (Windows)

```bash
# Run setup script
scripts\setup.bat
```

### 3. Manual Setup (Alternative)

If the automated setup fails:

```bash
# Create virtual environment
python3 -m venv venv

# Activate (Linux/Mac)
source venv/bin/activate

# Activate (Windows)
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Create directories
mkdir -p mock_data output logs evidence_storage data

# Copy environment template
cp .env.example .env
```

### 4. Configure API Keys

Edit the `.env` file and add your API key:

```bash
# For Anthropic Claude (recommended)
AI_PROVIDER=anthropic
ANTHROPIC_API_KEY=sk-ant-your-key-here

# OR for OpenAI GPT-4
AI_PROVIDER=openai
OPENAI_API_KEY=sk-your-key-here
```

### 5. Generate Mock Data

```bash
python scripts/generate_mock_data.py
```

This creates realistic forensic artifacts in `mock_data/`:
- `system_logs.log` - System and authentication logs
- `file_metadata.json` - File system information
- `network_traffic.csv` - Network connection data

### 6. Run Your First Analysis

```bash
python main.py
```

The system will:
1. Collect evidence from mock data
2. Run AI-powered analysis
3. Generate a forensic report in `output/`

**Expected output:**
```
Starting Forensic Analysis...
Collecting evidence...
  ✓ Collected 1 log evidence
  ✓ Collected 45 file metadata records
  ✓ Collected 1 network traffic log
Running AI analysis...
  ✓ Log Analysis completed
  ✓ File Analysis completed
  ✓ Network Analysis completed
  ✓ Correlation completed
Generating report...
  ✓ Report saved to output/forensic_report_CASE-2024-XXX.md
Analysis complete!
```

### 7. View the Report

```bash
# View in terminal
cat output/forensic_report_*.md

# Or open in your editor
code output/forensic_report_*.md
```

## Quick Command Reference

```bash
# Run analysis
python main.py

# Generate new mock data
python scripts/generate_mock_data.py

# Run tests
pytest tests/ -v

# Run with custom evidence path
python main.py --evidence-path /path/to/evidence

# Clean generated files
make clean  # Linux/Mac
# Or manually delete __pycache__, *.pyc files
```

## Project Structure Quick Reference

```
forensics-ai/
├── main.py                    # Entry point - run this!
├── src/
│   ├── collectors/            # Evidence collection
│   ├── agents/                # AI analysis agents
│   ├── analysis/              # Analysis orchestration
│   ├── reporting/             # Report generation
│   ├── storage/               # Evidence storage
│   └── chain_of_custody/      # Audit trail
├── mock_data/                 # Generated test data
├── output/                    # Generated reports
└── tests/                     # Test suite
```

## Troubleshooting

### Issue: "ModuleNotFoundError"

**Solution:**
```bash
# Ensure virtual environment is activated
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# Reinstall dependencies
pip install -r requirements.txt
```

### Issue: "API Key Error"

**Solution:**
```bash
# Check .env file exists
ls -la .env

# Verify API key is set
cat .env | grep API_KEY

# Ensure no extra spaces
# Correct:   ANTHROPIC_API_KEY=sk-ant-xxx
# Incorrect: ANTHROPIC_API_KEY = sk-ant-xxx
```

### Issue: "No Evidence Found"

**Solution:**
```bash
# Regenerate mock data
python scripts/generate_mock_data.py

# Verify files were created
ls -lh mock_data/

# Check paths in main.py match
```

### Issue: "Tests Failing"

**Solution:**
```bash
# Install test dependencies
pip install pytest pytest-asyncio pytest-cov

# Run tests with verbose output
pytest tests/ -v -s

# Run specific test file
pytest tests/test_collectors.py -v
```

## Next Steps

Now that you have the system running:

1. **Explore the Sample Report**: Check `output/SAMPLE_FORENSIC_REPORT.md` for what a complete analysis looks like

2. **Read the Architecture**: See `docs/ARCHITECTURE.md` for system design details

3. **Customize Analysis**: Modify agents in `src/agents/` to detect specific patterns

4. **Add Real Data**: Replace mock data with actual forensic artifacts (logs, network captures, etc.)

5. **Run Tests**: Execute `pytest tests/` to ensure everything works

6. **Review Strategic Discussion**: Read `docs/STRATEGIC_DISCUSSION.md` for insights on legal admissibility, real-time hunting, etc.

## Using Real Evidence

To analyze real forensic evidence:

1. **Prepare Your Evidence**:
```bash
mkdir my_evidence
cp /path/to/logs/*.log my_evidence/
cp /path/to/network/*.pcap my_evidence/
```

2. **Update main.py**:
```python
# Change evidence paths
LOG_PATH = "my_evidence/auth.log"
FILE_PATH = "my_evidence/"
NETWORK_PATH = "my_evidence/traffic.pcap"
```

3. **Run Analysis**:
```bash
python main.py
```

## Getting Help

- **Documentation**: See `docs/` directory
- **Sample Code**: Check `tests/` for usage examples
- **Sample Report**: Review `output/SAMPLE_FORENSIC_REPORT.md`
- **Configuration**: All settings in `src/config.py` and `.env`

## Performance Tips

- **Large Datasets**: Use `CHUNK_SIZE` in config to process data in batches
- **Slow Analysis**: Reduce `MAX_PARALLEL_AGENTS` if experiencing API rate limits
- **Memory Issues**: Process evidence files individually rather than all at once

## Security Reminders

⚠️ **Important Security Notes:**

- Never commit `.env` file to Git (already in `.gitignore`)
- Never share API keys publicly
- Keep evidence data secure and encrypted
- Follow data retention policies
- Maintain proper chain of custody

## What's Next?

You're now ready to:

✅ Collect forensic evidence  
✅ Run AI-powered analysis  
✅ Generate comprehensive reports  
✅ Maintain chain of custody  
✅ Investigate security incidents  

For advanced usage, see:
- `docs/ARCHITECTURE.md` - System design
- `docs/STRATEGIC_DISCUSSION.md` - Strategic considerations
- `tests/` - Code examples
- `src/` - Implementation details

Happy investigating! 🔍