#!/bin/bash
# Setup script for AI-Powered Digital Forensics System

set -e  # Exit on error

echo "=================================="
echo "Forensics AI - Setup Script"
echo "=================================="
echo ""

# Check Python version
echo "Checking Python version..."
python_version=$(python3 --version 2>&1 | grep -oP '\d+\.\d+')
required_version="3.9"

if (( $(echo "$python_version < $required_version" | bc -l) )); then
    echo "Error: Python 3.9+ is required. Found Python $python_version"
    exit 1
fi
echo "✓ Python $python_version detected"
echo ""

# Create virtual environment
echo "Creating virtual environment..."
if [ -d "venv" ]; then
    echo "Virtual environment already exists"
else
    python3 -m venv venv
    echo "✓ Virtual environment created"
fi
echo ""

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate
echo "✓ Virtual environment activated"
echo ""

# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip -q
echo "✓ pip upgraded"
echo ""

# Install dependencies
echo "Installing dependencies..."
pip install -r requirements.txt -q
echo "✓ Dependencies installed"
echo ""

# Create necessary directories
echo "Creating project directories..."
mkdir -p mock_data
mkdir -p output
mkdir -p logs
mkdir -p evidence_storage
mkdir -p data
echo "✓ Directories created"
echo ""

# Setup environment file
echo "Setting up environment configuration..."
if [ ! -f ".env" ]; then
    cp .env.example .env
    echo "✓ .env file created from template"
    echo ""
    echo "⚠️  IMPORTANT: Please edit .env and add your API keys:"
    echo "   - ANTHROPIC_API_KEY or OPENAI_API_KEY"
else
    echo "✓ .env file already exists"
fi
echo ""

# Generate mock data
echo "Generating mock forensic data..."
python scripts/generate_mock_data.py
echo "✓ Mock data generated"
echo ""

# Run tests
echo "Running tests to verify installation..."
pytest tests/ -v --tb=short
echo "✓ Tests passed"
echo ""

echo "=================================="
echo "Setup Complete!"
echo "=================================="
echo ""
echo "Next steps:"
echo "1. Edit .env and add your AI provider API key"
echo "2. Run: source venv/bin/activate"
echo "3. Run: python main.py"
echo ""
echo "For more information, see README.md"