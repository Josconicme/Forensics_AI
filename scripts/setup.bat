@echo off
REM Setup script for AI-Powered Digital Forensics System (Windows)

echo ==================================
echo Forensics AI - Setup Script
echo ==================================
echo.

REM Check Python version
echo Checking Python version...
python --version >nul 2>&1
if errorlevel 1 (
    echo Error: Python is not installed or not in PATH
    exit /b 1
)
echo Python detected
echo.

REM Create virtual environment
echo Creating virtual environment...
if exist venv (
    echo Virtual environment already exists
) else (
    python -m venv venv
    echo Virtual environment created
)
echo.

REM Activate virtual environment
echo Activating virtual environment...
call venv\Scripts\activate.bat
echo Virtual environment activated
echo.

REM Upgrade pip
echo Upgrading pip...
python -m pip install --upgrade pip -q
echo pip upgraded
echo.

REM Install dependencies
echo Installing dependencies...
pip install -r requirements.txt -q
echo Dependencies installed
echo.

REM Create necessary directories
echo Creating project directories...
if not exist mock_data mkdir mock_data
if not exist output mkdir output
if not exist logs mkdir logs
if not exist evidence_storage mkdir evidence_storage
if not exist data mkdir data
echo Directories created
echo.

REM Setup environment file
echo Setting up environment configuration...
if not exist .env (
    copy .env.example .env
    echo .env file created from template
    echo.
    echo WARNING: Please edit .env and add your API keys:
    echo    - ANTHROPIC_API_KEY or OPENAI_API_KEY
) else (
    echo .env file already exists
)
echo.

REM Generate mock data
echo Generating mock forensic data...
python scripts\generate_mock_data.py
echo Mock data generated
echo.

REM Run tests
echo Running tests to verify installation...
pytest tests\ -v --tb=short
echo Tests passed
echo.

echo ==================================
echo Setup Complete!
echo ==================================
echo.
echo Next steps:
echo 1. Edit .env and add your AI provider API key
echo 2. Run: venv\Scripts\activate.bat
echo 3. Run: python main.py
echo.
echo For more information, see README.md

pause