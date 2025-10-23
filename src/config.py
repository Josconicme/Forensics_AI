# src/config.py
"""
Configuration management for forensics system
"""
import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


class ForensicsConfig:
    """Configuration settings for the forensics system"""
    
    def __init__(self):
        # AI Provider Configuration
        self.AI_PROVIDER = os.getenv('AI_PROVIDER', 'openai').lower()
        
        # Anthropic Configuration
        self.ANTHROPIC_API_KEY = os.getenv('ANTHROPIC_API_KEY', '')
        self.ANTHROPIC_MODEL = os.getenv('CLAUDE_MODEL', 'claude-sonnet-4-20250514')
        
        # OpenAI Configuration
        self.OPENAI_API_KEY = os.getenv('OPENAI_API_KEY', '')
        self.OPENAI_MODEL = os.getenv('OPENAI_MODEL', 'gpt-4o')
        
        # Collector Configuration
        self.COLLECTOR_NAME = os.getenv('COLLECTOR_NAME', 'ForensicsCollector')
        
        # Database Configuration
        self.DB_PATH = os.getenv('DB_PATH', './output/evidence_db/forensics.db')
        
        # Chain of Custody Configuration
        self.CUSTODY_LOG_PATH = os.getenv('CUSTODY_LOG_PATH', './output/custody/chain_of_custody.log')
        
        # Report Configuration
        self.REPORT_OUTPUT_DIR = os.getenv('REPORT_OUTPUT_DIR', './output/reports')
        
        # Analysis Configuration
        self.ENABLE_AI_ANALYSIS = os.getenv('ENABLE_AI_ANALYSIS', 'true').lower() == 'true'
        
        # Logging Configuration
        self.LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    
    def validate(self):
        """Validate configuration and create necessary directories"""
        if self.AI_PROVIDER == 'openai':
            if not self.OPENAI_API_KEY:
                print("⚠️  WARNING: OPENAI_API_KEY not set in .env file")
                print("   AI-powered analysis will be limited or may fail")
                print("   Please add your API key to the .env file")
        elif self.AI_PROVIDER == 'anthropic':
            if not self.ANTHROPIC_API_KEY:
                print("⚠️  WARNING: ANTHROPIC_API_KEY not set in .env file")
                print("   AI-powered analysis will be limited or may fail")
                print("   Please add your API key to the .env file")
        else:
            print(f"⚠️  WARNING: Unknown AI_PROVIDER: {self.AI_PROVIDER}")
            print("   Valid options are: 'openai' or 'anthropic'")
        
        # Create directories if they don't exist
        Path(self.DB_PATH).parent.mkdir(parents=True, exist_ok=True)
        Path(self.CUSTODY_LOG_PATH).parent.mkdir(parents=True, exist_ok=True)
        Path(self.REPORT_OUTPUT_DIR).mkdir(parents=True, exist_ok=True)
    
    def display(self):
        """Display current configuration"""
        print("\n" + "=" * 70)
        print("CONFIGURATION")
        print("=" * 70)
        print(f"AI Provider: {self.AI_PROVIDER.upper()}")
        
        if self.AI_PROVIDER == 'openai':
            print(f"API Key Set: {'Yes' if self.OPENAI_API_KEY else 'No'}")
            print(f"Model: {self.OPENAI_MODEL}")
        elif self.AI_PROVIDER == 'anthropic':
            print(f"API Key Set: {'Yes' if self.ANTHROPIC_API_KEY else 'No'}")
            print(f"Model: {self.ANTHROPIC_MODEL}")
        
        print(f"Collector Name: {self.COLLECTOR_NAME}")
        print(f"Database Path: {self.DB_PATH}")
        print(f"Custody Log: {self.CUSTODY_LOG_PATH}")
        print(f"Report Output: {self.REPORT_OUTPUT_DIR}")
        print(f"AI Analysis: {'Enabled' if self.ENABLE_AI_ANALYSIS else 'Disabled'}")
        print("=" * 70 + "\n")


# Alias for backwards compatibility
Config = ForensicsConfig

# Global config instance
config = ForensicsConfig()