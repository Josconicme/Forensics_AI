"""
Configuration management for the AI Forensics System
"""
import os
from pathlib import Path
from typing import Optional
from pydantic import BaseModel, Field
from dotenv import load_dotenv

load_dotenv()

class Config(BaseModel):
    """System configuration"""
    
    # API Keys
    ANTHROPIC_API_KEY: Optional[str] = Field(default_factory=lambda: os.getenv("ANTHROPIC_API_KEY"))
    OPENAI_API_KEY: Optional[str] = Field(default_factory=lambda: os.getenv("OPENAI_API_KEY"))
    
    # LLM Settings
    LLM_MODEL: str = Field(default="claude-3-5-sonnet-20241022")
    LLM_TEMPERATURE: float = Field(default=0.0)
    LLM_MAX_TOKENS: int = Field(default=4096)
    
    # Paths
    BASE_DIR: Path = Field(default_factory=lambda: Path(__file__).parent.parent)
    MOCK_DATA_DIR: Path = Field(default_factory=lambda: Path(__file__).parent.parent / "mock_data")
    OUTPUT_DIR: Path = Field(default_factory=lambda: Path(__file__).parent.parent / "output")
    EVIDENCE_DIR: Path = Field(default_factory=lambda: Path(__file__).parent.parent / "output" / "evidence")
    REPORTS_DIR: Path = Field(default_factory=lambda: Path(__file__).parent.parent / "output" / "reports")
    
    # Chain of Custody
    ENABLE_BLOCKCHAIN_CUSTODY: bool = Field(default=True)
    HASH_ALGORITHM: str = Field(default="sha256")
    
    # Analysis Settings
    ANOMALY_THRESHOLD: float = Field(default=0.75)
    CONFIDENCE_THRESHOLD: float = Field(default=0.7)
    MAX_CONCURRENT_AGENTS: int = Field(default=5)
    
    # Security
    ENABLE_ENCRYPTION: bool = Field(default=True)
    PII_MASKING: bool = Field(default=True)
    
    # Logging
    LOG_LEVEL: str = Field(default="INFO")
    LOG_FILE: str = Field(default="forensics.log")
    
    class Config:
        env_file = ".env"
        case_sensitive = True
    
    def create_directories(self):
        """Create necessary directories if they don't exist"""
        for dir_path in [self.OUTPUT_DIR, self.EVIDENCE_DIR, self.REPORTS_DIR, self.MOCK_DATA_DIR]:
            dir_path.mkdir(parents=True, exist_ok=True)

# Global config instance
config = Config()
config.create_directories()