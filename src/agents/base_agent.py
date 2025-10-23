# src/agents/base_agent.py
"""
Base agent interface for AI-powered analysis
"""
from abc import ABC, abstractmethod
from typing import List, Dict, Any
from anthropic import Anthropic
from models.evidence import Evidence, Finding
from config import Config


class BaseAgent(ABC):
    """Abstract base class for analysis agents"""
    
    def __init__(self, api_key: str = None):
        """
        Initialize agent with API credentials
        
        Args:
            api_key: Anthropic API key (optional, will use config if not provided)
        """
        if api_key:
            self.api_key = api_key
        else:
            config = Config()
            self.api_key = config.ANTHROPIC_API_KEY
        
        # Initialize Anthropic client if API key is available
        if self.api_key:
            self.client = Anthropic(api_key=self.api_key)
        else:
            self.client = None
            print("[BaseAgent] Warning: No API key provided, AI analysis will be limited")
    
    @abstractmethod
    def analyze(self, evidence_list: List[Evidence]) -> List[Finding]:
        """
        Analyze evidence and generate findings
        
        Args:
            evidence_list: List of evidence items to analyze
        
        Returns:
            List of findings from analysis
        """
        pass
    
    def _call_claude(self, prompt: str, system_prompt: str = None) -> str:
        """
        Call Claude API for analysis
        
        Args:
            prompt: User prompt
            system_prompt: Optional system prompt
        
        Returns:
            Response text from Claude
        """
        if not self.client:
            return "AI analysis unavailable - no API key configured"
        
        try:
            messages = [{"role": "user", "content": prompt}]
            
            kwargs = {
                "model": "claude-sonnet-4-5-20250929",
                "max_tokens": 4096,
                "messages": messages
            }
            
            if system_prompt:
                kwargs["system"] = system_prompt
            
            response = self.client.messages.create(**kwargs)
            return response.content[0].text
        
        except Exception as e:
            print(f"[BaseAgent] Error calling Claude API: {e}")
            return f"Error during AI analysis: {str(e)}"
    
    def _parse_severity(self, text: str) -> str:
        """
        Extract severity level from text
        
        Returns:
            Severity level: 'critical', 'high', 'medium', 'low', or 'info'
        """
        text_lower = text.lower()
        
        if 'critical' in text_lower:
            return 'critical'
        elif 'high' in text_lower:
            return 'high'
        elif 'medium' in text_lower:
            return 'medium'
        elif 'low' in text_lower:
            return 'low'
        else:
            return 'info'
    
    def _parse_confidence(self, text: str) -> float:
        """
        Extract confidence score from text
        
        Returns:
            Confidence value between 0.0 and 1.0
        """
        text_lower = text.lower()
        
        # Look for percentage patterns
        import re
        percentage_match = re.search(r'(\d+)%', text)
        if percentage_match:
            return float(percentage_match.group(1)) / 100.0
        
        # Look for keywords
        if 'very high' in text_lower or 'certain' in text_lower:
            return 0.95
        elif 'high confidence' in text_lower:
            return 0.85
        elif 'moderate' in text_lower or 'medium' in text_lower:
            return 0.70
        elif 'low' in text_lower:
            return 0.50
        else:
            return 0.75  # Default confidence