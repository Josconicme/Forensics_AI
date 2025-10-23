# src/agents/base_agent.py
"""
Base agent interface for AI-powered analysis
"""
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional

try:
    from anthropic import Anthropic
except ImportError:
    Anthropic = None

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None

# Use absolute imports (no relative imports)
from models.evidence import Evidence, Finding
from config import config


class BaseAgent(ABC):
    """Abstract base class for analysis agents"""
    
    def __init__(self, agent_name: str = None, agent_description: str = None, llm_client=None):
        """
        Initialize agent with API credentials
        
        Args:
            agent_name: Name of the agent
            agent_description: Description of agent's purpose
            llm_client: Pre-configured LLM client (Anthropic or OpenAI)
        """
        self.agent_name = agent_name or self.__class__.__name__
        self.agent_description = agent_description or "AI-powered analysis agent"
        self.findings = []
        
        # Use provided client or create based on configuration
        if llm_client:
            self.llm_client = llm_client
            self.client = llm_client  # Backwards compatibility
        else:
            self.llm_client = self._initialize_llm_client()
            self.client = self.llm_client
        
        # Determine provider type
        self.ai_provider = config.AI_PROVIDER
    
    def _initialize_llm_client(self):
        """Initialize LLM client based on configuration"""
        if config.AI_PROVIDER == 'openai':
            if not OpenAI:
                print(f"[{self.agent_name}] Error: openai package not installed. Run: pip install openai")
                return None
            if config.OPENAI_API_KEY:
                return OpenAI(api_key=config.OPENAI_API_KEY)
            else:
                print(f"[{self.agent_name}] Warning: No OpenAI API key provided")
                return None
        elif config.AI_PROVIDER == 'anthropic':
            if not Anthropic:
                print(f"[{self.agent_name}] Error: anthropic package not installed. Run: pip install anthropic")
                return None
            if config.ANTHROPIC_API_KEY:
                return Anthropic(api_key=config.ANTHROPIC_API_KEY)
            else:
                print(f"[{self.agent_name}] Warning: No Anthropic API key provided")
                return None
        else:
            print(f"[{self.agent_name}] Warning: Unknown AI provider: {config.AI_PROVIDER}")
            return None
    
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
    
    def _query_llm(self, prompt: str, system_prompt: str = None, max_tokens: int = 4096) -> str:
        """
        Query LLM (OpenAI or Anthropic) for analysis
        
        Args:
            prompt: User prompt
            system_prompt: Optional system prompt
            max_tokens: Maximum tokens in response
        
        Returns:
            Response text from LLM
        """
        if not self.llm_client:
            return "AI analysis unavailable - no API key configured"
        
        try:
            if self.ai_provider == 'openai':
                return self._query_openai(prompt, system_prompt, max_tokens)
            elif self.ai_provider == 'anthropic':
                return self._query_anthropic(prompt, system_prompt, max_tokens)
            else:
                return f"Unknown AI provider: {self.ai_provider}"
        
        except Exception as e:
            print(f"[{self.agent_name}] Error calling LLM API: {e}")
            return f"Error during AI analysis: {str(e)}"
    
    def _query_openai(self, prompt: str, system_prompt: str = None, max_tokens: int = 4096) -> str:
        """Query OpenAI GPT API"""
        if not OpenAI:
            return "OpenAI package not installed"
        
        messages = []
        
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        
        messages.append({"role": "user", "content": prompt})
        
        response = self.llm_client.chat.completions.create(
            model=config.OPENAI_MODEL,
            messages=messages,
            max_tokens=max_tokens,
            temperature=0.7
        )
        
        return response.choices[0].message.content
    
    def _query_anthropic(self, prompt: str, system_prompt: str = None, max_tokens: int = 4096) -> str:
        """Query Anthropic Claude API"""
        if not Anthropic:
            return "Anthropic package not installed"
        
        messages = [{"role": "user", "content": prompt}]
        
        kwargs = {
            "model": config.ANTHROPIC_MODEL,
            "max_tokens": max_tokens,
            "messages": messages
        }
        
        if system_prompt:
            kwargs["system"] = system_prompt
        
        response = self.llm_client.messages.create(**kwargs)
        return response.content[0].text
    
    # Backwards compatibility alias
    def _call_claude(self, prompt: str, system_prompt: str = None) -> str:
        """
        Legacy method name - redirects to _query_llm
        
        Args:
            prompt: User prompt
            system_prompt: Optional system prompt
        
        Returns:
            Response text from LLM
        """
        return self._query_llm(prompt, system_prompt)
    
    def add_finding(self, finding: Finding):
        """Add a finding to the agent's findings list"""
        if not hasattr(self, 'findings'):
            self.findings = []
        self.findings.append(finding.to_dict())
    
    def clear_findings(self):
        """Clear all findings"""
        if not hasattr(self, 'findings'):
            self.findings = []
        else:
            self.findings.clear()
    
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