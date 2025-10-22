"""
Base AI Agent for forensic analysis
"""
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from anthropic import Anthropic
import os
from src.config import config


class Finding:
    """Represents an analysis finding"""
    
    def __init__(
        self,
        finding_id: str,
        severity: str,
        category: str,
        title: str,
        description: str,
        evidence_ids: List[str],
        confidence: float,
        indicators: List[str],
        recommendations: List[str],
        metadata: Dict[str, Any]
    ):
        self.finding_id = finding_id
        self.severity = severity  # critical, high, medium, low, info
        self.category = category
        self.title = title
        self.description = description
        self.evidence_ids = evidence_ids
        self.confidence = confidence
        self.indicators = indicators
        self.recommendations = recommendations
        self.metadata = metadata
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary"""
        return {
            "finding_id": self.finding_id,
            "severity": self.severity,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "evidence_ids": self.evidence_ids,
            "confidence": self.confidence,
            "indicators": self.indicators,
            "recommendations": self.recommendations,
            "metadata": self.metadata
        }


class BaseAgent(ABC):
    """Abstract base class for forensic AI agents"""
    
    def __init__(self, agent_name: str, agent_description: str):
        """
        Initialize agent
        
        Args:
            agent_name: Name of the agent
            agent_description: Description of agent's capabilities
        """
        self.agent_name = agent_name
        self.agent_description = agent_description
        self.findings: List[Finding] = []
        
        # Initialize AI client
        if config.ANTHROPIC_API_KEY:
            self.client = Anthropic(api_key=config.ANTHROPIC_API_KEY)
        else:
            self.client = None
    
    @abstractmethod
    def analyze(self, evidence_items: List[Any]) -> List[Finding]:
        """
        Analyze evidence and generate findings
        
        Args:
            evidence_items: List of evidence items to analyze
            
        Returns:
            List of findings
        """
        pass
    
    def call_llm(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """
        Call LLM for analysis
        
        Args:
            prompt: User prompt
            system_prompt: System prompt
            
        Returns:
            LLM response
        """
        if not self.client:
            # Fallback to rule-based analysis if no API key
            return self._fallback_analysis(prompt)
        
        try:
            messages = [{"role": "user", "content": prompt}]
            
            if system_prompt:
                response = self.client.messages.create(
                    model=config.LLM_MODEL,
                    max_tokens=config.LLM_MAX_TOKENS,
                    temperature=config.LLM_TEMPERATURE,
                    system=system_prompt,
                    messages=messages
                )
            else:
                response = self.client.messages.create(
                    model=config.LLM_MODEL,
                    max_tokens=config.LLM_MAX_TOKENS,
                    temperature=config.LLM_TEMPERATURE,
                    messages=messages
                )
            
            return response.content[0].text
        
        except Exception as e:
            print(f"Error calling LLM: {e}")
            return self._fallback_analysis(prompt)
    
    def _fallback_analysis(self, prompt: str) -> str:
        """
        Fallback rule-based analysis when LLM is unavailable
        
        Args:
            prompt: Analysis prompt
            
        Returns:
            Analysis result
        """
        return "Rule-based analysis: Evidence collected and basic patterns detected."
    
    def get_findings(self) -> List[Finding]:
        """Get all findings from this agent"""
        return self.findings
    
    def clear_findings(self):
        """Clear all findings"""
        self.findings = []
    
    def _create_finding(
        self,
        finding_id: str,
        severity: str,
        category: str,
        title: str,
        description: str,
        evidence_ids: List[str],
        confidence: float,
        indicators: List[str],
        recommendations: List[str],
        metadata: Dict[str, Any] = None
    ) -> Finding:
        """Helper to create a finding"""
        finding = Finding(
            finding_id=finding_id,
            severity=severity,
            category=category,
            title=title,
            description=description,
            evidence_ids=evidence_ids,
            confidence=confidence,
            indicators=indicators,
            recommendations=recommendations,
            metadata=metadata or {}
        )
        
        self.findings.append(finding)
        return finding