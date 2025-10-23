# src/agents/log_analysis_agent.py
"""
Log Analysis Agent - Analyzes system and application logs
"""
import json
import uuid
from datetime import datetime
from typing import List, Any
from collections import defaultdict

from agents.base_agent import BaseAgent
from models.finding import Finding, FindingType, Severity, MitreTactic


class LogAnalysisAgent(BaseAgent):
    """Analyzes logs for security events and anomalies"""
    
    def __init__(self, llm_client=None):
        super().__init__(
            agent_name="LogAnalysisAgent",
            agent_description="Analyzes system and application logs for security events",
            llm_client=llm_client
        )
        
        if not hasattr(self, 'findings'):
            self.findings = []
    
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
    
    def analyze(self, evidence_items: List[Any]) -> List[dict]:
        """Analyze log evidence"""
        self.clear_findings()
        
        if not evidence_items:
            return self.findings
        
        print(f"[{self.agent_name}] Analyzing {len(evidence_items)} evidence items...")
        
        for evidence in evidence_items:
            try:
                if evidence.evidence_type == "log":
                    self._analyze_single_log(evidence)
            except Exception as e:
                print(f"[{self.agent_name}] Error: {e}")
        
        print(f"[{self.agent_name}] Generated {len(self.findings)} findings.")
        return self.findings
    
    def _analyze_single_log(self, evidence: Any):
        """Analyze a single log file"""
        try:
            log_content = evidence.data.decode('utf-8', errors='ignore')
            log_lines = log_content.split('\n')
            
            self._detect_failed_logins(evidence, log_lines)
            
        except Exception as e:
            print(f"[{self.agent_name}] Error analyzing log: {e}")
    
    def _detect_failed_logins(self, evidence: Any, log_lines: List[str]):
        """Detect multiple failed login attempts"""
        failed_attempts = []
        
        for line in log_lines:
            line_lower = line.lower()
            if 'failed' in line_lower and ('login' in line_lower or 'auth' in line_lower):
                failed_attempts.append(line)
        
        if len(failed_attempts) > 5:
            finding = Finding(
                finding_id=str(uuid.uuid4()),
                type=FindingType.UNAUTHORIZED_ACCESS,
                severity=Severity.HIGH,
                title="Multiple Failed Login Attempts",
                description=f"Detected {len(failed_attempts)} failed login attempts.",
                evidence_ids=[evidence.evidence_id],
                timestamp=datetime.now(),
                confidence=0.85,
                agent_name=self.agent_name,
                mitre_tactics=[MitreTactic.CREDENTIAL_ACCESS],
                mitre_techniques=["T1110"],
                remediation=["Investigate failed login attempts", "Check for brute force attacks"],
                metadata={'total_failed': len(failed_attempts)}
            )
            self.add_finding(finding)