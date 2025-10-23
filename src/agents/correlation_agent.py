# src/agents/correlation_agent.py
"""Correlation agent for cross-evidence pattern detection"""
from typing import List
from datetime import datetime
from agents.base_agent import BaseAgent
from models.evidence import Evidence, Finding

class CorrelationAgent(BaseAgent):
    """Correlates findings across multiple evidence sources"""
    
    def __init__(self, api_key: str = None):
        super().__init__(api_key)
        self.agent_name = "CorrelationAgent"
    
    def correlate(self, all_evidence: List[Evidence], agent_findings: List[Finding]) -> List[Finding]:
        """Correlate findings across evidence"""
        findings = []
        
        print(f"[{self.agent_name}] Correlating {len(agent_findings)} findings...")
        
        # Check for attack chain patterns
        has_brute_force = any('brute force' in f.title.lower() for f in agent_findings)
        has_suspicious_account = any('account creation' in f.title.lower() for f in agent_findings)
        has_network_activity = any('connection' in f.title.lower() for f in agent_findings)
        
        if has_brute_force and has_suspicious_account:
            finding = Finding(
                finding_id=Finding.generate_id(),
                severity='critical',
                title='Attack Chain Detected: Compromise + Persistence',
                description='Brute force attack followed by suspicious account creation',
                evidence_ids=[e.evidence_id for e in all_evidence],
                timestamp=datetime.now(),
                confidence=0.95,
                indicators={'attack_stages': ['Initial Access', 'Persistence']},
                recommendations=[
                    'Initiate incident response',
                    'Isolate affected systems',
                    'Review all account activities'
                ]
            )
            findings.append(finding)
        
        if has_network_activity and (has_brute_force or has_suspicious_account):
            finding = Finding(
                finding_id=Finding.generate_id(),
                severity='critical',
                title='Data Exfiltration Suspected',
                description='Suspicious network activity after compromise',
                evidence_ids=[e.evidence_id for e in all_evidence],
                timestamp=datetime.now(),
                confidence=0.90,
                indicators={'attack_stages': ['Exfiltration']},
                recommendations=[
                    'Immediate containment required',
                    'Identify exfiltrated data',
                    'Notify legal and compliance'
                ]
            )
            findings.append(finding)
        
        return findings
    
    def analyze(self, evidence_list: List[Evidence]) -> List[Finding]:
        """Required by BaseAgent interface"""
        return []
