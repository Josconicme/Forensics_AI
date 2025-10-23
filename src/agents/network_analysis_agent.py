# src/agents/network_analysis_agent.py
"""Network analysis agent for examining network traffic"""
from typing import List
from datetime import datetime
from agents.base_agent import BaseAgent
from models.evidence import Evidence, Finding

class NetworkAnalysisAgent(BaseAgent):
    """Analyzes network traffic for suspicious patterns"""
    
    def __init__(self, api_key: str = None):
        super().__init__(api_key)
        self.agent_name = "NetworkAnalysisAgent"
    
    def analyze(self, evidence_list: List[Evidence]) -> List[Finding]:
        findings = []
        print(f"[{self.agent_name}] Analyzing {len(evidence_list)} network capture(s)...")
        
        for evidence in evidence_list:
            try:
                content = evidence.data.decode('utf-8', errors='ignore')
                
                # Check for suspicious IPs
                suspicious_ips = ['203.0.113.45', '198.51.100.78']
                for sus_ip in suspicious_ips:
                    if sus_ip in content:
                        finding = Finding(
                            finding_id=Finding.generate_id(),
                            severity='high',
                            title=f'Suspicious External Connection to {sus_ip}',
                            description=f'Connection to known malicious IP detected',
                            evidence_ids=[evidence.evidence_id],
                            timestamp=datetime.now(),
                            confidence=0.90,
                            indicators={'malicious_ip': sus_ip},
                            recommendations=['Block IP at firewall', 'Investigate source host']
                        )
                        findings.append(finding)
            except Exception as e:
                print(f"[{self.agent_name}] Error: {e}")
        
        return findings
