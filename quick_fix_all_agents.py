# quick_fix_all_agents.py
"""
Automatically create all agent files with correct structure
Run this to fix all agent issues at once
"""
from pathlib import Path

# Network Analysis Agent
network_agent = '''# src/agents/network_analysis_agent.py
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
'''

# Correlation Agent
correlation_agent = '''# src/agents/correlation_agent.py
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
'''

def main():
    print("Creating/Fixing all agent files...")
    
    agents_dir = Path('src/agents')
    agents_dir.mkdir(parents=True, exist_ok=True)
    
    # Create network agent
    network_path = agents_dir / 'network_analysis_agent.py'
    network_path.write_text(network_agent, encoding='utf-8')
    print(f"✓ Created {network_path}")
    
    # Create correlation agent
    correlation_path = agents_dir / 'correlation_agent.py'
    correlation_path.write_text(correlation_agent, encoding='utf-8')
    print(f"✓ Created {correlation_path}")
    
    print("\n✓ All agent files created successfully!")
    print("Now run: python main.py")

if __name__ == "__main__":
    main()