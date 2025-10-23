# src/agents/network_analysis_agent.py
"""
Network Analysis Agent - Analyzes network traffic and connections
"""
import json
import uuid
from datetime import datetime
from typing import List, Any
from collections import defaultdict

from agents.base_agent import BaseAgent
from models.finding import Finding, FindingType, Severity, MitreTactic


class NetworkAnalysisAgent(BaseAgent):
    """Analyzes network traffic for suspicious patterns"""
    
    def __init__(self, llm_client=None):
        super().__init__(
            agent_name="NetworkAnalysisAgent",
            agent_description="Analyzes network traffic and connection patterns",
            llm_client=llm_client
        )
        
        if not hasattr(self, 'findings'):
            self.findings = []
        
        self.suspicious_ports = [4444, 4445, 1337, 31337]
    
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
        """Analyze network evidence"""
        self.clear_findings()
        
        if not evidence_items:
            return self.findings
        
        print(f"[{self.agent_name}] Analyzing {len(evidence_items)} evidence items...")
        
        for evidence in evidence_items:
            try:
                if evidence.evidence_type == "network":
                    self._analyze_network_data(evidence)
            except Exception as e:
                print(f"[{self.agent_name}] Error: {e}")
        
        print(f"[{self.agent_name}] Generated {len(self.findings)} findings.")
        return self.findings
    
    def _analyze_network_data(self, evidence: Any):
        """Analyze network traffic data"""
        try:
            content = evidence.data.decode('utf-8', errors='ignore')
            
            if ',' in content:
                self._analyze_csv_network_data(evidence, content)
            
        except Exception as e:
            print(f"[{self.agent_name}] Error analyzing network data: {e}")
    
    def _analyze_csv_network_data(self, evidence: Any, content: str):
        """Analyze CSV network data"""
        lines = content.split('\n')
        connections = []
        
        for line in lines[1:]:
            if line.strip():
                parts = line.split(',')
                if len(parts) >= 3:
                    connections.append({
                        'source_ip': parts[0].strip(),
                        'dest_ip': parts[1].strip(),
                        'dest_port': parts[2].strip()
                    })
        
        if len(connections) > 10:
            finding = Finding(
                finding_id=str(uuid.uuid4()),
                type=FindingType.NETWORK_ANOMALY,
                severity=Severity.MEDIUM,
                title="Network Connections Detected",
                description=f"Analyzed {len(connections)} network connections.",
                evidence_ids=[evidence.evidence_id],
                timestamp=datetime.now(),
                confidence=0.70,
                agent_name=self.agent_name,
                mitre_tactics=[MitreTactic.DISCOVERY],
                mitre_techniques=["T1046"],
                remediation=["Review network connections for anomalies"],
                metadata={'total_connections': len(connections)}
            )
            self.add_finding(finding)