# src/analysis/analysis_engine.py
"""
Main analysis engine coordinating all AI agents
"""
from typing import List, Dict, Any
from datetime import datetime

from src.agents.file_analysis_agent import FileAnalysisAgent
from src.agents.log_analysis_agent import LogAnalysisAgent
from src.agents.network_analysis_agent import NetworkAnalysisAgent
from src.agents.correlation_agent import CorrelationAgent
from src.models.evidence import Evidence, Finding
from src.storage.evidence_store import EvidenceStore


class AnalysisEngine:
    """Orchestrates multi-agent evidence analysis"""
    
    def __init__(self, evidence_store: EvidenceStore, api_key: str = None):
        self.evidence_store = evidence_store
        
        # Initialize specialized agents
        self.file_agent = FileAnalysisAgent(api_key=api_key)
        self.log_agent = LogAnalysisAgent(api_key=api_key)
        self.network_agent = NetworkAnalysisAgent(api_key=api_key)
        self.correlation_agent = CorrelationAgent(api_key=api_key)
        
        self.findings: List[Finding] = []
    
    def analyze_all_evidence(self) -> List[Finding]:
        """
        Run comprehensive analysis on all stored evidence
        Returns list of findings
        """
        print("[AnalysisEngine] Starting comprehensive analysis...")
        
        # Get all evidence from store
        all_evidence = self.evidence_store.get_all_evidence()
        
        if not all_evidence:
            print("[AnalysisEngine] No evidence found to analyze")
            return []
        
        print(f"[AnalysisEngine] Analyzing {len(all_evidence)} evidence items...")
        
        # Separate evidence by type
        evidence_by_type = {
            'file': [],
            'log': [],
            'network': []
        }
        
        for evidence in all_evidence:
            if evidence.evidence_type in evidence_by_type:
                evidence_by_type[evidence.evidence_type].append(evidence)
        
        # Run specialized agents
        agent_findings = []
        
        # File analysis
        if evidence_by_type['file']:
            print(f"[AnalysisEngine] Running file analysis on {len(evidence_by_type['file'])} files...")
            file_findings = self.file_agent.analyze(evidence_by_type['file'])
            agent_findings.extend(file_findings)
            print(f"  → Found {len(file_findings)} file-related findings")
        
        # Log analysis
        if evidence_by_type['log']:
            print(f"[AnalysisEngine] Running log analysis on {len(evidence_by_type['log'])} logs...")
            log_findings = self.log_agent.analyze(evidence_by_type['log'])
            agent_findings.extend(log_findings)
            print(f"  → Found {len(log_findings)} log-related findings")
        
        # Network analysis
        if evidence_by_type['network']:
            print(f"[AnalysisEngine] Running network analysis on {len(evidence_by_type['network'])} captures...")
            network_findings = self.network_agent.analyze(evidence_by_type['network'])
            agent_findings.extend(network_findings)
            print(f"  → Found {len(network_findings)} network-related findings")
        
        # Correlation analysis
        print("[AnalysisEngine] Running correlation analysis...")
        correlated_findings = self.correlation_agent.correlate(
            all_evidence=all_evidence,
            agent_findings=agent_findings
        )
        print(f"  → Found {len(correlated_findings)} correlated patterns")
        
        # Combine all findings
        self.findings = agent_findings + correlated_findings
        
        # Sort by severity and confidence
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        self.findings.sort(
            key=lambda f: (severity_order.get(f.severity, 5), -f.confidence)
        )
        
        print(f"[AnalysisEngine] Analysis complete. Total findings: {len(self.findings)}")
        return self.findings
    
    def get_timeline(self) -> List[Dict[str, Any]]:
        """Generate incident timeline from evidence and findings"""
        timeline = []
        
        # Add evidence collection events
        all_evidence = self.evidence_store.get_all_evidence()
        for evidence in all_evidence:
            timeline.append({
                'timestamp': evidence.collected_timestamp,
                'event_type': 'evidence_collected',
                'description': f"Collected {evidence.evidence_type} evidence from {evidence.source_path}",
                'evidence_id': evidence.evidence_id
            })
        
        # Add finding events
        for finding in self.findings:
            timeline.append({
                'timestamp': finding.timestamp,
                'event_type': 'finding',
                'severity': finding.severity,
                'description': finding.title,
                'finding_id': finding.finding_id
            })
        
        # Sort by timestamp
        timeline.sort(key=lambda x: x['timestamp'])
        
        return timeline
    
    def get_summary_statistics(self) -> Dict[str, Any]:
        """Get summary statistics of analysis results"""
        if not self.findings:
            return {}
        
        severity_counts = {}
        for finding in self.findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
        
        avg_confidence = sum(f.confidence for f in self.findings) / len(self.findings)
        
        evidence_summary = self.evidence_store.get_evidence_summary()
        
        return {
            'total_findings': len(self.findings),
            'findings_by_severity': severity_counts,
            'average_confidence': round(avg_confidence, 2),
            'evidence_analyzed': evidence_summary.get('total_evidence', 0),
            'high_severity_count': severity_counts.get('critical', 0) + severity_counts.get('high', 0)
        }
    
    def get_findings_by_severity(self, severity: str) -> List[Finding]:
        """Get all findings of a specific severity level"""
        return [f for f in self.findings if f.severity == severity]
    
    def get_findings_for_evidence(self, evidence_id: str) -> List[Finding]:
        """Get all findings related to a specific piece of evidence"""
        return [f for f in self.findings if evidence_id in f.evidence_ids]