# src/analysis/analysis_engine.py
"""
Main analysis engine coordinating all AI agents
"""
from typing import List, Dict, Any
from datetime import datetime

from agents.file_analysis_agent import FileAnalysisAgent
from agents.log_analysis_agent import LogAnalysisAgent
from agents.network_analysis_agent import NetworkAnalysisAgent
from agents.correlation_agent import CorrelationAgent
from models.evidence import Evidence
from storage.evidence_store import EvidenceStore


class AnalysisEngine:
    """Orchestrates multi-agent evidence analysis"""
    
    def __init__(self, evidence_store: EvidenceStore, api_key: str = None):
        self.evidence_store = evidence_store
        
        # Create LLM client if API key provided
        llm_client = None
        if api_key:
            from anthropic import Anthropic
            llm_client = Anthropic(api_key=api_key)
        
        # Initialize specialized agents
        self.file_agent = FileAnalysisAgent(llm_client=llm_client)
        self.log_agent = LogAnalysisAgent(llm_client=llm_client)
        self.network_agent = NetworkAnalysisAgent(llm_client=llm_client)
        self.correlation_agent = CorrelationAgent(llm_client=llm_client)
        
        self.findings: List[Dict[str, Any]] = []
    
    def analyze_all_evidence(self) -> List[Dict[str, Any]]:
        """
        Run comprehensive analysis on all stored evidence
        Returns list of findings as dictionaries
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
        
        # Run specialized agents - all return List[dict]
        agent_findings = []
        
        # File analysis
        if evidence_by_type['file']:
            print(f"[AnalysisEngine] Running file analysis on {len(evidence_by_type['file'])} files...")
            file_findings = self.file_agent.analyze(evidence_by_type['file'])
            agent_findings.extend(file_findings)
            print(f"  -> Found {len(file_findings)} file-related findings")
        
        # Log analysis
        if evidence_by_type['log']:
            print(f"[AnalysisEngine] Running log analysis on {len(evidence_by_type['log'])} logs...")
            log_findings = self.log_agent.analyze(evidence_by_type['log'])
            agent_findings.extend(log_findings)
            print(f"  -> Found {len(log_findings)} log-related findings")
        
        # Network analysis
        if evidence_by_type['network']:
            print(f"[AnalysisEngine] Running network analysis on {len(evidence_by_type['network'])} captures...")
            network_findings = self.network_agent.analyze(evidence_by_type['network'])
            agent_findings.extend(network_findings)
            print(f"  -> Found {len(network_findings)} network-related findings")
        
        # Correlation analysis - also returns List[dict]
        if len(agent_findings) >= 2:
            print("[AnalysisEngine] Running correlation analysis...")
            correlated_findings = self.correlation_agent.analyze(agent_findings, all_evidence)
            print(f"  -> Found {len(correlated_findings)} correlated patterns")
            
            # Combine all findings
            self.findings = agent_findings + correlated_findings
        else:
            print("[AnalysisEngine] Skipping correlation (need at least 2 findings)")
            self.findings = agent_findings
        
        # Sort by severity and confidence
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        self.findings.sort(
            key=lambda f: (
                severity_order.get(f.get('severity', 'info').lower(), 5), 
                -f.get('confidence', 0)
            )
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
            timestamp = finding.get('timestamp')
            if isinstance(timestamp, str):
                timestamp = datetime.fromisoformat(timestamp)
            elif not isinstance(timestamp, datetime):
                timestamp = datetime.now()
            
            timeline.append({
                'timestamp': timestamp,
                'event_type': 'finding',
                'severity': finding.get('severity', 'unknown'),
                'description': finding.get('title', 'Unknown Finding'),
                'finding_id': finding.get('finding_id')
            })
        
        # Sort by timestamp
        timeline.sort(key=lambda x: x['timestamp'])
        
        return timeline
    
    def get_summary_statistics(self) -> Dict[str, Any]:
        """Get summary statistics of analysis results"""
        if not self.findings:
            return {
                'total_findings': 0,
                'findings_by_severity': {},
                'average_confidence': 0,
                'evidence_analyzed': 0,
                'high_severity_count': 0
            }
        
        severity_counts = {}
        for finding in self.findings:
            severity = finding.get('severity', 'unknown').lower()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        confidences = [f.get('confidence', 0) for f in self.findings]
        avg_confidence = sum(confidences) / len(confidences) if confidences else 0
        
        evidence_summary = self.evidence_store.get_evidence_summary()
        
        return {
            'total_findings': len(self.findings),
            'findings_by_severity': severity_counts,
            'average_confidence': round(avg_confidence, 2),
            'evidence_analyzed': evidence_summary.get('total_evidence', 0),
            'high_severity_count': severity_counts.get('critical', 0) + severity_counts.get('high', 0)
        }
    
    def get_findings_by_severity(self, severity: str) -> List[Dict[str, Any]]:
        """Get all findings of a specific severity level"""
        return [f for f in self.findings if f.get('severity', '').lower() == severity.lower()]
    
    def get_findings_for_evidence(self, evidence_id: str) -> List[Dict[str, Any]]:
        """Get all findings related to a specific piece of evidence"""
        return [f for f in self.findings if evidence_id in f.get('evidence_ids', [])]
    
    def get_high_priority_findings(self) -> List[Dict[str, Any]]:
        """Get critical and high severity findings"""
        return [
            f for f in self.findings 
            if f.get('severity', '').lower() in ['critical', 'high']
        ]
    
    def get_mitre_attack_coverage(self) -> Dict[str, List[str]]:
        """Get MITRE ATT&CK technique coverage from findings"""
        technique_map = {}
        
        for finding in self.findings:
            techniques = finding.get('mitre_techniques', [])
            for technique in techniques:
                if technique not in technique_map:
                    technique_map[technique] = []
                technique_map[technique].append(finding.get('title', 'Unknown'))
        
        return technique_map