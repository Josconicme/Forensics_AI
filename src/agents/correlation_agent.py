# src/agents/correlation_agent.py
"""
Correlation Agent - Correlates findings across multiple data sources
"""
import uuid
from datetime import datetime, timedelta
from typing import List, Dict, Any
from collections import defaultdict
from .base_agent import BaseAgent, Finding


class CorrelationAgent(BaseAgent):
    """Correlates findings from multiple agents to identify attack patterns"""
    
    def __init__(self, llm_client=None):
        super().__init__(
            agent_name="CorrelationAgent",
            agent_description="Correlates findings across multiple evidence sources to identify complex attack patterns",
            llm_client=llm_client
        )
    
    def analyze(self, all_findings: List[Finding], evidence_items: List[Any]) -> List[Finding]:
        """
        Correlate findings from multiple agents
        
        Args:
            all_findings: List of all findings from other agents
            evidence_items: List of all evidence items
            
        Returns:
            List of correlation findings
        """
        self.clear_findings()
        
        if len(all_findings) < 2:
            return self.findings
        
        # Run correlation analyses
        self._correlate_attack_chain(all_findings)
        self._correlate_timeline(all_findings)
        self._correlate_threat_indicators(all_findings)
        self._identify_attack_pattern(all_findings)
        
        # AI-powered correlation if available
        if self.llm_client:
            self._ai_correlation_analysis(all_findings)
        
        return self.findings
    
    def _correlate_attack_chain(self, findings: List[Finding]):
        """Identify multi-stage attack chains"""
        # Group findings by MITRE ATT&CK tactics
        attack_stages = {
            'reconnaissance': [],
            'initial_access': [],
            'execution': [],
            'persistence': [],
            'privilege_escalation': [],
            'defense_evasion': [],
            'credential_access': [],
            'discovery': [],
            'lateral_movement': [],
            'collection': [],
            'exfiltration': [],
            'impact': []
        }
        
        mitre_to_stage = {
            'T1046': 'reconnaissance',  # Network Service Discovery
            'T1110': 'initial_access',  # Brute Force
            'T1204': 'execution',  # User Execution
            'T1059': 'execution',  # Command and Scripting Interpreter
            'T1068': 'privilege_escalation',  # Exploitation for Privilege Escalation
            'T1070': 'defense_evasion',  # Indicator Removal
            'T1071': 'command_and_control',  # Application Layer Protocol
            'T1041': 'exfiltration',  # Exfiltration Over C2 Channel
            'T1486': 'impact',  # Data Encrypted for Impact
            'T1485': 'impact',  # Data Destruction
            'T1498': 'impact'  # Network Denial of Service
        }
        
        for finding in findings:
            if finding.mitre_attack:
                technique_id = finding.mitre_attack.split(' - ')[0]
                stage = mitre_to_stage.get(technique_id)
                if stage:
                    attack_stages[stage].append(finding)
        
        # Identify multi-stage attacks
        stages_with_findings = [stage for stage, finds in attack_stages.items() if finds]
        
        if len(stages_with_findings) >= 3:
            severity = "CRITICAL" if len(stages_with_findings) >= 5 else "HIGH"
            
            attack_chain_description = []
            for stage in stages_with_findings:
                stage_findings = attack_stages[stage]
                attack_chain_description.append(
                    f"**{stage.upper()}**: {len(stage_findings)} indicators"
                )
            
            correlation_finding = Finding(
                finding_id=str(uuid.uuid4()),
                agent_name=self.agent_name,
                severity=severity,
                title="Multi-Stage Attack Chain Detected",
                description=f"Correlated {len(stages_with_findings)} stages of a sophisticated attack campaign.\n\n" + 
                           "\n".join(attack_chain_description),
                evidence_ids=list(set([eid for f in findings for eid in f.evidence_ids])),
                timestamp=datetime.now(),
                confidence=0.85,
                indicators={
                    'attack_stages': stages_with_findings,
                    'total_indicators': len(findings),
                    'stage_details': {
                        stage: [f.title for f in finds]
                        for stage, finds in attack_stages.items() if finds
                    }
                },
                recommendations=[
                    "CRITICAL: Full incident response required",
                    "Isolate affected systems immediately",
                    "Engage threat intelligence team",
                    "Perform comprehensive forensic analysis",
                    "Review all systems for lateral movement",
                    "Initiate containment and eradication procedures"
                ]
            )
            self.add_finding(correlation_finding)
    
    def _correlate_timeline(self, findings: List[Finding]):
        """Build attack timeline from correlated findings"""
        # Sort findings by timestamp
        sorted_findings = sorted(findings, key=lambda x: x.timestamp)
        
        if len(sorted_findings) < 3:
            return
        
        # Calculate time span
        first_event = sorted_findings[0].timestamp
        last_event = sorted_findings[-1].timestamp
        duration = last_event - first_event
        
        # Build timeline
        timeline_events = []
        for i, finding in enumerate(sorted_findings):
            timeline_events.append({
                'sequence': i + 1,
                'timestamp': finding.timestamp.isoformat(),
                'severity': finding.severity,
                'title': finding.title,
                'agent': finding.agent_name
            })
        
        timeline_finding = Finding(
            finding_id=str(uuid.uuid4()),
            agent_name=self.agent_name,
            severity="INFO",
            title="Attack Timeline Reconstruction",
            description=f"Reconstructed timeline of {len(sorted_findings)} security events over {duration}.",
            evidence_ids=list(set([eid for f in findings for eid in f.evidence_ids])),
            timestamp=datetime.now(),
            confidence=0.90,
            indicators={
                'duration': str(duration),
                'first_event': first_event.isoformat(),
                'last_event': last_event.isoformat(),
                'event_count': len(sorted_findings),
                'timeline': timeline_events
            },
            recommendations=[
                "Review timeline for attack progression",
                "Identify initial compromise vector",
                "Determine attacker dwell time",
                "Map events to MITRE ATT&CK framework"
            ]
        )
        self.add_finding(timeline_finding)
    
    def _correlate_threat_indicators(self, findings: List[Finding]):
        """Correlate common threat indicators across findings"""
        # Extract common indicators
        ip_addresses = set()
        domains = set()
        file_hashes = set()
        
        for finding in findings:
            indicators = finding.indicators
            
            # Extract IPs
            if 'top_attacking_ips' in indicators:
                ip_addresses.update(indicators['top_attacking_ips'].keys())
            if 'scanning_ips' in indicators:
                for scanner in indicators['scanning_ips']:
                    ip_addresses.add(scanner.get('ip'))
            
            # Extract domains
            if 'c2_indicators' in indicators:
                for c2 in indicators['c2_indicators']:
                    conn = c2.get('connection', {})
                    if 'destination_domain' in conn:
                        domains.add(conn['destination_domain'])
        
        # Create IOC summary if significant indicators found
        if len(ip_addresses) > 2 or len(domains) > 0:
            ioc_finding = Finding(
                finding_id=str(uuid.uuid4()),
                agent_name=self.agent_name,
                severity="HIGH",
                title="Consolidated Indicators of Compromise (IOCs)",
                description=f"Aggregated {len(ip_addresses)} unique IP addresses and {len(domains)} domains across multiple findings.",
                evidence_ids=list(set([eid for f in findings for eid in f.evidence_ids])),
                timestamp=datetime.now(),
                confidence=0.80,
                indicators={
                    'malicious_ips': list(ip_addresses),
                    'malicious_domains': list(domains),
                    'file_hashes': list(file_hashes)
                },
                recommendations=[
                    "Block all identified IPs and domains at network perimeter",
                    "Add IOCs to threat intelligence platform",
                    "Search entire environment for these indicators",
                    "Share IOCs with security community (e.g., MISP, threat feeds)",
                    "Create detection rules for these indicators"
                ]
            )
            self.add_finding(ioc_finding)
    
    def _identify_attack_pattern(self, findings: List[Finding]):
        """Identify known attack patterns from findings"""
        # Pattern matching for common attack scenarios
        finding_titles = [f.title.lower() for f in findings]
        mitre_techniques = [f.mitre_attack for f in findings if f.mitre_attack]
        
        patterns = {
            'ransomware': {
                'keywords': ['ransomware', 'encrypted', 'ransom note', 'mass file'],
                'confidence': 0.95,
                'severity': 'CRITICAL'
            },
            'apt_campaign': {
                'keywords': ['c2 communication', 'lateral movement', 'data exfiltration', 'privilege escalation'],
                'confidence': 0.85,
                'severity': 'CRITICAL'
            },
            'brute_force_attack': {
                'keywords': ['brute force', 'failed authentication', 'password'],
                'confidence': 0.80,
                'severity': 'HIGH'
            },
            'insider_threat': {
                'keywords': ['data exfiltration', 'unusual hour', 'mass file', 'suspicious files'],
                'confidence': 0.70,
                'severity': 'HIGH'
            },
            'web_attack': {
                'keywords': ['sql injection', 'xss', 'command injection', 'web exploit'],
                'confidence': 0.75,
                'severity': 'HIGH'
            }
        }
        
        detected_patterns = []
        
        for pattern_name, pattern_data in patterns.items():
            matches = sum(1 for keyword in pattern_data['keywords'] 
                         if any(keyword in title for title in finding_titles))
            
            if matches >= 2:
                detected_patterns.append({
                    'pattern': pattern_name,
                    'matches': matches,
                    'confidence': pattern_data['confidence'],
                    'severity': pattern_data['severity']
                })
        
        if detected_patterns:
            # Sort by matches
            detected_patterns.sort(key=lambda x: x['matches'], reverse=True)
            primary_pattern = detected_patterns[0]
            
            pattern_finding = Finding(
                finding_id=str(uuid.uuid4()),
                agent_name=self.agent_name,
                severity=primary_pattern['severity'],
                title=f"Attack Pattern Identified: {primary_pattern['pattern'].replace('_', ' ').title()}",
                description=f"Correlation analysis identified a {primary_pattern['pattern'].replace('_', ' ')} attack pattern based on {primary_pattern['matches']} matching indicators.",
                evidence_ids=list(set([eid for f in findings for eid in f.evidence_ids])),
                timestamp=datetime.now(),
                confidence=primary_pattern['confidence'],
                indicators={
                    'primary_pattern': primary_pattern['pattern'],
                    'all_patterns': detected_patterns,
                    'related_findings': len(findings)
                },
                recommendations=[
                    f"Follow {primary_pattern['pattern'].replace('_', ' ')} incident response playbook",
                    "Activate incident response team",
                    "Document all findings and actions taken",
                    "Prepare for potential data breach notification if required"
                ]
            )
            self.add_finding(pattern_finding)
    
    def _ai_correlation_analysis(self, findings: List[Finding]):
        """Use LLM to identify complex correlations"""
        # Create summary of all findings
        findings_summary = []
        for i, finding in enumerate(findings[:10], 1):  # Limit to prevent context overflow
            findings_summary.append(
                f"{i}. [{finding.severity}] {finding.title}\n"
                f"   Agent: {finding.agent_name}\n"
                f"   Confidence: {finding.confidence:.0%}\n"
                f"   Description: {finding.description[:150]}..."
            )
        
        prompt = f"""Analyze these correlated security findings to identify the overall attack narrative:

{chr(10).join(findings_summary)}

Provide:
1. Overall assessment of the incident
2. Likely threat actor profile and motivation
3. Attack sophistication level
4. Recommended prioritization of response actions
5. Potential business impact

Focus on connecting the dots between different findings."""

        try:
            analysis = self._query_llm(prompt)
            
            if analysis and len(analysis) > 100:
                ai_finding = Finding(
                    finding_id=str(uuid.uuid4()),
                    agent_name=self.agent_name,
                    severity="INFO",
                    title="AI-Powered Incident Analysis",
                    description=analysis,
                    evidence_ids=list(set([eid for f in findings for eid in f.evidence_ids])),
                    timestamp=datetime.now(),
                    confidence=0.70,
                    indicators={
                        'analysis_type': 'LLM-based correlation',
                        'findings_analyzed': len(findings)
                    },
                    recommendations=[
                        "Use AI analysis to supplement human investigation",
                        "Verify AI conclusions with forensic evidence",
                        "Document AI findings in incident report"
                    ]
                )
                self.add_finding(ai_finding)
        except Exception as e:
            self.log(f"AI correlation analysis failed: {e}", "WARNING")