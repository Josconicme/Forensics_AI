# src/agents/correlation_agent.py
"""
Correlation Agent - Correlates findings across multiple data sources
"""
import uuid
from datetime import datetime, timedelta
from typing import List, Dict, Any
from collections import defaultdict
from agents.base_agent import BaseAgent
from models.finding import Finding, FindingType, Severity, MitreTactic


class CorrelationAgent(BaseAgent):
    """Correlates findings from multiple agents to identify attack patterns"""
    
    def __init__(self, llm_client=None):
        super().__init__(
            agent_name="CorrelationAgent",
            agent_description="Correlates findings across multiple evidence sources to identify complex attack patterns",
            llm_client=llm_client
        )
    
    def analyze(self, all_findings: List[dict], evidence_items: List[Any]) -> List[dict]:
        """
        Correlate findings from multiple agents
        
        Args:
            all_findings: List of all findings (as dicts) from other agents
            evidence_items: List of all evidence items
            
        Returns:
            List of correlation findings (as dicts)
        """
        self.clear_findings()
        
        if len(all_findings) < 2:
            return self.findings
        
        print(f"[{self.agent_name}] Correlating {len(all_findings)} findings...")
        
        # Run correlation analyses
        self._correlate_attack_chain(all_findings)
        self._correlate_timeline(all_findings)
        self._correlate_threat_indicators(all_findings)
        self._identify_attack_pattern(all_findings)
        
        # AI-powered correlation if available
        if self.llm_client:
            self._ai_correlation_analysis(all_findings)
        
        print(f"[{self.agent_name}] Generated {len(self.findings)} correlation findings")
        return self.findings
    
    def _correlate_attack_chain(self, findings: List[dict]):
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
            'command_and_control': [],
            'exfiltration': [],
            'impact': []
        }
        
        # Map MITRE techniques to stages
        technique_to_stage = {
            'T1046': 'reconnaissance',
            'T1110': 'initial_access',
            'T1204': 'execution',
            'T1059': 'execution',
            'T1053': 'persistence',
            'T1068': 'privilege_escalation',
            'T1070': 'defense_evasion',
            'T1027': 'defense_evasion',
            'T1003': 'credential_access',
            'T1071': 'command_and_control',
            'T1041': 'exfiltration',
            'T1486': 'impact',
            'T1485': 'impact',
            'T1498': 'impact'
        }
        
        # Categorize findings by attack stage
        for finding in findings:
            # Handle both dict and object access
            mitre_techniques = finding.get('mitre_techniques', [])
            
            for technique in mitre_techniques:
                # Extract technique ID (e.g., "T1204.002" -> "T1204")
                technique_id = technique.split('.')[0] if '.' in technique else technique
                stage = technique_to_stage.get(technique_id)
                
                if stage:
                    attack_stages[stage].append(finding)
                    break  # Only count finding once
        
        # Identify multi-stage attacks
        stages_with_findings = [stage for stage, finds in attack_stages.items() if finds]
        
        if len(stages_with_findings) >= 3:
            severity = Severity.CRITICAL if len(stages_with_findings) >= 5 else Severity.HIGH
            
            attack_chain_description = []
            for stage in stages_with_findings:
                stage_findings = attack_stages[stage]
                attack_chain_description.append(
                    f"**{stage.replace('_', ' ').upper()}**: {len(stage_findings)} indicators"
                )
            
            # Collect all evidence IDs
            all_evidence_ids = []
            for f in findings:
                all_evidence_ids.extend(f.get('evidence_ids', []))
            
            correlation_finding = Finding(
                finding_id=str(uuid.uuid4()),
                type=FindingType.ANOMALY,
                severity=severity,
                title="Multi-Stage Attack Chain Detected",
                description=f"Correlated {len(stages_with_findings)} stages of a sophisticated attack campaign.\n\n" + 
                           "\n".join(attack_chain_description),
                evidence_ids=list(set(all_evidence_ids)),
                timestamp=datetime.now(),
                confidence=0.85,
                agent_name=self.agent_name,
                mitre_tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.EXECUTION],
                mitre_techniques=['T1204', 'T1059'],
                remediation=[
                    "CRITICAL: Full incident response required",
                    "Isolate affected systems immediately",
                    "Engage threat intelligence team",
                    "Perform comprehensive forensic analysis",
                    "Review all systems for lateral movement",
                    "Initiate containment and eradication procedures"
                ],
                metadata={
                    'attack_stages': stages_with_findings,
                    'total_indicators': len(findings),
                    'stage_details': {
                        stage: [f.get('title', 'Unknown') for f in finds[:5]]
                        for stage, finds in attack_stages.items() if finds
                    }
                }
            )
            self.add_finding(correlation_finding)
    
    def _correlate_timeline(self, findings: List[dict]):
        """Build attack timeline from correlated findings"""
        # Sort findings by timestamp
        sorted_findings = sorted(
            findings, 
            key=lambda x: datetime.fromisoformat(x['timestamp']) if isinstance(x.get('timestamp'), str) 
                         else x.get('timestamp', datetime.now())
        )
        
        if len(sorted_findings) < 3:
            return
        
        # Calculate time span
        first_event = datetime.fromisoformat(sorted_findings[0]['timestamp']) if isinstance(sorted_findings[0].get('timestamp'), str) else sorted_findings[0].get('timestamp', datetime.now())
        last_event = datetime.fromisoformat(sorted_findings[-1]['timestamp']) if isinstance(sorted_findings[-1].get('timestamp'), str) else sorted_findings[-1].get('timestamp', datetime.now())
        duration = last_event - first_event
        
        # Build timeline
        timeline_events = []
        for i, finding in enumerate(sorted_findings[:20], 1):  # Limit to 20 events
            timestamp = finding.get('timestamp')
            if isinstance(timestamp, str):
                timestamp = datetime.fromisoformat(timestamp)
            
            timeline_events.append({
                'sequence': i,
                'timestamp': timestamp.isoformat(),
                'severity': finding.get('severity', 'unknown'),
                'title': finding.get('title', 'Unknown Finding'),
                'agent': finding.get('agent_name', 'Unknown')
            })
        
        # Collect all evidence IDs
        all_evidence_ids = []
        for f in findings:
            all_evidence_ids.extend(f.get('evidence_ids', []))
        
        timeline_finding = Finding(
            finding_id=str(uuid.uuid4()),
            type=FindingType.ANOMALY,
            severity=Severity.INFO,
            title="Attack Timeline Reconstruction",
            description=f"Reconstructed timeline of {len(sorted_findings)} security events over {duration}.",
            evidence_ids=list(set(all_evidence_ids)),
            timestamp=datetime.now(),
            confidence=0.90,
            agent_name=self.agent_name,
            mitre_tactics=[],
            mitre_techniques=[],
            remediation=[
                "Review timeline for attack progression",
                "Identify initial compromise vector",
                "Determine attacker dwell time",
                "Map events to MITRE ATT&CK framework"
            ],
            metadata={
                'duration': str(duration),
                'first_event': first_event.isoformat(),
                'last_event': last_event.isoformat(),
                'event_count': len(sorted_findings),
                'timeline': timeline_events
            }
        )
        self.add_finding(timeline_finding)
    
    def _correlate_threat_indicators(self, findings: List[dict]):
        """Correlate common threat indicators across findings"""
        # Extract common indicators
        ip_addresses = set()
        domains = set()
        file_paths = set()
        
        for finding in findings:
            # Get IOCs from finding
            iocs = finding.get('iocs', [])
            for ioc in iocs:
                if isinstance(ioc, str):
                    # Simple heuristics to categorize IOCs
                    if '.' in ioc and any(char.isdigit() for char in ioc):
                        # Likely IP or domain
                        if ioc.count('.') == 3 and all(part.isdigit() for part in ioc.split('.')):
                            ip_addresses.add(ioc)
                        else:
                            domains.add(ioc)
                    elif '/' in ioc or '\\' in ioc:
                        # Likely file path
                        file_paths.add(ioc)
            
            # Check metadata for additional indicators
            metadata = finding.get('metadata', {})
            if 'suspicious_ips' in metadata:
                ip_addresses.update(metadata['suspicious_ips'])
            if 'file_path' in metadata:
                file_paths.add(metadata['file_path'])
        
        # Create IOC summary if significant indicators found
        total_iocs = len(ip_addresses) + len(domains) + len(file_paths)
        
        if total_iocs > 3:
            # Collect all evidence IDs
            all_evidence_ids = []
            for f in findings:
                all_evidence_ids.extend(f.get('evidence_ids', []))
            
            ioc_finding = Finding(
                finding_id=str(uuid.uuid4()),
                type=FindingType.MALWARE,
                severity=Severity.HIGH,
                title="Consolidated Indicators of Compromise (IOCs)",
                description=f"Aggregated {len(ip_addresses)} unique IP addresses, {len(domains)} domains, and {len(file_paths)} suspicious files across multiple findings.",
                evidence_ids=list(set(all_evidence_ids)),
                timestamp=datetime.now(),
                confidence=0.80,
                agent_name=self.agent_name,
                mitre_tactics=[MitreTactic.COMMAND_AND_CONTROL],
                mitre_techniques=['T1071'],
                iocs=list(ip_addresses)[:10] + list(domains)[:10] + list(file_paths)[:10],
                remediation=[
                    "Block all identified IPs and domains at network perimeter",
                    "Add IOCs to threat intelligence platform",
                    "Search entire environment for these indicators",
                    "Share IOCs with security community (e.g., MISP, threat feeds)",
                    "Create detection rules for these indicators"
                ],
                metadata={
                    'total_ips': len(ip_addresses),
                    'total_domains': len(domains),
                    'total_files': len(file_paths),
                    'sample_ips': list(ip_addresses)[:5],
                    'sample_domains': list(domains)[:5]
                }
            )
            self.add_finding(ioc_finding)
    
    def _identify_attack_pattern(self, findings: List[dict]):
        """Identify known attack patterns from findings"""
        # Pattern matching for common attack scenarios
        finding_titles = [f.get('title', '').lower() for f in findings]
        finding_descriptions = [f.get('description', '').lower() for f in findings]
        
        patterns = {
            'ransomware': {
                'keywords': ['ransomware', 'encrypted', 'ransom', 'mass file', 'crypto', 'locked'],
                'confidence': 0.95,
                'severity': Severity.CRITICAL
            },
            'apt_campaign': {
                'keywords': ['c2', 'command and control', 'lateral movement', 'exfiltration', 'privilege escalation'],
                'confidence': 0.85,
                'severity': Severity.CRITICAL
            },
            'brute_force_attack': {
                'keywords': ['brute force', 'failed authentication', 'password', 'login attempts'],
                'confidence': 0.80,
                'severity': Severity.HIGH
            },
            'malware_infection': {
                'keywords': ['suspicious file', 'malware', 'trojan', 'backdoor', 'virus'],
                'confidence': 0.85,
                'severity': Severity.HIGH
            },
            'data_exfiltration': {
                'keywords': ['exfiltration', 'unusual traffic', 'large transfer', 'suspicious connection'],
                'confidence': 0.75,
                'severity': Severity.HIGH
            }
        }
        
        detected_patterns = []
        
        for pattern_name, pattern_data in patterns.items():
            matches = 0
            for keyword in pattern_data['keywords']:
                if any(keyword in title for title in finding_titles) or \
                   any(keyword in desc for desc in finding_descriptions):
                    matches += 1
            
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
            
            # Collect all evidence IDs
            all_evidence_ids = []
            for f in findings:
                all_evidence_ids.extend(f.get('evidence_ids', []))
            
            pattern_finding = Finding(
                finding_id=str(uuid.uuid4()),
                type=FindingType.MALWARE if 'malware' in primary_pattern['pattern'] else FindingType.ANOMALY,
                severity=primary_pattern['severity'],
                title=f"Attack Pattern Identified: {primary_pattern['pattern'].replace('_', ' ').title()}",
                description=f"Correlation analysis identified a '{primary_pattern['pattern'].replace('_', ' ')}' attack pattern based on {primary_pattern['matches']} matching indicators across {len(findings)} findings.",
                evidence_ids=list(set(all_evidence_ids)),
                timestamp=datetime.now(),
                confidence=primary_pattern['confidence'],
                agent_name=self.agent_name,
                mitre_tactics=[MitreTactic.IMPACT],
                mitre_techniques=['T1486'] if 'ransomware' in primary_pattern['pattern'] else [],
                remediation=[
                    f"Follow {primary_pattern['pattern'].replace('_', ' ')} incident response playbook",
                    "Activate incident response team",
                    "Document all findings and actions taken",
                    "Prepare for potential data breach notification if required",
                    "Preserve forensic evidence for investigation"
                ],
                metadata={
                    'primary_pattern': primary_pattern['pattern'],
                    'all_patterns': detected_patterns,
                    'related_findings': len(findings),
                    'confidence_level': primary_pattern['confidence']
                }
            )
            self.add_finding(pattern_finding)
    
    def _ai_correlation_analysis(self, findings: List[dict]):
        """Use LLM to identify complex correlations"""
        # Create summary of all findings
        findings_summary = []
        for i, finding in enumerate(findings[:10], 1):  # Limit to prevent context overflow
            severity = finding.get('severity', 'unknown')
            title = finding.get('title', 'Unknown')
            agent_name = finding.get('agent_name', 'Unknown')
            confidence = finding.get('confidence', 0)
            description = finding.get('description', '')
            
            findings_summary.append(
                f"{i}. [{severity.upper()}] {title}\n"
                f"   Agent: {agent_name}\n"
                f"   Confidence: {confidence:.0%}\n"
                f"   Description: {description[:150]}..."
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
                # Collect all evidence IDs
                all_evidence_ids = []
                for f in findings:
                    all_evidence_ids.extend(f.get('evidence_ids', []))
                
                ai_finding = Finding(
                    finding_id=str(uuid.uuid4()),
                    type=FindingType.ANOMALY,
                    severity=Severity.INFO,
                    title="AI-Powered Incident Analysis",
                    description=analysis,
                    evidence_ids=list(set(all_evidence_ids)),
                    timestamp=datetime.now(),
                    confidence=0.70,
                    agent_name=self.agent_name,
                    mitre_tactics=[],
                    mitre_techniques=[],
                    remediation=[
                        "Use AI analysis to supplement human investigation",
                        "Verify AI conclusions with forensic evidence",
                        "Document AI findings in incident report"
                    ],
                    metadata={
                        'analysis_type': 'LLM-based correlation',
                        'findings_analyzed': len(findings)
                    }
                )
                self.add_finding(ai_finding)
        except Exception as e:
            print(f"[{self.agent_name}] AI correlation analysis failed: {e}")
    
    def _query_llm(self, prompt: str) -> str:
        """Query the LLM for analysis"""
        if not self.llm_client:
            return ""
        
        try:
            response = self.llm_client.messages.create(
                model="claude-3-5-sonnet-20241022",
                max_tokens=2000,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )
            return response.content[0].text
        except Exception as e:
            print(f"[{self.agent_name}] LLM query failed: {e}")
            return ""

    
    def add_finding(self, finding):
        """Add a finding to the agent's findings list"""
        if not hasattr(self, 'findings'):
            self.findings = []
        if hasattr(finding, 'to_dict'):
            self.findings.append(finding.to_dict())
        else:
            self.findings.append(finding)
    
    def clear_findings(self):
        """Clear all findings"""
        if not hasattr(self, 'findings'):
            self.findings = []
        else:
            self.findings.clear()
