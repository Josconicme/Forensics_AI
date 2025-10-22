# src/agents/network_analysis_agent.py
"""
Network Analysis Agent - Analyzes network traffic for security incidents
"""
import json
import uuid
import re
from datetime import datetime
from typing import List, Any, Dict
from collections import defaultdict, Counter
from .base_agent import BaseAgent, Finding


class NetworkAnalysisAgent(BaseAgent):
    """Analyzes network traffic for suspicious patterns and threats"""
    
    def __init__(self, llm_client=None):
        super().__init__(
            agent_name="NetworkAnalysisAgent",
            agent_description="Analyzes network traffic, connections, and protocols for security threats",
            llm_client=llm_client
        )
        
        # Known malicious ports
        self.suspicious_ports = [
            4444, 4445, 5555, 6666, 7777, 8888, 9999,  # Common backdoor ports
            31337, 12345, 54321,  # Trojan ports
            1337, 3389  # RDP abuse
        ]
        
        # Command and Control domains patterns
        self.c2_patterns = [
            r'\d+\.\d+\.\d+\.\d+',  # IP addresses
            r'\.tk$', r'\.ml$', r'\.ga$',  # Free TLDs
            r'\.onion$'  # Tor
        ]
    
    def analyze(self, evidence_items: List[Any]) -> List[Finding]:
        """
        Analyze network evidence
        
        Args:
            evidence_items: List of network evidence items
            
        Returns:
            List of findings
        """
        self.clear_findings()
        
        for evidence in evidence_items:
            if evidence.evidence_type != "network_traffic":
                continue
            
            # Parse network data
            try:
                content = evidence.data.decode('utf-8')
                network_data = json.loads(content)
            except Exception as e:
                self.log(f"Failed to parse network data: {e}", "ERROR")
                continue
            
            # Run analysis functions
            self._detect_port_scanning(evidence, network_data)
            self._detect_data_exfiltration(evidence, network_data)
            self._detect_c2_communication(evidence, network_data)
            self._detect_ddos_patterns(evidence, network_data)
            self._detect_dns_tunneling(evidence, network_data)
            self._detect_suspicious_connections(evidence, network_data)
            
            # AI analysis if available
            if self.llm_client:
                self._ai_network_analysis(evidence, network_data)
        
        return self.findings
    
    def _detect_port_scanning(self, evidence: Any, network_data: Dict):
        """Detect port scanning activity"""
        connections = network_data.get('connections', [])
        
        # Group by source IP
        source_activities = defaultdict(lambda: {'ports': set(), 'connections': []})
        
        for conn in connections:
            src_ip = conn.get('source_ip')
            dst_port = conn.get('destination_port')
            
            if src_ip and dst_port:
                source_activities[src_ip]['ports'].add(dst_port)
                source_activities[src_ip]['connections'].append(conn)
        
        # Detect scanning (many ports from single source)
        scanners = []
        for src_ip, activity in source_activities.items():
            if len(activity['ports']) > 20:  # Threshold
                scanners.append({
                    'ip': src_ip,
                    'ports_scanned': len(activity['ports']),
                    'total_connections': len(activity['connections'])
                })
        
        if scanners:
            finding = Finding(
                finding_id=str(uuid.uuid4()),
                agent_name=self.agent_name,
                severity="HIGH",
                title="Port Scanning Activity Detected",
                description=f"Detected {len(scanners)} IP addresses performing port scanning activities.",
                evidence_ids=[evidence.evidence_id],
                timestamp=datetime.now(),
                confidence=0.85,
                indicators={
                    'scanning_ips': scanners
                },
                recommendations=[
                    "Block scanning IP addresses at firewall",
                    "Investigate if scanning originated from compromised internal hosts",
                    "Review systems targeted by scans for vulnerabilities",
                    "Enable intrusion detection/prevention systems"
                ],
                mitre_attack="T1046 - Network Service Discovery"
            )
            self.add_finding(finding)
    
    def _detect_data_exfiltration(self, evidence: Any, network_data: Dict):
        """Detect potential data exfiltration"""
        connections = network_data.get('connections', [])
        
        # Group by source and calculate total bytes transferred
        data_transfers = defaultdict(lambda: {'total_bytes': 0, 'connections': 0, 'destinations': set()})
        
        for conn in connections:
            src_ip = conn.get('source_ip')
            dst_ip = conn.get('destination_ip')
            bytes_sent = conn.get('bytes_sent', 0)
            
            if src_ip and bytes_sent > 0:
                data_transfers[src_ip]['total_bytes'] += bytes_sent
                data_transfers[src_ip]['connections'] += 1
                data_transfers[src_ip]['destinations'].add(dst_ip)
        
        # Detect large data transfers (potential exfiltration)
        exfiltration_candidates = []
        threshold = 100 * 1024 * 1024  # 100 MB
        
        for src_ip, transfer_data in data_transfers.items():
            if transfer_data['total_bytes'] > threshold:
                exfiltration_candidates.append({
                    'source_ip': src_ip,
                    'total_bytes': transfer_data['total_bytes'],
                    'connections': transfer_data['connections'],
                    'unique_destinations': len(transfer_data['destinations'])
                })
        
        if exfiltration_candidates:
            finding = Finding(
                finding_id=str(uuid.uuid4()),
                agent_name=self.agent_name,
                severity="CRITICAL",
                title="Potential Data Exfiltration Detected",
                description=f"Detected {len(exfiltration_candidates)} sources with unusually large data transfers.",
                evidence_ids=[evidence.evidence_id],
                timestamp=datetime.now(),
                confidence=0.75,
                indicators={
                    'exfiltration_candidates': exfiltration_candidates
                },
                recommendations=[
                    "IMMEDIATE: Investigate and potentially block suspicious data transfers",
                    "Identify what data was accessed and transmitted",
                    "Check if destination IPs are known malicious or cloud storage",
                    "Review user activity logs for the source systems",
                    "Implement DLP (Data Loss Prevention) controls"
                ],
                mitre_attack="T1041 - Exfiltration Over C2 Channel"
            )
            self.add_finding(finding)
    
    def _detect_c2_communication(self, evidence: Any, network_data: Dict):
        """Detect command and control communication patterns"""
        connections = network_data.get('connections', [])
        
        c2_indicators = []
        
        for conn in connections:
            dst_ip = conn.get('destination_ip', '')
            dst_port = conn.get('destination_port')
            protocol = conn.get('protocol', '').lower()
            
            # Check for suspicious ports
            if dst_port in self.suspicious_ports:
                c2_indicators.append({
                    'reason': 'Suspicious port',
                    'connection': conn,
                    'risk': 'HIGH'
                })
            
            # Check for suspicious domains/IPs
            dst_domain = conn.get('destination_domain', '')
            for pattern in self.c2_patterns:
                if re.search(pattern, dst_domain):
                    c2_indicators.append({
                        'reason': 'Suspicious domain pattern',
                        'connection': conn,
                        'risk': 'MEDIUM'
                    })
            
            # Check for beaconing (regular interval connections)
            # This would require timestamp analysis in production
        
        if c2_indicators:
            finding = Finding(
                finding_id=str(uuid.uuid4()),
                agent_name=self.agent_name,
                severity="CRITICAL",
                title="Command and Control Communication Detected",
                description=f"Detected {len(c2_indicators)} potential C2 communication indicators.",
                evidence_ids=[evidence.evidence_id],
                timestamp=datetime.now(),
                confidence=0.80,
                indicators={
                    'c2_indicators': c2_indicators[:10]
                },
                recommendations=[
                    "IMMEDIATE: Isolate affected systems from network",
                    "Block C2 destinations at firewall and DNS",
                    "Perform full malware analysis on compromised systems",
                    "Search for additional infected systems",
                    "Review initial infection vector",
                    "Engage incident response team"
                ],
                mitre_attack="T1071 - Application Layer Protocol"
            )
            self.add_finding(finding)
    
    def _detect_ddos_patterns(self, evidence: Any, network_data: Dict):
        """Detect DDoS attack patterns"""
        connections = network_data.get('connections', [])
        
        # Count connections to each destination
        destination_counts = Counter()
        source_ips = defaultdict(set)
        
        for conn in connections:
            dst = f"{conn.get('destination_ip')}:{conn.get('destination_port')}"
            src = conn.get('source_ip')
            destination_counts[dst] += 1
            source_ips[dst].add(src)
        
        # Detect high connection volumes
        ddos_targets = []
        for destination, count in destination_counts.items():
            if count > 1000:  # Threshold
                ddos_targets.append({
                    'target': destination,
                    'connection_count': count,
                    'unique_sources': len(source_ips[destination])
                })
        
        if ddos_targets:
            finding = Finding(
                finding_id=str(uuid.uuid4()),
                agent_name=self.agent_name,
                severity="HIGH",
                title="Potential DDoS Attack Pattern",
                description=f"Detected {len(ddos_targets)} targets receiving abnormally high connection volumes.",
                evidence_ids=[evidence.evidence_id],
                timestamp=datetime.now(),
                confidence=0.70,
                indicators={
                    'ddos_targets': ddos_targets
                },
                recommendations=[
                    "Enable DDoS protection services",
                    "Implement rate limiting",
                    "Review and block malicious source IPs",
                    "Scale infrastructure if legitimate traffic spike"
                ],
                mitre_attack="T1498 - Network Denial of Service"
            )
            self.add_finding(finding)
    
    def _detect_dns_tunneling(self, evidence: Any, network_data: Dict):
        """Detect DNS tunneling for data exfiltration"""
        dns_queries = network_data.get('dns_queries', [])
        
        suspicious_dns = []
        
        for query in dns_queries:
            domain = query.get('domain', '')
            query_type = query.get('type', '')
            
            # Unusually long subdomain (common in DNS tunneling)
            parts = domain.split('.')
            if len(parts) > 5 or any(len(part) > 50 for part in parts):
                suspicious_dns.append({
                    'domain': domain,
                    'reason': 'Unusually long subdomain',
                    'query_type': query_type
                })
            
            # High entropy in subdomain (encoded data)
            if parts:
                subdomain = parts[0]
                if len(subdomain) > 20 and self._calculate_entropy(subdomain) > 3.5:
                    suspicious_dns.append({
                        'domain': domain,
                        'reason': 'High entropy subdomain',
                        'query_type': query_type
                    })
        
        if len(suspicious_dns) > 5:
            finding = Finding(
                finding_id=str(uuid.uuid4()),
                agent_name=self.agent_name,
                severity="HIGH",
                title="Potential DNS Tunneling Detected",
                description=f"Detected {len(suspicious_dns)} suspicious DNS queries indicating possible tunneling.",
                evidence_ids=[evidence.evidence_id],
                timestamp=datetime.now(),
                confidence=0.75,
                indicators={
                    'suspicious_queries': suspicious_dns[:10]
                },
                recommendations=[
                    "Investigate source systems making suspicious DNS queries",
                    "Block identified malicious domains",
                    "Implement DNS monitoring and filtering",
                    "Check for malware on source systems"
                ],
                mitre_attack="T1071.004 - Application Layer Protocol: DNS"
            )
            self.add_finding(finding)
    
    def _detect_suspicious_connections(self, evidence: Any, network_data: Dict):
        """Detect other suspicious network connections"""
        connections = network_data.get('connections', [])
        
        suspicious = []
        
        for conn in connections:
            flags = []
            
            # Connections to unusual countries (if geolocation data available)
            country = conn.get('destination_country', '')
            if country in ['CN', 'RU', 'KP', 'IR']:  # High-risk countries
                flags.append('High-risk country')
            
            # Unencrypted sensitive protocols
            protocol = conn.get('protocol', '').upper()
            dst_port = conn.get('destination_port')
            if protocol in ['HTTP', 'FTP', 'TELNET'] or dst_port in [21, 23, 80]:
                flags.append('Unencrypted protocol')
            
            # Connections at unusual hours
            timestamp = conn.get('timestamp')
            if timestamp:
                try:
                    dt = datetime.fromisoformat(timestamp)
                    if dt.hour < 6 or dt.hour > 22:
                        flags.append('Unusual hour')
                except:
                    pass
            
            if flags:
                suspicious.append({
                    'connection': conn,
                    'flags': flags
                })
        
        if len(suspicious) > 10:
            finding = Finding(
                finding_id=str(uuid.uuid4()),
                agent_name=self.agent_name,
                severity="MEDIUM",
                title="Suspicious Network Connections",
                description=f"Detected {len(suspicious)} network connections with suspicious characteristics.",
                evidence_ids=[evidence.evidence_id],
                timestamp=datetime.now(),
                confidence=0.60,
                indicators={
                    'suspicious_connections': suspicious[:10]
                },
                recommendations=[
                    "Review suspicious connections for legitimacy",
                    "Implement secure protocols (HTTPS, SSH, SFTP)",
                    "Consider geofencing for unusual geographic connections",
                    "Monitor off-hours activity"
                ]
            )
            self.add_finding(finding)
    
    def _calculate_entropy(self, string: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not string:
            return 0
        
        import math
        entropy = 0
        for char in set(string):
            p = string.count(char) / len(string)
            entropy -= p * math.log2(p)
        return entropy
    
    def _ai_network_analysis(self, evidence: Any, network_data: Dict):
        """Use LLM for advanced network pattern analysis"""
        connections = network_data.get('connections', [])[:15]
        
        conn_summary = "\n".join([
            f"- {c.get('source_ip')}:{c.get('source_port')} -> "
            f"{c.get('destination_ip')}:{c.get('destination_port')} "
            f"[{c.get('protocol')}] {c.get('bytes_sent', 0)} bytes"
            for c in connections
        ])
        
        prompt = f"""Analyze these network connections for security threats:

{conn_summary}

Identify:
1. Attack patterns or malicious behavior
2. Data exfiltration indicators
3. Command and control communications
4. Network reconnaissance activity

Provide security assessment."""

        try:
            analysis = self._query_llm(prompt)
            
            if analysis and len(analysis) > 50:
                finding = Finding(
                    finding_id=str(uuid.uuid4()),
                    agent_name=self.agent_name,
                    severity="INFO",
                    title="AI-Powered Network Traffic Analysis",
                    description=analysis,
                    evidence_ids=[evidence.evidence_id],
                    timestamp=datetime.now(),
                    confidence=0.65,
                    indicators={'analysis_type': 'LLM-based network analysis'},
                    recommendations=["Verify AI findings with network analysis tools"]
                )
                self.add_finding(finding)
        except Exception as e:
            self.log(f"AI network analysis failed: {e}", "WARNING")