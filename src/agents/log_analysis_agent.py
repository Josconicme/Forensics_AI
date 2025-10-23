# src/agents/log_analysis_agent.py
"""
Log analysis agent for examining log files
"""
from typing import List, Dict, Any
from datetime import datetime
import re
from collections import Counter

from agents.base_agent import BaseAgent
from models.evidence import Evidence, Finding


class LogAnalysisAgent(BaseAgent):
    """Analyzes log files for security incidents"""
    
    def __init__(self, api_key: str = None):
        """Initialize log analysis agent"""
        super().__init__(api_key)
        self.agent_name = "LogAnalysisAgent"
    
    def analyze(self, evidence_list: List[Evidence]) -> List[Finding]:
        """
        Analyze log evidence for security incidents
        
        Args:
            evidence_list: List of log evidence items
        
        Returns:
            List of findings
        """
        findings = []
        
        print(f"[{self.agent_name}] Analyzing {len(evidence_list)} log file(s)...")
        
        for evidence in evidence_list:
            # Pattern-based analysis
            findings.extend(self._analyze_log_patterns(evidence))
            
            # AI-powered analysis if available
            if self.client:
                findings.extend(self._analyze_log_ai(evidence))
        
        return findings
    
    def _analyze_log_patterns(self, evidence: Evidence) -> List[Finding]:
        """Pattern-based log analysis"""
        findings = []
        
        try:
            content = evidence.data.decode('utf-8', errors='ignore')
            lines = content.split('\n')
            source_path = evidence.source_path.lower()
            
            # Apache/Web server log analysis
            if 'apache' in source_path or 'access' in source_path:
                findings.extend(self._analyze_web_logs(evidence, lines))
            
            # Windows security log analysis
            elif 'windows' in source_path or 'security' in source_path:
                findings.extend(self._analyze_windows_logs(evidence, lines))
        
        except Exception as e:
            print(f"[{self.agent_name}] Error analyzing patterns: {e}")
        
        return findings
    
    def _analyze_web_logs(self, evidence: Evidence, lines: List[str]) -> List[Finding]:
        """Analyze web server logs"""
        findings = []
        
        # Track suspicious patterns
        sql_injection_attempts = []
        path_traversal_attempts = []
        scanner_ips = set()
        
        for line in lines:
            # SQL injection detection
            if re.search(r"('|%27)(OR|or|AND|and|UNION|union|SELECT|select)", line):
                sql_injection_attempts.append(line)
                ip_match = re.match(r'^([\d.]+)', line)
                if ip_match:
                    scanner_ips.add(ip_match.group(1))
            
            # Path traversal detection
            if re.search(r'\.\./|\.\.\\|%2e%2e', line, re.IGNORECASE):
                path_traversal_attempts.append(line)
                ip_match = re.match(r'^([\d.]+)', line)
                if ip_match:
                    scanner_ips.add(ip_match.group(1))
            
            # Scanner detection
            if re.search(r'(sqlmap|nikto|nmap|burp|acunetix)', line, re.IGNORECASE):
                ip_match = re.match(r'^([\d.]+)', line)
                if ip_match:
                    scanner_ips.add(ip_match.group(1))
        
        # Generate findings
        if sql_injection_attempts:
            finding = Finding(
                finding_id=Finding.generate_id(),
                severity='high',
                title='SQL Injection Attack Detected',
                description=f'Detected {len(sql_injection_attempts)} SQL injection attempts in {evidence.source_path}',
                evidence_ids=[evidence.evidence_id],
                timestamp=datetime.now(),
                confidence=0.90,
                indicators={
                    'attack_type': 'SQL Injection',
                    'attempt_count': len(sql_injection_attempts),
                    'attacker_ips': list(scanner_ips)
                },
                recommendations=[
                    'Block attacker IPs at firewall level',
                    'Review and patch vulnerable SQL queries',
                    'Implement WAF rules for SQL injection',
                    'Check database logs for unauthorized access'
                ]
            )
            findings.append(finding)
        
        if path_traversal_attempts:
            finding = Finding(
                finding_id=Finding.generate_id(),
                severity='high',
                title='Path Traversal Attack Detected',
                description=f'Detected {len(path_traversal_attempts)} path traversal attempts in {evidence.source_path}',
                evidence_ids=[evidence.evidence_id],
                timestamp=datetime.now(),
                confidence=0.85,
                indicators={
                    'attack_type': 'Path Traversal',
                    'attempt_count': len(path_traversal_attempts),
                    'attacker_ips': list(scanner_ips)
                },
                recommendations=[
                    'Block attacker IPs immediately',
                    'Verify file system permissions',
                    'Review application input validation',
                    'Check for unauthorized file access'
                ]
            )
            findings.append(finding)
        
        if scanner_ips:
            finding = Finding(
                finding_id=Finding.generate_id(),
                severity='medium',
                title='Vulnerability Scanning Detected',
                description=f'Detected automated scanning tools from {len(scanner_ips)} IP(s)',
                evidence_ids=[evidence.evidence_id],
                timestamp=datetime.now(),
                confidence=0.95,
                indicators={
                    'attack_type': 'Reconnaissance',
                    'scanner_ips': list(scanner_ips)
                },
                recommendations=[
                    'Block scanner IPs',
                    'Review security posture',
                    'Implement rate limiting',
                    'Monitor for follow-up attacks'
                ]
            )
            findings.append(finding)
        
        return findings
    
    def _analyze_windows_logs(self, evidence: Evidence, lines: List[str]) -> List[Finding]:
        """Analyze Windows security logs"""
        findings = []
        
        failed_logins = []
        account_creations = []
        privilege_changes = []
        
        for line in lines:
            # Failed login detection (Event ID 4625)
            if '4625' in line:
                failed_logins.append(line)
            
            # Account creation (Event ID 4720)
            if '4720' in line:
                account_creations.append(line)
            
            # Privilege changes (Event ID 4672)
            if '4672' in line:
                privilege_changes.append(line)
        
        # Check for brute force pattern
        if len(failed_logins) > 10:
            # Extract usernames
            usernames = []
            for line in failed_logins:
                match = re.search(r'admin|administrator|backdoor', line, re.IGNORECASE)
                if match:
                    usernames.append(match.group(0))
            
            username_counts = Counter(usernames)
            most_targeted = username_counts.most_common(1)[0] if username_counts else ('unknown', 0)
            
            finding = Finding(
                finding_id=Finding.generate_id(),
                severity='critical',
                title='Brute Force Attack Detected',
                description=f'Detected {len(failed_logins)} failed login attempts, indicating brute force attack',
                evidence_ids=[evidence.evidence_id],
                timestamp=datetime.now(),
                confidence=0.95,
                indicators={
                    'attack_type': 'Brute Force',
                    'failed_attempts': len(failed_logins),
                    'most_targeted_account': most_targeted[0]
                },
                recommendations=[
                    'Implement account lockout policies',
                    'Enable MFA for all accounts',
                    'Block attacker IPs',
                    'Review successful logins after failed attempts',
                    'Change passwords for targeted accounts'
                ]
            )
            findings.append(finding)
        
        # Suspicious account creation
        if account_creations:
            for line in account_creations:
                if re.search(r'backdoor|hack|temp|test', line, re.IGNORECASE):
                    finding = Finding(
                        finding_id=Finding.generate_id(),
                        severity='critical',
                        title='Suspicious Account Creation Detected',
                        description='Detected creation of suspiciously named user account',
                        evidence_ids=[evidence.evidence_id],
                        timestamp=datetime.now(),
                        confidence=0.90,
                        indicators={'attack_type': 'Persistence', 'event': line[:200]},
                        recommendations=[
                            'Disable suspicious accounts immediately',
                            'Review all recent account creations',
                            'Check for unauthorized privilege escalation',
                            'Audit Active Directory changes'
                        ]
                    )
                    findings.append(finding)
                    break
        
        return findings
    
    def _analyze_log_ai(self, evidence: Evidence) -> List[Finding]:
        """AI-powered log analysis"""
        findings = []
        
        try:
            content = evidence.data.decode('utf-8', errors='ignore')
            lines = content.split('\n')
            sample = '\n'.join(lines[:50])  # First 50 lines
            
            prompt = f"""Analyze these log entries for security incidents:

Log File: {evidence.source_path}
Total Lines: {len(lines)}
Sample:
{sample}

Identify any security incidents, attack patterns, or anomalies.
Format: SEVERITY: | TITLE: | DESCRIPTION: | CONFIDENCE:"""
            
            response = self._call_claude(prompt, "You are a security analyst reviewing logs.")
            
            severity = self._parse_severity(response)
            if severity in ['critical', 'high', 'medium']:
                finding = Finding(
                    finding_id=Finding.generate_id(),
                    severity=severity,
                    title="AI-Detected Log Anomaly",
                    description=response[:400],
                    evidence_ids=[evidence.evidence_id],
                    timestamp=datetime.now(),
                    confidence=self._parse_confidence(response),
                    indicators={'log_file': evidence.source_path},
                    recommendations=['Review full log file', 'Investigate flagged events']
                )
                findings.append(finding)
        
        except Exception as e:
            print(f"[{self.agent_name}] Error in AI analysis: {e}")
        
        return findings