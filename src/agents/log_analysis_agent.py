# src/agents/log_analysis_agent.py
"""
Log Analysis Agent - Analyzes system and application logs for security incidents
"""
import re
import uuid
from typing import List, Dict, Any
from collections import Counter, defaultdict
from datetime import datetime
from .base_agent import BaseAgent, Finding


class LogAnalysisAgent(BaseAgent):
    """Analyzes logs for security incidents and anomalies"""
    
    def __init__(self, llm_client=None):
        super().__init__(
            agent_name="LogAnalysisAgent",
            agent_description="Analyzes system and application logs for security incidents, authentication failures, and suspicious patterns",
            llm_client=llm_client
        )
    
    def analyze(self, evidence_items: List[Any]) -> List[Finding]:
        """
        Analyze log evidence
        
        Args:
            evidence_items: List of log evidence items
            
        Returns:
            List of findings
        """
        self.clear_findings()
        
        for evidence in evidence_items:
            if evidence.evidence_type != "log_file":
                continue
            
            # Parse log content
            try:
                content = evidence.data.decode('utf-8')
            except:
                content = evidence.data.decode('latin-1')
            
            # Run multiple analysis patterns
            self._detect_brute_force(evidence, content)
            self._detect_privilege_escalation(evidence, content)
            self._detect_suspicious_commands(evidence, content)
            self._detect_error_patterns(evidence, content)
            
            # AI-powered analysis if LLM available
            if self.llm_client:
                self._ai_powered_analysis(evidence, content)
        
        return self.findings
    
    def _detect_brute_force(self, evidence: Any, content: str):
        """Detect brute force authentication attempts"""
        failed_auth_patterns = [
            r'Failed password',
            r'authentication failure',
            r'Invalid user',
            r'Failed login',
            r'Connection closed by authenticating user'
        ]
        
        failed_attempts = []
        ip_addresses = defaultdict(int)
        users = defaultdict(int)
        
        lines = content.split('\n')
        for line in lines:
            for pattern in failed_auth_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    failed_attempts.append(line)
                    
                    # Extract IP address
                    ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
                    if ip_match:
                        ip_addresses[ip_match.group()] += 1
                    
                    # Extract username
                    user_match = re.search(r'user[=:\s]+(\w+)', line, re.IGNORECASE)
                    if user_match:
                        users[user_match.group(1)] += 1
        
        # Threshold for brute force detection
        if len(failed_attempts) > 10:
            severity = "HIGH" if len(failed_attempts) > 50 else "MEDIUM"
            confidence = min(0.95, 0.5 + (len(failed_attempts) / 100))
            
            # Find top offenders
            top_ips = sorted(ip_addresses.items(), key=lambda x: x[1], reverse=True)[:5]
            top_users = sorted(users.items(), key=lambda x: x[1], reverse=True)[:5]
            
            finding = Finding(
                finding_id=str(uuid.uuid4()),
                agent_name=self.agent_name,
                severity=severity,
                title="Brute Force Authentication Attempts Detected",
                description=f"Detected {len(failed_attempts)} failed authentication attempts across {len(ip_addresses)} unique IP addresses.",
                evidence_ids=[evidence.evidence_id],
                timestamp=datetime.now(),
                confidence=confidence,
                indicators={
                    'total_failed_attempts': len(failed_attempts),
                    'unique_ips': len(ip_addresses),
                    'unique_users': len(users),
                    'top_attacking_ips': dict(top_ips),
                    'top_targeted_users': dict(top_users),
                    'sample_attempts': failed_attempts[:5]
                },
                recommendations=[
                    "Implement rate limiting on authentication endpoints",
                    "Block or investigate suspicious IP addresses",
                    "Enable multi-factor authentication for all accounts",
                    "Review and strengthen password policies",
                    "Consider implementing IP geolocation blocking if attacks are from unexpected regions"
                ],
                mitre_attack="T1110 - Brute Force"
            )
            self.add_finding(finding)
    
    def _detect_privilege_escalation(self, evidence: Any, content: str):
        """Detect privilege escalation attempts"""
        priv_esc_patterns = [
            r'sudo',
            r'su -',
            r'privilege escalation',
            r'gained administrator',
            r'elevated privileges',
            r'RunAs',
            r'UAC'
        ]
        
        escalations = []
        lines = content.split('\n')
        
        for line in lines:
            for pattern in priv_esc_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    escalations.append(line)
        
        if len(escalations) > 5:
            finding = Finding(
                finding_id=str(uuid.uuid4()),
                agent_name=self.agent_name,
                severity="HIGH",
                title="Potential Privilege Escalation Activity",
                description=f"Detected {len(escalations)} privilege escalation related events.",
                evidence_ids=[evidence.evidence_id],
                timestamp=datetime.now(),
                confidence=0.75,
                indicators={
                    'escalation_count': len(escalations),
                    'sample_events': escalations[:5]
                },
                recommendations=[
                    "Review all privilege escalation events for legitimacy",
                    "Verify that administrative access was authorized",
                    "Check for compromised accounts",
                    "Audit sudo/administrative access logs"
                ],
                mitre_attack="T1068 - Exploitation for Privilege Escalation"
            )
            self.add_finding(finding)
    
    def _detect_suspicious_commands(self, evidence: Any, content: str):
        """Detect suspicious command execution"""
        suspicious_commands = [
            r'nc\s+-[lep]',  # netcat
            r'wget.*http',
            r'curl.*http',
            r'powershell.*-enc',  # encoded powershell
            r'base64\s+-d',
            r'/etc/shadow',
            r'/etc/passwd',
            r'mimikatz',
            r'procdump',
            r'reg save HKLM\\SAM'
        ]
        
        suspicious_activity = []
        lines = content.split('\n')
        
        for line in lines:
            for pattern in suspicious_commands:
                if re.search(pattern, line, re.IGNORECASE):
                    suspicious_activity.append(line)
        
        if suspicious_activity:
            finding = Finding(
                finding_id=str(uuid.uuid4()),
                agent_name=self.agent_name,
                severity="CRITICAL",
                title="Suspicious Command Execution Detected",
                description=f"Detected {len(suspicious_activity)} suspicious commands that may indicate malicious activity.",
                evidence_ids=[evidence.evidence_id],
                timestamp=datetime.now(),
                confidence=0.85,
                indicators={
                    'suspicious_commands': suspicious_activity
                },
                recommendations=[
                    "Immediately investigate the source and context of these commands",
                    "Check if these commands were executed by authorized personnel",
                    "Scan affected systems for malware",
                    "Review network logs for data exfiltration",
                    "Consider isolating affected systems"
                ],
                mitre_attack="T1059 - Command and Scripting Interpreter"
            )
            self.add_finding(finding)
    
    def _detect_error_patterns(self, evidence: Any, content: str):
        """Detect error patterns that might indicate security issues"""
        error_patterns = [
            r'error',
            r'exception',
            r'failed',
            r'denied',
            r'unauthorized'
        ]
        
        errors = defaultdict(int)
        lines = content.split('\n')
        
        for line in lines:
            for pattern in error_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    errors[pattern] += 1
        
        total_errors = sum(errors.values())
        
        if total_errors > 100:
            finding = Finding(
                finding_id=str(uuid.uuid4()),
                agent_name=self.agent_name,
                severity="MEDIUM",
                title="High Volume of System Errors",
                description=f"Detected {total_errors} error-related log entries which may indicate system instability or attack attempts.",
                evidence_ids=[evidence.evidence_id],
                timestamp=datetime.now(),
                confidence=0.60,
                indicators={
                    'total_errors': total_errors,
                    'error_breakdown': dict(errors)
                },
                recommendations=[
                    "Investigate the root cause of high error rates",
                    "Check if errors correlate with known attack patterns",
                    "Review system health and resource utilization"
                ]
            )
            self.add_finding(finding)
    
    def _ai_powered_analysis(self, evidence: Any, content: str):
        """Use LLM for advanced pattern recognition"""
        # Sample a portion of logs for AI analysis
        lines = content.split('\n')
        sample_size = min(50, len(lines))
        sample_lines = lines[:sample_size]
        
        prompt = f"""Analyze the following log entries for security incidents:

{chr(10).join(sample_lines)}

Identify any:
1. Security incidents or threats
2. Unusual patterns or anomalies
3. Potential indicators of compromise (IOCs)
4. Timeline of suspicious activities

Provide a brief analysis focusing on security implications."""

        try:
            analysis = self._query_llm(prompt)
            
            if analysis and len(analysis) > 50:
                finding = Finding(
                    finding_id=str(uuid.uuid4()),
                    agent_name=self.agent_name,
                    severity="INFO",
                    title="AI-Powered Log Analysis",
                    description=analysis,
                    evidence_ids=[evidence.evidence_id],
                    timestamp=datetime.now(),
                    confidence=0.70,
                    indicators={
                        'analysis_type': 'LLM-based pattern recognition',
                        'sample_size': sample_size
                    },
                    recommendations=[
                        "Review AI analysis findings with human analyst",
                        "Correlate with other evidence sources"
                    ]
                )
                self.add_finding(finding)
        except Exception as e:
            self.log(f"AI analysis failed: {str(e)}", "WARNING")