# src/agents/file_analysis_agent.py
"""
File analysis agent for examining file artifacts
"""
from typing import List, Dict, Any
from datetime import datetime
import re

from agents.base_agent import BaseAgent
from models.evidence import Evidence, Finding


class FileAnalysisAgent(BaseAgent):
    """Analyzes file artifacts for suspicious patterns"""
    
    def __init__(self, api_key: str = None):
        """Initialize file analysis agent"""
        super().__init__(api_key)
        self.agent_name = "FileAnalysisAgent"
    
    def analyze(self, evidence_list: List[Evidence]) -> List[Finding]:
        """
        Analyze file evidence for suspicious patterns
        
        Args:
            evidence_list: List of file evidence items
        
        Returns:
            List of findings
        """
        findings = []
        
        print(f"[{self.agent_name}] Analyzing {len(evidence_list)} file(s)...")
        
        for evidence in evidence_list:
            # Basic pattern-based analysis
            findings.extend(self._analyze_file_basic(evidence))
            
            # AI-powered analysis if available
            if self.client:
                findings.extend(self._analyze_file_ai(evidence))
        
        return findings
    
    def _analyze_file_basic(self, evidence: Evidence) -> List[Finding]:
        """Basic pattern-based file analysis"""
        findings = []
        
        try:
            # Decode file content
            content = evidence.data.decode('utf-8', errors='ignore')
            source_path = evidence.source_path.lower()
            
            # Check for suspicious executable
            if source_path.endswith('.exe'):
                suspicious_patterns = [
                    (r'nc\.exe|netcat', 'Netcat command detected'),
                    (r'cmd\.exe.*-e', 'Reverse shell pattern'),
                    (r'powershell.*-enc', 'Encoded PowerShell command'),
                    (r'invoke-expression|iex', 'PowerShell code execution'),
                ]
                
                for pattern, description in suspicious_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        finding = Finding(
                            finding_id=Finding.generate_id(),
                            severity='high',
                            title=f'Suspicious Pattern in Executable: {description}',
                            description=f'Found suspicious pattern "{description}" in file {evidence.source_path}',
                            evidence_ids=[evidence.evidence_id],
                            timestamp=datetime.now(),
                            confidence=0.85,
                            indicators={'pattern': pattern, 'file': evidence.source_path},
                            recommendations=[
                                'Quarantine the suspicious executable',
                                'Perform dynamic malware analysis',
                                'Check process execution logs for this file'
                            ]
                        )
                        findings.append(finding)
            
            # Check for sensitive data files
            if source_path.endswith('.csv') and 'confidential' in source_path:
                # Look for sensitive data patterns
                if re.search(r'\d{3}-\d{2}-\d{4}', content):  # SSN pattern
                    finding = Finding(
                        finding_id=Finding.generate_id(),
                        severity='high',
                        title='Sensitive Data Detected: SSN Pattern',
                        description=f'File {evidence.source_path} contains data matching SSN patterns',
                        evidence_ids=[evidence.evidence_id],
                        timestamp=datetime.now(),
                        confidence=0.90,
                        indicators={'file': evidence.source_path, 'data_type': 'SSN'},
                        recommendations=[
                            'Verify if data exfiltration occurred',
                            'Check access logs for this file',
                            'Implement DLP policies',
                            'Review data handling procedures'
                        ]
                    )
                    findings.append(finding)
                
                if re.search(r'\d{4}-\d{4}-\d{4}-\d{4}', content):  # Credit card pattern
                    finding = Finding(
                        finding_id=Finding.generate_id(),
                        severity='critical',
                        title='Sensitive Data Detected: Credit Card Numbers',
                        description=f'File {evidence.source_path} contains credit card number patterns',
                        evidence_ids=[evidence.evidence_id],
                        timestamp=datetime.now(),
                        confidence=0.95,
                        indicators={'file': evidence.source_path, 'data_type': 'Credit Card'},
                        recommendations=[
                            'Immediate incident response required',
                            'Notify compliance and legal teams',
                            'Assess scope of data exposure',
                            'Implement encryption for sensitive data'
                        ]
                    )
                    findings.append(finding)
        
        except Exception as e:
            print(f"[{self.agent_name}] Error in basic analysis: {e}")
        
        return findings
    
    def _analyze_file_ai(self, evidence: Evidence) -> List[Finding]:
        """AI-powered file analysis using Claude"""
        findings = []
        
        try:
            content = evidence.data.decode('utf-8', errors='ignore')[:2000]  # Limit content
            
            prompt = f"""Analyze this file artifact from a security investigation:

File: {evidence.source_path}
Size: {len(evidence.data)} bytes
Content sample:
{content}

Identify any security concerns, malicious patterns, or indicators of compromise.
Format your response as:
SEVERITY: [critical/high/medium/low]
TITLE: [brief title]
DESCRIPTION: [detailed description]
CONFIDENCE: [percentage]
RECOMMENDATIONS: [bullet points]
"""
            
            system_prompt = "You are a digital forensics analyst examining file artifacts for security threats."
            
            response = self._call_claude(prompt, system_prompt)
            
            # Parse AI response
            severity = self._parse_severity(response)
            confidence = self._parse_confidence(response)
            
            # Extract title
            title_match = re.search(r'TITLE:\s*(.+)', response, re.IGNORECASE)
            title = title_match.group(1).strip() if title_match else "AI-Detected Security Issue"
            
            # Extract recommendations
            recommendations = []
            rec_section = re.search(r'RECOMMENDATIONS?:(.*?)(?:\n\n|\Z)', response, re.IGNORECASE | re.DOTALL)
            if rec_section:
                rec_lines = rec_section.group(1).strip().split('\n')
                recommendations = [line.strip('- •*').strip() for line in rec_lines if line.strip()]
            
            if severity in ['critical', 'high', 'medium']:
                finding = Finding(
                    finding_id=Finding.generate_id(),
                    severity=severity,
                    title=title,
                    description=response[:500],
                    evidence_ids=[evidence.evidence_id],
                    timestamp=datetime.now(),
                    confidence=confidence,
                    indicators={'file': evidence.source_path, 'analysis_type': 'AI'},
                    recommendations=recommendations[:5]
                )
                findings.append(finding)
        
        except Exception as e:
            print(f"[{self.agent_name}] Error in AI analysis: {e}")
        
        return findings