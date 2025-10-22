# src/agents/file_analysis_agent.py
"""
File Analysis Agent - Analyzes file metadata for suspicious patterns
"""
import json
import uuid
from datetime import datetime, timedelta
from typing import List, Any, Dict
from collections import defaultdict
from .base_agent import BaseAgent, Finding


class FileAnalysisAgent(BaseAgent):
    """Analyzes file metadata and filesystem artifacts"""
    
    def __init__(self, llm_client=None):
        super().__init__(
            agent_name="FileAnalysisAgent",
            agent_description="Analyzes file metadata, timestamps, and filesystem artifacts for suspicious patterns",
            llm_client=llm_client
        )
        
        # Suspicious file extensions
        self.suspicious_extensions = [
            '.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js',
            '.scr', '.pif', '.msi', '.hta', '.jar', '.sh', '.elf'
        ]
        
        # Ransomware file extensions
        self.ransomware_extensions = [
            '.encrypted', '.locked', '.crypto', '.crypt', '.cerber',
            '.locky', '.zepto', '.odin', '.thor', '.aesir', '.wannacry'
        ]
    
    def analyze(self, evidence_items: List[Any]) -> List[Finding]:
        """
        Analyze file evidence
        
        Args:
            evidence_items: List of file evidence items
            
        Returns:
            List of findings
        """
        self.clear_findings()
        
        for evidence in evidence_items:
            if evidence.evidence_type != "file_metadata":
                continue
            
            # Parse file metadata
            try:
                content = evidence.data.decode('utf-8')
                file_data = json.loads(content)
            except Exception as e:
                self.log(f"Failed to parse file metadata: {e}", "ERROR")
                continue
            
            # Run analysis functions
            self._detect_ransomware_indicators(evidence, file_data)
            self._detect_suspicious_files(evidence, file_data)
            self._detect_timestamp_anomalies(evidence, file_data)
            self._detect_hidden_files(evidence, file_data)
            self._detect_mass_file_changes(evidence, file_data)
            
            # AI analysis if available
            if self.llm_client:
                self._ai_file_analysis(evidence, file_data)
        
        return self.findings
    
    def _detect_ransomware_indicators(self, evidence: Any, file_data: Dict):
        """Detect potential ransomware activity"""
        ransomware_indicators = []
        encrypted_files = []
        ransom_notes = []
        
        files = file_data.get('files', [])
        
        for file_info in files:
            filename = file_info.get('name', '').lower()
            extension = file_info.get('extension', '').lower()
            
            # Check for ransomware extensions
            if any(ext in extension for ext in self.ransomware_extensions):
                encrypted_files.append(file_info)
            
            # Check for ransom note files
            if any(note in filename for note in ['readme', 'decrypt', 'recovery', 'help', 'ransom']):
                if extension in ['.txt', '.html', '.htm']:
                    ransom_notes.append(file_info)
        
        # Check for mass encryption pattern
        if len(encrypted_files) > 10 or len(ransom_notes) > 0:
            severity = "CRITICAL" if len(encrypted_files) > 50 else "HIGH"
            
            finding = Finding(
                finding_id=str(uuid.uuid4()),
                agent_name=self.agent_name,
                severity=severity,
                title="Potential Ransomware Activity Detected",
                description=f"Detected {len(encrypted_files)} encrypted files and {len(ransom_notes)} potential ransom notes.",
                evidence_ids=[evidence.evidence_id],
                timestamp=datetime.now(),
                confidence=0.90 if len(ransom_notes) > 0 else 0.75,
                indicators={
                    'encrypted_files_count': len(encrypted_files),
                    'ransom_notes': [f['name'] for f in ransom_notes],
                    'sample_encrypted_files': [f['name'] for f in encrypted_files[:10]]
                },
                recommendations=[
                    "IMMEDIATE ACTION: Isolate affected systems from network",
                    "Do not pay ransom - contact law enforcement",
                    "Identify ransomware variant for possible decryption tools",
                    "Restore from clean backups if available",
                    "Scan entire network for lateral movement",
                    "Preserve evidence for forensic analysis"
                ],
                mitre_attack="T1486 - Data Encrypted for Impact"
            )
            self.add_finding(finding)
    
    def _detect_suspicious_files(self, evidence: Any, file_data: Dict):
        """Detect suspicious executable files and locations"""
        suspicious_files = []
        files = file_data.get('files', [])
        
        suspicious_locations = [
            'temp', 'tmp', 'appdata', 'programdata', 'public',
            'users\\public', 'windows\\temp', '/tmp/', '/var/tmp/'
        ]
        
        for file_info in files:
            path = file_info.get('path', '').lower()
            extension = file_info.get('extension', '').lower()
            
            # Check for executables in suspicious locations
            if extension in self.suspicious_extensions:
                if any(loc in path for loc in suspicious_locations):
                    suspicious_files.append(file_info)
        
        if len(suspicious_files) > 0:
            finding = Finding(
                finding_id=str(uuid.uuid4()),
                agent_name=self.agent_name,
                severity="HIGH",
                title="Suspicious Files in Unusual Locations",
                description=f"Found {len(suspicious_files)} potentially malicious files in unusual system locations.",
                evidence_ids=[evidence.evidence_id],
                timestamp=datetime.now(),
                confidence=0.70,
                indicators={
                    'suspicious_files': [
                        {'name': f['name'], 'path': f['path'], 'size': f.get('size', 0)}
                        for f in suspicious_files[:10]
                    ]
                },
                recommendations=[
                    "Analyze suspicious files with antivirus and sandbox",
                    "Check file hashes against threat intelligence databases",
                    "Review file creation and modification timestamps",
                    "Investigate parent processes that created these files"
                ],
                mitre_attack="T1204 - User Execution"
            )
            self.add_finding(finding)
    
    def _detect_timestamp_anomalies(self, evidence: Any, file_data: Dict):
        """Detect timestamp manipulation (timestomping)"""
        anomalies = []
        files = file_data.get('files', [])
        
        for file_info in files:
            created = file_info.get('created')
            modified = file_info.get('modified')
            accessed = file_info.get('accessed')
            
            if created and modified:
                try:
                    created_dt = datetime.fromisoformat(created)
                    modified_dt = datetime.fromisoformat(modified)
                    
                    # Modified date before created date (timestomping)
                    if modified_dt < created_dt:
                        anomalies.append({
                            'file': file_info['name'],
                            'issue': 'Modified date before created date',
                            'created': created,
                            'modified': modified
                        })
                    
                    # Very old modified date on recently created file
                    now = datetime.now()
                    if (now - created_dt).days < 7 and (now - modified_dt).days > 365:
                        anomalies.append({
                            'file': file_info['name'],
                            'issue': 'Suspiciously old modification date',
                            'created': created,
                            'modified': modified
                        })
                        
                except Exception as e:
                    continue
        
        if len(anomalies) > 0:
            finding = Finding(
                finding_id=str(uuid.uuid4()),
                agent_name=self.agent_name,
                severity="MEDIUM",
                title="File Timestamp Anomalies Detected",
                description=f"Detected {len(anomalies)} files with suspicious timestamp patterns indicating possible anti-forensics.",
                evidence_ids=[evidence.evidence_id],
                timestamp=datetime.now(),
                confidence=0.80,
                indicators={
                    'anomaly_count': len(anomalies),
                    'anomalies': anomalies[:10]
                },
                recommendations=[
                    "Investigate files with timestamp anomalies",
                    "Check $MFT and journal entries for original timestamps",
                    "Correlate with other evidence sources",
                    "May indicate attacker anti-forensics techniques"
                ],
                mitre_attack="T1070.006 - Indicator Removal: Timestomp"
            )
            self.add_finding(finding)
    
    def _detect_hidden_files(self, evidence: Any, file_data: Dict):
        """Detect hidden files that may be malicious"""
        hidden_files = []
        files = file_data.get('files', [])
        
        for file_info in files:
            is_hidden = file_info.get('is_hidden', False)
            name = file_info.get('name', '')
            
            # Unix hidden files (starting with .)
            if name.startswith('.') or is_hidden:
                hidden_files.append(file_info)
        
        if len(hidden_files) > 20:  # Threshold for suspicious hidden files
            finding = Finding(
                finding_id=str(uuid.uuid4()),
                agent_name=self.agent_name,
                severity="LOW",
                title="Unusual Number of Hidden Files",
                description=f"Detected {len(hidden_files)} hidden files which may warrant investigation.",
                evidence_ids=[evidence.evidence_id],
                timestamp=datetime.now(),
                confidence=0.50,
                indicators={
                    'hidden_files_count': len(hidden_files),
                    'sample_files': [f['name'] for f in hidden_files[:10]]
                },
                recommendations=[
                    "Review hidden files for legitimacy",
                    "Check if hidden files are system or application files",
                    "Investigate any hidden executables"
                ]
            )
            self.add_finding(finding)
    
    def _detect_mass_file_changes(self, evidence: Any, file_data: Dict):
        """Detect mass file modifications in short time period"""
        files = file_data.get('files', [])
        
        # Group files by modification time (within 1 hour windows)
        time_windows = defaultdict(list)
        
        for file_info in files:
            modified = file_info.get('modified')
            if modified:
                try:
                    mod_dt = datetime.fromisoformat(modified)
                    # Group by hour
                    window = mod_dt.replace(minute=0, second=0, microsecond=0)
                    time_windows[window].append(file_info)
                except:
                    continue
        
        # Check for suspicious mass modifications
        for window, modified_files in time_windows.items():
            if len(modified_files) > 50:  # Threshold
                finding = Finding(
                    finding_id=str(uuid.uuid4()),
                    agent_name=self.agent_name,
                    severity="HIGH",
                    title="Mass File Modification Event",
                    description=f"Detected {len(modified_files)} files modified within a 1-hour window at {window}.",
                    evidence_ids=[evidence.evidence_id],
                    timestamp=datetime.now(),
                    confidence=0.75,
                    indicators={
                        'modified_count': len(modified_files),
                        'time_window': window.isoformat(),
                        'sample_files': [f['name'] for f in modified_files[:10]]
                    },
                    recommendations=[
                        "Investigate what caused mass file modifications",
                        "Check for ransomware or wiper malware",
                        "Review system and application logs for this timeframe",
                        "Verify if modifications were authorized"
                    ],
                    mitre_attack="T1485 - Data Destruction"
                )
                self.add_finding(finding)
    
    def _ai_file_analysis(self, evidence: Any, file_data: Dict):
        """Use LLM for advanced file pattern analysis"""
        files = file_data.get('files', [])[:20]  # Sample
        
        file_summary = "\n".join([
            f"- {f.get('name')} ({f.get('extension')}) in {f.get('path')} [Size: {f.get('size', 0)} bytes]"
            for f in files
        ])
        
        prompt = f"""Analyze the following file system artifacts for security concerns:

{file_summary}

Look for:
1. Suspicious file patterns or naming conventions
2. Indicators of malware or intrusion
3. Data exfiltration staging
4. Unusual file locations or configurations

Provide security assessment."""

        try:
            analysis = self._query_llm(prompt)
            
            if analysis and len(analysis) > 50:
                finding = Finding(
                    finding_id=str(uuid.uuid4()),
                    agent_name=self.agent_name,
                    severity="INFO",
                    title="AI-Powered File System Analysis",
                    description=analysis,
                    evidence_ids=[evidence.evidence_id],
                    timestamp=datetime.now(),
                    confidence=0.65,
                    indicators={'analysis_type': 'LLM-based file analysis'},
                    recommendations=["Verify AI findings with manual analysis"]
                )
                self.add_finding(finding)
        except Exception as e:
            self.log(f"AI file analysis failed: {e}", "WARNING")