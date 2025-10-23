"""
File Analysis Agent - Analyzes file metadata for suspicious patterns
"""
import json
import uuid
import math
from datetime import datetime, timedelta
from typing import List, Any, Dict
from collections import defaultdict
from agents.base_agent import BaseAgent
from models.finding import Finding, FindingType, Severity, MitreTactic


class FileAnalysisAgent(BaseAgent):
    """Analyzes file metadata and filesystem artifacts"""
    
    def __init__(self, llm_client=None):
        super().__init__(
            agent_name="FileAnalysisAgent",
            agent_description="Analyzes file metadata, timestamps, and filesystem artifacts for suspicious patterns",
            llm_client=llm_client
        )
        
        # Initialize findings list if not done by parent
        if not hasattr(self, 'findings'):
            self.findings = []
        
        # Suspicious file extensions
        self.suspicious_extensions = [
            '.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js',
            '.scr', '.pif', '.msi', '.hta', '.jar', '.sh', '.elf',
            '.com', '.deb', '.rpm', '.dmg', '.iso', '.apk'
        ]
        
        # Ransomware file extensions
        self.ransomware_extensions = [
            '.encrypted', '.locked', '.crypto', '.crypt', '.cerber',
            '.locky', '.zepto', '.odin', '.thor', '.aesir', '.wannacry',
            '.cryptowall', '.tesla', '.dharma', '.phobos', '.conti'
        ]
        
        # Suspicious file names and patterns
        self.suspicious_patterns = [
            'malware', 'virus', 'trojan', 'backdoor', 'keylogger',
            'ransomware', 'cryptor', 'miner', 'botnet', 'c2',
            'payload', 'shell', 'reverse', 'bind', 'connect',
            'hidden', 'stealth', 'obfuscated', 'packed', 'encoded',
            'mimikatz', 'procdump', 'psexec', 'credential'
        ]
        
        # Suspicious locations
        self.suspicious_paths = [
            'temp', 'tmp', 'cache', 'cookies', 'appdata',
            'programdata', 'public', 'users\\public',
            'windows\\temp', '/tmp/', '/var/tmp/', '/dev/shm/',
            'system32\\config', 'system32\\drivers', 'downloads'
        ]
    
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
        """
        Analyze file evidence
        
        Args:
            evidence_items: List of file evidence items
            
        Returns:
            List of findings
        """
        self.clear_findings()
        
        if not evidence_items:
            return self.findings
        
        print(f"[{self.agent_name}] Analyzing {len(evidence_items)} evidence items...")
        
        for evidence in evidence_items:
            try:
                if evidence.evidence_type == "file":
                    # Handle individual file evidence
                    self._analyze_single_file(evidence)
                elif evidence.evidence_type == "file_metadata":
                    # Handle JSON metadata evidence (legacy)
                    try:
                        content = evidence.data.decode('utf-8')
                        file_data = json.loads(content)
                        # Run analysis functions
                        self._detect_ransomware_indicators(evidence, file_data)
                        self._detect_suspicious_files(evidence, file_data)
                        self._detect_timestamp_anomalies(evidence, file_data)
                        self._detect_hidden_files(evidence, file_data)
                        self._detect_mass_file_changes(evidence, file_data)
                        
                        # AI analysis if available
                        if self.llm_client:
                            self._ai_file_analysis(evidence, file_data)
                    except json.JSONDecodeError as e:
                        print(f"[{self.agent_name}] Failed to parse file metadata: {e}")
            except Exception as e:
                print(f"[{self.agent_name}] Error processing evidence {evidence.evidence_id}: {e}")
        
        print(f"[{self.agent_name}] Analysis complete. Generated {len(self.findings)} findings.")
        return self.findings
    
    def _analyze_single_file(self, evidence: Any):
        """Analyze a single file evidence item"""
        try:
            # Extract file information from evidence
            file_path = evidence.source_path or ""
            file_name = evidence.metadata.get('filename', '')
            file_extension = evidence.metadata.get('file_extension', '')
            file_size = evidence.metadata.get('file_size', 0)
            content = evidence.data
            
            if not file_name and file_path:
                # Extract filename from path if not in metadata
                file_name = file_path.split('/')[-1].split('\\')[-1]
            
            if not file_extension and file_name:
                # Extract extension from filename
                if '.' in file_name:
                    file_extension = '.' + file_name.split('.')[-1]
            
            # Analyze file for various threats
            self._check_single_file_suspicious(evidence, file_path, file_name, file_extension, content, file_size)
            self._check_file_content(evidence, content, file_name)
            self._check_file_location(evidence, file_path, file_name, file_extension)
            
        except Exception as e:
            print(f"[{self.agent_name}] Error analyzing file {getattr(evidence, 'source_path', 'unknown')}: {e}")
    
    def _check_single_file_suspicious(self, evidence: Any, file_path: str, file_name: str, 
                                     file_extension: str, content: bytes, file_size: int):
        """Check if a single file is suspicious"""
        suspicious_reasons = []
        risk_score = 0
        
        # Check file extension
        if file_extension.lower() in self.suspicious_extensions:
            suspicious_reasons.append("suspicious_extension")
            risk_score += 3
        
        # Check file name patterns
        file_name_lower = file_name.lower()
        for pattern in self.suspicious_patterns:
            if pattern in file_name_lower:
                suspicious_reasons.append(f"suspicious_pattern_{pattern}")
                risk_score += 4
                break  # Only count once
        
        # Check file location
        file_path_lower = file_path.lower()
        for loc in self.suspicious_paths:
            if loc in file_path_lower:
                suspicious_reasons.append("suspicious_location")
                risk_score += 2
                break  # Only count once
        
        # Check for ransomware extensions
        for ext in self.ransomware_extensions:
            if ext in file_extension.lower():
                suspicious_reasons.append("ransomware_extension")
                risk_score += 5
                break
        
        # Check if hidden file (Unix-style)
        if file_name.startswith('.') and len(file_name) > 1:
            suspicious_reasons.append("hidden_file")
            risk_score += 2
        
        # Check file size anomalies
        if file_size == 0:
            suspicious_reasons.append("zero_byte_file")
            risk_score += 1
        elif file_size > 100 * 1024 * 1024:  # > 100MB
            suspicious_reasons.append("unusually_large_file")
            risk_score += 1
        
        # Check file content for suspicious strings (only for small files)
        if content and len(content) < 1000000:  # Only for files < 1MB
            try:
                content_str = content.decode('utf-8', errors='ignore').lower()
                suspicious_keywords = [
                    'malware', 'virus', 'trojan', 'backdoor', 'keylogger',
                    'password', 'credential', 'mimikatz', 'psexec',
                    'nc.exe', 'cmd.exe /c', 'powershell -enc', 'base64'
                ]
                keyword_hits = 0
                for keyword in suspicious_keywords:
                    if keyword in content_str:
                        suspicious_reasons.append(f"keyword_{keyword.replace(' ', '_')}")
                        keyword_hits += 1
                        if keyword_hits >= 3:  # Cap keyword score
                            break
                risk_score += min(keyword_hits, 3)
            except Exception:
                pass
        
        # Generate finding if suspicious
        if suspicious_reasons and risk_score >= 3:
            severity = Severity.CRITICAL if risk_score >= 8 else Severity.HIGH if risk_score >= 5 else Severity.MEDIUM
            
            finding = Finding(
                finding_id=str(uuid.uuid4()),
                type=FindingType.SUSPICIOUS_FILE,
                severity=severity,
                title=f"Suspicious File Detected: {file_name}",
                description=f"File '{file_name}' exhibits {len(suspicious_reasons)} suspicious indicators (risk score: {risk_score}).",
                evidence_ids=[evidence.evidence_id],
                timestamp=datetime.now(),
                confidence=min(0.95, 0.5 + (risk_score / 20)),
                agent_name=self.agent_name,
                mitre_tactics=[MitreTactic.EXECUTION],
                mitre_techniques=["T1204.002"],  # User Execution: Malicious File
                iocs=[file_path] if file_path else [file_name],
                remediation=[
                    f"Quarantine file: {file_name}",
                    "Scan with multiple antivirus engines",
                    "Analyze file hash against threat intelligence databases",
                    "Review file creation/modification timestamps",
                    "Check process execution history",
                    "Inspect file with sandbox or static analysis tools"
                ],
                metadata={
                    'file_path': file_path,
                    'file_name': file_name,
                    'file_extension': file_extension,
                    'file_size': file_size,
                    'suspicious_reasons': suspicious_reasons,
                    'risk_score': risk_score
                }
            )
            self.add_finding(finding)
    
    def _check_file_content(self, evidence: Any, content: bytes, file_name: str):
        """Check file content for specific threats"""
        if not content or len(content) < 100:
            return
        
        # Check for high entropy (potential encryption/packing)
        sample_size = min(1000, len(content))
        entropy = self._calculate_entropy(content[:sample_size])
        
        if entropy > 7.0:
            finding = Finding(
                finding_id=str(uuid.uuid4()),
                type=FindingType.ANOMALY,
                severity=Severity.MEDIUM,
                title=f"High Entropy Content: {file_name}",
                description=f"File exhibits high entropy ({entropy:.2f}/8.0), potentially indicating encrypted, packed, or obfuscated content.",
                evidence_ids=[evidence.evidence_id],
                timestamp=datetime.now(),
                confidence=0.70 if entropy < 7.5 else 0.85,
                agent_name=self.agent_name,
                mitre_tactics=[MitreTactic.DEFENSE_EVASION],
                mitre_techniques=["T1027"],  # Obfuscated Files or Information
                remediation=[
                    "Analyze file with entropy visualization tools",
                    "Check for known packers (UPX, ASPack, etc.)",
                    "Attempt unpacking with automated tools",
                    "Submit to sandbox for behavioral analysis",
                    "Verify if file is legitimate encrypted application data"
                ],
                metadata={
                    'entropy': round(entropy, 3),
                    'sample_size': sample_size,
                    'file_size': len(content),
                    'entropy_threshold': 7.0
                }
            )
            self.add_finding(finding)
        
        # Check for embedded executables (MZ header)
        if b'MZ' in content[:100] or b'PE\x00\x00' in content[:1000]:
            finding = Finding(
                finding_id=str(uuid.uuid4()),
                type=FindingType.SUSPICIOUS_FILE,
                severity=Severity.HIGH,
                title=f"Embedded Executable Detected: {file_name}",
                description="File contains executable code signatures, possibly indicating embedded malware or droppers.",
                evidence_ids=[evidence.evidence_id],
                timestamp=datetime.now(),
                confidence=0.88,
                agent_name=self.agent_name,
                mitre_tactics=[MitreTactic.EXECUTION, MitreTactic.DEFENSE_EVASION],
                mitre_techniques=["T1027.009"],  # Embedded Payloads
                remediation=[
                    "Extract and analyze embedded executable",
                    "Scan with antivirus and behavioral analysis",
                    "Check digital signatures",
                    "Review file origin and download source"
                ],
                metadata={
                    'has_mz_header': b'MZ' in content[:100],
                    'has_pe_header': b'PE\x00\x00' in content[:1000]
                }
            )
            self.add_finding(finding)
    
    def _calculate_entropy(self, data: bytes) -> float:
        """
        Calculate Shannon entropy of byte data
        
        Args:
            data: Byte data to analyze
            
        Returns:
            Entropy value (0-8, where 8 is maximum randomness)
        """
        if not data:
            return 0.0
        
        # Count byte frequencies
        byte_counts = defaultdict(int)
        for byte in data:
            byte_counts[byte] += 1
        
        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        
        for count in byte_counts.values():
            if count > 0:
                probability = count / data_len
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _check_file_location(self, evidence: Any, file_path: str, file_name: str, file_extension: str):
        """Check if file is in a suspicious location"""
        if not file_path:
            return
        
        file_path_lower = file_path.lower()
        suspicious_location = None
        
        for loc in self.suspicious_paths:
            if loc in file_path_lower:
                suspicious_location = loc
                break
        
        if suspicious_location and file_extension.lower() in self.suspicious_extensions:
            finding = Finding(
                finding_id=str(uuid.uuid4()),
                type=FindingType.SUSPICIOUS_FILE,
                severity=Severity.HIGH,
                title=f"Executable in Suspicious Location: {file_name}",
                description=f"Executable file found in suspicious system location ('{suspicious_location}'): {file_path}",
                evidence_ids=[evidence.evidence_id],
                timestamp=datetime.now(),
                confidence=0.80,
                agent_name=self.agent_name,
                mitre_tactics=[MitreTactic.EXECUTION, MitreTactic.PERSISTENCE],
                mitre_techniques=["T1204.002", "T1574"],
                iocs=[file_path],
                remediation=[
                    "Quarantine the suspicious executable",
                    "Analyze file hash against threat intelligence",
                    "Review file creation timestamp and parent process",
                    "Check for persistence mechanisms",
                    "Scan with multiple antivirus engines"
                ],
                metadata={
                    'file_path': file_path,
                    'file_name': file_name,
                    'suspicious_location': suspicious_location,
                    'file_extension': file_extension
                }
            )
            self.add_finding(finding)
    
    def _detect_ransomware_indicators(self, evidence: Any, file_data: dict):
        """Detect ransomware indicators from file metadata"""
        ransomware_count = 0
        affected_files = []
        
        files = file_data.get('files', [])
        for file_info in files:
            file_name = file_info.get('name', '')
            file_ext = file_info.get('extension', '')
            
            if any(ext in file_ext.lower() for ext in self.ransomware_extensions):
                ransomware_count += 1
                affected_files.append(file_name)
        
        if ransomware_count > 5:  # Threshold for ransomware alert
            finding = Finding(
                finding_id=str(uuid.uuid4()),
                type=FindingType.MALWARE,
                severity=Severity.CRITICAL,
                title="Potential Ransomware Activity Detected",
                description=f"Detected {ransomware_count} files with ransomware-associated extensions, indicating possible encryption attack.",
                evidence_ids=[evidence.evidence_id],
                timestamp=datetime.now(),
                confidence=0.90,
                agent_name=self.agent_name,
                mitre_tactics=[MitreTactic.IMPACT],
                mitre_techniques=["T1486"],  # Data Encrypted for Impact
                iocs=affected_files[:10],
                remediation=[
                    "CRITICAL: Immediately isolate affected systems from network",
                    "Identify ransomware variant for decryption options",
                    "Check for available decryptors (No More Ransom project)",
                    "Do NOT pay ransom without consulting authorities",
                    "Restore from clean, verified backups",
                    "Report to incident response team and law enforcement",
                    "Preserve forensic evidence for investigation"
                ],
                metadata={
                    'ransomware_file_count': ransomware_count,
                    'sample_files': affected_files[:20],
                    'detection_threshold': 5
                }
            )
            self.add_finding(finding)
    
    def _detect_suspicious_files(self, evidence: Any, file_data: dict):
        """Detect suspicious files from metadata"""
        suspicious_count = 0
        files = file_data.get('files', [])
        
        for file_info in files:
            file_name = file_info.get('name', '')
            file_ext = file_info.get('extension', '')
            
            # Check for suspicious patterns
            if any(pattern in file_name.lower() for pattern in self.suspicious_patterns):
                suspicious_count += 1
            elif file_ext.lower() in self.suspicious_extensions:
                suspicious_count += 1
        
        if suspicious_count > 0:
            print(f"[{self.agent_name}] Detected {suspicious_count} suspicious files in metadata")
    
    def _detect_timestamp_anomalies(self, evidence: Any, file_data: dict):
        """Detect timestamp anomalies (timestomping)"""
        files = file_data.get('files', [])
        anomalies = []
        
        for file_info in files:
            created = file_info.get('created')
            modified = file_info.get('modified')
            accessed = file_info.get('accessed')
            
            # Check for suspicious timestamp patterns
            if created and modified:
                if created > modified:  # Created after modified (impossible)
                    anomalies.append(file_info.get('name'))
        
        if len(anomalies) > 3:
            print(f"[{self.agent_name}] Detected {len(anomalies)} timestamp anomalies")
    
    def _detect_hidden_files(self, evidence: Any, file_data: dict):
        """Detect hidden files"""
        files = file_data.get('files', [])
        hidden_count = sum(1 for f in files if f.get('name', '').startswith('.'))
        
        if hidden_count > 10:
            print(f"[{self.agent_name}] Detected {hidden_count} hidden files")
    
    def _detect_mass_file_changes(self, evidence: Any, file_data: dict):
        """Detect mass file changes (possible ransomware)"""
        files = file_data.get('files', [])
        
        # Group files by modification time
        time_groups = defaultdict(int)
        for file_info in files:
            modified = file_info.get('modified')
            if modified:
                # Group by minute
                time_key = modified[:16] if isinstance(modified, str) else str(modified)[:16]
                time_groups[time_key] += 1
        
        # Check for mass modifications
        max_changes = max(time_groups.values()) if time_groups else 0
        if max_changes > 50:
            print(f"[{self.agent_name}] Detected mass file changes: {max_changes} files modified in same minute")
    
    def _ai_file_analysis(self, evidence: Any, file_data: dict):
        """AI-powered file analysis"""
        if not self.llm_client:
            return
        
        try:
            # Prepare file summary for AI analysis
            files = file_data.get('files', [])
            summary = {
                'total_files': len(files),
                'suspicious_extensions': [],
                'suspicious_names': [],
                'locations': set()
            }
            
            for file_info in files:
                file_name = file_info.get('name', '')
                file_ext = file_info.get('extension', '')
                file_path = file_info.get('path', '')
                
                if file_ext in self.suspicious_extensions:
                    summary['suspicious_extensions'].append(file_ext)
                if any(p in file_name.lower() for p in self.suspicious_patterns):
                    summary['suspicious_names'].append(file_name)
                if file_path:
                    summary['locations'].add(file_path.split('/')[0])
            
            # AI analysis would go here
            print(f"[{self.agent_name}] AI analysis: {summary['total_files']} files analyzed")
            
        except Exception as e:
            print(f"[{self.agent_name}] AI analysis error: {e}")