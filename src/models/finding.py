"""
Finding model for forensic analysis results.

This module defines the data structure for security findings
discovered during forensic analysis.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Optional, Any
from enum import Enum


class Severity(Enum):
    """Severity levels for findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    
    def __lt__(self, other):
        """Enable severity comparison."""
        order = {
            'critical': 5,
            'high': 4,
            'medium': 3,
            'low': 2,
            'info': 1
        }
        return order[self.value] < order[other.value]
    
    def __gt__(self, other):
        """Enable severity comparison."""
        order = {
            'critical': 5,
            'high': 4,
            'medium': 3,
            'low': 2,
            'info': 1
        }
        return order[self.value] > order[other.value]


class FindingType(Enum):
    """Types of security findings."""
    BRUTE_FORCE = "brute_force"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFILTRATION = "data_exfiltration"
    MALWARE = "malware"
    RANSOMWARE = "ransomware"
    C2_COMMUNICATION = "c2_communication"
    PORT_SCAN = "port_scan"
    SUSPICIOUS_PROCESS = "suspicious_process"
    SUSPICIOUS_FILE = "suspicious_file"
    SUSPICIOUS_NETWORK = "suspicious_network"
    CREDENTIAL_ACCESS = "credential_access"
    PERSISTENCE = "persistence"
    DEFENSE_EVASION = "defense_evasion"
    DISCOVERY = "discovery"
    COLLECTION = "collection"
    IMPACT = "impact"
    ANOMALY = "anomaly"
    OTHER = "other"


class MitreTactic(Enum):
    """MITRE ATT&CK Tactics."""
    INITIAL_ACCESS = "TA0001"
    EXECUTION = "TA0002"
    PERSISTENCE = "TA0003"
    PRIVILEGE_ESCALATION = "TA0004"
    DEFENSE_EVASION = "TA0005"
    CREDENTIAL_ACCESS = "TA0006"
    DISCOVERY = "TA0007"
    LATERAL_MOVEMENT = "TA0008"
    COLLECTION = "TA0009"
    COMMAND_AND_CONTROL = "TA0011"
    EXFILTRATION = "TA0010"
    IMPACT = "TA0040"


@dataclass
class Finding:
    """
    Represents a security finding from forensic analysis.
    
    Attributes:
        finding_id: Unique identifier for the finding
        type: Type of finding
        severity: Severity level
        title: Short title describing the finding
        description: Detailed description
        evidence_ids: List of related evidence IDs
        timestamp: When the finding occurred
        confidence: Confidence score (0.0 to 1.0)
        agent_name: Name of AI agent that discovered the finding
        mitre_tactics: MITRE ATT&CK tactics
        mitre_techniques: MITRE ATT&CK techniques
        iocs: Indicators of Compromise
        affected_systems: List of affected systems/hosts
        affected_users: List of affected user accounts
        remediation: Recommended remediation steps
        references: External references/links
        metadata: Additional metadata
        created_at: When the finding was created
    """
    
    finding_id: str
    type: FindingType
    severity: Severity
    title: str
    description: str
    evidence_ids: List[str]
    timestamp: datetime
    confidence: float
    agent_name: str
    
    # MITRE ATT&CK Mapping
    mitre_tactics: List[MitreTactic] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    
    # Technical Details
    iocs: List[str] = field(default_factory=list)
    affected_systems: List[str] = field(default_factory=list)
    affected_users: List[str] = field(default_factory=list)
    
    # Response Information
    remediation: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    
    # Additional Data
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)
    
    def __post_init__(self):
        """Validate finding data after initialization."""
        # Validate confidence score
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"Confidence must be between 0.0 and 1.0, got {self.confidence}")
        
        # Convert string enums to proper enums if needed
        if isinstance(self.type, str):
            self.type = FindingType(self.type)
        
        if isinstance(self.severity, str):
            self.severity = Severity(self.severity)
        
        # Ensure timestamp is datetime
        if isinstance(self.timestamp, str):
            self.timestamp = datetime.fromisoformat(self.timestamp.replace('Z', '+00:00'))
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert finding to dictionary format.
        
        Returns:
            Dictionary representation of the finding
        """
        return {
            'finding_id': self.finding_id,
            'type': self.type.value,
            'severity': self.severity.value,
            'title': self.title,
            'description': self.description,
            'evidence_ids': self.evidence_ids,
            'timestamp': self.timestamp.isoformat(),
            'confidence': self.confidence,
            'agent_name': self.agent_name,
            'mitre_tactics': [t.value for t in self.mitre_tactics],
            'mitre_techniques': self.mitre_techniques,
            'iocs': self.iocs,
            'affected_systems': self.affected_systems,
            'affected_users': self.affected_users,
            'remediation': self.remediation,
            'references': self.references,
            'metadata': self.metadata,
            'created_at': self.created_at.isoformat()
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Finding':
        """
        Create Finding from dictionary.
        
        Args:
            data: Dictionary containing finding data
            
        Returns:
            Finding instance
        """
        # Convert string values back to enums
        if 'type' in data and isinstance(data['type'], str):
            data['type'] = FindingType(data['type'])
        
        if 'severity' in data and isinstance(data['severity'], str):
            data['severity'] = Severity(data['severity'])
        
        if 'mitre_tactics' in data:
            data['mitre_tactics'] = [MitreTactic(t) if isinstance(t, str) else t 
                                     for t in data['mitre_tactics']]
        
        return cls(**data)
    
    def is_critical(self) -> bool:
        """Check if finding is critical severity."""
        return self.severity == Severity.CRITICAL
    
    def is_high_confidence(self, threshold: float = 0.8) -> bool:
        """
        Check if finding has high confidence.
        
        Args:
            threshold: Confidence threshold (default: 0.8)
            
        Returns:
            True if confidence exceeds threshold
        """
        return self.confidence >= threshold
    
    def add_ioc(self, ioc: str) -> None:
        """
        Add an Indicator of Compromise.
        
        Args:
            ioc: IOC to add (IP, hash, domain, etc.)
        """
        if ioc not in self.iocs:
            self.iocs.append(ioc)
    
    def add_affected_system(self, system: str) -> None:
        """
        Add an affected system.
        
        Args:
            system: System hostname or identifier
        """
        if system not in self.affected_systems:
            self.affected_systems.append(system)
    
    def add_affected_user(self, user: str) -> None:
        """
        Add an affected user account.
        
        Args:
            user: Username or account identifier
        """
        if user not in self.affected_users:
            self.affected_users.append(user)
    
    def add_remediation_step(self, step: str) -> None:
        """
        Add a remediation step.
        
        Args:
            step: Remediation action to take
        """
        if step not in self.remediation:
            self.remediation.append(step)
    
    def get_summary(self) -> str:
        """
        Get a brief summary of the finding.
        
        Returns:
            Human-readable summary string
        """
        return (f"[{self.severity.value.upper()}] {self.title} "
                f"(Confidence: {self.confidence:.0%})")
    
    def __str__(self) -> str:
        """String representation of the finding."""
        return self.get_summary()
    
    def __repr__(self) -> str:
        """Detailed representation of the finding."""
        return (f"Finding(id='{self.finding_id}', "
                f"type={self.type.value}, "
                f"severity={self.severity.value}, "
                f"confidence={self.confidence})")


@dataclass
class FindingCollection:
    """
    Collection of findings for a case.
    
    Attributes:
        case_id: Case identifier
        findings: List of findings
        created_at: When collection was created
    """
    
    case_id: str
    findings: List[Finding] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)
    
    def add_finding(self, finding: Finding) -> None:
        """
        Add a finding to the collection.
        
        Args:
            finding: Finding to add
        """
        self.findings.append(finding)
    
    def get_by_severity(self, severity: Severity) -> List[Finding]:
        """
        Get findings by severity level.
        
        Args:
            severity: Severity level to filter by
            
        Returns:
            List of findings with specified severity
        """
        return [f for f in self.findings if f.severity == severity]
    
    def get_by_type(self, finding_type: FindingType) -> List[Finding]:
        """
        Get findings by type.
        
        Args:
            finding_type: Type to filter by
            
        Returns:
            List of findings of specified type
        """
        return [f for f in self.findings if f.type == finding_type]
    
    def get_critical_findings(self) -> List[Finding]:
        """Get all critical severity findings."""
        return self.get_by_severity(Severity.CRITICAL)
    
    def get_high_confidence_findings(self, threshold: float = 0.8) -> List[Finding]:
        """
        Get high confidence findings.
        
        Args:
            threshold: Confidence threshold
            
        Returns:
            List of high confidence findings
        """
        return [f for f in self.findings if f.is_high_confidence(threshold)]
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about the findings.
        
        Returns:
            Dictionary with finding statistics
        """
        return {
            'total_findings': len(self.findings),
            'by_severity': {
                'critical': len(self.get_by_severity(Severity.CRITICAL)),
                'high': len(self.get_by_severity(Severity.HIGH)),
                'medium': len(self.get_by_severity(Severity.MEDIUM)),
                'low': len(self.get_by_severity(Severity.LOW)),
                'info': len(self.get_by_severity(Severity.INFO))
            },
            'high_confidence_count': len(self.get_high_confidence_findings()),
            'average_confidence': sum(f.confidence for f in self.findings) / len(self.findings) if self.findings else 0.0,
            'unique_iocs': len(set(ioc for f in self.findings for ioc in f.iocs)),
            'affected_systems': len(set(sys for f in self.findings for sys in f.affected_systems)),
            'affected_users': len(set(user for f in self.findings for user in f.affected_users))
        }
    
    def sort_by_severity(self, reverse: bool = True) -> None:
        """
        Sort findings by severity.
        
        Args:
            reverse: If True, sort from critical to info (default: True)
        """
        self.findings.sort(key=lambda f: f.severity, reverse=reverse)
    
    def sort_by_confidence(self, reverse: bool = True) -> None:
        """
        Sort findings by confidence.
        
        Args:
            reverse: If True, sort from high to low confidence (default: True)
        """
        self.findings.sort(key=lambda f: f.confidence, reverse=reverse)
    
    def sort_by_timestamp(self, reverse: bool = False) -> None:
        """
        Sort findings by timestamp.
        
        Args:
            reverse: If True, sort newest first (default: False)
        """
        self.findings.sort(key=lambda f: f.timestamp, reverse=reverse)
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert collection to dictionary.
        
        Returns:
            Dictionary representation
        """
        return {
            'case_id': self.case_id,
            'findings': [f.to_dict() for f in self.findings],
            'created_at': self.created_at.isoformat(),
            'statistics': self.get_statistics()
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'FindingCollection':
        """
        Create FindingCollection from dictionary.
        
        Args:
            data: Dictionary containing collection data
            
        Returns:
            FindingCollection instance
        """
        collection = cls(case_id=data['case_id'])
        
        if 'findings' in data:
            collection.findings = [Finding.from_dict(f) for f in data['findings']]
        
        if 'created_at' in data:
            collection.created_at = datetime.fromisoformat(data['created_at'])
        
        return collection
    
    def __len__(self) -> int:
        """Get number of findings in collection."""
        return len(self.findings)
    
    def __iter__(self):
        """Iterate over findings."""
        return iter(self.findings)
    
    def __getitem__(self, index: int) -> Finding:
        """Get finding by index."""
        return self.findings[index]


# Helper functions for creating findings

def create_brute_force_finding(
    finding_id: str,
    evidence_ids: List[str],
    timestamp: datetime,
    confidence: float,
    target_account: str,
    source_ip: str,
    attempt_count: int,
    agent_name: str = "LogAnalysisAgent"
) -> Finding:
    """
    Create a brute force attack finding.
    
    Args:
        finding_id: Unique identifier
        evidence_ids: Related evidence IDs
        timestamp: Time of attack
        confidence: Confidence score
        target_account: Targeted account name
        source_ip: Source IP address
        attempt_count: Number of failed attempts
        agent_name: Name of detecting agent
        
    Returns:
        Finding instance
    """
    return Finding(
        finding_id=finding_id,
        type=FindingType.BRUTE_FORCE,
        severity=Severity.HIGH if attempt_count > 5 else Severity.MEDIUM,
        title=f"Brute Force Attack Against Account '{target_account}'",
        description=f"Detected {attempt_count} failed login attempts against account '{target_account}' from IP {source_ip}. "
                   f"This pattern is consistent with password guessing or credential stuffing attacks.",
        evidence_ids=evidence_ids,
        timestamp=timestamp,
        confidence=confidence,
        agent_name=agent_name,
        mitre_tactics=[MitreTactic.CREDENTIAL_ACCESS],
        mitre_techniques=["T1110"],
        iocs=[source_ip],
        affected_users=[target_account],
        remediation=[
            f"Disable or reset password for account '{target_account}'",
            f"Block source IP {source_ip} at firewall",
            "Implement account lockout policy",
            "Enable multi-factor authentication",
            "Review other accounts for similar activity"
        ]
    )


def create_malware_finding(
    finding_id: str,
    evidence_ids: List[str],
    timestamp: datetime,
    confidence: float,
    file_path: str,
    file_hash: str,
    malware_family: str = "Unknown",
    agent_name: str = "FileAnalysisAgent"
) -> Finding:
    """
    Create a malware detection finding.
    
    Args:
        finding_id: Unique identifier
        evidence_ids: Related evidence IDs
        timestamp: Time of detection
        confidence: Confidence score
        file_path: Path to malicious file
        file_hash: SHA-256 hash of file
        malware_family: Malware family name
        agent_name: Name of detecting agent
        
    Returns:
        Finding instance
    """
    return Finding(
        finding_id=finding_id,
        type=FindingType.MALWARE,
        severity=Severity.CRITICAL,
        title=f"Malware Detected: {malware_family}",
        description=f"Malicious file detected at '{file_path}'. File exhibits characteristics "
                   f"consistent with {malware_family} malware family.",
        evidence_ids=evidence_ids,
        timestamp=timestamp,
        confidence=confidence,
        agent_name=agent_name,
        mitre_tactics=[MitreTactic.EXECUTION],
        mitre_techniques=["T1204"],
        iocs=[file_hash, file_path],
        remediation=[
            f"Quarantine file: {file_path}",
            "Scan all systems for similar IOCs",
            "Submit sample to malware analysis lab",
            "Review process execution logs",
            "Check for additional persistence mechanisms"
        ]
    )


def create_data_exfiltration_finding(
    finding_id: str,
    evidence_ids: List[str],
    timestamp: datetime,
    confidence: float,
    destination_ip: str,
    data_volume_mb: float,
    agent_name: str = "NetworkAnalysisAgent"
) -> Finding:
    """
    Create a data exfiltration finding.
    
    Args:
        finding_id: Unique identifier
        evidence_ids: Related evidence IDs
        timestamp: Time of exfiltration
        confidence: Confidence score
        destination_ip: Destination IP address
        data_volume_mb: Volume of data in MB
        agent_name: Name of detecting agent
        
    Returns:
        Finding instance
    """
    return Finding(
        finding_id=finding_id,
        type=FindingType.DATA_EXFILTRATION,
        severity=Severity.CRITICAL,
        title=f"Data Exfiltration to External IP",
        description=f"Large outbound data transfer detected to external IP {destination_ip}. "
                   f"Approximately {data_volume_mb:.1f} MB of data was transferred, consistent with data theft.",
        evidence_ids=evidence_ids,
        timestamp=timestamp,
        confidence=confidence,
        agent_name=agent_name,
        mitre_tactics=[MitreTactic.EXFILTRATION],
        mitre_techniques=["T1041"],
        iocs=[destination_ip],
        remediation=[
            f"Block destination IP {destination_ip}",
            "Identify source of exfiltrated data",
            "Implement DLP solution",
            "Review firewall logs for similar transfers",
            "Notify affected parties per breach notification requirements"
        ]
    )