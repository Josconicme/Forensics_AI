# src/reporting/report_generator.py
"""
Automated forensic report generation
"""
from datetime import datetime
from typing import List, Dict, Any
from pathlib import Path
import json
import sys
sys.path.append(str(Path(__file__).parent.parent))

from models.evidence import Finding, Evidence
from storage.evidence_store import EvidenceStore


class ReportGenerator:
    """Generates comprehensive forensic reports"""
    
    def __init__(self, output_dir: str = "./output/reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_markdown_report(
        self,
        findings: List[Finding],
        evidence_store: EvidenceStore,
        timeline: List[Dict[str, Any]],
        summary_stats: Dict[str, Any],
        case_name: str = "Digital Forensics Investigation"
    ) -> str:
        """Generate comprehensive markdown report"""
        
        report_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        report_filename = f"forensic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        report_path = self.output_dir / report_filename
        
        # Build report content
        report_lines = []
        
        # Header
        report_lines.append(f"# Forensic Investigation Report")
        report_lines.append(f"## {case_name}\n")
        report_lines.append(f"**Report Generated:** {report_timestamp}\n")
        report_lines.append(f"**Report ID:** {report_filename}\n")
        report_lines.append("---\n")
        
        # Executive Summary
        report_lines.append("## Executive Summary\n")
        report_lines.append(f"This forensic investigation analyzed **{summary_stats.get('evidence_analyzed', 0)} pieces of evidence** ")
        report_lines.append(f"and identified **{summary_stats.get('total_findings', 0)} security findings**.\n")
        
        critical_high = summary_stats.get('high_severity_count', 0)
        if critical_high > 0:
            report_lines.append(f"⚠️ **{critical_high} high-severity findings require immediate attention.**\n")
        
        report_lines.append(f"Average finding confidence: **{summary_stats.get('average_confidence', 0):.0%}**\n")
        report_lines.append("---\n")
        
        # Key Findings Summary
        report_lines.append("## Key Findings Summary\n")
        severity_counts = summary_stats.get('findings_by_severity', {})
        
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            count = severity_counts.get(severity, 0)
            if count > 0:
                icon = self._get_severity_icon(severity)
                report_lines.append(f"- {icon} **{severity.upper()}**: {count} finding(s)")
        
        report_lines.append("\n---\n")
        
        # Detailed Findings
        report_lines.append("## Detailed Findings\n")
        
        for idx, finding in enumerate(findings, 1):
            icon = self._get_severity_icon(finding.severity)
            report_lines.append(f"### {idx}. {icon} {finding.title}\n")
            report_lines.append(f"**Finding ID:** `{finding.finding_id}`  ")
            report_lines.append(f"**Severity:** {finding.severity.upper()}  ")
            report_lines.append(f"**Confidence:** {finding.confidence:.0%}  ")
            report_lines.append(f"**Timestamp:** {finding.timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n")
            
            report_lines.append(f"**Description:**  \n{finding.description}\n")
            
            # Indicators
            if finding.indicators:
                report_lines.append("**Key Indicators:**")
                for key, value in finding.indicators.items():
                    report_lines.append(f"- {key}: `{value}`")
                report_lines.append("")
            
            # Evidence references
            if finding.evidence_ids:
                report_lines.append(f"**Related Evidence:** {', '.join([f'`{eid}`' for eid in finding.evidence_ids])}\n")
            
            # Recommendations
            if finding.recommendations:
                report_lines.append("**Recommendations:**")
                for rec in finding.recommendations:
                    report_lines.append(f"- {rec}")
                report_lines.append("")
            
            report_lines.append("---\n")
        
        # Timeline
        report_lines.append("## Incident Timeline\n")
        report_lines.append("Chronological sequence of events based on evidence analysis:\n")
        
        for event in timeline[-20:]:  # Show last 20 events
            timestamp_str = event['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
            event_type = event.get('event_type', 'unknown')
            
            if event_type == 'finding':
                severity = event.get('severity', 'info')
                icon = self._get_severity_icon(severity)
                report_lines.append(f"- **{timestamp_str}** {icon} {event['description']}")
            else:
                report_lines.append(f"- **{timestamp_str}** 📁 {event['description']}")
        
        report_lines.append("\n---\n")
        
        # Evidence Inventory
        report_lines.append("## Evidence Inventory\n")
        all_evidence = evidence_store.get_all_evidence()
        
        evidence_by_type = {}
        for evidence in all_evidence:
            if evidence.evidence_type not in evidence_by_type:
                evidence_by_type[evidence.evidence_type] = []
            evidence_by_type[evidence.evidence_type].append(evidence)
        
        for etype, evidence_list in evidence_by_type.items():
            report_lines.append(f"### {etype.upper()} Evidence ({len(evidence_list)} items)\n")
            report_lines.append("| Evidence ID | Source Path | Collected | Size | SHA256 Hash |")
            report_lines.append("|------------|-------------|-----------|------|-------------|")
            
            for evidence in evidence_list[:10]:  # Limit to 10 per type
                size_kb = len(evidence.data) / 1024
                timestamp_str = evidence.collected_timestamp.strftime('%Y-%m-%d %H:%M')
                hash_short = evidence.hash_sha256[:16] + "..."
                source_short = evidence.source_path[-40:] if len(evidence.source_path) > 40 else evidence.source_path
                
                report_lines.append(
                    f"| `{evidence.evidence_id}` | `{source_short}` | {timestamp_str} | {size_kb:.1f} KB | `{hash_short}` |"
                )
            
            report_lines.append("")
        
        report_lines.append("---\n")
        
        # Chain of Custody Note
        report_lines.append("## Chain of Custody\n")
        report_lines.append("All evidence items have been collected with cryptographic hash verification ")
        report_lines.append("to ensure integrity. Each piece of evidence includes:\n")
        report_lines.append("- Unique evidence identifier")
        report_lines.append("- SHA-256 and MD5 hash values")
        report_lines.append("- Collection timestamp")
        report_lines.append("- Collector information")
        report_lines.append("- Source path and metadata\n")
        report_lines.append("Evidence integrity can be verified at any time by recomputing hashes.\n")
        report_lines.append("---\n")
        
        # Methodology
        report_lines.append("## Analysis Methodology\n")
        report_lines.append("This investigation utilized AI-powered multi-agent analysis:\n")
        report_lines.append("1. **Evidence Collection**: Automated collectors gathered artifacts with hash verification")
        report_lines.append("2. **Specialized Analysis**: Domain-specific AI agents analyzed different evidence types")
        report_lines.append("3. **Correlation**: Cross-reference analysis identified patterns across evidence sources")
        report_lines.append("4. **Confidence Scoring**: Each finding includes a confidence metric based on evidence strength")
        report_lines.append("5. **Timeline Reconstruction**: Events ordered chronologically for incident understanding\n")
        report_lines.append("---\n")
        
        # Conclusions
        report_lines.append("## Conclusions and Recommendations\n")
        
        critical_findings = [f for f in findings if f.severity in ['critical', 'high']]
        if critical_findings:
            report_lines.append("### Immediate Actions Required\n")
            for finding in critical_findings[:5]:
                report_lines.append(f"**{finding.title}**")
                if finding.recommendations:
                    for rec in finding.recommendations[:2]:
                        report_lines.append(f"- {rec}")
                report_lines.append("")
        
        report_lines.append("### Next Steps\n")
        report_lines.append("1. Review and validate all high-severity findings")
        report_lines.append("2. Implement recommended security controls")
        report_lines.append("3. Conduct additional targeted investigation if needed")
        report_lines.append("4. Preserve evidence for potential legal proceedings")
        report_lines.append("5. Update incident response procedures based on lessons learned\n")
        
        report_lines.append("---\n")
        report_lines.append(f"*Report generated by AI-Powered Digital Forensics System*  ")
        report_lines.append(f"*Generated at: {report_timestamp}*\n")
        
        # Write report to file
        report_content = "\n".join(report_lines)
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        print(f"[ReportGenerator] Report generated: {report_path}")
        return str(report_path)
    
    def generate_json_report(
        self,
        findings: List[Finding],
        timeline: List[Dict[str, Any]],
        summary_stats: Dict[str, Any]
    ) -> str:
        """Generate machine-readable JSON report"""
        
        report_filename = f"forensic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        report_path = self.output_dir / report_filename
        
        report_data = {
            'report_metadata': {
                'generated_at': datetime.now().isoformat(),
                'report_id': report_filename,
                'format_version': '1.0'
            },
            'summary': summary_stats,
            'findings': [f.to_dict() for f in findings],
            'timeline': [
                {
                    **event,
                    'timestamp': event['timestamp'].isoformat()
                }
                for event in timeline
            ]
        }
        
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2)
        
        print(f"[ReportGenerator] JSON report generated: {report_path}")
        return str(report_path)
    
    def _get_severity_icon(self, severity: str) -> str:
        """Get emoji icon for severity level"""
        icons = {
            'critical': '🔴',
            'high': '🟠',
            'medium': '🟡',
            'low': '🔵',
            'info': 'ℹ️'
        }
        return icons.get(severity, '⚪')
    
    def generate_executive_summary(self, findings: List[Finding]) -> str:
        """Generate brief executive summary"""
        critical_high = len([f for f in findings if f.severity in ['critical', 'high']])
        
        summary = f"Investigation identified {len(findings)} findings"
        if critical_high > 0:
            summary += f", including {critical_high} requiring immediate attention"
        
        return summary