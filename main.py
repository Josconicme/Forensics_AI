# main.py
"""
AI-Powered Digital Forensics System - Main Entry Point
"""
import sys
from pathlib import Path
from datetime import datetime
import argparse

# Add src to path BEFORE any imports
sys.path.insert(0, str(Path(__file__).parent / 'src'))

# Now import from src modules using absolute imports
from collectors.log_collector import LogCollector
from collectors.file_collector import FileCollector
from collectors.network_collector import NetworkCollector
from storage.evidence_store import EvidenceStore
from chain_of_custody.custody_manager import CustodyManager
from analysis.analysis_engine import AnalysisEngine
from reporting.report_generator import ReportGenerator
from config import config


class ForensicsSystem:
    """Main forensics system orchestrator"""
    
    def __init__(self, cfg):
        self.config = cfg
        
        # Initialize components
        print("[System] Initializing Digital Forensics System...")
        print(f"[System] AI Provider: {self.config.AI_PROVIDER.upper()}")
        
        # Display which model is being used
        if self.config.AI_PROVIDER == 'openai':
            print(f"[System] Model: {self.config.OPENAI_MODEL}")
        elif self.config.AI_PROVIDER == 'anthropic':
            print(f"[System] Model: {self.config.ANTHROPIC_MODEL}")
        
        self.evidence_store = EvidenceStore(self.config.DB_PATH)
        self.custody_manager = CustodyManager(self.config.CUSTODY_LOG_PATH)
        
        # Initialize LLM client based on provider
        llm_client = None
        api_key = None
        
        if self.config.AI_PROVIDER == 'openai':
            if self.config.OPENAI_API_KEY:
                from openai import OpenAI
                llm_client = OpenAI(api_key=self.config.OPENAI_API_KEY)
                api_key = self.config.OPENAI_API_KEY
                print("[System] ✓ OpenAI client initialized")
            else:
                print("[System] ⚠️  WARNING: No OpenAI API key found")
        elif self.config.AI_PROVIDER == 'anthropic':
            if self.config.ANTHROPIC_API_KEY:
                from anthropic import Anthropic
                llm_client = Anthropic(api_key=self.config.ANTHROPIC_API_KEY)
                api_key = self.config.ANTHROPIC_API_KEY
                print("[System] ✓ Anthropic client initialized")
            else:
                print("[System] ⚠️  WARNING: No Anthropic API key found")
        else:
            print(f"[System] ⚠️  WARNING: Unknown AI provider: {self.config.AI_PROVIDER}")
        
        # Initialize analysis engine with LLM client
        self.analysis_engine = AnalysisEngine(
            evidence_store=self.evidence_store,
            api_key=api_key
        )
        self.report_generator = ReportGenerator(self.config.REPORT_OUTPUT_DIR)
        
        # Initialize collectors
        self.log_collector = LogCollector(
            self.evidence_store,
            self.custody_manager
        )
        self.file_collector = FileCollector(
            self.evidence_store,
            self.custody_manager
        )
        self.network_collector = NetworkCollector(
            self.evidence_store,
            self.custody_manager
        )
        
        print("[System] Initialization complete.\n")
    
    def collect_evidence(self, evidence_paths: dict):
        """
        Collect evidence from specified paths
        
        Args:
            evidence_paths: dict with keys 'logs', 'files', 'network'
        """
        print("=" * 70)
        print("PHASE 1: EVIDENCE COLLECTION")
        print("=" * 70)
        
        total_collected = 0
        
        # Collect logs
        if 'logs' in evidence_paths and evidence_paths['logs']:
            print("\n[Collection] Collecting log evidence...")
            for log_path in evidence_paths['logs']:
                try:
                    evidence = self.log_collector.collect(log_path)
                    if evidence:
                        total_collected += 1
                        print(f"  ✓ Collected: {log_path}")
                except Exception as e:
                    print(f"  ✗ Failed to collect {log_path}: {e}")
        
        # Collect files
        if 'files' in evidence_paths and evidence_paths['files']:
            print("\n[Collection] Collecting file evidence...")
            for file_path in evidence_paths['files']:
                try:
                    evidence = self.file_collector.collect(file_path)
                    if evidence:
                        total_collected += 1
                        print(f"  ✓ Collected: {file_path}")
                except Exception as e:
                    print(f"  ✗ Failed to collect {file_path}: {e}")
        
        # Collect network captures
        if 'network' in evidence_paths and evidence_paths['network']:
            print("\n[Collection] Collecting network evidence...")
            for net_path in evidence_paths['network']:
                try:
                    evidence = self.network_collector.collect(net_path)
                    if evidence:
                        total_collected += 1
                        print(f"  ✓ Collected: {net_path}")
                except Exception as e:
                    print(f"  ✗ Failed to collect {net_path}: {e}")
        
        print(f"\n[Collection] Total evidence items collected: {total_collected}")
        print(f"[Collection] Evidence stored in: {self.config.DB_PATH}")
        
        # Verify integrity
        print("\n[Collection] Verifying evidence integrity...")
        all_evidence = self.evidence_store.get_all_evidence()
        integrity_passed = 0
        for evidence in all_evidence:
            if evidence.verify_integrity():
                integrity_passed += 1
        
        print(f"[Collection] Integrity check: {integrity_passed}/{len(all_evidence)} passed ✓\n")
    
    def analyze_evidence(self):
        """Run AI-powered analysis on collected evidence"""
        print("=" * 70)
        print("PHASE 2: AI-POWERED ANALYSIS")
        print("=" * 70)
        print(f"Using: {self.config.AI_PROVIDER.upper()}")
        print()
        
        findings = self.analysis_engine.analyze_all_evidence()
        
        if findings:
            print(f"\n[Analysis] Analysis complete!")
            print(f"[Analysis] Total findings: {len(findings)}")
            
            # Show summary by severity
            severity_counts = {}
            for finding in findings:
                # Handle both dict and object
                severity = finding.get('severity') if isinstance(finding, dict) else finding.severity
                severity = severity.lower() if severity else 'unknown'
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            print("\n[Analysis] Findings by severity:")
            for severity in ['critical', 'high', 'medium', 'low', 'info']:
                count = severity_counts.get(severity, 0)
                if count > 0:
                    icon = "🔴" if severity == 'critical' else "🟠" if severity == 'high' else "🟡" if severity == 'medium' else "🟢"
                    print(f"  {icon} {severity.upper()}: {count}")
            
            # Show confidence stats
            if findings:
                confidences = [f.get('confidence', 0) if isinstance(f, dict) else f.confidence for f in findings]
                avg_confidence = sum(confidences) / len(confidences) if confidences else 0
                print(f"\n[Analysis] Average confidence: {avg_confidence:.1%}")
        else:
            print("[Analysis] No findings identified.")
        
        print()
        return findings
    
    def generate_report(self):
        """Generate comprehensive forensic report"""
        print("=" * 70)
        print("PHASE 3: REPORT GENERATION")
        print("=" * 70)
        print()
        
        findings = self.analysis_engine.findings
        timeline = self.analysis_engine.get_timeline()
        summary_stats = self.analysis_engine.get_summary_statistics()
        
        # Generate markdown report
        md_report_path = self.report_generator.generate_markdown_report(
            findings=findings,
            evidence_store=self.evidence_store,
            timeline=timeline,
            summary_stats=summary_stats,
            case_name=f"AI-Powered Forensic Investigation ({self.config.AI_PROVIDER.upper()})"
        )
        
        # Generate JSON report
        json_report_path = self.report_generator.generate_json_report(
            findings=findings,
            timeline=timeline,
            summary_stats=summary_stats
        )
        
        print(f"\n[Report] Markdown report: {md_report_path}")
        print(f"[Report] JSON report: {json_report_path}")
        print(f"[Report] AI Provider: {self.config.AI_PROVIDER.upper()}\n")
        
        return md_report_path, json_report_path
    
    def run_full_investigation(self, evidence_paths: dict):
        """Run complete investigation workflow"""
        start_time = datetime.now()
        
        print("\n" + "=" * 70)
        print(" AI-POWERED DIGITAL FORENSICS SYSTEM")
        print("=" * 70)
        print(f" Investigation started: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f" AI Provider: {self.config.AI_PROVIDER.upper()}")
        if self.config.AI_PROVIDER == 'openai':
            print(f" Model: {self.config.OPENAI_MODEL}")
        elif self.config.AI_PROVIDER == 'anthropic':
            print(f" Model: {self.config.ANTHROPIC_MODEL}")
        print("=" * 70 + "\n")
        
        # Phase 1: Collection
        self.collect_evidence(evidence_paths)
        
        # Phase 2: Analysis
        self.analyze_evidence()
        
        # Phase 3: Reporting
        md_report, json_report = self.generate_report()
        
        # Summary
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        print("=" * 70)
        print("INVESTIGATION COMPLETE")
        print("=" * 70)
        print(f"Duration: {duration:.2f} seconds")
        print(f"AI Provider: {self.config.AI_PROVIDER.upper()}")
        print(f"Reports generated in: {self.config.REPORT_OUTPUT_DIR}")
        print("=" * 70 + "\n")
        
        return md_report, json_report
    
    def show_custody_chain(self):
        """Display chain of custody log"""
        print("\n" + "=" * 70)
        print("CHAIN OF CUSTODY LOG")
        print("=" * 70 + "\n")
        
        events = self.custody_manager.get_custody_log()
        
        if not events:
            print("No custody events recorded.")
            return
        
        for event in events[-20:]:  # Show last 20 events
            print(f"[{event['timestamp']}]")
            print(f"  Event: {event['event_type']}")
            print(f"  Evidence ID: {event.get('evidence_id', 'N/A')}")
            print(f"  Actor: {event.get('actor', 'N/A')}")
            if 'details' in event:
                print(f"  Details: {event['details']}")
            print()


def main():
    """Main entry point with CLI interface"""
    parser = argparse.ArgumentParser(
        description="AI-Powered Digital Forensics System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run demo with mock data
  python main.py --mode demo
  
  # Analyze custom files with OpenAI
  python main.py --mode custom --files /path/to/file1 /path/to/file2
  
  # Show chain of custody
  python main.py --custody
  
  # Use specific AI provider (set in .env):
  # AI_PROVIDER=openai or AI_PROVIDER=anthropic
        """
    )
    parser.add_argument(
        '--mode',
        choices=['demo', 'custom', 'analyze', 'report'],
        default='demo',
        help='Operation mode (default: demo)'
    )
    parser.add_argument(
        '--logs',
        nargs='+',
        help='Log file paths to analyze'
    )
    parser.add_argument(
        '--files',
        nargs='+',
        help='File paths to analyze'
    )
    parser.add_argument(
        '--network',
        nargs='+',
        help='Network capture paths to analyze'
    )
    parser.add_argument(
        '--custody',
        action='store_true',
        help='Show chain of custody log'
    )
    parser.add_argument(
        '--provider',
        choices=['openai', 'anthropic'],
        help='Override AI provider from .env file'
    )
    
    args = parser.parse_args()
    
    # Load configuration
    cfg = config
    
    # Override provider if specified
    if args.provider:
        cfg.AI_PROVIDER = args.provider
        print(f"[CLI] Overriding AI provider to: {args.provider}")
    
    # Validate configuration
    cfg.validate()
    
    # Display configuration
    if args.mode != 'custody':
        cfg.display()
    
    # Initialize system
    try:
        forensics_system = ForensicsSystem(cfg)
    except Exception as e:
        print(f"\n❌ Error initializing system: {e}")
        print("\nPlease check your .env file configuration.")
        return 1
    
    if args.custody:
        forensics_system.show_custody_chain()
        return 0
    
    if args.mode == 'demo':
        # Run with demo/mock data
        print("Running in DEMO mode with mock data...\n")
        
        evidence_paths = {
            'logs': [
                './mock_data/logs/apache_access.log',
                './mock_data/logs/windows_security.log'
            ],
            'files': [
                './mock_data/files/suspicious_executable.exe',
                './mock_data/files/confidential_data.csv'
            ],
            'network': [
                './mock_data/network/capture.pcap'
            ]
        }
        
        forensics_system.run_full_investigation(evidence_paths)
    
    elif args.mode == 'custom':
        # Custom evidence paths
        evidence_paths = {
            'logs': args.logs or [],
            'files': args.files or [],
            'network': args.network or []
        }
        
        if not any(evidence_paths.values()):
            print("❌ Error: No evidence paths specified.")
            print("Use --logs, --files, or --network to specify paths.")
            return 1
        
        forensics_system.run_full_investigation(evidence_paths)
    
    elif args.mode == 'analyze':
        # Analyze existing evidence
        print("Analyzing existing evidence in database...\n")
        forensics_system.analyze_evidence()
        forensics_system.generate_report()
    
    elif args.mode == 'report':
        # Generate report only
        print("Generating report from existing analysis...\n")
        forensics_system.generate_report()
    
    return 0


if __name__ == "__main__":
    sys.exit(main())