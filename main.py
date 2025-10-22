import asyncio
from datetime import datetime
import os
from langchain_anthropic import ChatAnthropic
from langchain_openai import ChatOpenAI

from src.collectors.log_collector import LogCollector
from src.collectors.file_collector import FileCollector
from src.collectors.network_collector import NetworkCollector
from src.storage.evidence_store import EvidenceStore
from src.chain_of_custody.custody_manager import CustodyManager
from src.analysis.analysis_engine import AnalysisEngine
from src.reporting.report_generator import ReportGenerator
from src.config import Config
from src.utils.logger import logger


async def main():
    """Main entry point for forensic analysis."""
    
    logger.logger.info("=== Starting Forensic Analysis System ===")
    
    # Generate case ID
    case_id = f"CASE-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    logger.logger.info(f"Case ID: {case_id}")
    
    try:
        # 1. Initialize components
        logger.logger.info("Initializing components...")
        
        # Initialize LLM
        if Config.AI_PROVIDER == "anthropic":
            llm = ChatAnthropic(
                model=Config.ANTHROPIC_MODEL,
                anthropic_api_key=os.getenv("ANTHROPIC_API_KEY")
            )
            logger.logger.info(f"Using Anthropic Claude: {Config.ANTHROPIC_MODEL}")
        else:
            llm = ChatOpenAI(
                model=Config.OPENAI_MODEL,
                openai_api_key=os.getenv("OPENAI_API_KEY")
            )
            logger.logger.info(f"Using OpenAI: {Config.OPENAI_MODEL}")
        
        # Initialize storage and custody
        store = EvidenceStore(storage_path="./evidence_storage")
        custody = CustodyManager(db_path="./data/custody.db")
        
        # 2. Collect Evidence
        logger.logger.info("\n=== Collecting Evidence ===")
        
        log_collector = LogCollector()
        file_collector = FileCollector()
        network_collector = NetworkCollector()
        
        log_evidence = log_collector.collect("./mock_data/system_logs.log")
        logger.evidence_collected(f"{len(log_evidence)} items", "./mock_data/system_logs.log", "LOG")
        
        file_evidence = file_collector.collect("./mock_data/")
        logger.evidence_collected(f"{len(file_evidence)} items", "./mock_data/", "FILE")
        
        network_evidence = network_collector.collect("./mock_data/network_traffic.csv")
        logger.evidence_collected(f"{len(network_evidence)} items", "./mock_data/network_traffic.csv", "NETWORK")
        
        all_evidence = log_evidence + file_evidence + network_evidence
        logger.logger.info(f"Total evidence collected: {len(all_evidence)} items")
        
        # 3. Store Evidence
        logger.logger.info("\n=== Storing Evidence ===")
        for evidence in all_evidence:
            store.store_evidence(evidence)
            custody.record_action(
                evidence_id=evidence.evidence_id,
                action="INGESTED",
                agent="Collector",
                hash_value=evidence.hash,
                metadata=evidence.metadata
            )
            logger.evidence_stored(evidence.evidence_id, evidence.hash)
        
        # 4. Run Analysis
        logger.logger.info("\n=== Running AI Analysis ===")
        logger.analysis_started(case_id, len(all_evidence))
        
        engine = AnalysisEngine(
            evidence_store=store,
            custody_manager=custody,
            llm_client=llm
        )
        
        start_time = datetime.now()
        results = await engine.analyze_case(case_id, all_evidence)
        duration = (datetime.now() - start_time).total_seconds()
        
        logger.analysis_completed(case_id, len(results.get('findings', [])), duration)
        
        # 5. Generate Report
        logger.logger.info("\n=== Generating Report ===")
        
        generator = ReportGenerator()
        report = generator.generate_report(
            case_id=case_id,
            analysis_results=results,
            evidence_list=all_evidence,
            custody_chain=[custody.get_chain(e.evidence_id) for e in all_evidence]
        )
        
        # Save report
        output_path = f"./output/forensic_report_{case_id}.md"
        generator.save_report(report, "./output", format="markdown")
        generator.save_report(report, "./output", format="json")
        
        logger.report_generated(case_id, output_path)
        
        # 6. Display Summary
        logger.logger.info("\n=== Analysis Complete ===")
        logger.logger.info(f"Case ID: {case_id}")
        logger.logger.info(f"Evidence Items: {len(all_evidence)}")
        logger.logger.info(f"Findings: {len(results.get('findings', []))}")
        logger.logger.info(f"Duration: {duration:.2f}s")
        logger.logger.info(f"Report: {output_path}")
        
        print(f"\n✅ Analysis complete! Report saved to: {output_path}")
        
    except Exception as e:
        logger.error("main", f"Fatal error: {e}", e)
        raise


if __name__ == "__main__":
    asyncio.run(main())