"""
Logging utility for the forensics system.

Provides centralized logging configuration with file and console outputs,
rotating file handlers, and component-specific logging levels.
"""

import logging
import sys
from pathlib import Path
from logging.handlers import RotatingFileHandler
from typing import Optional
from datetime import datetime


# Color codes for console output
class LogColors:
    """ANSI color codes for terminal output."""
    RESET = '\033[0m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'


class ColoredFormatter(logging.Formatter):
    """Custom formatter with colors for different log levels."""
    
    COLORS = {
        'DEBUG': LogColors.BLUE,
        'INFO': LogColors.GREEN,
        'WARNING': LogColors.YELLOW,
        'ERROR': LogColors.RED,
        'CRITICAL': LogColors.RED + LogColors.BOLD
    }
    
    def format(self, record):
        """Format log record with colors."""
        # Save original levelname
        levelname = record.levelname
        
        # Add color to levelname
        if levelname in self.COLORS:
            record.levelname = f"{self.COLORS[levelname]}{levelname}{LogColors.RESET}"
        
        # Format the message
        result = super().format(record)
        
        # Restore original levelname
        record.levelname = levelname
        
        return result


def setup_logger(
    name: str = "forensics",
    log_level: str = "INFO",
    log_file: Optional[str] = None,
    max_file_size_mb: int = 10,
    backup_count: int = 5,
    enable_console: bool = True,
    enable_file: bool = True,
    use_colors: bool = True
) -> logging.Logger:
    """
    Set up and configure a logger.
    
    Args:
        name: Logger name
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Path to log file (default: logs/forensics.log)
        max_file_size_mb: Maximum size of log file before rotation
        backup_count: Number of backup files to keep
        enable_console: Enable console output
        enable_file: Enable file output
        use_colors: Use colored output in console
        
    Returns:
        Configured logger instance
    """
    # Create logger
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, log_level.upper()))
    
    # Clear existing handlers to avoid duplicates
    logger.handlers.clear()
    
    # Create formatters
    if use_colors:
        console_formatter = ColoredFormatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
    else:
        console_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
    
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Console handler
    if enable_console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.DEBUG)
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)
    
    # File handler
    if enable_file:
        # Create logs directory if it doesn't exist
        if log_file is None:
            log_file = "logs/forensics.log"
        
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Rotating file handler
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=max_file_size_mb * 1024 * 1024,
            backupCount=backup_count
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
    
    return logger


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance.
    
    Args:
        name: Logger name (usually __name__)
        
    Returns:
        Logger instance
    """
    return logging.getLogger(name)


class ForensicsLogger:
    """
    Forensics-specific logger with convenience methods.
    """
    
    def __init__(self, name: str = "forensics"):
        """
        Initialize forensics logger.
        
        Args:
            name: Logger name
        """
        self.logger = get_logger(name)
    
    def evidence_collected(self, evidence_id: str, source: str, evidence_type: str):
        """Log evidence collection."""
        self.logger.info(
            f"Evidence collected: {evidence_id} | Type: {evidence_type} | Source: {source}"
        )
    
    def evidence_stored(self, evidence_id: str, hash_value: str):
        """Log evidence storage."""
        self.logger.info(
            f"Evidence stored: {evidence_id} | Hash: {hash_value[:16]}..."
        )
    
    def custody_recorded(self, evidence_id: str, action: str, agent: str):
        """Log chain of custody event."""
        self.logger.info(
            f"Chain of custody: {evidence_id} | Action: {action} | Agent: {agent}"
        )
    
    def analysis_started(self, case_id: str, evidence_count: int):
        """Log analysis start."""
        self.logger.info(
            f"Analysis started: {case_id} | Evidence items: {evidence_count}"
        )
    
    def analysis_completed(self, case_id: str, findings_count: int, duration: float):
        """Log analysis completion."""
        self.logger.info(
            f"Analysis completed: {case_id} | Findings: {findings_count} | "
            f"Duration: {duration:.2f}s"
        )
    
    def agent_analysis(self, agent_name: str, evidence_count: int, findings_count: int):
        """Log agent analysis results."""
        self.logger.info(
            f"Agent analysis: {agent_name} | Evidence: {evidence_count} | "
            f"Findings: {findings_count}"
        )
    
    def finding_detected(self, finding_id: str, severity: str, finding_type: str, confidence: float):
        """Log finding detection."""
        self.logger.warning(
            f"Finding detected: {finding_id} | Severity: {severity} | "
            f"Type: {finding_type} | Confidence: {confidence:.0%}"
        )
    
    def critical_finding(self, finding_id: str, description: str):
        """Log critical finding."""
        self.logger.critical(
            f"CRITICAL FINDING: {finding_id} | {description}"
        )
    
    def report_generated(self, case_id: str, output_path: str):
        """Log report generation."""
        self.logger.info(
            f"Report generated: {case_id} | Output: {output_path}"
        )
    
    def error(self, component: str, error_msg: str, exception: Optional[Exception] = None):
        """Log error."""
        if exception:
            self.logger.error(
                f"Error in {component}: {error_msg}",
                exc_info=True
            )
        else:
            self.logger.error(f"Error in {component}: {error_msg}")
    
    def integrity_check(self, evidence_id: str, passed: bool):
        """Log integrity check."""
        if passed:
            self.logger.info(f"Integrity check passed: {evidence_id}")
        else:
            self.logger.error(f"Integrity check FAILED: {evidence_id}")
    
    def api_call(self, provider: str, model: str, tokens: Optional[int] = None):
        """Log AI API call."""
        if tokens:
            self.logger.debug(
                f"AI API call: {provider} | Model: {model} | Tokens: {tokens}"
            )
        else:
            self.logger.debug(f"AI API call: {provider} | Model: {model}")
    
    def performance_metric(self, operation: str, duration: float, items_processed: int = 0):
        """Log performance metric."""
        if items_processed > 0:
            rate = items_processed / duration if duration > 0 else 0
            self.logger.debug(
                f"Performance: {operation} | Duration: {duration:.2f}s | "
                f"Items: {items_processed} | Rate: {rate:.2f} items/s"
            )
        else:
            self.logger.debug(
                f"Performance: {operation} | Duration: {duration:.2f}s"
            )


class AuditLogger:
    """
    Audit logger for security-sensitive operations.
    """
    
    def __init__(self, log_file: str = "logs/audit.log"):
        """
        Initialize audit logger.
        
        Args:
            log_file: Path to audit log file
        """
        self.logger = setup_logger(
            name="audit",
            log_level="INFO",
            log_file=log_file,
            enable_console=False,
            enable_file=True
        )
    
    def log_access(self, user: str, resource: str, action: str, success: bool):
        """
        Log access attempt.
        
        Args:
            user: User identifier
            resource: Resource being accessed
            action: Action attempted
            success: Whether access was granted
        """
        status = "SUCCESS" if success else "DENIED"
        self.logger.info(
            f"ACCESS {status}: User={user} | Resource={resource} | Action={action}"
        )
    
    def log_modification(self, user: str, resource: str, changes: str):
        """
        Log resource modification.
        
        Args:
            user: User identifier
            resource: Resource modified
            changes: Description of changes
        """
        self.logger.warning(
            f"MODIFICATION: User={user} | Resource={resource} | Changes={changes}"
        )
    
    def log_deletion(self, user: str, resource: str, reason: str):
        """
        Log resource deletion.
        
        Args:
            user: User identifier
            resource: Resource deleted
            reason: Reason for deletion
        """
        self.logger.warning(
            f"DELETION: User={user} | Resource={resource} | Reason={reason}"
        )
    
    def log_security_event(self, event_type: str, details: str, severity: str = "HIGH"):
        """
        Log security event.
        
        Args:
            event_type: Type of security event
            details: Event details
            severity: Severity level
        """
        self.logger.critical(
            f"SECURITY EVENT [{severity}]: Type={event_type} | Details={details}"
        )


# Global logger instances
_main_logger: Optional[ForensicsLogger] = None
_audit_logger: Optional[AuditLogger] = None


def initialize_logging(
    log_level: str = "INFO",
    log_file: str = "logs/forensics.log",
    audit_log_file: str = "logs/audit.log"
):
    """
    Initialize global logging system.
    
    Args:
        log_level: Logging level
        log_file: Main log file path
        audit_log_file: Audit log file path
    """
    global _main_logger, _audit_logger
    
    # Setup main logger
    setup_logger(
        name="forensics",
        log_level=log_level,
        log_file=log_file,
        enable_console=True,
        enable_file=True
    )
    
    _main_logger = ForensicsLogger("forensics")
    _audit_logger = AuditLogger(audit_log_file)
    
    _main_logger.logger.info("Logging system initialized")


def get_forensics_logger() -> ForensicsLogger:
    """
    Get the global forensics logger.
    
    Returns:
        ForensicsLogger instance
    """
    global _main_logger
    if _main_logger is None:
        initialize_logging()
    return _main_logger


def get_audit_logger() -> AuditLogger:
    """
    Get the global audit logger.
    
    Returns:
        AuditLogger instance
    """
    global _audit_logger
    if _audit_logger is None:
        initialize_logging()
    return _audit_logger


# Convenience functions
def log_info(message: str):
    """Log info message."""
    get_forensics_logger().logger.info(message)


def log_warning(message: str):
    """Log warning message."""
    get_forensics_logger().logger.warning(message)


def log_error(message: str, exception: Optional[Exception] = None):
    """Log error message."""
    if exception:
        get_forensics_logger().logger.error(message, exc_info=True)
    else:
        get_forensics_logger().logger.error(message)


def log_critical(message: str):
    """Log critical message."""
    get_forensics_logger().logger.critical(message)


def log_debug(message: str):
    """Log debug message."""
    get_forensics_logger().logger.debug(message)