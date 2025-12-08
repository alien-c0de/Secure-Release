import os
import json
from colorama import Fore, Style
from Utils.logger_config import get_logger

# Initialize logger for this module
logger = get_logger(__name__)


def generate(results, config):
    """Generate JSON report from scan results."""
    logger.info("Starting JSON report generation")
    
    report_dir = config.get('report_dir', './reports')
    logger.debug(f"Report directory: {report_dir}")
    
    try:
        # Ensure report directory exists
        os.makedirs(report_dir, exist_ok=True)
        logger.debug(f"Ensured report directory exists: {report_dir}")
        
        report_path = os.path.join(report_dir, 'security_report.json')
        
        # Log summary of results
        total_issues = sum(len(v) if isinstance(v, list) else 0 for v in results.values())
        logger.info(f"Generating JSON report with {total_issues} total issues")
        
        for scan_type, findings in results.items():
            count = len(findings) if isinstance(findings, list) else 0
            logger.debug(f"{scan_type}: {count} findings")

        # Write JSON report
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=4, ensure_ascii=False)
        
        file_size = os.path.getsize(report_path)
        logger.info(f"JSON report successfully written to: {report_path} (Size: {file_size} bytes)")
        
        print(Fore.LIGHTMAGENTA_EX + f"[+] JSON report generated at: {report_path}", flush=True)
        
    except PermissionError as e:
        logger.error(f"Permission denied writing JSON report: {str(e)}", exc_info=True)
        print(f"[!] Permission denied: Unable to write JSON report to {report_path}")
        
    except IOError as e:
        logger.error(f"IO error writing JSON report: {str(e)}", exc_info=True)
        print(f"[!] IO error: Failed to write JSON report - {str(e)}")
        
    except Exception as e:
        logger.error(f"Unexpected error generating JSON report: {str(e)}", exc_info=True)
        print(f"[!] Failed to write JSON report: {e}")