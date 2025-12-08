import argparse
import asyncio
import os
import pyfiglet
from time import perf_counter
from colorama import Fore, Style
from Core import (
    code_analyzer_py,
    secret_scanner,
    dependency_checker,
    code_analyzer,
)
from Reports import html_report, json_report, notifier
from Utils import config
from Utils.logger_config import get_logger

# Initialize logger for main module
logger = get_logger(__name__)

async def run_scans(cfg: dict):
    """Run all enabled scans and collect results."""
    logger.info("="*60)
    logger.info("Starting security scan process")
    logger.info(f"Configuration loaded: {cfg.get('Assessment_Project_Details', {}).get('name', 'Unknown')}")
    
    print("[+] Code Scanning Started...")
    start_time = perf_counter()
    
    logger.info("Launching concurrent scans: dependency_checker, secret_scanner, code_analyzer")

    try:
        # Launch scans concurrently (each function takes cfg explicitly)
        results = await asyncio.gather(
            dependency_checker.scan(cfg),
            secret_scanner.scan(cfg),
            code_analyzer.scan(cfg),
            return_exceptions=True
        )
        
        logger.info("All scan tasks completed")

        # Check for exceptions in results
        for idx, result in enumerate(results):
            if isinstance(result, Exception):
                scanner_names = ["dependency_checker", "secret_scanner", "code_analyzer"]
                logger.error(f"Scanner {scanner_names[idx]} failed with exception", exc_info=result)

        combined_results = {
            "Dependency Scan": results[0] if not isinstance(results[0], Exception) else [],
            "Secret Scanner": results[1] if not isinstance(results[1], Exception) else [],
            "Code Analyzer": results[2] if not isinstance(results[2], Exception) else [],
        }
        
        # Log summary of findings
        for scan_type, findings in combined_results.items():
            count = len(findings) if isinstance(findings, list) else 0
            logger.info(f"{scan_type}: {count} issues found")

        # Generate reports
        logger.info("Generating HTML report")
        html_report.generate(combined_results, cfg)
        
        logger.info("Generating JSON report")
        json_report.generate(combined_results, cfg)

        # Trigger alerts if configured
        if cfg.get('notify', {}).get('email') or cfg.get('notify', {}).get('slack'):
            logger.info("Sending notifications")
            notifier.send_alerts(combined_results, cfg)
        else:
            logger.debug("Notifications disabled in config")

        elapsed_time = round(perf_counter() - start_time, 2)
        logger.info(f"Security scans completed successfully in {elapsed_time} seconds")
        
        print(Fore.LIGHTBLUE_EX + f"[+] Security scans completed. Reports generated.")
        print(
            Fore.YELLOW
            + Style.BRIGHT
            + f"\n⏱️ Total Time Taken: {elapsed_time} Seconds.",
            flush=True,
        )
        print(Style.RESET_ALL)
        
    except Exception as e:
        logger.critical(f"Fatal error during scan execution: {str(e)}", exc_info=True)
        raise


def main():
    logger.info("Secure Release Tool starting")
    
    # Clear terminal screen
    if os.name == "nt":
        os.system("cls")
    else:
        os.system("clear")

    # CLI args
    parser = argparse.ArgumentParser(description="CI/CD Pipeline Security Tool")
    parser.add_argument(
        "-c", "--config", required=True, help="Path to configuration YAML file"
    )
    args = parser.parse_args()
    
    logger.info(f"Loading configuration from: {args.config}")

    try:
        # Load config once
        cfg = config.load_config(args.config)
        logger.debug(f"Configuration loaded successfully: {list(cfg.keys())}")

        # Fancy header
        figlet_name = cfg.get("tool_info", {}).get("tool_name", "Tool Name")
        terminal_header = pyfiglet.figlet_format(figlet_name, font="doom")
        print(Fore.YELLOW + Style.BRIGHT + terminal_header + Fore.RESET + Style.RESET_ALL)

        # Pass cfg everywhere (no globals)
        footer_owner = cfg.get("tool_info", {}).get("owner_title", "Footer Owner")
        author = cfg.get("tool_info", {}).get("author", "Author")
        year = cfg.get("tool_info", {}).get("year", "2025")
        email = cfg.get("tool_info", {}).get("email", "email@example.com")
        github = cfg.get("tool_info", {}).get("github", "https://github.com/your-repo")
        version = cfg.get("tool_info", {}).get("version", "1.0.0")

        asyncio.run(run_scans(cfg))
        
        print(Fore.YELLOW + f"📢 {footer_owner} 👽: {author} Ver: {version} © {year}", flush=True)
        print(Fore.YELLOW + f"📧 {email} ", flush=True)
        print(Fore.YELLOW + f"🚀 {github}", flush=True)
        print(Style.RESET_ALL)
        
        logger.info("Secure Release Tool completed successfully")
        logger.info("="*60)
        
    except Exception as e:
        logger.critical(f"Application failed to start: {str(e)}", exc_info=True)
        print(Fore.RED + f"[!] Fatal error: {str(e)}" + Fore.RESET)
        raise

if __name__ == "__main__":
    main()
