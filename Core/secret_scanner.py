import asyncio
import json
from pathlib import Path
from colorama import Fore, Style

from detect_secrets.core.scan import scan_file
from detect_secrets.settings import default_settings
from Utils import file_utils  # Binary detector
from Utils.logger_config import get_logger

# Initialize logger for this module
logger = get_logger(__name__)

# ============================================================
#                ⭐ STANDARDIZED SEVERITY MAP ⭐
# ============================================================
DETECT_SECRET_SEVERITY_MAP = {
    "AWSKeyDetector": "CRITICAL",
    "AWSSecretKey": "CRITICAL",
    "PrivateKeyDetector": "CRITICAL",
    "HighEntropyString": "MEDIUM",
    "JWTDetector": "HIGH",
    "StripeDetector": "CRITICAL",
    "SlackBotTokenDetector": "HIGH",
    "BasicAuthDetector": "MEDIUM",
    "GenericCredentialDetector": "MEDIUM",
    "SecretKeywordDetector": "LOW",
}

def get_severity(plugin_name: str) -> str:
    severity = DETECT_SECRET_SEVERITY_MAP.get(plugin_name, "INFO")
    logger.debug(f"Mapped plugin '{plugin_name}' to severity: {severity}")
    return severity


# ============================================================
#              ⭐ DETECT-SECRETS SCANNING (Optimized)
# ============================================================
def scan_with_detect_secrets(file_path: Path):
    """Sync function that scans a single file."""
    logger.debug(f"Scanning file with detect-secrets: {file_path}")
    findings = []

    try:
        with default_settings():
            secrets = scan_file(str(file_path))

            if not secrets:
                logger.debug(f"No secrets found in: {file_path}")
                return findings

            # logger.info(f"Found {len(secrets)} potential secrets in: {file_path}")

            for secret in secrets:
                plugin = getattr(secret, "type", "Unknown")
                line_num = secret.line_number
                
                logger.debug(f"Secret detected: {plugin} at line {line_num}")

                findings.append({
                    "severity": get_severity(plugin),
                    "plugin": plugin,
                    "file": str(file_path),
                    "line": line_num,
                    "match": secret.secret_value,
                    "type": plugin,
                    "details": {
                        "Verified": getattr(secret, "is_verified", None),
                        "SecretHash": getattr(secret, "secret_hash", None),
                        "Commit": getattr(secret, "commit", None),
                        "Path": getattr(secret, "filename", None),
                    },
                    "tool": "detect-secrets",
                })
        
    except Exception as e:
        logger.error(f"Error scanning file {file_path} with detect-secrets: {str(e)}", exc_info=True)

    return findings


async def run_detect_secrets(directory_path: str):
    """Async wrapper scanning all files in a directory."""
    logger.info(f"Starting detect-secrets scan for directory: {directory_path}")
    dirpath = Path(directory_path).resolve()

    if not dirpath.exists():
        logger.warning(f"Directory does not exist: {dirpath}")
        return []

    results = []
    tasks = []
    file_count = 0

    for fp in dirpath.rglob("*"):
        if fp.is_file() and not file_utils.is_binary(fp):
            tasks.append(asyncio.to_thread(scan_with_detect_secrets, fp))
            file_count += 1

    logger.info(f"Queued {file_count} files for detect-secrets scanning")

    if not tasks:
        logger.warning("No files found to scan")
        return []

    try:
        # Run all file scans concurrently
        all_lists = await asyncio.gather(*tasks, return_exceptions=True)

        for idx, lst in enumerate(all_lists):
            if isinstance(lst, Exception):
                logger.error(f"Scan task {idx} failed", exc_info=lst)
                continue
            results.extend(lst)

        logger.info(f"detect-secrets scan completed: {len(results)} secrets found")
        
    except Exception as e:
        logger.error(f"Error during detect-secrets scanning: {str(e)}", exc_info=True)

    return results


# ============================================================
#                ⭐ TRUFFLEHOG3 SCANNER (Optimized)
# ============================================================
async def run_trufflehog3_scan(target_dir: str):
    """Runs TruffleHog3 in filesystem mode."""
    logger.info(f"Starting TruffleHog3 scan for: {target_dir}")
    
    cmd = [
        "trufflehog3",
        "filesystem",
        target_dir,
        "-f", "JSON"
    ]
    
    logger.debug(f"TruffleHog3 command: {' '.join(cmd)}")

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        stdout, stderr = await proc.communicate()

        if stderr:
            stderr_decoded = stderr.decode(errors="ignore")
            logger.warning(f"TruffleHog3 stderr: {stderr_decoded[:500]}")
            print(Fore.YELLOW + "[trufflehog3 warning] " + stderr_decoded[:200])

        stdout_decoded = stdout.decode(errors="ignore")
        logger.debug(f"TruffleHog3 raw output length: {len(stdout_decoded)} chars")

        try:
            raw = json.loads(stdout_decoded)
            logger.debug("Successfully parsed TruffleHog3 output")
        except Exception as e:
            logger.error(f"Failed to parse TruffleHog3 JSON: {str(e)}")
            logger.debug(f"Raw output (first 500 chars): {stdout_decoded[:500]}")
            return []

        findings = []
        for f in raw:
            rule_info = f.get("rule", {})
            severity = rule_info.get("severity", "MEDIUM")
            
            findings.append({
                "severity": severity,
                "file": f.get("path"),
                "line": int(f.get("line", 0)),
                "secret": f.get("secret"),
                "rule id": rule_info.get("id"),
                "message": rule_info.get("message"),
                "context": f.get("context"),
                "id": f.get("id"),
                "tool": "TruffleHog3",
            })
            
            logger.debug(f"TruffleHog3 found: {severity} in {f.get('path')}")

        logger.info(f"TruffleHog3 scan completed: {len(findings)} findings")
        return findings
        
    except FileNotFoundError:
        logger.error("TruffleHog3 executable not found. Is it installed?")
        print(Fore.RED + "[!] TruffleHog3 not found. Please install it." + Fore.RESET)
        return []
    except Exception as e:
        logger.error(f"TruffleHog3 scan failed: {str(e)}", exc_info=True)
        return []


# ============================================================
#     ⭐ COMBINED SECRET SCAN (Detect-Secrets + TruffleHog3)
# ============================================================
async def scan(config):
    logger.info("="*50)
    logger.info("Starting Secret Scanner")
    
    target_dirs = config.get("target_dirs", ["./"])
    exclude_dirs = config.get("exclude_dirs", [])
    
    logger.info(f"Target directories: {target_dirs}")
    logger.info(f"Exclude directories: {exclude_dirs}")

    # Normalize nested lists (Streamlit fix)
    if isinstance(target_dirs, list) and len(target_dirs) == 1 and isinstance(target_dirs[0], list):
        target_dirs = target_dirs[0]
        logger.debug("Flattened nested target_dirs list")

    # Only valid dirs
    valid_dirs = [
        str(Path(d).resolve()) for d in target_dirs
        if Path(d).is_dir() and not any(ex in str(Path(d).resolve()) for ex in exclude_dirs)
    ]

    if not valid_dirs:
        logger.warning("No valid directories found to scan")
        print(Fore.RED + "[!] No valid directories to scan.")
        return []

    logger.info(f"Valid directories for scanning: {len(valid_dirs)}")

    # Build tasks
    detect_tasks = [run_detect_secrets(d) for d in valid_dirs]
    truffle_tasks = [run_trufflehog3_scan(d) for d in valid_dirs]
    
    logger.info(f"Total scan tasks: {len(detect_tasks)} detect-secrets + {len(truffle_tasks)} TruffleHog3")

    try:
        # Run both scanners concurrently
        detect_results, truffle_results = await asyncio.gather(
            asyncio.gather(*detect_tasks, return_exceptions=True),
            asyncio.gather(*truffle_tasks, return_exceptions=True),
        )

        # Flatten and handle exceptions
        combined = []
        
        for result in detect_results:
            if isinstance(result, Exception):
                logger.error("detect-secrets task failed", exc_info=result)
                continue
            combined.extend(result)
        
        for result in truffle_results:
            if isinstance(result, Exception):
                logger.error("TruffleHog3 task failed", exc_info=result)
                continue
            combined.extend(result)

        logger.info(f"Secret scanning completed: {len(combined)} total findings")
        logger.info("="*50)
        
        print(Fore.BLUE + Style.BRIGHT + f"[+] 📢 Secret scan found" + Fore.WHITE + Style.BRIGHT, len(combined), Fore.BLUE + Style.BRIGHT + f"issues (Detect-Secrets + TruffleHog3).", Fore.RESET)
        return combined
        
    except Exception as e:
        logger.error(f"Error during secret scanning: {str(e)}", exc_info=True)
        return []
