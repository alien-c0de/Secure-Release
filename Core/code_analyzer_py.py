import asyncio
import json
import os
from pathlib import Path
import tempfile
from colorama import Fore, Style
from Utils.logger_config import get_logger

# Initialize logger for this module
logger = get_logger(__name__)

# ============================================================
# 🔧 Subprocess Runner (Streaming + Windows Friendly)
# ============================================================
async def run_command(cmd, cwd=None, timeout=1200):
    """
    Runs a command & streams stdout in real-time.
    Prevents Semgrep hanging by:
    - enabling streaming
    - disabling buffering
    - avoiding deadlocks
    """
    logger.debug(f"Executing command: {cmd[:150]}..." if len(cmd) > 150 else f"Executing command: {cmd}")
    logger.debug(f"Working directory: {cwd}")
    logger.debug(f"Timeout: {timeout}s")

    try:
        process = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd
        )

        # Stream stdout live
        line_count = 0
        while True:
            line = await process.stdout.readline()
            if not line:
                break
            line_count += 1
            print(Fore.YELLOW + "[semgrep] " + Fore.RESET + line.decode(errors="ignore").rstrip())

        logger.debug(f"Streamed {line_count} lines of output")

        # Read stderr
        stderr = await process.stderr.read()
        stderr_decoded = stderr.decode(errors='ignore')

        if process.returncode != 0:
            logger.error(f"Command failed with return code {process.returncode}")
            logger.error(f"STDERR: {stderr_decoded[:500]}")
            print(Fore.RED + f"[!] Error running command:\n{stderr_decoded[:200]}" + Fore.RESET)
        else:
            logger.debug("Command completed successfully")
            if stderr_decoded.strip():
                logger.warning(f"Command succeeded but had stderr: {stderr_decoded[:500]}")

        return ""  # all output was already streamed
        
    except asyncio.TimeoutError:
        logger.error(f"Command timeout after {timeout} seconds")
        raise
    except Exception as e:
        logger.error(f"Command execution failed: {str(e)}", exc_info=True)
        raise


# ============================================================
# 🔍 Semgrep (Balanced Mode)
# Python-only + Bandit + OWASP + Security Audit
# ============================================================
async def run_semgrep(directory):
    """
    Enhanced Semgrep parser:
    ✓ Extracts ONLY OWASP 2021 category
    ✓ Replaces pattern_name with CWE details
    ✓ Falls back correctly when metadata is missing
    ✓ Uses a safe balanced ruleset
    """
    logger.info(f"Starting Semgrep scan for directory: {directory}")

    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".json")
    os.close(tmp_fd)
    logger.debug(f"Created temporary report file: {tmp_path}")

    # -----------------------------------------------
    # Balanced Mode (Fast + good coverage)
    # -----------------------------------------------
    cmd = (
        f'semgrep scan --quiet --json '
        f'--no-git-ignore '
        f'--exclude node_modules '
        f'--exclude .git '
        f'--exclude __pycache__ '
        f'--exclude .venv '
        f'--config p/bandit '
        f'--config auto '
        f'--config p/security-audit '
        f'--config p/default '
        f'"{directory}" '
        f'--output "{tmp_path}"'
    )

    logger.debug("Executing Semgrep with balanced ruleset")
    await run_command(cmd)

    # -----------------------------------------------
    # Read JSON (Windows safe)
    # -----------------------------------------------
    data = {}
    for attempt in range(1, 11):
        try:
            with open(tmp_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            logger.debug(f"Successfully read Semgrep output on attempt {attempt}")
            break
        except (PermissionError, json.JSONDecodeError) as e:
            logger.warning(f"Attempt {attempt}/10 failed to read Semgrep output: {str(e)}")
            await asyncio.sleep(0.25)
    else:
        logger.error(f"Could not read Semgrep output after 10 attempts: {tmp_path}")
        print(Fore.RED + f"[!] Could not read Semgrep output at: {tmp_path}")
        try:
            os.remove(tmp_path)
        except:
            pass
        return []

    findings = []
    results = data.get("results", [])
    logger.info(f"Semgrep found {len(results)} potential issues")

    # -----------------------------------------------
    # Parse Each Finding
    # -----------------------------------------------
    for idx, result in enumerate(results):
        meta = result.get("extra", {}).get("metadata", {})

        # -------------------------
        # Extract OWASP → only 2021
        # -------------------------
        owasp_list = meta.get("owasp", [])
        owasp_2021 = "UNKNOWN"

        if isinstance(owasp_list, list):
            for item in owasp_list:
                if "2021" in item:
                    owasp_2021 = item   # Keep full value like: A03:2021 - Injection
                    break
        elif isinstance(owasp_list, str) and "2021" in owasp_list:
            owasp_2021 = owasp_list

        # -------------------------
        # Extract CWE for pattern_name
        # -------------------------
        cwe_list = meta.get("cwe", [])
        if isinstance(cwe_list, list) and len(cwe_list) > 0:
            cwe_final = cwe_list[0]  # Example: "CWE-89: Improper Neutralization…"
        elif isinstance(cwe_list, str):
            cwe_final = cwe_list
        else:
            # fallback to Semgrep rule ID
            cwe_final = result.get("check_id", "Unknown Rule")

        severity = result.get("extra", {}).get("severity", "UNKNOWN")
        file_path = result.get("path")
        line_num = result.get("start", {}).get("line")

        logger.debug(f"Finding {idx+1}: {severity} in {file_path}:{line_num} - {cwe_final}")

        findings.append({
            "severity": severity,
            "owasp": owasp_2021,
            "file": file_path,
            "line": line_num,
            "CWE": cwe_final,       # <-- Replace rule ID with CWE!
            "description": result.get("extra", {}).get("message"),
            "tool": "Semgrep (Balanced)",
        })

    # Cleanup
    try:
        os.remove(tmp_path)
        logger.debug(f"Removed temporary file: {tmp_path}")
    except Exception as e:
        logger.warning(f"Could not remove temporary file {tmp_path}: {str(e)}")

    logger.info(f"Semgrep scan completed: {len(findings)} findings")
    return findings


# ============================================================
# 🚀 Combined SAST Scan
# ============================================================
async def scan(config):
    """
    Runs balanced Semgrep scan across all target directories.
    """
    logger.info("="*50)
    logger.info("Starting Code Analyzer (Python) scan")

    results = []
    target_dirs = config.get("target_dirs", ["./"])

    # Fix nested Streamlit list (e.g. [["C:/path"]])
    if isinstance(target_dirs, list) and len(target_dirs) == 1 and isinstance(target_dirs[0], list):
        target_dirs = target_dirs[0]
        logger.debug("Flattened nested target_dirs list")

    logger.info(f"Target directories: {target_dirs}")

    tasks = []
    for d in target_dirs:
        resolved = Path(d).resolve()
        logger.debug(f"Adding scan task for directory: {resolved}")
        tasks.append(run_semgrep(resolved))

    logger.info(f"Total scan tasks: {len(tasks)}")

    try:
        all_results = await asyncio.gather(*tasks, return_exceptions=True)

        for idx, r in enumerate(all_results):
            if isinstance(r, Exception):
                logger.error(f"Scan task {idx} failed", exc_info=r)
                continue
            results.extend(r)

        logger.info(f"All code analyzer tasks completed")
        
    except Exception as e:
        logger.error(f"Error during code analysis: {str(e)}", exc_info=True)

    print(Fore.GREEN + Style.BRIGHT + f"[+] 📢 Code Analyzer scan found" + Fore.WHITE + Style.BRIGHT, len(results), Fore.GREEN + Style.BRIGHT + f"issues.", Fore.RESET)
    logger.info(f"Code Analyzer scan completed: {len(results)} total findings")
    logger.info("="*50)
    
    return results


# ============================================================
# 🧪 Local Testing
# ============================================================
if __name__ == "__main__":
    import asyncio
    logger.info("Running standalone test")
    cfg = {"target_dirs": ["./Sample_code/dvpwa"]}
    asyncio.run(scan(cfg))