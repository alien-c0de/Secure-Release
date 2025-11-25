import asyncio
import json
from pathlib import Path
from colorama import Fore, Style

from detect_secrets.core.scan import scan_file
from detect_secrets.settings import default_settings
from Utils import file_utils  # Binary detector


# ============================================================
#                ★ STANDARDIZED SEVERITY MAP ★
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
    return DETECT_SECRET_SEVERITY_MAP.get(plugin_name, "INFO")


# ============================================================
#              ★ DETECT-SECRETS SCANNING (Optimized)
# ============================================================
def scan_with_detect_secrets(file_path: Path):
    """Sync function that scans a single file."""
    findings = []

    with default_settings():
        secrets = scan_file(str(file_path))

        if not secrets:
            return findings

        for secret in secrets:
            plugin = getattr(secret, "type", "Unknown")

            findings.append({
                "severity": get_severity(plugin),
                "plugin": plugin,
                "file": str(file_path),
                "line": secret.line_number,
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

    return findings


async def run_detect_secrets(directory_path: str):
    """Async wrapper scanning all files in a directory."""
    dirpath = Path(directory_path).resolve()

    results = []
    tasks = []

    for fp in dirpath.rglob("*"):
        if fp.is_file() and not file_utils.is_binary(fp):
            tasks.append(asyncio.to_thread(scan_with_detect_secrets, fp))

    if not tasks:
        return []

    # Run all file scans concurrently
    all_lists = await asyncio.gather(*tasks)

    for lst in all_lists:
        results.extend(lst)

    return results


# ============================================================
#                ★ TRUFFLEHOG3 SCANNER (Optimized)
# ============================================================
async def run_trufflehog3_scan(target_dir: str):
    """Runs TruffleHog3 in filesystem mode."""
    cmd = [
        "trufflehog3",
        "filesystem",
        target_dir,
        "-f", "JSON"
    ]

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )

    stdout, stderr = await proc.communicate()

    if stderr:
        print(Fore.YELLOW + "[trufflehog3 warning] " + stderr.decode(errors="ignore"))

    try:
        raw = json.loads(stdout.decode(errors="ignore"))
    except Exception as e:
        print(Fore.RED + f"[!] Failed to parse TruffleHog3 output: {e}")
        return []

    findings = []
    for f in raw:
        findings.append({
            "severity": f.get("rule", {}).get("severity", "MEDIUM"),
            "file": f.get("path"),
            "line": int(f.get("line", 0)),
            "secret": f.get("secret"),
            "rule id": f.get("rule", {}).get("id"),
            "message": f.get("rule", {}).get("message"),
            "context": f.get("context"),
            "id": f.get("id"),
            "tool": "TruffleHog3",
        })

    return findings


# ============================================================
#     ★ COMBINED SECRET SCAN (Detect-Secrets + TruffleHog3)
# ============================================================
async def scan(config):
    target_dirs = config.get("target_dirs", ["./"])
    exclude_dirs = config.get("exclude_dirs", [])

    # Normalize nested lists (Streamlit fix)
    if isinstance(target_dirs, list) and len(target_dirs) == 1 and isinstance(target_dirs[0], list):
        target_dirs = target_dirs[0]

    # Only valid dirs
    valid_dirs = [
        str(Path(d).resolve()) for d in target_dirs
        if Path(d).is_dir() and not any(ex in str(Path(d).resolve()) for ex in exclude_dirs)
    ]

    if not valid_dirs:
        print(Fore.RED + "[!] No valid directories to scan.")
        return []

    # Build tasks
    detect_tasks = [run_detect_secrets(d) for d in valid_dirs]
    truffle_tasks = [run_trufflehog3_scan(d) for d in valid_dirs]

    # Run both scanners concurrently
    detect_results, truffle_results = await asyncio.gather(
        asyncio.gather(*detect_tasks),
        asyncio.gather(*truffle_tasks),
    )

    # Flatten
    combined = [item for sub in detect_results for item in sub]
    combined += [item for sub in truffle_results for item in sub]

    # print(Fore.BLUE + Style.BRIGHT + f"[+] 📢 Secret scan found {len(combined)} issues (Detect-Secrets + TruffleHog3)" + Style.RESET_ALL)
    print(Fore.BLUE + Style.BRIGHT + f"[+] 📢 Secret scan found" + Fore.WHITE + Style.BRIGHT, len(combined), Fore.BLUE + Style.BRIGHT + f"issues (Detect-Secrets + TruffleHog3).", Fore.RESET)
    return combined
