from pathlib import Path
import asyncio
import json
from colorama import Fore, Style
from detect_secrets.core.scan import scan_file
from detect_secrets.settings import default_settings
from Utils import file_utils  # Custom utility (e.g., for binary check)


# ----------------------------------------------------------
#  Detect-Secrets Scanner
# ----------------------------------------------------------
async def run_detect_secrets(directory_path):
    results = []
    try:
        directory = Path(directory_path).resolve()
        for file_path in directory.rglob("*"):

            if not file_path.is_file():
                continue

            abs_path = file_path.resolve()

            # Skip binary files if helper is available
            if file_utils.is_binary(abs_path):
                continue

            try:
                file_results = await asyncio.to_thread(
                    scan_with_detect_secrets,
                    abs_path
                )
                results.extend(file_results)
            except Exception as e:
                print(f"[!] Error scanning {abs_path}: {e}")

    except Exception as e:
        print(f"[!] Exception during detect-secrets scan: {e}")

    return results


def scan_with_detect_secrets(file_path: Path):
    findings = []
    with default_settings():
        secrets = scan_file(str(file_path))
        if secrets:
            for secret in secrets:
                findings.append({
                    "tool": "detect-secrets",
                    "severity": "HIGH",
                    "file": str(file_path),
                    "line": secret.line_number,
                    "type": secret.type or "Unknown Secret",
                    "match": secret.secret_value,
                    "details": {
                        "SourceID": getattr(secret, 'source_id', None),
                        "SourceType": getattr(secret, 'source_type', None),
                        "Verified": getattr(secret, 'is_verified', None),
                        "SecretHash": getattr(secret, 'secret_hash', None),
                        "Commit": getattr(secret, 'commit', None),
                        "Path": getattr(secret, 'filename', None),
                    }
                })
    return findings


# ----------------------------------------------------------
#  TruffleHog3 Scanner
# ----------------------------------------------------------
async def run_trufflehog3_scan(target_dir):
    """
    Runs trufflehog3 filesystem scanning for local folders.
    Command: trufflehog3 filesystem <target> -f JSON
    """
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
        print("TruffleHog3 Warning:", stderr.decode(errors="ignore"))

    try:
        findings = json.loads(stdout.decode(errors="ignore"))
    except Exception as e:
        print("❌ Failed to parse trufflehog3 output:", e)
        return []

    normalized = []
    for f in findings:
        normalized.append({
            "tool": "TruffleHog3",
            "severity": f.get("rule", {}).get("severity", "MEDIUM"),
            "file": f.get("path"),
            "line": int(f.get("line", 0)),
            "secret": f.get("secret"),
            "rule_id": f.get("rule", {}).get("id"),
            "message": f.get("rule", {}).get("message"),
            "context": f.get("context"),
            "id": f.get("id"),
        })

    return normalized


# ----------------------------------------------------------
#  MAIN SECRET SCAN COMBINING BOTH
# ----------------------------------------------------------
async def scan(config):

    target_dirs = config.get("target_dirs", ['.'])
    if isinstance(target_dirs, list) and len(target_dirs) == 1 and isinstance(target_dirs[0], list):
        target_dirs = target_dirs[0]

    exclude_dirs = config.get("exclude_dirs", [])

    valid_dirs = [
        str(Path(d).resolve())
        for d in target_dirs
        if Path(d).is_dir() and not any(e in str(Path(d).resolve()) for e in exclude_dirs)
    ]

    detect_tasks = []
    truffle_tasks = []

    for dir_path in valid_dirs:
        detect_tasks.append(run_detect_secrets(dir_path))
        truffle_tasks.append(run_trufflehog3_scan(dir_path))

    # Run both scanners in parallel
    detect_results, truffle_results = await asyncio.gather(
        asyncio.gather(*detect_tasks),
        asyncio.gather(*truffle_tasks)
    )

    # Flatten
    combined = []
    for r in detect_results:
        combined.extend(r)
    for r in truffle_results:
        combined.extend(r)

    print(
        Fore.BLUE + Style.BRIGHT +
        f"[+] 📢 Total Secrets Found: {len(combined)} (Detect-Secrets + TruffleHog3)"
        + Style.RESET_ALL
    )

    return combined
