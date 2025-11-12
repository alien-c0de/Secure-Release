from pathlib import Path
import asyncio
from colorama import Fore, Style
from detect_secrets.core.scan import scan_file
from detect_secrets.settings import default_settings
from Utils import file_utils  # Custom utility (e.g., for binary check)

async def run_detect_secrets(directory_path):
    results = []
    try:
        directory = Path(directory_path).resolve()  # Always work with absolute paths
        for file_path in directory.rglob("*"):  # Recursively iterate over files
            if file_path.is_file():
                abs_path = file_path.resolve()  # Ensure full path

                # Skip binary files if helper is available
                if file_utils.is_binary(abs_path):
                    continue

                try:
                    # print(f"[+] Scanning {abs_path} with detect-secrets...")
                    file_results = await asyncio.to_thread(
                        scan_with_detect_secrets, abs_path
                    )
                    results.extend(file_results)
                except Exception as e:
                    print(f"[!] Error scanning {abs_path}: {e}")
    except Exception as e:
        print(f"[!] Exception during scan of {directory_path}: {e}")
    return results

def scan_with_detect_secrets(file_path: Path):
    findings = []
    with default_settings():
        secrets = scan_file(str(file_path))  # detect-secrets expects str
        if secrets:
            for secret in secrets:
                findings.append({
                    "severity": "High",  # Default severity
                    "file": str(file_path),
                    "line": secret.line_number,
                    "type": secret.type or "Unknown Secret",
                    "match": secret.secret_value,  # Already redacted
                    "Tool Details": {
                        "SourceID": getattr(secret, 'source_id', None),
                        "SourceType": getattr(secret, 'source_type', None),
                        "Verified": getattr(secret, 'is_verified', None),
                        "SecretHash": getattr(secret, 'secret_hash', None),
                        "Commit": getattr(secret, 'commit', None),
                        "Path": getattr(secret, 'filename', None)
                    }
                })
    return findings

async def scan(config):
    # print(Fore.BLUE + f"\n[+] 🕵️ Running Secret Scanner...", flush=True)

    target_dirs = config.get('target_dirs', ['.'])
    if isinstance(target_dirs, list) and len(target_dirs) == 1 and isinstance(target_dirs[0], list):
        target_dirs = target_dirs[0]
    exclude_dirs = config.get('exclude_dirs', [])

    valid_dirs = [
        str(Path(d).resolve())
        for d in target_dirs
        if Path(d).is_dir() and not any(e in str(Path(d).resolve()) for e in exclude_dirs)
    ]

    tasks = [run_detect_secrets(dir_path) for dir_path in valid_dirs]
    all_results = await asyncio.gather(*tasks)

    secret_results = []
    for result in all_results:
        secret_results.extend(result)

    print(Fore.BLUE + Style.BRIGHT + f"[+] 📢 Secret Scanner found" + Fore.WHITE + Style.BRIGHT, len(secret_results), Fore.BLUE + Style.BRIGHT + f"issues.", Fore.RESET)
    # print(f"[+] detect-secrets found {len(secret_results)} potential secrets.")

    return secret_results