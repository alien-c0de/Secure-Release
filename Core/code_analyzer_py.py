import asyncio
import json
import os
from pathlib import Path
import tempfile
from colorama import Fore, Style

# ============================================================
# 🔧 Subprocess Runner (Streaming + Windows Friendly)
# ============================================================
async def run_command(cmd, cwd=None, timeout=60000):
    """Run any command and return stdout as string."""
    process = await asyncio.create_subprocess_shell(
        cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=cwd
    )
    stdout, stderr = await process.communicate()

    if process.returncode != 0:
        print(Fore.RED + f"[!] Error running {cmd}: {stderr.decode().strip()}")

    return stdout.decode().strip()

# async def run_command(cmd, cwd=None, timeout=1200):
#     """
#     Runs a command & streams stdout in real-time.
#     Prevents Semgrep hanging by:
#     - enabling streaming
#     - disabling buffering
#     - avoiding deadlocks
#     """

#     # print(Fore.CYAN + f"[>] Executing: {cmd}" + Fore.RESET)

#     process = await asyncio.create_subprocess_shell(
#         cmd,
#         stdout=asyncio.subprocess.PIPE,
#         stderr=asyncio.subprocess.PIPE,
#         cwd=cwd
#     )

#     # Stream stdout live
#     while True:
#         line = await process.stdout.readline()
#         if not line:
#             break
#         print(Fore.YELLOW + "[semgrep] " + Fore.RESET + line.decode(errors="ignore").rstrip())

#     # Read stderr
#     stderr = await process.stderr.read()

#     if process.returncode != 0:
#         print(Fore.RED + f"[!] Error running command:\n{stderr.decode(errors='ignore')}" + Fore.RESET)

#     return ""  # all output was already streamed


# ============================================================
# 🔍 Semgrep (Balanced Mode)
# Python-only + Bandit + OWASP + Security Audit
# ============================================================
async def run_semgrep(directory):
    """
    Enhanced Semgrep parser:
    ✔ Extracts ONLY OWASP 2021 category
    ✔ Replaces pattern_name with CWE details
    ✔ Falls back correctly when metadata is missing
    ✔ Uses a safe balanced ruleset
    """

    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".json")
    os.close(tmp_fd)

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

    await run_command(cmd)

    # -----------------------------------------------
    # Read JSON (Windows safe)
    # -----------------------------------------------
    data = {}
    for _ in range(10):
        try:
            with open(tmp_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            break
        except (PermissionError, json.JSONDecodeError):
            await asyncio.sleep(0.25)
    else:
        print(Fore.RED + f"[!] Could not read Semgrep output at: {tmp_path}")
        os.remove(tmp_path)
        return []

    findings = []

    # -----------------------------------------------
    # Parse Each Finding
    # -----------------------------------------------
    for result in data.get("results", []):
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

        findings.append({
            "severity": result.get("extra", {}).get("severity", "UNKNOWN"),
            "owasp": owasp_2021,
            "file": result.get("path"),
            "line": result.get("start", {}).get("line"),
            "CWE": cwe_final,       # <-- Replace rule ID with CWE!
            "description": result.get("extra", {}).get("message"),
            "tool": "Semgrep (Balanced)",
        })

    os.remove(tmp_path)
    return findings


# ============================================================
# 🚀 Combined SAST Scan
# ============================================================
async def scan(config):
    """
    Runs balanced Semgrep scan across all target directories.
    """

    results = []
    target_dirs = config.get("target_dirs", ["./"])

    # Fix nested Streamlit list (e.g. [["C:/path"]])
    if isinstance(target_dirs, list) and len(target_dirs) == 1 and isinstance(target_dirs[0], list):
        target_dirs = target_dirs[0]

    tasks = []
    for d in target_dirs:
        resolved = Path(d).resolve()
        tasks.append(run_semgrep(resolved))

    all_results = await asyncio.gather(*tasks)

    for r in all_results:
        results.extend(r)

    # print(Fore.GREEN + Style.BRIGHT + f"[+] Balanced SAST completed: {len(results)} findings." + Fore.RESET)
    print(Fore.GREEN + Style.BRIGHT + f"[+] 📢 Code Analyzer scan found" + Fore.WHITE + Style.BRIGHT, len(results), Fore.GREEN + Style.BRIGHT + f"issues.", Fore.RESET)
    return results


# ============================================================
# 🧪 Local Testing
# ============================================================
if __name__ == "__main__":
    import asyncio
    cfg = {"target_dirs": ["./Sample_code/dvpwa"]}
    asyncio.run(scan(cfg))
