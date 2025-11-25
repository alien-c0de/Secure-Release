import asyncio
import json
import os
from pathlib import Path
import tempfile
from colorama import Fore, Style

# ------------------------------
# 🛠 Subprocess Wrapper
# ------------------------------
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


# async def run_command(cmd, cwd=None, timeout=6000):
#     print(Fore.CYAN + f"[>] Executing: {cmd}" + Fore.RESET)

#     process = await asyncio.create_subprocess_shell(
#         cmd,
#         stdout=asyncio.subprocess.PIPE,
#         stderr=asyncio.subprocess.PIPE,
#         cwd=cwd
#     )

#     while True:
#         line = await process.stdout.readline()
#         if not line:
#             break
#         print(Fore.YELLOW + "[semgrep] " + Fore.RESET + line.decode().rstrip())

#     stderr = await process.stderr.read()

#     if process.returncode != 0:
#         print(Fore.RED + f"[!] Error running command:\n{stderr.decode()}" + Fore.RESET)

#     return ""  # We already streamed everything live


# ------------------------------
# 🔍 Semgrep (Includes Bandit rules)
# ------------------------------
async def run_semgrep(directory):
    """Run Semgrep with Bandit rules + OWASP + Security Audit."""
    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".json")
    os.close(tmp_fd)  # Semgrep will write to it

    # Semgrep with Bandit built-in (**p/bandit**)
    # cmd = (
    #     f'semgrep scan --verbose --json '
    #     f'--config p/bandit '           # ← Bandit rules
    #     f'--config p/owasp-top-ten '
    #     f'--config p/security-audit '
    #     f'--config p/default '
    #     f'"{directory}" '
    #     f'--output "{tmp_path}"'
    # )

    cmd = (
        f'semgrep scan --verbose --json '
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
    print (cmd)
    await run_command(cmd)

    # Read JSON output (handles Windows timing issues)
    data = {}
    for _ in range(10):
        try:
            with open(tmp_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            break
        except (PermissionError, json.JSONDecodeError):
            await asyncio.sleep(0.2)
    else:
        print(Fore.RED + f"[!] Could not read Semgrep output at: {tmp_path}")
        os.remove(tmp_path)
        return []

    findings = []
    for result in data.get("results", []):

        owasp = (
            result.get("extra", {})
                  .get("metadata", {})
                  .get("owasp", ["UNKNOWN"])
        )

        findings.append({
            "severity": result.get("extra", {}).get("severity", "UNKNOWN"),
            "owasp": owasp[0] if isinstance(owasp, list) else owasp,
            "file": result.get("path"),
            "line": result.get("start", {}).get("line"),
            "pattern_name": result.get("check_id"),
            "description": result.get("extra", {}).get("message"),
            "tool": "Semgrep (incl. Bandit)",
        })

    os.remove(tmp_path)
    return findings


# ------------------------------
# 🚀 Combined Secure Scan (Python Only)
# ------------------------------
async def scan(config):
    # print(Fore.CYAN + "[>] Running Python SAST Analyzer (Semgrep + Bandit rules)...")

    results = []
    target_dirs = config.get("target_dirs", ["./"])

    # Fix nested list (sometimes Streamlit returns [[path]])
    if isinstance(target_dirs, list) and len(target_dirs) == 1 and isinstance(target_dirs[0], list):
        target_dirs = target_dirs[0]

    tasks = []
    for d in target_dirs:
        resolved = Path(d).resolve()
        tasks.append(run_semgrep(resolved))

    # Run all scans concurrently
    all_results = await asyncio.gather(*tasks)

    for r in all_results:
        results.extend(r)

    print(
        Fore.GREEN + Style.BRIGHT +
        f"[+] Found {len(results)} issues via Semgrep (incl. Bandit rules)."
        + Fore.RESET
    )
    return results