import asyncio
import json
import os
from pathlib import Path
import tempfile
from colorama import Fore, Style

# ------------------------------
# ✅ Helper: Check if tool exists
# ------------------------------
def is_tool_available(tool_name):
    try:
        __import__(tool_name)
        return True
    except ImportError:
        return False


# ------------------------------
# 🧠 Helper: Run shell command async
# ------------------------------
# async def run_command(command):
#     """Run a shell command asynchronously and return its stdout."""
#     process = await asyncio.create_subprocess_shell(
#         command,
#         stdout=asyncio.subprocess.PIPE,
#         stderr=asyncio.subprocess.PIPE,
#     )
#     stdout, stderr = await process.communicate()

#     if process.returncode != 0 and not stdout:
#         print(Fore.RED + f"[!] Error running {command}: {stderr.decode().strip()}")
#     return stdout.decode().strip()


# ------------------------------
# 🐍 Bandit (Python SAST)
# ------------------------------
async def run_bandit(directory):
    """Run Bandit on Python code and parse results safely (Windows compatible)."""
    # print(Fore.CYAN + f"[>] Running Bandit scan on: {directory}")
    findings = []

    # Create a temp JSON file and immediately close it
    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".json")
    os.close(tmp_fd)  # Important: close file handle before Bandit writes to it

    cmd = f'bandit -r "{directory}" -f json -o "{tmp_path}"'
    process = await asyncio.create_subprocess_shell(
        cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    await process.communicate()

    # Wait briefly for Bandit to finish writing to file (Windows sometimes delays file release)
    for _ in range(10):
        try:
            with open(tmp_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            break
        except (PermissionError, json.JSONDecodeError):
            await asyncio.sleep(0.2)
    else:
        print(Fore.RED + f"[!] Failed to read Bandit output from {tmp_path}")
        os.remove(tmp_path)
        return []

    # Parse results
    for issue in data.get("results", []):
        findings.append({
            "tool": "Bandit",
            "impact": issue.get("issue_severity", "UNKNOWN"),
            "file": issue.get("filename"),
            "line": issue.get("line_number"),
            "pattern_name": issue.get("test_name"),
            "description": issue.get("issue_text"),
        })

    os.remove(tmp_path)
    return findings

async def run_command(cmd, cwd=None, timeout=600):
    """Run a subprocess command and return stdout."""
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

# ------------------------------
# 🌐 Semgrep (Multi-language SAST)
# ------------------------------
async def run_semgrep(directory):
    """Run Semgrep on multi-language source safely (Windows-compatible)."""
    # print(Fore.CYAN + f"[>] Running Semgrep OWASP scan on: {directory}")

    # ✅ Step 1: Create a temp file but close it before writing
    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".json")
    os.close(tmp_fd)

    # ✅ Step 2: Run semgrep with --output instead of shell redirection
    # (Avoids file lock + quoting issues on Windows)
    cmd = (
        f'semgrep --quiet --json '
        f'--config p/owasp-top-ten --config p/python --config p/javascript '
        f'--config p/security-audit "{directory}" '
        f'--output "{tmp_path}"'
    )

    await run_command(cmd)

    # ✅ Step 3: Wait a bit for Windows file release
    data = {}
    for _ in range(10):
        try:
            with open(tmp_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            break
        except (PermissionError, json.JSONDecodeError):
            await asyncio.sleep(0.2)
    else:
        print(Fore.RED + f"[!] Failed to read Semgrep output file: {tmp_path}")
        os.remove(tmp_path)
        return []

    # ✅ Step 4: Parse results
    findings = []
    for result in data.get("results", []):
        findings.append({
            "tool": "Semgrep",
            "impact": result.get("extra", {}).get("severity", "UNKNOWN"),
            "file": result.get("path"),
            "line": result.get("start", {}).get("line"),
            "pattern_name": result.get("check_id"),
            "description": result.get("extra", {}).get("message"),
        })

    os.remove(tmp_path)
    return findings


# ------------------------------
# 🔍 Combined Secure Scan
# ------------------------------
async def scan(config):
    print(Fore.LIGHTGREEN_EX + "\n[+] 🧑‍💻 Running Secure Code Analyzer (Bandit + Semgrep)...", flush=True)

    results = []
    target_dirs = config.get("target_dirs", ["."])
    if isinstance(target_dirs, list) and len(target_dirs) == 1 and isinstance(target_dirs[0], list):
        target_dirs = target_dirs[0]

    tasks = []
    for directory in target_dirs:
        directory = Path(directory).resolve()
        tasks.append(run_bandit(directory))
        tasks.append(run_semgrep(directory))

    # Run all scanners concurrently
    all_results = await asyncio.gather(*tasks)
    for r in all_results:
        results.extend(r)

    # Display summary
    # print(
    #     Fore.LIGHTGREEN_EX + Style.BRIGHT +
    #     f"[+] 📢 Code Analyzer completed — total findings: {len(results)}" +
    #     Fore.RESET
    # )
    print(Fore.LIGHTGREEN_EX + Style.BRIGHT  + f"[+] 📢 Code Analyzer found" + Fore.WHITE + Style.BRIGHT, len(results), Fore.LIGHTGREEN_EX + Style.BRIGHT + f"issues.", Fore.RESET)
    return results


# ------------------------------
# 🧪 Example test run
# ------------------------------
if __name__ == "__main__":
    import asyncio

    config = {"target_dirs": ["./Sample_code/dvpwa"]}
    asyncio.run(scan(config))
