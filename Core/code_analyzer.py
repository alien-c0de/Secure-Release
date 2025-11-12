import asyncio
import json
import os
from pathlib import Path
import tempfile
from colorama import Fore, Style


def is_semgrep_available():
    """Check if semgrep is installed."""
    from shutil import which
    return which("semgrep") is not None

async def scan(config):
    # print(Fore.LIGHTGREEN_EX + f"\n[+] 🧑‍💻 Running Static Code Analyzer...", flush=True)
    results = []

    if not is_semgrep_available():
        print(Fore.RED + "[!] Semgrep is not installed. Skipping code analysis." + Fore.RESET)
        return results

    target_dirs = config.get("target_dirs", ["."])
    if isinstance(target_dirs, list) and len(target_dirs) == 1 and isinstance(target_dirs[0], list):
        target_dirs = target_dirs[0]

    for directory in target_dirs:
        directory = Path(directory).resolve()

        with tempfile.NamedTemporaryFile(mode="w+", delete=False, suffix=".json") as tmp_report:
            tmp_path = tmp_report.name
            cmd = f'semgrep --config=p/java --json "{directory}" --output "{tmp_path}" --quiet'

            await run_subprocess(cmd)
            await asyncio.sleep(0.1)

            try:
                with open(tmp_path, "r", encoding="utf-8") as f:
                    semgrep_result = json.load(f)

                    for issue in semgrep_result.get("results", []):
                        check_id = issue.get("check_id")
                        file_path = issue.get("path")
                        start_line = issue.get("start", {}).get("line")
                        message = issue.get("extra", {}).get("message", "")

                        # Extract metadata safely
                        metadata = issue.get("extra", {}).get("metadata", {})
                        impact = metadata.get("impact") or issue.get("extra", {}).get("severity", "UNKNOWN")
                        owasp = metadata.get("owasp", "N/A")

                        # Ensure OWASP is always a string (in case it's a list or empty)
                        if isinstance(owasp, list):
                            owasp = ", ".join(owasp) if owasp else "N/A"

                        results.append(
                            {   
                                "impact": impact if impact else "UNKNOWN",
                                "file": file_path,
                                "line": start_line,
                                "pattern_name": check_id,
                                "line_content": message,
                                "owasp": owasp if owasp else "N/A",
                            }
                        )
            except Exception as e:
                print(f"[!] Failed to parse Semgrep report: {e}")

            # Cleanup
            try:
                os.remove(tmp_path)
            except Exception as e:
                print(f"[!] Could not delete temp file: {e}")

    print(Fore.LIGHTGREEN_EX + Style.BRIGHT + f"[+] 📢 Static Code Analyzer found" + Fore.WHITE + Style.BRIGHT, len(results), Fore.LIGHTGREEN_EX + Style.BRIGHT + f"issues.", Fore.RESET)
    return results


async def run_subprocess(cmd):
    CREATE_NO_WINDOW = 0x08000000  # Windows-specific flag
    process = await asyncio.create_subprocess_shell(
        cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        creationflags=CREATE_NO_WINDOW,  # 👈 suppresses extra console spam
        shell=True
    )
    stdout, stderr = await process.communicate()

    if process.returncode != 0:
        raise Exception(
            f"Command failed with exit code {process.returncode}\n"
            f"STDOUT: {stdout.decode()}\nSTDERR: {stderr.decode()}"
        )
