import asyncio
import json
import os
from pathlib import Path
from colorama import Fore, Style

# -------------------------------------------------
# 🔧 Run shell commands async
# -------------------------------------------------
async def run_cmd(cmd, cwd=None, timeout=900):
    """Run a shell command asynchronously and return stdout."""
    # print(Fore.CYAN + f"[dependency-checker] ▶ {cmd}" + Fore.RESET)

    try:
        process = await asyncio.create_subprocess_shell(
            cmd,
            cwd=cwd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)

        # if process.returncode != 0:
        #     print(Fore.RED + f"[✖] Command failed: {stderr.decode()}" + Fore.RESET)

        return stdout.decode().strip(), stderr.decode().strip()

    except asyncio.TimeoutError:
        print(Fore.RED + f"[⏳ Timeout] {cmd} exceeded {timeout} seconds" + Fore.RESET)
        return "", ""


# -------------------------------------------------
# 🐍 1. Safety Scanner (Python dependencies)
# -------------------------------------------------
async def run_safety(file_path: Path):
    """Run Safety only on the specific file (no full directory scan)."""
    if not file_path.exists():
        return []

    cmd = f'safety scan --output json --file="{file_path}"'
    stdout, _ = await run_cmd(cmd, cwd=file_path.parent)

    try:
        parsed = json.loads(stdout)
    except Exception:
        return []

    results = []
    projects = parsed.get("scan_results", {}).get("projects", [])

    for project in projects:
        for file_entry in project.get("files", []):
            deps = file_entry.get("results", {}).get("dependencies", [])

            for dep in deps:
                package = dep.get("name", "unknown")

                for spec in dep.get("specifications", []):
                    version = spec.get("raw", "unknown")
                    vuln_info = spec.get("vulnerabilities", {})

                    for v in vuln_info.get("known_vulnerabilities", []):
                        ignored = v.get("ignored") or {}

                        results.append({
                            "package": package,
                            "current version": version,
                            "advisory id": v.get("id", "N/A"),
                            "affected range": v.get("vulnerable_spec", "unknown"),
                            "file": str(file_path),
                            "ignored": ignored.get("code", None),
                            "ignored reason": ignored.get("reason", None),
                            "tool": "Safety",
                        })

    return results

# -------------------------------------------------
# ☕ 2. Java OWASP Dependency-Check (Local CLI)
# -------------------------------------------------
async def run_dependency_check(directory: Path):
    """Run OWASP Dependency-Check CLI in isolated mode."""
    report_dir = directory / "dc-report"
    report_dir.mkdir(exist_ok=True)

    output_json = report_dir / "dependency-check.json"

    cmd = (
        f'dependency-check --scan "{directory}" '
        f'--format JSON --out "{report_dir}" --disableBundleAudit '
        f'--enableExperimental'
    )

    _, stderr = await run_cmd(cmd, cwd=directory)

    # Read report
    if not output_json.exists():
        print(Fore.RED + "[✖] No dependency-check JSON report found!" + Fore.RESET)
        return []

    try:
        data = json.loads(output_json.read_text())
    except Exception:
        return []

    findings = []
    for dep in data.get("dependencies", []):
        vulns = dep.get("vulnerabilities", [])
        for v in vulns:
            findings.append({
                "tool": "OWASP Dependency-Check",
                "file": dep.get("fileName"),
                "severity": v.get("severity", "UNKNOWN"),
                "cwe": v.get("cwe", ""),
                "description": v.get("description", "")[:200],
                "name": v.get("name", ""),
                "source": v.get("source", ""),
            })

    return findings


# -------------------------------------------------
# 🚀 MAIN ENGINE
# -------------------------------------------------
async def scan(cfg):
    """
    Runs only:
      ✔ Safety scan (Python) for specific files
      ✔ OWASP DC scan for Java
    """

    results = []
    dep_files = cfg.get("dependency_files", {})
    project_path = Path(cfg.get("target_dirs", ["./"])[0])

    safety_targets = dep_files.get("python", [])   # list of filenames
    java_scan = dep_files.get("java", [])          # any file means Java project exists

    # ----------------------------
    # 1️⃣ Safety file-by-file scan
    # ----------------------------
    tasks = []
    for file in safety_targets:
        fp = project_path / file
        tasks.append(run_safety(fp))

    # ----------------------------
    # 2️⃣ Java Dependency-Check
    # ----------------------------
    if java_scan:
        tasks.append(run_dependency_check(project_path))

    # Run all scans in parallel
    all_results = await asyncio.gather(*tasks)

    for res in all_results:
        results.extend(res)

    # print(Fore.GREEN + f"[✓] Dependency scan complete. {len(results)} findings collected." + Fore.RESET)
    print(Fore.CYAN + Style.BRIGHT + f"[+] 📢 Dependency scan found" + Fore.WHITE + Style.BRIGHT, len(results), Fore.CYAN + Style.BRIGHT + f"issues.", Fore.RESET)
    return results
