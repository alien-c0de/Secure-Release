import asyncio
import json
import os
from pathlib import Path
from colorama import Fore, Style
from Utils.logger_config import get_logger

# Initialize logger for this module
logger = get_logger(__name__)

# -------------------------------------------------
# 🔧 Run shell commands async
# -------------------------------------------------
async def run_cmd(cmd, cwd=None, timeout=900):
    """Run a shell command asynchronously and return stdout."""
    logger.debug(f"Executing command: {cmd[:100]}..." if len(cmd) > 100 else f"Executing command: {cmd}")
    logger.debug(f"Working directory: {cwd}")
    logger.debug(f"Timeout: {timeout}s")
    
    try:
        process = await asyncio.create_subprocess_shell(
            cmd,
            cwd=cwd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
        
        stdout_decoded = stdout.decode().strip()
        stderr_decoded = stderr.decode().strip()

        if process.returncode != 0:
            logger.warning(f"Command returned non-zero exit code {process.returncode}")
            logger.warning(f"STDERR: {stderr_decoded[:500]}")  # Log first 500 chars
        else:
            logger.debug(f"Command completed successfully")

        return stdout_decoded, stderr_decoded

    except asyncio.TimeoutError:
        logger.error(f"Command timeout after {timeout} seconds: {cmd[:100]}")
        print(Fore.RED + f"[⏳ Timeout] {cmd} exceeded {timeout} seconds" + Fore.RESET)
        return "", ""
    except Exception as e:
        logger.error(f"Command execution failed: {str(e)}", exc_info=True)
        return "", ""

# -------------------------------------------------
# 🐍 1. Safety Scanner (Python dependencies)
# -------------------------------------------------
async def run_safety(file_path: Path):
    """Run Safety only on the specific file (no full directory scan)."""
    logger.info(f"Starting Safety scan for: {file_path}")
    
    if not file_path.exists():
        logger.warning(f"File not found: {file_path}")
        return []

    cmd = f'safety scan --output json --file="{file_path}"'
    stdout, stderr = await run_cmd(cmd, cwd=file_path.parent)

    try:
        parsed = json.loads(stdout)
        logger.debug(f"Successfully parsed Safety output")
    except Exception as e:
        logger.error(f"Failed to parse Safety JSON output: {str(e)}")
        logger.debug(f"Raw output (first 500 chars): {stdout[:500]}")
        return []

    # Use a dictionary to group vulnerabilities by package
    vuln_dict = {}
    projects = parsed.get("scan_results", {}).get("projects", [])
    logger.info(f"Safety found {len(projects)} project(s) to analyze")

    for project in projects:
        for file_entry in project.get("files", []):
            deps = file_entry.get("results", {}).get("dependencies", [])
            logger.debug(f"Processing {len(deps)} dependencies")

            for dep in deps:
                package = dep.get("name", "unknown")

                for spec in dep.get("specifications", []):
                    version = spec.get("raw", "unknown")
                    vuln_info = spec.get("vulnerabilities", {})

                    # Create a unique key for each package+version combination
                    key = f"{package}@{version}@{file_path}"

                    for v in vuln_info.get("known_vulnerabilities", []):
                        ignored = v.get("ignored") or {}
                        advisory_id = v.get("id", "N/A")
                        affected_range = v.get("vulnerable_spec", "unknown")
                        
                        logger.debug(f"Vulnerability found: {package}@{version} - {advisory_id}")

                        # If this package+version is new, create an entry
                        if key not in vuln_dict:
                            vuln_dict[key] = {
                                "package": package,
                                "current version": version,
                                "affected range": affected_range,
                                "file": str(file_path),
                                "ignored": ignored.get("code", None),
                                "ignored reason": ignored.get("reason", None),
                                "tool": "Safety",
                                "advisory ids": advisory_id  # Start with first ID as string
                            }
                        else:
                            # Append subsequent IDs with comma separator
                            vuln_dict[key]["advisory ids"] += f", {advisory_id}"

    # Convert dictionary back to list
    results = list(vuln_dict.values())
    
    # Count total advisories by splitting the string
    total_advisories = sum(len(v["advisory ids"].split(", ")) for v in results)
    logger.info(f"Safety scan completed: {len(results)} unique packages with {total_advisories} total vulnerabilities in {file_path}")
    
    # Log details for each package
    for result in results:
        logger.debug(f"Package: {result['package']} - Advisory IDs: {result['advisory ids']}")
    
    return results

# -------------------------------------------------
# ☕ 2. Java OWASP Dependency-Check (Local CLI)
# -------------------------------------------------
async def run_dependency_check(directory: Path):
    """Run OWASP Dependency-Check CLI in isolated mode."""
    logger.info(f"Starting OWASP Dependency-Check scan for: {directory}")
    
    report_dir = directory / "dc-report"
    report_dir.mkdir(exist_ok=True)
    logger.debug(f"Created report directory: {report_dir}")

    output_json = report_dir / "dependency-check.json"

    cmd = (
        f'dependency-check --scan "{directory}" '
        f'--format JSON --out "{report_dir}" --disableBundleAudit '
        f'--enableExperimental'
    )

    _, stderr = await run_cmd(cmd, cwd=directory)

    # Read report
    if not output_json.exists():
        logger.error(f"Dependency-Check report not generated: {output_json}")
        print(Fore.RED + "[✖] No dependency-check JSON report found!" + Fore.RESET)
        return []

    logger.debug(f"Reading Dependency-Check report from: {output_json}")

    try:
        data = json.loads(output_json.read_text())
        logger.debug("Successfully parsed Dependency-Check JSON")
    except Exception as e:
        logger.error(f"Failed to parse Dependency-Check output: {str(e)}", exc_info=True)
        return []

    findings = []
    dependencies = data.get("dependencies", [])
    logger.info(f"Analyzing {len(dependencies)} dependencies")

    for dep in dependencies:
        vulns = dep.get("vulnerabilities", [])
        file_name = dep.get("fileName", "unknown")
        
        if vulns:
            logger.debug(f"Found {len(vulns)} vulnerabilities in {file_name}")
        
        for v in vulns:
            findings.append({
                "tool": "OWASP Dependency-Check",
                "file": file_name,
                "severity": v.get("severity", "UNKNOWN"),
                "cwe": v.get("cwe", ""),
                "description": v.get("description", "")[:200],
                "name": v.get("name", ""),
                "source": v.get("source", ""),
            })

    logger.info(f"OWASP Dependency-Check completed: {len(findings)} findings")
    return findings

# -------------------------------------------------
# 🚀 MAIN ENGINE
# -------------------------------------------------
async def scan(cfg):
    """
    Runs only:
      ✓ Safety scan (Python) for specific files
      ✓ OWASP DC scan for Java
    """
    logger.info("="*50)
    logger.info("Starting Dependency Checker scan")
    
    results = []
    dep_files = cfg.get("dependency_files", {})
    target_dirs = cfg.get("target_dirs", ["./"])
    
    if isinstance(target_dirs, list) and target_dirs:
        project_path = Path(target_dirs[0])
    else:
        project_path = Path("./")
    
    logger.info(f"Project path: {project_path}")

    safety_targets = dep_files.get("python", [])   # list of filenames
    java_scan = dep_files.get("java", [])          # any file means Java project exists
    
    logger.info(f"Python dependency files to scan: {safety_targets}")
    logger.info(f"Java scanning enabled: {bool(java_scan)}")

    # ----------------------------
    # 1️⃣ Safety file-by-file scan
    # ----------------------------
    tasks = []
    for file in safety_targets:
        fp = project_path / file
        logger.debug(f"Adding Safety scan task for: {fp}")
        tasks.append(run_safety(fp))

    # ----------------------------
    # 2️⃣ Java Dependency-Check
    # ----------------------------
    if java_scan:
        logger.info("Adding Java Dependency-Check task")
        tasks.append(run_dependency_check(project_path))
    else:
        logger.debug("Java scanning not enabled")

    logger.info(f"Total scan tasks to execute: {len(tasks)}")

    # Run all scans in parallel
    try:
        all_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Check for exceptions
        for idx, result in enumerate(all_results):
            if isinstance(result, Exception):
                logger.error(f"Scan task {idx} failed with exception", exc_info=result)
                continue
            results.extend(result)
        
        logger.info(f"All dependency scan tasks completed")
        
    except Exception as e:
        logger.error(f"Error during dependency scanning: {str(e)}", exc_info=True)

    print(Fore.CYAN + Style.BRIGHT + f"[+] 📢 Dependency scan found" + Fore.WHITE + Style.BRIGHT, len(results), Fore.CYAN + Style.BRIGHT + f"issues.", Fore.RESET)
    logger.info(f"Dependency scan completed: {len(results)} total findings")
    logger.info("="*50)
    
    return results