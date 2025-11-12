import os
import json
import asyncio
import tempfile
from pathlib import Path
from colorama import Fore, Style
from Utils import config
cfg = config.load_config("config.yaml")
from Core.logger import setup_logger
logger = setup_logger("dep-checker", cfg)

async def scan(config):
    # print(Fore.CYAN + f"\n[+] 📦 Running Dependency Scan...", flush=True)
    results = []

    # Check which languages are defined in the config
    dependency_files = config.get('dependency_files', {})

    if 'python' in dependency_files:
        results += await scan_python(config, dependency_files['python'])
    if 'node' in dependency_files:
        results += await scan_node(config, dependency_files['node'])
    if 'java' in dependency_files:
        results += await scan_java(config)
    if 'dotnet' in dependency_files:
        results += await scan_dotnet(config, dependency_files['dotnet'])

    # print(f"[+] Dependency scan complete: {len(results)} issues found.")
    print(Fore.CYAN + Style.BRIGHT + f"[+] 📢 Dependency scan found" + Fore.WHITE + Style.BRIGHT, len(results), Fore.CYAN + Style.BRIGHT + f"issues.", Fore.RESET)
    return results

async def scan_single_file(req_file):
    """Scan one requirement file and return the results."""
    try:
        # logger.info(f"Running safety scan for {req_file}")
        output = await run_subprocess_py(f"safety scan --output json --file={req_file}", cfg.get("target_dirs", ["./"])[0])
        
        parsed = json.loads(output)
        results = []

        projects = parsed.get("scan_results", {}).get("projects", [])
        for project in projects:
            for file_entry in project.get("files", []):
                file_path = file_entry.get("location", "unknown")

                for dependency in file_entry.get("results", {}).get("dependencies", []):
                    package_name = dependency.get("name", "unknown")

                    for spec in dependency.get("specifications", []):
                        version = spec.get("raw") or "unknown"
                        vulnerabilities = spec.get("vulnerabilities", {}).get("known_vulnerabilities", [])
                        remediation_value = None
                        remediation = spec.get("vulnerabilities", {}).get("remediation", {}) or {}
                        remediation_value = remediation.get("recommended")

                        for vuln in vulnerabilities:
                            ignored = vuln.get("ignored") or {}
                            ignored_reason = ignored.get("reason", "")
                            more_info_url = extract_more_info(ignored_reason)

                            results.append({
                                "file": file_path,
                                "package": package_name,
                                "current ver": version,
                                "advisory id": vuln.get("id", "N/A"),
                                "severity": ignored.get("code", "unknown").upper(),
                                "affected ver range": vuln.get("vulnerable_spec", "unknown"),
                                "description": ignored_reason[:150],
                                "recommended ver": remediation_value,  # Not available
                                "reference URL": more_info_url
                            })
        
        # logger.info(f"Safety scan completed for {req_file}")
        return results

    except json.JSONDecodeError:
        logger.error(f"Invalid JSON from safety for {req_file}")
        return []
    except Exception as e:
        logger.error(f"Safety scan failed for {req_file}: {e}")
        return []

def extract_more_info(ignored_reason):
    """Extract more info URL from ignored reason."""
    if "See " in ignored_reason:
        return ignored_reason.split("See ")[-1].strip()
    return "N/A"

async def scan_python(config, python_files):
    """Scan all python dependency files concurrently."""
    # logger.info("[>] Scanning Python dependencies with Safety...")
    tasks = []
    for dep_file in python_files:
        files = find_files(config, dep_file)
        for req_file in files:
            tasks.append(scan_single_file(req_file))
    
    all_results = await asyncio.gather(*tasks)
    # Flatten the list of lists
    return [item for sublist in all_results for item in sublist]

async def run_subprocess_py(command, cwd=None, timeout=60):
    try:
        # logger.info(f"Executing command: {command} in {cwd or 'current directory'}")
        
        # Create subprocess with optional working directory
        process = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd  # Set the working directory
        )

        # Wait for the process to complete or timeout
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            process.kill()
            await process.communicate()
            raise RuntimeError(f"Command '{command}' timed out after {timeout} seconds")

        # if process.returncode != 0:
        #     error_message = stderr.decode().strip()
        #     raise RuntimeError(f"Command '{command}' failed with code {process.returncode}: {error_message}")

        output = stdout.decode().strip()
        return output

    except Exception as e:
        logger.error(f"Error running subprocess: {e}")
        raise

# Node.js: npm audit
async def scan_node(config, node_files):
    print("[>] Scanning Node.js dependencies...")
    results = []
    for dep_file in node_files:
        files = find_files(config, dep_file)
        for file in files:
            dir_path = os.path.dirname(file)
            try:
                output = await run_subprocess(f"npm audit --json", cwd=dir_path)
                audit_data = json.loads(output)
                advisories = audit_data.get("vulnerabilities", {})
                for pkg, info in advisories.items():
                    results.append({
                        "file": file,
                        "package": pkg,
                        "version": info.get("installedVersion"),
                        "vuln_id": info.get("via", [{}])[0].get("source", "N/A"),
                        "severity": info.get("severity"),
                        "description": info.get("via", [{}])[0].get("title", "")[:150]
                    })
            except Exception as e:
                print(f"[!] Node audit failed: {e}")
    return results

async def run_subprocess(cmd):
    # print(f"[>] Running command: {cmd}")
    process = await asyncio.create_subprocess_shell(
        cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        shell=True  # Needed to run .bat files on Windows
    )
    stdout, stderr = await process.communicate()

    # if stdout:
    #     print(stdout.decode())
    # if stderr:
    #     print(stderr.decode())

    # if process.returncode != 0:
    #     raise Exception(f"Command failed with exit code {process.returncode}")
    
async def scan_java(config):
    # print("[>] Scanning Java dependencies...")
    results = []

    dirs = config.get('target_dirs', ['.'])
    if isinstance(dirs, list) and len(dirs) == 1 and isinstance(dirs[0], list):
        dirs = dirs[0]

    dep_check_path = config.get('tools', {}).get('dependency_check', 'dependency-check.bat')
    dep_check_path_quoted = f'"{Path(dep_check_path)}"'

    for d in dirs: 
        try:
            if isinstance(d, list):
                d = d[0]
            scan_dir_quoted = f'"{Path(d).resolve()}"'

            report_path = os.path.join(tempfile.gettempdir(), "depcheck-report.json")
            report_path_quoted = f'"{report_path}"'

            project_name = "ProjScan"
            cmd = f'{dep_check_path_quoted} --project "{project_name}" --scan {scan_dir_quoted} --format JSON --out {report_path_quoted} --noupdate'
            # print(f"[>] Running command:\n{cmd}")
            await run_subprocess(cmd)

            # Parse JSON report
            with open(report_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                dependencies = data.get("dependencies", [])

                for dep in dependencies:
                    file_name = dep.get("fileName", "unknown")
                    file_path = dep.get("filePath", "unknown")
                    
                    for vuln in dep.get("vulnerabilities", []):
                        results.append({
                            "fileName": file_name,
                            "filePath": file_path,
                            "name": vuln.get("name", "N/A"),  # CVE ID
                            "severity": vuln.get("severity", "unknown"),
                            "description": (vuln.get("description") or "")[:150]
                        })
                        # print(f"[+] Found vulnerability: {vuln.get('name')} in {file_name}")

        except Exception as e:
            print(f"[!] Java audit failed: {e}")

    return results

# .NET: dotnet list package
async def scan_dotnet(config, dotnet_files):
    print("[>] Scanning .NET dependencies...")
    results = []
    for dep_file in dotnet_files:
        files = find_files(config, dep_file)
        for file in files:
            dir_path = os.path.dirname(file)
            try:
                output = await run_subprocess("dotnet list package --vulnerable --include-transitive", cwd=dir_path)
                for line in output.splitlines():
                    if "[" in line and "]" in line:
                        parts = line.strip().split()
                        if len(parts) >= 3:
                            results.append({
                                "file": file,
                                "package": parts[0],
                                "version": parts[1],
                                "vuln_id": parts[-1].strip('[]'),
                                "severity": "Unknown",
                                "description": "Vulnerability found via .NET audit"
                            })
            except Exception as e:
                print(f"[!] .NET audit failed: {e}")
    return results

# Utility to find files
def find_files(config, filename):
    targets = config.get('target_dirs', ['.'])
    matches = []
    for path in targets:
        for root, _, files in os.walk(path):
            for f in files:
                if f == filename:
                    matches.append(os.path.join(root, f))
    return matches