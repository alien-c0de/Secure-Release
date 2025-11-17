# Core/api_scanner.py
import asyncio
import time
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin
from colorama import Fore, Style
import pyfiglet
import os

try:
    from zapv2 import ZAPv2
except Exception:
    ZAPv2 = None

import aiohttp


@dataclass
class ApiFinding:
    tool: str
    severity: str
    title: str
    description: str
    endpoint: str
    method: str = ""
    parameter: str = ""
    evidence: str = ""
    owasp: str = ""
    cwe: str = ""
    references: List[str] = None

    def to_dict(self):
        d = asdict(self)
        d["references"] = d["references"] or []
        return d


# ---------------------------
# Helpers
# ---------------------------
def _severity_from_zap_risk(risk: str) -> str:
    if not risk:
        return "UNKNOWN"
    r = risk.strip().upper()
    mapping = {
        "HIGH": "HIGH",
        "MEDIUM": "MEDIUM",
        "LOW": "LOW",
        "INFORMATIONAL": "INFO",
        "INFO": "INFO",
    }
    return mapping.get(r, "UNKNOWN")

def _make_auth_headers(auth_cfg: Dict[str, Any]) -> Dict[str, str]:
    if not auth_cfg:
        return {}
    mode = (auth_cfg.get("type") or "").lower()
    if mode == "api_key":
        return {auth_cfg.get("header", "x-api-key"): auth_cfg.get("value", "")}
    if mode == "bearer":
        token = auth_cfg.get("token", "")
        return {"Authorization": f"Bearer {token}"} if token else {}
    return auth_cfg.get("headers", {})

def _normalize_url(base_url: str, path: str) -> str:
    if path.startswith("http://") or path.startswith("https://"):
        return path
    return urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))

# ---------------------------
# Async Fuzzer (aiohttp)
# ---------------------------
DEFAULT_FUZZ_WORDS = [
    "'", "\"", "<script>alert(1)</script>", "../../etc/passwd", "%00",
    "${{7*7}}", "`id`", "OR 1=1", "{{7*7}}"
]

async def _fuzz_single_request(session, method, endpoint, params, headers, json_payload, timeout, fuzz, param_keys, header_keys) -> List[ApiFinding]:
    findings: List[ApiFinding] = []
    try:
        async with session.request(
            method=method,
            url=endpoint,
            params=params or None,
            headers=headers or None,
            json=json_payload,
            timeout=timeout,
            allow_redirects=False,
        ) as resp:
            status = resp.status
            body_text = (await resp.text())[:2000]

            if 500 <= status < 600:
                findings.append(
                    ApiFinding(
                        tool="Fuzzer",
                        severity="MEDIUM",
                        title=f"{method} {endpoint} returned {status}",
                        description="Server error during fuzzing (possible injection).",
                        endpoint=endpoint,
                        method=method,
                        parameter=",".join(param_keys + header_keys) or "(body)",
                        evidence=body_text[:400],
                        owasp="A03:2021 – Injection",
                    )
                )

            if fuzz in body_text:
                findings.append(
                    ApiFinding(
                        tool="Fuzzer",
                        severity="LOW",
                        title="Reflected input detected",
                        description="Reflected payload found in response (possible XSS).",
                        endpoint=endpoint,
                        method=method,
                        parameter=",".join(param_keys + header_keys) or "(body)",
                        evidence=f"Reflected: {fuzz}",
                        owasp="A03:2021 – Injection",
                    )
                )
    except Exception as exc:
        findings.append(
            ApiFinding(
                tool="Fuzzer",
                severity="LOW",
                title="Request error during fuzzing",
                description=str(exc),
                endpoint=endpoint,
                method=method,
            )
        )
    return findings

async def _run_simple_fuzzer(base_url: str, targets: List[Dict[str, Any]], auth_cfg: Dict[str, Any], timeout: int = 15) -> List[ApiFinding]:
    findings: List[ApiFinding] = []
    headers = _make_auth_headers(auth_cfg)

    async with aiohttp.ClientSession() as session:
        print(Fore.GREEN + f"\n[+] 📢 Running Fuzzer ...", flush=True)
        tasks = []
        for t in targets:
            method = (t.get("method") or "GET").upper()
            path = t.get("path") or "/"
            endpoint = _normalize_url(base_url, path)
            param_keys = t.get("params") or []
            header_keys = t.get("headers") or []
            body_template = t.get("body_template") or None

            for fuzz in DEFAULT_FUZZ_WORDS:
                params = {k: fuzz for k in param_keys}
                fuzz_headers = headers.copy()
                for hk in header_keys:
                    fuzz_headers[hk] = fuzz

                json_payload = None
                if isinstance(body_template, dict):
                    json_payload = {k: (fuzz if isinstance(v, str) else v) for k, v in body_template.items()}

                tasks.append(
                    _fuzz_single_request(session, method, endpoint, params, fuzz_headers, json_payload, timeout, fuzz, param_keys, header_keys)
                )

        results = await asyncio.gather(*tasks)
        for r in results:
            findings.extend(r)

    print(Fore.GREEN + Style.BRIGHT + f"[+] 📢 Fuzzer found" + Fore.WHITE + Style.BRIGHT, len(findings), Fore.GREEN + Style.BRIGHT + f"issues.", Fore.RESET)
    return findings

# ---------------------------
# ZAP runner (blocking)
# ---------------------------
async def _run_zap_scan(base_url: str, zap_cfg: Dict[str, Any], timeout_sec: int = 300) -> List[ApiFinding]:
    findings: List[ApiFinding] = []
    if ZAPv2 is None:
        return findings

    api_key = zap_cfg.get("api_key") or ""
    proxy = zap_cfg.get("proxy") or "http://127.0.0.1:8081"
    zap = ZAPv2(apikey=api_key, proxies={"http": proxy, "https": proxy})

    try:
        print(Fore.CYAN + f"\n[+] 📢 Running ZAP Scan...", flush=True)
        # Start the spider scan
        scan_id = zap.spider.scan(base_url)
        
        # Wait for the spider scan to complete with timeout and backoff
        start_time = time.time()
        interval = 1  # initial interval in seconds
        max_interval = 5  # maximum interval between checks
        
        while True:
            status = int(zap.spider.status(scan_id))
            if status >= 100:
                break  # Scan completed
            
            elapsed = time.time() - start_time
            if elapsed > timeout_sec:
                raise TimeoutError(f"Spider scan did not complete in {timeout_sec} seconds.")
            
            time.sleep(interval)
            interval = min(interval + 1, max_interval)  # gradually increase interval, cap at max_interval

        # Collect findings, skipping INFO level vulnerabilities
        for a in zap.core.alerts():
            severity = _severity_from_zap_risk(a.get("risk"))
            if severity == "INFO":
                continue  # Skip low importance findings
            
            findings.append(
                ApiFinding(
                    tool="ZAP",
                    severity=severity,
                    title=a.get("alert", "ZAP Alert"),
                    description=a.get("desc", "") or a.get("description", "") or "",
                    endpoint=a.get("url", base_url),
                    method=a.get("method", ""),
                    parameter=a.get("param", ""),
                    evidence=a.get("evidence", ""),
                    owasp=a.get("wascid", ""),
                    references=[a.get("reference", "")] if a.get("reference") else [],
                )
            )
        print(Fore.CYAN + Style.BRIGHT + f"[+] 📢 ZAP Scan found" + Fore.WHITE + Style.BRIGHT, len(findings), Fore.CYAN + Style.BRIGHT + f"issues.", Fore.RESET)
    except TimeoutError as te:
        findings.append(
            ApiFinding(
                tool="ZAP",
                severity="HIGH",
                title="Spider Scan Timeout",
                description=str(te),
                endpoint=base_url,
            )
        )
    except Exception as exc:
        findings.append(
            ApiFinding(
                tool="ZAP",
                severity="LOW",
                title="ZAP Execution Error",
                description=str(exc),
                endpoint=base_url,
            )
        )

    return [f for f in findings if isinstance(f, ApiFinding)]

# ---------------------------
# Public entry point
# ---------------------------
async def scan_api(cfg: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    if os.name == 'nt':
        os.system('cls')
    else:
        os.system('clear')
    
    # Fancy header
    figlet_name = cfg.get("tool_info", {}).get("tool_name", "Tool Name")
    terminal_header = pyfiglet.figlet_format(figlet_name, font="doom")
    print(Fore.YELLOW + Style.BRIGHT + terminal_header + Fore.RESET + Style.RESET_ALL)
    print(Fore.GREEN + Style.BRIGHT + "🚀 Starting API Vulnerability Scans... Please Wait...\n", flush=True)

    api_cfg = cfg.get("API_Scanner", {})
    base_url = api_cfg.get("base_url", "").strip()
    # openapi_url = api_cfg.get("openapi_url", "").strip() or None
    auth_cfg = api_cfg.get("auth", {}) or {}

    results: Dict[str, List[ApiFinding]] = {"ZAP": [], "Fuzzer": []}
    tasks = []

    zap_cfg = api_cfg.get("zap", {}) or {}
    if zap_cfg.get("enabled") and base_url:
        tasks.append(_run_zap_scan(base_url, zap_cfg))

    fuzzer_cfg = api_cfg.get("fuzzer", {})
    targets = fuzzer_cfg.get("targets") or []
    if base_url and targets:
        tasks.append(_run_simple_fuzzer(base_url, targets, auth_cfg))

    results_list = await asyncio.gather(*tasks, return_exceptions=True)

    idx = 0
    # if openapi_url:
    #     results["Schemathesis"] = results_list[idx]; idx += 1
    if base_url and targets:
        results["ZAP"] = results_list[idx]; idx += 1
    if zap_cfg.get("enabled") and base_url:
        results["Fuzzer"] = results_list[idx]; idx += 1
        
    # return {k: [f.to_dict() for f in v if isinstance(f, ApiFinding)] for k, v in results.items()}
    safe_results = {}
    for k, v in results.items():
        if not isinstance(v, list):
            # Log unexpected type
            print(f"[WARN] {k} returned {type(v)} instead of list: {v}")
            v = []
        safe_results[k] = [f.to_dict() for f in v if isinstance(f, ApiFinding)]

    return safe_results
