#!/usr/bin/env python3
import os
import sys
import json
import time
import urllib.request
import urllib.parse
import urllib.error
from typing import Dict, List, Optional, Tuple

NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]


def read_cves_from_stdin() -> List[str]:
    """Read CVE IDs from stdin, return unique list preserving first-seen order."""
    cves: List[str] = []
    for line in sys.stdin:
        s = line.strip()
        if s:
            cves.append(s)

    seen = set()
    out: List[str] = []
    for c in cves:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out


def pick_cvss(metrics: Dict) -> Tuple[Optional[str], Optional[float], Optional[str], Optional[str]]:
    """
    Return (severity, baseScore, vectorString, metricType)
    Preference: v4.0, v3.1, v3.0, v2
    """
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key) or []
        if not arr:
            continue
        m = arr[0] or {}
        cv = (m.get("cvssData") or {})
        return cv.get("baseSeverity"), cv.get("baseScore"), cv.get("vectorString"), key
    return None, None, None, None


def fetch_cve(api_key: str, cve_id: str, timeout: int = 30) -> Dict:
    """Fetch a single CVE from the NVD 2.0 API and return parsed JSON."""
    params = urllib.parse.urlencode({"cveId": cve_id})
    url = f"{NVD_ENDPOINT}?{params}"
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "apiKey": api_key,
            "User-Agent": "netsec-recon-nvd-classify/1.1",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8", errors="replace")
        return json.loads(body)


def load_port_mapping(path: Optional[str]) -> Dict[str, List[str]]:
    """
    Read lines like:
      22/tcp ssh -> CVE-2023-38408

    Return:
      { "22/tcp ssh": ["CVE-...","CVE-..."], "443/tcp ssl/http": [...] }
    """
    mapping: Dict[str, List[str]] = {}
    if not path:
        return mapping

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                s = line.strip()
                if not s or "->" not in s:
                    continue
                left, right = [x.strip() for x in s.split("->", 1)]
                cve = right.strip()
                if not left or not cve:
                    continue
                mapping.setdefault(left, []).append(cve)
    except FileNotFoundError:
        return mapping

    return mapping


def classify_all(
    api_key: str,
    cve_ids: List[str],
    sleep_seconds: float = 0.7,
) -> Tuple[Dict[str, List[Tuple[str, str, str]]], Dict[str, str]]:
    """
    Return:
      buckets: {severity: [(cve, score_txt, metric_txt), ...]}
      sev_by_cve: {cve: severity}
    """
    buckets: Dict[str, List[Tuple[str, str, str]]] = {k: [] for k in SEVERITY_ORDER}
    sev_by_cve: Dict[str, str] = {}

    for idx, cve_id in enumerate(cve_ids):
        if idx > 0:
            time.sleep(sleep_seconds)

        try:
            data = fetch_cve(api_key, cve_id)
            vulns = data.get("vulnerabilities") or []
            if not vulns:
                buckets["UNKNOWN"].append((cve_id, "n/a", "NoRecord"))
                sev_by_cve[cve_id] = "UNKNOWN"
                continue

            cve = (vulns[0] or {}).get("cve") or {}
            metrics = cve.get("metrics") or {}
            severity, score, _vector, metric_type = pick_cvss(metrics)

            sev_norm = (severity or "UNKNOWN").upper()
            if sev_norm not in buckets:
                sev_norm = "UNKNOWN"

            score_txt = f"{score:.1f}" if isinstance(score, (int, float)) else "n/a"
            metric_txt = metric_type or "n/a"

            buckets[sev_norm].append((cve_id, score_txt, metric_txt))
            sev_by_cve[cve_id] = sev_norm

        except urllib.error.HTTPError as e:
            # Preserve the HTTP status code for troubleshooting (e.g., 401, 403, 404, 429)
            buckets["UNKNOWN"].append((cve_id, "n/a", f"HTTP {e.code}"))
            sev_by_cve[cve_id] = "UNKNOWN"
        except Exception:
            buckets["UNKNOWN"].append((cve_id, "n/a", "Error"))
            sev_by_cve[cve_id] = "UNKNOWN"

    # Sort within each bucket by score desc when possible
    def score_key(item: Tuple[str, str, str]) -> float:
        _cve, score_txt, _metric = item
        try:
            return float(score_txt)
        except Exception:
            return -1.0

    for k in SEVERITY_ORDER:
        buckets[k].sort(key=score_key, reverse=True)

    return buckets, sev_by_cve


def main() -> int:
    api_key = os.environ.get("NVD_API_KEY", "").strip()
    if not api_key:
        print("NVD_API_KEY is missing in environment.")
        return 2

    map_file = sys.argv[1] if len(sys.argv) > 1 else None

    cve_ids = read_cves_from_stdin()
    if not cve_ids:
        print("No CVEs provided.")
        return 0

    buckets, sev_by_cve = classify_all(api_key, cve_ids)

    counts = {k: len(buckets[k]) for k in SEVERITY_ORDER}
    print("NVD severity summary:")
    print(
        f"CRITICAL={counts['CRITICAL']}, HIGH={counts['HIGH']}, "
        f"MEDIUM={counts['MEDIUM']}, LOW={counts['LOW']}, UNKNOWN={counts['UNKNOWN']}"
    )
    print()

    # Severity buckets
    for sev in SEVERITY_ORDER:
        if not buckets[sev]:
            continue
        print(sev)
        for cve_id, score_txt, metric_txt in buckets[sev]:
            print(f"- {cve_id} (CVSS {score_txt}, {metric_txt})")
        print()

    # Port mapping grouped
    mapping = load_port_mapping(map_file)
    if mapping:
        print("Port mapping (best-effort from Nmap):")
        for port in sorted(mapping.keys()):
            cves = mapping[port]

            # Deduplicate while preserving order
            seen = set()
            cves_clean: List[str] = []
            for c in cves:
                if c not in seen:
                    seen.add(c)
                    cves_clean.append(c)

            print(f"{port}")
            for c in cves_clean:
                sev = sev_by_cve.get(c, "UNKNOWN")
                print(f"- [{sev}] {c}")
            print()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
