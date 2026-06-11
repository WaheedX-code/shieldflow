import json, requests, os, hashlib
from datetime import datetime

WEBHOOK_GITLEAKS = os.getenv("WEBHOOK_GITLEAKS", "http://10.180.251.70:3001/api/v1/hooks/webhook_63e0d4f2-3e52-45b4-b5bd-d3fd1fc7c9d8")
WEBHOOK_TRIVY = os.getenv("WEBHOOK_TRIVY", "http://10.180.251.70:3001/api/v1/hooks/webhook_667913be-db76-4ba3-ae0c-d85e1cbadccb")
WEBHOOK_ZAP = os.getenv("WEBHOOK_ZAP", "http://10.180.251.70:3001/api/v1/hooks/webhook_4c00a4d5-580a-4a1e-8561-3af61999be1f")
WEBHOOK_SEMGREP = os.getenv("WEBHOOK_SEMGREP", "http://10.180.251.70:3001/api/v1/hooks/webhook_63e0d4f2-3e52-45b4-b5bd-d3fd1fc7c9d8")

def enrich_with_nvd(cve_id):
    if not cve_id:
        return {}
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        resp = requests.get(url, timeout=10)
        data = resp.json()
        vuln = data["vulnerabilities"][0]["cve"]
        metrics = vuln.get("metrics", {})
        cvss = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", [{}]))[0].get("cvssData", {})
        return {
            "cvss_score": cvss.get("baseScore"),
            "cvss_vector": cvss.get("vectorString"),
            "severity_label": cvss.get("baseSeverity"),
            "cve_description": vuln["descriptions"][0]["value"]
        }
    except Exception as e:
        print(f"[WARN] NVD lookup failed for {cve_id}: {e}")
        return {}
        import hashlib
FINGERPRINT_FILE = "/tmp/soar_seen.txt"

def fingerprint(finding):
    raw = f"{finding.get('tool','')}-{finding.get('file','')}-{finding.get('rule_id','')}"
    return hashlib.sha256(raw.encode()).hexdigest()

def is_duplicate(finding):
    fp = fingerprint(finding)
    if os.path.exists(FINGERPRINT_FILE):
        with open(FINGERPRINT_FILE) as f:
            seen = f.read().splitlines()
        if fp in seen:
            return True
    with open(FINGERPRINT_FILE, "a") as f:
        f.write(fp + "\n")
    return False
def parse_sarif(filepath, tool_name):
    findings = []
    try:
        with open(filepath) as f:
            data = json.load(f)
        for run in data.get("runs", []):
            for result in run.get("results", []):
                loc = result.get("locations", [{}])[0]
                phys = loc.get("physicalLocation", {})
                findings.append({
                    "tool": tool_name,
                    "rule_id": result.get("ruleId", "unknown"),
                    "severity": result.get("level", "warning"),
                    "description": result.get("message", {}).get("text", ""),
                    "file": phys.get("artifactLocation", {}).get("uri", ""),
                    "line": phys.get("region", {}).get("startLine", 0),
                    "cve_id": None,
                    "timestamp": datetime.utcnow().isoformat()
                })
    except Exception as e:
        print(f"[WARN] Could not parse {filepath}: {e}")
    return findings

def parse_trivy(filepath):
    findings = []
    try:
        with open(filepath) as f:
            data = json.load(f)
        for result in data.get("Results", []):
            for vuln in result.get("Vulnerabilities", []):
                findings.append({
                    "tool": "trivy",
                    "rule_id": vuln.get("VulnerabilityID", ""),
                    "severity": vuln.get("Severity", "UNKNOWN").lower(),
                    "description": vuln.get("Title", ""),
                    "file": vuln.get("PkgName", ""),
                    "line": 0,
                    "cve_id": vuln.get("VulnerabilityID", ""),
                    "installed_version": vuln.get("InstalledVersion", ""),
                    "fixed_version": vuln.get("FixedVersion", ""),
                    "timestamp": datetime.utcnow().isoformat()
                })
    except Exception as e:
        print(f"[WARN] Could not parse {filepath}: {e}")
    return findings

def parse_zap(filepath):
    findings = []
    risk_map = {"3": "high", "2": "medium", "1": "low", "0": "info"}
    try:
        with open(filepath) as f:
            data = json.load(f)
        for alert in data.get("site", [{}])[0].get("alerts", []):
            findings.append({
                "tool": "zap",
                "rule_id": alert.get("pluginid", ""),
                "severity": risk_map.get(alert.get("riskcode", "1"), "low"),
                "description": alert.get("alert", ""),
                "file": alert.get("uri", ""),
                "line": 0,
                "cve_id": None,
                "cwe_id": alert.get("cweid", ""),
                "timestamp": datetime.utcnow().isoformat()
            })
    except Exception as e:
        print(f"[WARN] Could not parse {filepath}: {e}")
    return findings

def post_to_soar(finding):
    if finding.get("cve_id"):
        enrichment = enrich_with_nvd(finding["cve_id"])
        finding.update(enrichment)

    tool = finding.get("tool", "")
    if tool == "trivy":
        webhook = WEBHOOK_TRIVY
    elif tool == "zap":
        webhook = WEBHOOK_ZAP
    elif tool == "gitleaks":
        webhook = WEBHOOK_GITLEAKS
    else:
        webhook = WEBHOOK_SEMGREP

    try:
        resp = requests.post(webhook, json=finding, timeout=10)
        if resp.status_code == 200:
            print(f"[OK]   Sent: {finding['tool']} | {finding['rule_id']}")
        else:
            print(f"[FAIL] Status {resp.status_code}: {finding['rule_id']}")
    except Exception as e:
        print(f"[ERROR] Could not reach SOAR: {e}")

if __name__ == "__main__":
    all_findings = []
    if os.path.exists("reports/semgrep.sarif"):
        all_findings += parse_sarif("reports/semgrep.sarif", "semgrep")
    if os.path.exists("reports/gitleaks.sarif"):
        all_findings += parse_sarif("reports/gitleaks.sarif", "gitleaks")
    if os.path.exists("reports/trivy.json"):
        all_findings += parse_trivy("reports/trivy.json")
    if os.path.exists("reports/zap.json"):
        all_findings += parse_zap("reports/zap.json")
    print(f"[INFO] Total findings to send: {len(all_findings)}")
    for finding in all_findings:
        if is_duplicate(finding):
            print(f"[SKIP] Duplicate: {finding['tool']} | {finding['rule_id']}")
        else:
            post_to_soar(finding)
    print("[DONE] All findings sent to SOAR.")
