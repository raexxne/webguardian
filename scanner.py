import time
import json
import os
from dotenv import load_dotenv
from zapv2 import ZAPv2

load_dotenv()

ZAP_API_KEY = os.environ.get("ZAP_API_KEY")
ZAP_PROXY = os.environ.get("ZAP_PROXY", "http://127.0.0.1:8080")

POLL_INTERVAL = 1
ACTIVE_SCAN_RECURSE = False
REMOVE_INFORMATIONAL = True

OWASP_MAPPING = {
    "SQL Injection": "A03:2021 – Injection",
    "Cross Site Scripting": "A03:2021 – Injection",
    "XSS": "A03:2021 – Injection",
    "Broken Authentication": "A07:2021 – Identification and Authentication Failures",
    "Security Misconfiguration": "A05:2021 – Security Misconfiguration",
    "Information Disclosure": "A01:2021 – Broken Access Control",
    "Missing": "A05:2021 – Security Misconfiguration"
}

def clean_evidence_text(value, max_len=300):
    text = str(value or "").strip()
    if not text:
        return ""
    text = " ".join(text.split())
    if len(text) > max_len:
        text = text[:max_len].rstrip() + "..."
    return text


def extract_alert_evidence(alert):
    evidence_items = []

    mappings = [
        ("Matched Evidence", alert.get("evidence")),
        ("Parameter", alert.get("param")),
        ("Attack Payload", alert.get("attack")),
        ("Additional Info", alert.get("otherinfo"))
    ]

    for label, raw_value in mappings:
        value = clean_evidence_text(raw_value)
        if value:
            evidence_items.append({
                "label": label,
                "value": value
            })

    return evidence_items


def get_zap_client():
    if not ZAP_API_KEY:
        raise RuntimeError("ZAP_API_KEY is not set in .env")

    return ZAPv2(
        apikey=ZAP_API_KEY,
        proxies={
            "http": ZAP_PROXY,
            "https": ZAP_PROXY
        }
    )


def run_zap_scan(target_url):
    try:
        zap = get_zap_client()

        print(f"[+] Connecting to ZAP at {ZAP_PROXY}...")
        print(f"[+] Connected to ZAP version: {zap.core.version}")

        print(f"[+] Opening target: {target_url}")
        zap.urlopen(target_url)

        # =========================
        # ACTIVE SCAN ONLY
        # =========================
        print("[*] Starting Active Scan...")
        scan_id = zap.ascan.scan(
            url=target_url,
            recurse=ACTIVE_SCAN_RECURSE
        )

        while int(zap.ascan.status(scan_id)) < 100:
            print(f"Active scan progress: {zap.ascan.status(scan_id)}%")
            time.sleep(POLL_INTERVAL)

        print("[+] Active scan completed")

        raw_alerts = zap.core.alerts(baseurl=target_url)
        print("RAW ALERT COUNT:", len(raw_alerts))

        ignored_alerts = [
            "User Agent Fuzzer",
            "Modern Web Application"
        ]

        grouped_vulnerabilities = {}

        for alert in raw_alerts:
            name = alert.get("alert", "")
            risk = alert.get("risk", "")
            url = alert.get("url", "")

            if name in ignored_alerts:
                continue

            if REMOVE_INFORMATIONAL and str(risk).lower() == "informational":
                continue

            if name not in grouped_vulnerabilities:
                cvss = alert.get("cvss", "")
                confidence = alert.get("confidence", "")

                owasp_category = "Uncategorized"
                for keyword in OWASP_MAPPING:
                    if keyword.lower() in name.lower():
                        owasp_category = OWASP_MAPPING[keyword]
                        break

                grouped_vulnerabilities[name] = {
                    "name": name,
                    "risk": risk,
                    "confidence": confidence,
                    "description": alert.get("description"),
                    "solution": alert.get("solution"),
                    "cwe": alert.get("cweid"),
                    "reference": alert.get("reference"),
                    "owasp_category": owasp_category,
                    "cvss_score": cvss,
                    "count": 1,
                    "affected_urls": [url] if url else [],

                    # real evidence from ZAP
                    "evidence_details": extract_alert_evidence(alert)
                }
            else:
                grouped_vulnerabilities[name]["count"] += 1

                if url and url not in grouped_vulnerabilities[name]["affected_urls"]:
                    grouped_vulnerabilities[name]["affected_urls"].append(url)

                new_evidence = extract_alert_evidence(alert)
                for item in new_evidence:
                    if item not in grouped_vulnerabilities[name]["evidence_details"]:
                        grouped_vulnerabilities[name]["evidence_details"].append(item)

        final_results = list(grouped_vulnerabilities.values())

        risk_priority = {
            "High": 1,
            "Medium": 2,
            "Low": 3
        }

        final_results.sort(key=lambda x: risk_priority.get(x["risk"], 4))

        print(f"[+] Final grouped vulnerabilities: {len(final_results)}")
        return json.dumps(final_results)

    except Exception as e:
        print("ZAP ERROR:", str(e))
        raise