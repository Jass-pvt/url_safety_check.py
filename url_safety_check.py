
import sys
import re
import ssl
import socket
import argparse
from urllib.parse import urlparse
import requests
import tldextract
import whois
from datetime import datetime

# ---------------------
# Basic heuristics
# ---------------------
def looks_like_ip(url):
    try:
        host = urlparse(url).hostname or ""
        # IPv4 or IPv6
        return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host)) or ":" in host and host.count(":") >= 2
    except:
        return False

def suspicious_chars(url):
    # many %-encoding, @, multiple dashes, or long query strings
    return any([
        "%" in url and url.count("%") > 5,
        "@" in url,
        url.count("-") > 5,
        len(url) > 200,
        url.count("?") > 2,
    ])

# ---------------------
# HTTPS & certificate
# ---------------------
def check_https_and_cert(url, timeout=6):
    parsed = urlparse(url)
    scheme = parsed.scheme
    host = parsed.hostname
    port = parsed.port or (443 if scheme == "https" else 80)
    result = {"scheme": scheme, "host": host, "port": port, "https": scheme == "https", "cert_valid": False, "cert_expires": None, "cert_issuer": None}
    if scheme != "https":
        return result
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        # parse expiry
        not_after = cert.get("notAfter")
        if not_after:
            exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            result["cert_expires"] = exp.isoformat()
            result["cert_valid"] = exp > datetime.utcnow()
        result["cert_issuer"] = dict(x[0] for x in cert.get("issuer", ()))
    except Exception as e:
        result["error"] = str(e)
    return result

# ---------------------
# WHOIS / domain age
# ---------------------
def domain_whois_info(url):
    try:
        ext = tldextract.extract(url)
        domain = ext.registered_domain
        if not domain:
            return {"domain": None}
        w = whois.whois(domain)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        age_days = None
        if created:
            age_days = (datetime.utcnow() - created).days
        return {"domain": domain, "created": created.isoformat() if created else None, "age_days": age_days, "registrar": w.registrar}
    except Exception as e:
        return {"error": str(e)}

# ---------------------
# Page analysis (forms, input fields)
# ---------------------
def analyze_page(url, timeout=8):
    try:
        headers = {"User-Agent": "Mozilla/5.0 (compatible; UrlSafetyBot/1.0)"}
        resp = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        text = resp.text.lower()
        info = {"status_code": resp.status_code, "final_url": resp.url, "len": len(text)}
        # look for forms & input types
        forms = re.findall(r"<form[^>]*>(.*?)</form>", text, flags=re.S)
        info["num_forms"] = len(forms)
        info["sensitive_inputs"] = []
        for f in forms:
            inputs = re.findall(r"<input[^>]*>", f)
            for inp in inputs:
                if re.search(r'type="(password|email|tel|number|text)"', inp) or "name=" in inp:
                    if re.search(r'type="password"', inp) or re.search(r'name=["\']?(password|pass|pwd|card|ccnum|ssn)["\']?', inp):
                        info["sensitive_inputs"].append(inp[:200])
        # check for obvious phishing keywords
        phishing_keywords = ["confirm your", "verify your", "update your", "password expired", "bank account", "social security", "credit card", "security alert"]
        info["phishing_keywords_found"] = [k for k in phishing_keywords if k in text[:2000]]
        return info
    except Exception as e:
        return {"error": str(e)}

# ---------------------
# VirusTotal lookup (optional)
# ---------------------
def virustotal_lookup(url, api_key):
    try:
        headers = {"x-apikey": api_key}
        # v3 URL analysis
        resp = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url})
        if resp.status_code != 200 and resp.status_code != 201:
            return {"error": f"VT upload failed {resp.status_code} {resp.text}"}
        data = resp.json()
        analysis_id = data.get("data", {}).get("id")
        # fetch analysis
        r2 = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers)
        if r2.status_code != 200:
            return {"error": f"VT analysis failed {r2.status_code}"}
        summary = r2.json()
        # keep small summary
        stats = summary.get("data", {}).get("attributes", {}).get("stats", {})
        return {"virustotal_stats": stats}
    except Exception as e:
        return {"error": str(e)}

# ---------------------
# Google Safe Browsing lookup (optional)
# ---------------------
def google_safe_browsing_lookup(url, api_key):
    try:
        gsb_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        payload = {
            "client": {"clientId": "YourApp", "clientVersion": "0.1"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        r = requests.post(gsb_url, params={"key": api_key}, json=payload, timeout=10)
        if r.status_code != 200:
            return {"error": f"GSB failed {r.status_code}: {r.text}"}
        matches = r.json().get("matches")
        return {"matches": matches}
    except Exception as e:
        return {"error": str(e)}

# ---------------------
# Heuristic score summary
# ---------------------
def heuristic_score(results):
    score = 0
    reasons = []
    # suspicious URL heuristics
    if results.get("looks_like_ip"):
        score += 3; reasons.append("URL uses IP address")
    if results.get("suspicious_chars"):
        score += 2; reasons.append("Suspicious characters/length in URL")
    if results.get("page_info", {}).get("num_forms", 0) > 0 and not results.get("https_ok"):
        score += 3; reasons.append("Form present over non-HTTPS")
    if results.get("page_info", {}).get("sensitive_inputs"):
        score += 2; reasons.append("Page requests sensitive inputs (password/cc)")
    if results.get("whois", {}).get("age_days") is not None and results["whois"]["age_days"] < 90:
        score += 2; reasons.append("Domain age is very new (< 90 days)")
    if results.get("https_valid") is False:
        score += 4; reasons.append("SSL certificate invalid/expired or error")
    # virus_total or gsb positive matches add big weight
    if results.get("virustotal", {}).get("virustotal_stats", {}).get("malicious", 0) > 0:
        score += 10; reasons.append("VirusTotal flagged malicious")
    if results.get("gsb", {}).get("matches"):
        score += 10; reasons.append("Google Safe Browsing flagged the URL")
    # interpret
    level = "unknown"
    if score >= 10:
        level = "dangerous"
    elif score >= 5:
        level = "suspicious"
    elif score >= 1:
        level = "caution"
    else:
        level = "likely safe"
    return {"score": score, "level": level, "reasons": reasons}

# ---------------------
# Orchestrator
# ---------------------
def run_checks(url, vt_key=None, gsb_key=None):
    out = {}
    out["looks_like_ip"] = looks_like_ip(url)
    out["suspicious_chars"] = suspicious_chars(url)
    cert = check_https_and_cert(url)
    out["https_ok"] = cert.get("https", False)
    out["https_valid"] = cert.get("cert_valid", None)
    out["cert_info"] = {"expires": cert.get("cert_expires"), "issuer": cert.get("cert_issuer")}
    out["whois"] = domain_whois_info(url)
    out["page_info"] = analyze_page(url)
    if vt_key:
        out["virustotal"] = virustotal_lookup(url, vt_key)
    if gsb_key:
        out["gsb"] = google_safe_browsing_lookup(url, gsb_key)
    out["heuristic"] = heuristic_score(out)
    return out

# ---------------------
# Example usage (replace with your desired URL)
# ---------------------
#---------------------
#Enter your link below
#---------------------
url_to_check = "https://www.google.com" # Replace with the URL you want to check
result = run_checks(url_to_check)
import json
print(json.dumps(result, indent=2, default=str))


