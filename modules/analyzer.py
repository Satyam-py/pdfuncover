# modules/analyzer.py

import os
import json
import logging
from datetime import datetime


# ==========================================
# LOGGING SETUP
# ==========================================

os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    filename="logs/analyzer.log",
    level=logging.ERROR,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

log = logging.getLogger(__name__)


# ==========================================
# SCORING WEIGHTS
# ==========================================

# Centralised — change scores here, affects everything
SCORES = {
    "js_detected":          20,
    "openaction":           15,
    "js_obfuscation":       20,
    "js_decoded_preview":   10,  # JS content was extractable = active script
    "url_found":             5,  # per URL, capped at 20
    "ip_found":              8,  # per IP, capped at 20
    "embedded_file":        25,
    "executable_payload":   40,
    "shellcode_pattern":    35,
    "high_entropy_stream":  15,  # per stream, capped at 30
    "compressed_objects":   10,
    "encrypted_pdf":        15,
    "jbig2_detected":       25,  # CVE-2010-0188 vector
    "acroform_detected":    10,
    "aa_trigger":           15,
    "xfa_form":             20,
    "invalid_header":       20,
    "suspicious_filename":  30,
    "zero_pages":           25,
    "suspicious_title":      5,
}

# MITRE ATT&CK mappings for each finding type
MITRE_MAP = {
    "js_detected":          "T1059.007 — JavaScript execution",
    "openaction":           "T1204.002 — Malicious file auto-execution",
    "js_obfuscation":       "T1027 — Obfuscated files or information",
    "high_entropy_stream":  "T1027.002 — Software packing",
    "embedded_file":        "T1027 — Embedded payload",
    "executable_payload":   "T1204.002 — User execution: malicious file",
    "shellcode_pattern":    "T1055 — Process injection",
    "url_found":            "T1071.001 — Web protocol C2",
    "ip_found":             "T1071.001 — Web protocol C2",
    "acroform_detected":    "T1114 — Email/form data collection",
    "aa_trigger":           "T1204 — User execution trigger",
    "xfa_form":             "T1566.001 — Spearphishing attachment",
    "encrypted_pdf":        "T1027 — Encrypted/encoded file",
    "jbig2_detected":       "T1203 — Exploitation for client execution",
    "invalid_header":       "T1036 — Masquerading",
}


# ==========================================
# HELPERS
# ==========================================

def safe_get(d, *keys, default=None):
    """
    Safely traverse nested dicts without KeyError.
    safe_get(results, 'JavaScript', 'Suspicious Keywords', default=[])
    """

    current = d

    for key in keys:

        if not isinstance(current, dict):
            return default

        current = current.get(key, default)

        if current is default:
            return default

    return current


def cap(value, maximum):
    """Return value capped at maximum."""
    return min(value, maximum)


# ==========================================
# ANALYSIS ENGINE
# ==========================================

def analyze_results(metadata, embedded_results):
    """
    Run full threat analysis across metadata and embedded results.
    Returns structured analysis dict with score, threat level,
    MITRE mappings, and per-category findings.
    """

    analysis          = {}
    suspicious_findings = []
    mitre_techniques  = []
    score             = 0

    # ==========================================
    # HEADER VALIDATION
    # ==========================================

    header_analysis = {"Invalid Header": False}

    if not safe_get(
        embedded_results, "Header Validation", "Valid PDF Header",
        default=True
    ):

        header_analysis["Invalid Header"] = True
        score += SCORES["invalid_header"]
        suspicious_findings.append("Invalid PDF header — possible spoofed file")
        mitre_techniques.append(MITRE_MAP["invalid_header"])

    analysis["Header Analysis"] = header_analysis

    # ==========================================
    # JAVASCRIPT ANALYSIS
    # ==========================================

    js_analysis = {
        "Obfuscation Detected":  False,
        "Obfuscation Patterns":  [],
        "Exploit Indicators":    [],
        "Decoded JS Preview":    ""
    }

    obfuscation_patterns = [
        "eval",
        "unescape",
        "fromCharCode",
        "atob",
        "base64",
        "app.launchURL",
        "this.exportDataObject",
        "submitForm",
        "Collab.collectEmailInfo",
        "util.printf",
        "app.alert",
        "getAnnots"
    ]

    exploit_indicators = [
        "app.launchURL",
        "this.exportDataObject",
        "Collab.collectEmailInfo",
        "util.printf"
    ]

    js_keywords = safe_get(
        embedded_results, "JavaScript", "Suspicious Keywords", default=[]
    )

    for keyword in js_keywords:

        if keyword in obfuscation_patterns:
            js_analysis["Obfuscation Detected"] = True
            js_analysis["Obfuscation Patterns"].append(keyword)

        if keyword in exploit_indicators:
            js_analysis["Exploit Indicators"].append(keyword)

    # JS detected
    if safe_get(embedded_results, "JavaScript", "JavaScript Detected"):
        score += SCORES["js_detected"]
        suspicious_findings.append("Embedded JavaScript detected")
        mitre_techniques.append(MITRE_MAP["js_detected"])

    # OpenAction
    if safe_get(embedded_results, "JavaScript", "OpenAction Found"):
        score += SCORES["openaction"]
        suspicious_findings.append("OpenAction auto-execution trigger found")
        mitre_techniques.append(MITRE_MAP["openaction"])

    # Obfuscation
    if js_analysis["Obfuscation Detected"]:
        score += SCORES["js_obfuscation"]
        suspicious_findings.append(
            f"JavaScript obfuscation detected: "
            f"{', '.join(js_analysis['Obfuscation Patterns'])}"
        )
        mitre_techniques.append(MITRE_MAP["js_obfuscation"])

    # Decoded JS preview available = active script content
    preview = safe_get(
        embedded_results, "JavaScript", "Decoded JS Preview", default=""
    )

    if preview:
        js_analysis["Decoded JS Preview"] = preview
        score += SCORES["js_decoded_preview"]

    analysis["JavaScript Analysis"] = js_analysis

    # ==========================================
    # IOC ANALYSIS
    # ==========================================

    ioc_analysis = {
        "URLs Found":    0,
        "Domains Found": 0,
        "IPs Found":     0,
        "URL List":      [],
        "IP List":       []
    }

    urls    = safe_get(embedded_results, "IOCs", "URLs",    default=[])
    domains = safe_get(embedded_results, "IOCs", "Domains", default=[])
    ips     = safe_get(embedded_results, "IOCs", "IPs",     default=[])

    ioc_analysis["URLs Found"]    = len(urls)
    ioc_analysis["Domains Found"] = len(domains)
    ioc_analysis["IPs Found"]     = len(ips)
    ioc_analysis["URL List"]      = urls
    ioc_analysis["IP List"]       = ips

    if urls:
        url_score = cap(len(urls) * SCORES["url_found"], 20)
        score += url_score
        suspicious_findings.append(
            f"{len(urls)} URL(s) found inside PDF"
        )
        mitre_techniques.append(MITRE_MAP["url_found"])

    if ips:
        ip_score = cap(len(ips) * SCORES["ip_found"], 20)
        score += ip_score
        suspicious_findings.append(
            f"{len(ips)} IP address(es) found inside PDF"
        )
        mitre_techniques.append(MITRE_MAP["ip_found"])

    analysis["IOC Analysis"] = ioc_analysis

    # ==========================================
    # EMBEDDED FILE ANALYSIS
    # ==========================================

    embedded_analysis = {
        "Embedded Files":       [],
        "Executables Detected": False,
        "Executable Indicators":[],
        "Suspicious Files":     []
    }

    extracted_files = safe_get(
        embedded_results, "Embedded Files", "Extracted Files", default=[]
    )

    suspicious_files = safe_get(
        embedded_results, "Embedded Files", "Suspicious Files", default=[]
    )

    dangerous_extensions = [
        ".exe", ".dll", ".bat", ".cmd",
        ".ps1", ".vbs", ".js", ".scr",
        ".hta", ".jar", ".sh"
    ]

    for file_path in extracted_files:

        embedded_analysis["Embedded Files"].append(file_path)
        lower_path = file_path.lower()

        for ext in dangerous_extensions:

            if lower_path.endswith(ext):
                embedded_analysis["Executables Detected"] = True
                embedded_analysis["Executable Indicators"].append(ext)

    embedded_analysis["Suspicious Files"] = suspicious_files

    if extracted_files:
        score += SCORES["embedded_file"]
        suspicious_findings.append(
            f"{len(extracted_files)} embedded file(s) detected"
        )
        mitre_techniques.append(MITRE_MAP["embedded_file"])

    if embedded_analysis["Executables Detected"]:
        score += SCORES["executable_payload"]
        suspicious_findings.append(
            f"Executable payload detected: "
            f"{', '.join(set(embedded_analysis['Executable Indicators']))}"
        )
        mitre_techniques.append(MITRE_MAP["executable_payload"])

    if suspicious_files:
        score += SCORES["suspicious_filename"]
        for sf in suspicious_files:
            suspicious_findings.append(f"Dangerous embedded file: {sf}")

    analysis["Embedded File Analysis"] = embedded_analysis

    # ==========================================
    # STREAM / ENTROPY ANALYSIS
    # ==========================================

    stream_analysis = {
        "High Entropy Streams":    [],
        "Shellcode Findings":      [],
        "Decompressed Content":    False
    }

    high_entropy = safe_get(
        embedded_results, "Streams", "High Entropy Streams", default=[]
    )

    shellcode_findings = safe_get(
        embedded_results, "Streams", "Decompressed Findings", default=[]
    )

    stream_analysis["High Entropy Streams"] = high_entropy
    stream_analysis["Shellcode Findings"]   = shellcode_findings

    if high_entropy:
        entropy_score = cap(
            len(high_entropy) * SCORES["high_entropy_stream"], 30
        )
        score += entropy_score
        suspicious_findings.append(
            f"{len(high_entropy)} high-entropy stream(s) — "
            "possible encrypted/packed payload"
        )
        mitre_techniques.append(MITRE_MAP["high_entropy_stream"])

    if shellcode_findings:
        score += SCORES["shellcode_pattern"]
        for finding in shellcode_findings:
            suspicious_findings.append(f"Shellcode pattern: {finding}")
        mitre_techniques.append(MITRE_MAP["shellcode_pattern"])

    analysis["Stream Analysis"] = stream_analysis

    # ==========================================
    # COMPRESSION / ENCRYPTION
    # ==========================================

    compression_analysis = {
        "Compressed Objects": False,
        "Filters":            [],
        "JBIG2 Detected":     False
    }

    if safe_get(
        embedded_results, "Compression", "Compressed Objects Found"
    ):
        compression_analysis["Compressed Objects"] = True
        compression_analysis["Filters"] = safe_get(
            embedded_results, "Compression", "Filters", default=[]
        )
        score += SCORES["compressed_objects"]
        suspicious_findings.append("Compressed objects present")

    if safe_get(embedded_results, "Compression", "JBIG2 Warning"):
        compression_analysis["JBIG2 Detected"] = True
        score += SCORES["jbig2_detected"]
        suspicious_findings.append(
            "JBIG2Decode detected — CVE-2010-0188 exploit vector"
        )
        mitre_techniques.append(MITRE_MAP["jbig2_detected"])

    if safe_get(embedded_results, "Encryption", "Encrypted"):
        score += SCORES["encrypted_pdf"]
        suspicious_findings.append("Encrypted PDF")
        mitre_techniques.append(MITRE_MAP["encrypted_pdf"])

    analysis["Compression Analysis"] = compression_analysis

    # ==========================================
    # ACROFORM / AA / XFA ANALYSIS
    # ==========================================

    form_analysis = {
        "AcroForm Detected":       False,
        "Additional Actions Found": False,
        "XFA Form Detected":       False
    }

    if safe_get(embedded_results, "AcroForm", "AcroForm Detected"):
        form_analysis["AcroForm Detected"] = True
        score += SCORES["acroform_detected"]
        suspicious_findings.append(
            "AcroForm detected — possible data exfiltration via submitForm"
        )
        mitre_techniques.append(MITRE_MAP["acroform_detected"])

    if safe_get(embedded_results, "AcroForm", "Additional Actions Found"):
        form_analysis["Additional Actions Found"] = True
        score += SCORES["aa_trigger"]
        suspicious_findings.append(
            "/AA trigger found — action fires on page open/close"
        )
        mitre_techniques.append(MITRE_MAP["aa_trigger"])

    if safe_get(embedded_results, "AcroForm", "XFA Form Detected"):
        form_analysis["XFA Form Detected"] = True
        score += SCORES["xfa_form"]
        suspicious_findings.append(
            "XFA form detected — used in exploit delivery"
        )
        mitre_techniques.append(MITRE_MAP["xfa_form"])

    analysis["Form Analysis"] = form_analysis

    # ==========================================
    # METADATA ANOMALIES
    # ==========================================

    meta_analysis = {
        "Suspicious Title":    False,
        "Missing Author":      False,
        "Missing Creator":     False,
        "Date Mismatch":       False,
        "Suspicious Producer": False
    }

    meta_flags = metadata.get("Suspicious Flags", [])

    for flag in meta_flags:

        flag_lower = flag.lower()

        if "title" in flag_lower:
            meta_analysis["Suspicious Title"] = True
            score += SCORES["suspicious_title"]
            suspicious_findings.append(flag)
            mitre_techniques.append(MITRE_MAP.get("suspicious_title", ""))

        if "author" in flag_lower:
            meta_analysis["Missing Author"] = True
            suspicious_findings.append(flag)

        if "creator" in flag_lower:
            meta_analysis["Missing Creator"] = True
            suspicious_findings.append(flag)

        if "modified" in flag_lower or "differ" in flag_lower:
            meta_analysis["Date Mismatch"] = True
            suspicious_findings.append(flag)

        if "producer" in flag_lower:
            meta_analysis["Suspicious Producer"] = True
            suspicious_findings.append(flag)

        if "0 pages" in flag_lower:
            score += SCORES["zero_pages"]
            suspicious_findings.append(flag)

    analysis["Metadata Analysis"] = meta_analysis

    # ==========================================
    # THREAT LEVEL
    # ==========================================

    # Cap score at 100
    score = min(score, 100)

    if score <= 15:
        threat_level = "CLEAN"

    elif score <= 35:
        threat_level = "LOW"

    elif score <= 55:
        threat_level = "MEDIUM"

    elif score <= 75:
        threat_level = "HIGH"

    else:
        threat_level = "CRITICAL"

    # Deduplicate MITRE techniques
    mitre_techniques = list(dict.fromkeys(
        t for t in mitre_techniques if t
    ))

    # ==========================================
    # FINAL RESULTS
    # ==========================================

    analysis["Risk Score"]          = score
    analysis["Threat Level"]        = threat_level
    analysis["Suspicious Findings"] = suspicious_findings
    analysis["MITRE ATT&CK"]        = mitre_techniques

    return analysis


# ==========================================
# REPORT GENERATOR
# ==========================================

def generate_report(pdf_path, metadata, embedded_results, analysis):
    """
    Generate both a human-readable .txt report and a
    machine-readable .json report. Returns the txt report path.
    """

    try:
        os.makedirs("output/reports", exist_ok=True)
    except OSError as e:
        log.error(f"Could not create reports directory: {e}")
        return None

    timestamp    = datetime.now().strftime("%Y%m%d_%H%M%S")
    txt_path     = os.path.join("output/reports", f"report_{timestamp}.txt")
    json_path    = os.path.join("output/reports", f"report_{timestamp}.json")

    # ==========================================
    # JSON REPORT
    # ==========================================

    try:

        json_report = {
            "generated":       datetime.now().isoformat(),
            "target":          pdf_path,
            "threat_level":    analysis.get("Threat Level"),
            "risk_score":      analysis.get("Risk Score"),
            "mitre_techniques":analysis.get("MITRE ATT&CK", []),
            "findings":        analysis.get("Suspicious Findings", []),
            "metadata":        {
                k: v for k, v in metadata.items()
                if k != "Suspicious Flags"
            },
            "iocs": {
                "urls":    safe_get(embedded_results, "IOCs", "URLs",    default=[]),
                "domains": safe_get(embedded_results, "IOCs", "Domains", default=[]),
                "ips":     safe_get(embedded_results, "IOCs", "IPs",     default=[])
            },
            "embedded_files":  safe_get(
                embedded_results, "Embedded Files", "Extracted Files", default=[]
            )
        }

        with open(json_path, "w", encoding="utf-8") as jf:
            json.dump(json_report, jf, indent=2, default=str)

    except OSError as e:
        log.error(f"Failed to write JSON report: {e}")

    # ==========================================
    # TXT REPORT
    # ==========================================

    sep  = "=" * 62
    thin = "-" * 62

    try:

        with open(txt_path, "w", encoding="utf-8") as r:

            def w(line=""):
                r.write(line + "\n")

            w(sep)
            w("  PDF MALWARE ANALYSIS REPORT")
            w(sep)
            w(f"  Generated  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            w(f"  Target     : {pdf_path}")
            w(f"  MD5        : {metadata.get('MD5', 'N/A')}")
            w(f"  SHA256     : {metadata.get('SHA256', 'N/A')}")
            w()

            # VERDICT
            w(sep)
            w("  VERDICT")
            w(sep)
            threat = analysis.get("Threat Level", "UNKNOWN")
            score  = analysis.get("Risk Score", 0)
            w(f"  Threat Level : {threat}")
            w(f"  Risk Score   : {score}/100")
            w()

            # MITRE ATT&CK
            mitre = analysis.get("MITRE ATT&CK", [])

            if mitre:
                w(sep)
                w("  MITRE ATT&CK TECHNIQUES")
                w(sep)
                for technique in mitre:
                    w(f"  [*] {technique}")
                w()

            # SUSPICIOUS FINDINGS
            findings = analysis.get("Suspicious Findings", [])

            if findings:
                w(sep)
                w("  SUSPICIOUS FINDINGS")
                w(sep)
                for finding in findings:
                    w(f"  [!] {finding}")
                w()

            # METADATA
            w(sep)
            w("  METADATA")
            w(sep)

            meta_fields = [
                "File Name", "File Size", "Pages",
                "Title", "Author", "Creator", "Producer",
                "CreationDate", "ModDate", "PDF version",
                "Encrypted", "JavaScript", "Linearized"
            ]

            for field in meta_fields:
                if field in metadata:
                    w(f"  {field:<18}: {metadata[field]}")
            w()

            # HASHES
            w(sep)
            w("  HASHES")
            w(sep)
            w(f"  MD5    : {metadata.get('MD5',    'N/A')}")
            w(f"  SHA1   : {metadata.get('SHA1',   'N/A')}")
            w(f"  SHA256 : {metadata.get('SHA256', 'N/A')}")
            w()

            # IOCs
            urls    = safe_get(embedded_results, "IOCs", "URLs",    default=[])
            domains = safe_get(embedded_results, "IOCs", "Domains", default=[])
            ips     = safe_get(embedded_results, "IOCs", "IPs",     default=[])

            if urls or domains or ips:
                w(sep)
                w("  INDICATORS OF COMPROMISE")
                w(sep)
                for url    in urls:    w(f"  URL    : {url}")
                for domain in domains: w(f"  DOMAIN : {domain}")
                for ip     in ips:     w(f"  IP     : {ip}")
                w()

            # EMBEDDED FILES
            extracted = safe_get(
                embedded_results, "Embedded Files", "Extracted Files", default=[]
            )

            if extracted:
                w(sep)
                w("  EMBEDDED FILES")
                w(sep)
                for f_path in extracted:
                    w(f"  EXTRACTED : {f_path}")
                w()

            # STREAM ANALYSIS
            high_entropy = safe_get(
                embedded_results, "Streams", "High Entropy Streams", default=[]
            )
            shellcode = safe_get(
                embedded_results, "Streams", "Decompressed Findings", default=[]
            )

            if high_entropy or shellcode:
                w(sep)
                w("  STREAM ANALYSIS")
                w(sep)
                for s in high_entropy: w(f"  [HIGH ENTROPY] {s}")
                for s in shellcode:    w(f"  [SHELLCODE]    {s}")
                w()

            # MITIGATION
            w(sep)
            w("  MITIGATION RECOMMENDATIONS")
            w(sep)

            recommendations = [
                "Do not open suspicious PDFs directly",
                "Disable JavaScript in PDF reader settings",
                "Open untrusted files in an isolated sandbox",
                "Scan extracted payloads with AV / YARA rules",
                "Block identified domains and IPs at the firewall",
                "Submit file hash to VirusTotal for multi-engine scan",
                "Patch PDF reader to latest version"
            ]

            for rec in recommendations:
                w(f"  - {rec}")
            w()

            w(sep)
            w(f"  Report also saved as JSON: {json_path}")
            w(sep)

    except OSError as e:
        log.error(f"Failed to write TXT report: {e}")
        return None

    return txt_path