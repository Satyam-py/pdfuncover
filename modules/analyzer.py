# modules/analyzer.py

import os
import re
import json
from datetime import datetime


def analyze_results(metadata, embedded_results):

    analysis = {}

    suspicious_findings = []

    score = 0

    # ==========================================
    # JAVASCRIPT ANALYSIS
    # ==========================================

    js_analysis = {
        "Obfuscation Detected": False,
        "Obfuscation Patterns": [],
        "Exploit Indicators": []
    }

    suspicious_patterns = [
        "eval",
        "unescape",
        "fromCharCode",
        "atob",
        "base64",
        "app.launchURL",
        "this.exportDataObject",
        "submitForm",
        "Collab.collectEmailInfo",
        "util.printf"
    ]

    js_keywords = embedded_results.get(
        "JavaScript",
        {}
    ).get(
        "Suspicious Keywords",
        []
    )

    for keyword in js_keywords:

        if keyword in suspicious_patterns:

            js_analysis[
                "Obfuscation Detected"
            ] = True

            js_analysis[
                "Obfuscation Patterns"
            ].append(keyword)

    # Risk scoring

    if embedded_results.get(
        "JavaScript",
        {}
    ).get(
        "JavaScript Detected"
    ):

        score += 20

        suspicious_findings.append(
            "Embedded JavaScript detected"
        )

    if embedded_results.get(
        "JavaScript",
        {}
    ).get(
        "OpenAction Found"
    ):

        score += 15

        suspicious_findings.append(
            "OpenAction trigger detected"
        )

    if js_analysis[
        "Obfuscation Detected"
    ]:

        score += 20

        suspicious_findings.append(
            "JavaScript obfuscation detected"
        )

    analysis["JavaScript Analysis"] = js_analysis

    # ==========================================
    # IOC ANALYSIS
    # ==========================================

    ioc_analysis = {
        "URLs Found": 0,
        "Domains Found": 0,
        "IPs Found": 0
    }

    urls = embedded_results.get(
        "IOCs",
        {}
    ).get(
        "URLs",
        []
    )

    domains = embedded_results.get(
        "IOCs",
        {}
    ).get(
        "Domains",
        []
    )

    ips = embedded_results.get(
        "IOCs",
        {}
    ).get(
        "IPs",
        []
    )

    ioc_analysis["URLs Found"] = len(urls)
    ioc_analysis["Domains Found"] = len(domains)
    ioc_analysis["IPs Found"] = len(ips)

    if urls:

        score += 10

        suspicious_findings.append(
            "Suspicious URLs detected"
        )

    if ips:

        score += 10

        suspicious_findings.append(
            "IP addresses detected"
        )

    analysis["IOC Analysis"] = ioc_analysis

    # ==========================================
    # EMBEDDED FILE ANALYSIS
    # ==========================================

    embedded_analysis = {
        "Embedded Files": [],
        "Executables Detected": False,
        "Executable Indicators": []
    }

    extracted_files = embedded_results.get(
        "Embedded Files",
        {}
    ).get(
        "Extracted Files",
        []
    )

    executable_patterns = [
        ".exe",
        ".dll",
        ".bat",
        ".cmd",
        ".ps1"
    ]

    for file_path in extracted_files:

        embedded_analysis[
            "Embedded Files"
        ].append(file_path)

        lower_path = file_path.lower()

        for pattern in executable_patterns:

            if pattern in lower_path:

                embedded_analysis[
                    "Executables Detected"
                ] = True

                embedded_analysis[
                    "Executable Indicators"
                ].append(pattern)

    if extracted_files:

        score += 25

        suspicious_findings.append(
            "Embedded files detected"
        )

    if embedded_analysis[
        "Executables Detected"
    ]:

        score += 40

        suspicious_findings.append(
            "Executable payload detected"
        )

    analysis[
        "Embedded File Analysis"
    ] = embedded_analysis

    # ==========================================
    # COMPRESSION / ENCRYPTION
    # ==========================================

    if embedded_results.get(
        "Compression",
        {}
    ).get(
        "Compressed Objects Found"
    ):

        score += 10

        suspicious_findings.append(
            "Compressed objects detected"
        )

    if embedded_results.get(
        "Encryption",
        {}
    ).get(
        "Encrypted"
    ):

        score += 15

        suspicious_findings.append(
            "Encrypted PDF detected"
        )

    # ==========================================
    # THREAT LEVEL
    # ==========================================

    if score <= 20:
        threat_level = "LOW"

    elif score <= 50:
        threat_level = "MEDIUM"

    elif score <= 80:
        threat_level = "HIGH"

    else:
        threat_level = "CRITICAL"

    # ==========================================
    # FINAL ANALYSIS
    # ==========================================

    analysis["Risk Score"] = score
    analysis["Threat Level"] = threat_level
    analysis["Suspicious Findings"] = suspicious_findings

    return analysis


# ==========================================
# REPORT GENERATOR
# ==========================================

def generate_report(
    pdf_path,
    metadata,
    embedded_results,
    analysis
):

    os.makedirs(
        "output/reports",
        exist_ok=True
    )

    report_path = os.path.join(
        "output/reports",
        "report.txt"
    )

    with open(report_path, "w") as report:

        report.write("=" * 60 + "\n")
        report.write(
            " PDF MALWARE ANALYSIS REPORT \n"
        )
        report.write("=" * 60 + "\n\n")

        report.write(
            f"Generated : {datetime.now()}\n"
        )

        report.write(
            f"Target PDF : {pdf_path}\n\n"
        )

        # ======================================
        # SUMMARY
        # ======================================

        report.write("=" * 60 + "\n")
        report.write(" SUMMARY \n")
        report.write("=" * 60 + "\n")

        report.write(
            f"Threat Level : "
            f"{analysis['Threat Level']}\n"
        )

        report.write(
            f"Risk Score   : "
            f"{analysis['Risk Score']}/100\n\n"
        )

        # ======================================
        # SUSPICIOUS FINDINGS
        # ======================================

        report.write("=" * 60 + "\n")
        report.write(" SUSPICIOUS FINDINGS \n")
        report.write("=" * 60 + "\n")

        for finding in analysis[
            "Suspicious Findings"
        ]:

            report.write(f"- {finding}\n")

        report.write("\n")

        # ======================================
        # IOCS
        # ======================================

        report.write("=" * 60 + "\n")
        report.write(" INDICATORS OF COMPROMISE \n")
        report.write("=" * 60 + "\n")

        for url in embedded_results.get(
            "IOCs",
            {}
        ).get(
            "URLs",
            []
        ):

            report.write(f"URL : {url}\n")

        for domain in embedded_results.get(
            "IOCs",
            {}
        ).get(
            "Domains",
            []
        ):

            report.write(f"DOMAIN : {domain}\n")

        for ip in embedded_results.get(
            "IOCs",
            {}
        ).get(
            "IPs",
            []
        ):

            report.write(f"IP : {ip}\n")

        report.write("\n")

        # ======================================
        # EMBEDDED FILES
        # ======================================

        report.write("=" * 60 + "\n")
        report.write(" EMBEDDED FILES \n")
        report.write("=" * 60 + "\n")

        for file_path in embedded_results.get(
            "Embedded Files",
            {}
        ).get(
            "Extracted Files",
            []
        ):

            report.write(
                f"EXTRACTED : {file_path}\n"
            )

        report.write("\n")

        # ======================================
        # MITIGATION
        # ======================================

        report.write("=" * 60 + "\n")
        report.write(" MITIGATION RECOMMENDATIONS \n")
        report.write("=" * 60 + "\n")

        recommendations = [
            "Do not open suspicious PDFs directly",
            "Disable JavaScript in PDF readers",
            "Open suspicious files in sandbox environment",
            "Scan extracted payloads with AV/YARA",
            "Block suspicious domains and IPs"
        ]

        for rec in recommendations:

            report.write(f"- {rec}\n")

        report.write("\n")

    return report_path