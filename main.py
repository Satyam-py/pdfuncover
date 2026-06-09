#!/usr/bin/env python3

# main.py

import argparse
import subprocess
import sys
import os
import random
import logging

from pathlib import Path
from colorama import Fore, Style, init

from modules.metadata import extract_metadata
from modules.embedded_extraction import extract_embedded_objects
from modules.analyzer import analyze_results, generate_report

init(autoreset=True)


# ==========================================
# COLORS
# ==========================================

R  = Fore.RED     + Style.BRIGHT
G  = Fore.GREEN   + Style.BRIGHT
Y  = Fore.YELLOW  + Style.BRIGHT
C  = Fore.CYAN    + Style.BRIGHT
W  = Fore.WHITE   + Style.BRIGHT
M  = Fore.MAGENTA + Style.BRIGHT
D  = Fore.WHITE   + Style.DIM
RS = Style.RESET_ALL


# ==========================================
# LOGGING
# ==========================================

os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    filename="logs/main.log",
    level=logging.ERROR,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

log = logging.getLogger(__name__)


# ==========================================
# BANNER ARTS
# ==========================================

ARTS = [

f"""{R}
  +--------------------------------------------------------+
  |  {W}PDFUNCOVER{R} — Malware Analysis Toolkit               |
  +---------------------------+----------------------------+
  |{RS}                           {R}|{RS}                            {R}|
  |{RS}   {C}______________________{RS}  {R}|{RS}  {Y}|'''''''''''''''''''''|{RS}  {R}|
  |{RS}  {C}|                    |{RS} {R}|{RS}  {Y}|   JAVASCRIPT ENGINE  |{RS}  {R}|
  |{RS}  {C}| {W}>_ scanning pdf...{C} |{RS} {R}|{RS}  {Y}|_____________________|{RS}  {R}|
  |{RS}  {C}|                    |{RS} {R}|{RS}  {R}|  eval()              |{RS}  {R}|
  |{RS}  {C}|  {G}[==========>    {C}  |{RS} {R}|{RS}  {R}|  app.launchURL()     |{RS}  {R}|
  |{RS}  {C}|____________________|{RS} {R}|{RS}  {R}|  unescape()         |{RS}  {R}|
  |{RS}  {C}//____________________\\{RS}{R}|{RS}  {R}|_____________________|{RS}  {R}|
  |{RS}       {C}| SCAN |{RS}           {R}|{RS}   {Y}\(@)(@)(@)(@)(@)(@)/{RS}    {R}|
  +---------------------------+----------------------------+
  |{RS}   {C}o  O  o{RS}                {R}|{RS}       {Y}.'\/\/\/'.{RS}         {R}|
  |{RS}        {C}o  O{RS}               {R}|{RS}        {Y})========({RS}        {R}|
  |{RS}           {C}o{RS}                {R}|{RS}      {Y}.'  IOCs    '.{RS}      {R}|
  |{RS}  {W}|^^^^^^^^^^^^^^^^^^^^^^^^|{RS}{R}|{RS}     {Y}/  urls / ips  \\{RS}    {R}|
  |{RS}  {W}|   EMBEDDED  FILES      |{RS}{R}|{RS}    {Y}/   domains      \\{RS}   {R}|
  |{RS}  {W}|________________________|{RS}{R}|{RS}   {Y}|    hashes        |{RS}   {R}|
  |{RS}  {W}|(@)(@)  secret.txt      |{RS}{R}|{RS}   {Y}"                 "{RS}   {R}|
  |{RS}  {W}= = = = = = = = = = = = ={RS}{R}|{RS}    {Y}'_______________'{RS}     {R}|
  +---------------------------+----------------------------+{RS}""",

f"""{G}
  +--------------------------------------------------------+
  |  {W}PDFUNCOVER{G} — Malware Analysis Toolkit               |
  +---------------------------+----------------------------+
  |{RS}                           {G}|{RS}                            {G}|
  |{RS}    {C}_____________________  {G}|{RS}                            {G}|
  |{RS}   {C}|                   | {G}|{RS}  {Y}|'''''''''''''''''''''|{RS}  {G}|
  |{RS}   {C}| {W}>_ scan active   {C}| {G}|{RS}  {Y}|   JAVASCRIPT ENGINE  |{RS}  {G}|
  |{RS}   {C}|                   | {G}|{RS}  {Y}|_____________________|{RS}  {G}|
  |{RS}   {C}|  {G}[=======>       {C}| {G}|{RS}  {R}|  eval()              |{RS}  {G}|
  |{RS}   {C}|___________________| {G}|{RS}  {R}|  submitForm()       |{RS}  {G}|
  |{RS}  {C}//___________________\\\\{G}|{RS}  {R}|  fromCharCode()     |{RS}  {G}|
  |{RS}      {C}| ANALYZE |{RS}          {G}|{RS}  {R}|_____________________|{RS}  {G}|
  |{RS}                           {G}|{RS}   {Y}\(@)(@)(@)(@)(@)(@)/   {G}|{RS}
  +---------------------------+----------------------------+
  |{RS}  {W}|^^^^^^^^^^^^^^^^^^^^^^^| {G}|{RS}       {Y}.'\/\/\/'.{RS}         {G}|
  |{RS}  {W}|  EMBEDDED  FILES      | {G}|{RS}        {Y})========({RS}        {G}|
  |{RS}  {W}|_______________________| {G}|{RS}      {Y}.'  REPORT   '.{RS}      {G}|
  |{RS}  {W}|(@) malware.exe        | {G}|{RS}     {Y}/  txt + json   \\{RS}    {G}|
  |{RS}  {W}|(@) secret.txt         | {G}|{RS}    {Y}/  MITRE ATT&CK   \\{RS}   {G}|
  |{RS}  {W}= = = = = = = = = = = = {G}|{RS}   {Y}'___________________'{RS}    {G}|
  +---------------------------+----------------------------+{RS}""",

f"""{C}
  +--------------------------------------------------------+
  |  {W}PDFUNCOVER{C} — Malware Analysis Toolkit               |
  +---------------------------+----------------------------+
  |{RS}                           {C}|{RS}                            {C}|
  |{RS}   {Y}  /\\_/\\  /\\_/\\        {C}  |{RS}  {G}[+] Header Validation  {C} |
  |{RS}   {Y} ( o.o )( o.o )       {C} |{RS}  {G}[+] Stream Entropy     {C} |
  |{RS}   {Y} =( Y )=( Y )=        {C} |{RS}  {G}[+] Shellcode Detect   {C} |
  |{RS}   {Y}   )   (  )   (       {C} |{RS}  {G}[+] IOC Extraction     {C} |
  |{RS}   {Y}  (_)-(_)(_)-(_)      {C} |{RS}  {G}[+] JS Analysis        {C} |
  |{RS}                           {C}|{RS}  {G}[+] AcroForm / XFA      {C} |
  |{RS}  {R} < sniffing ur PDFs   {C} |{RS}  {G}[+] MITRE ATT&CK Map   {C} |
  |{RS}                           {C}|{RS}  {G}[+] Dual Report Output  {C} |
  +---------------------------+----------------------------+{RS}"""
]


# ==========================================
# BANNER
# ==========================================

def banner():
    os.system("clear")
    art = random.choice(ARTS)
    print(art)
    print(f"\n{D}  {'─' * 50}{RS}")
    print(f"  {G}={RS} [ {W}PDFUNCOVER — PDF Malware Analysis Toolkit{RS}  ]")
    print(f"  {G}={RS} [ {C}metadata / ioc / streams / entropy / forms{RS}  ]")
    print(f"  {G}={RS} [ {C}output: reports (txt+json) / embedded / img{RS}  ]")
    print(f"  {R}+{RS} --=[ {Y}for educational and research use only{RS}   ]")
    print(f"{D}  {'─' * 50}{RS}\n")


# ==========================================
# OUTPUT HELPERS
# ==========================================

def print_section(title):
    print(f"\n{M}{'=' * 70}")
    print(f"{Y}{Style.BRIGHT}[ {title} ]")
    print(f"{M}{'=' * 70}{RS}")


def status(msg):
    print(f"{C}[{G}+{C}]{RS} {W}{msg}{RS}")


def warning(msg):
    print(f"{C}[{Y}!{C}]{RS} {Y}{msg}{RS}")


def error(msg):
    print(f"{C}[{R}X{C}]{RS} {R}{msg}{RS}")


def print_dictionary(data, indent=0):
    """
    Recursively print a nested dict with color formatting.
    Skips empty lists and None values cleanly.
    """

    if not isinstance(data, dict):
        return

    spacing = " " * indent

    for key, value in data.items():

        # Skip internal keys
        if key.startswith("_"):
            continue

        if isinstance(value, dict):

            print(f"{spacing}{C}[+]{RS} {Y}{key}{RS}")
            print_dictionary(value, indent + 4)

        elif isinstance(value, list):

            if not value:
                continue

            print(f"{spacing}{C}[+]{RS} {Y}{key}{RS}")

            for item in value:
                print(f"{' ' * (indent + 4)}{G}→{RS} {W}{item}{RS}")

        elif value is None or value == "":
            continue

        else:
            print(
                f"{spacing}{G}{key:<32}{RS}: {W}{value}{RS}"
            )


def print_verdict(threat, score):
    """
    Print final verdict with appropriate color per threat level.
    """

    color_map = {
        "CLEAN":    G,
        "LOW":      C,
        "MEDIUM":   Y,
        "HIGH":     R,
        "CRITICAL": M,
    }

    color = color_map.get(threat, M)

    verdict_art = {
        "CLEAN":    f"{G}  [✓] No significant threats detected.",
        "LOW":      f"{C}  [~] Low risk. Review findings.",
        "MEDIUM":   f"{Y}  [!] Medium risk. Treat with caution.",
        "HIGH":     f"{R}  [!!] HIGH RISK. Do not open this file.",
        "CRITICAL": f"{M}  [!!!] CRITICAL. Likely malicious payload.",
    }

    print(f"\n{M}{'=' * 70}{RS}")
    print(f"{color}{Style.BRIGHT}  Threat Level : {threat}{RS}")
    print(f"{color}{Style.BRIGHT}  Risk Score   : {score}/100{RS}")
    print(verdict_art.get(threat, ""))
    print(f"{M}{'=' * 70}{RS}")


def validate_input(pdf_path):
    """
    Validate PDF path before analysis.
    Returns (is_valid, error_message).
    """

    path = Path(pdf_path)

    if not path.exists():
        return False, f"File not found: {pdf_path}"

    if not path.is_file():
        return False, f"Not a file: {pdf_path}"

    if path.stat().st_size == 0:
        return False, f"File is empty: {pdf_path}"

    if path.suffix.lower() not in (".pdf", ""):
        warning(f"File extension is not .pdf — analyzing anyway")

    max_size = 50 * 1024 * 1024  # 50MB limit

    if path.stat().st_size > max_size:
        return False, (
            f"File too large ({path.stat().st_size / 1024 / 1024:.1f} MB). "
            f"Max supported: 50MB"
        )

    return True, ""


# ==========================================
# MAIN
# ==========================================

def main():

    parser = argparse.ArgumentParser(
        prog="pdfuncover",
        formatter_class=argparse.RawTextHelpFormatter,
        description=f"""{R}{Style.BRIGHT}
PDFUNCOVER — PDF Malware Analysis Toolkit

Examples:
  python main.py sample.pdf
  python main.py malware.pdf --normalize
  python main.py malware.pdf --no-banner

Features:
  • PDF Header Validation
  • Metadata Extraction & Anomaly Detection
  • JavaScript Detection + JS Content Preview
  • Stream Entropy Analysis (Shannon)
  • Shellcode Pattern Detection
  • IOC Extraction (URLs / Domains / IPs)
  • Embedded File Extraction (dual strategy)
  • AcroForm / AA / XFA Detection
  • MITRE ATT\\&CK Technique Mapping
  • Dual Report Output (TXT + JSON)
{RS}"""
    )

    parser.add_argument(
        "pdf",
        help="Path to target PDF file"
    )

    parser.add_argument(
        "--normalize",
        action="store_true",
        help="Normalize PDF with qpdf before analysis (recommended for obfuscated PDFs)"
    )

    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Skip banner (useful for scripting / piping output)"
    )

    parser.add_argument(
        "--output-dir",
        default="output",
        help="Base output directory (default: output/)"
    )

    args = parser.parse_args()

    # ==========================================
    # BANNER
    # ==========================================

    if not args.no_banner:
        banner()
    else:
        print(f"{G}[PDFUNCOVER]{RS} Starting analysis...\n")

    # ==========================================
    # INPUT VALIDATION
    # ==========================================

    valid, err = validate_input(args.pdf)

    if not valid:
        error(err)
        sys.exit(1)

    pdf_path = args.pdf
    status(f"Target     : {pdf_path}")

    try:
        file_size = Path(pdf_path).stat().st_size
        status(f"File size  : {file_size / 1024:.1f} KB")
    except OSError:
        pass

    # ==========================================
    # NORMALIZATION
    # ==========================================

    if args.normalize:

        if not shutil.which("qpdf"):
            warning("qpdf not installed — skipping normalization")

        else:

            status("Normalizing PDF with qpdf...")

            os.makedirs(args.output_dir, exist_ok=True)

            normalized_pdf = os.path.join(
                args.output_dir, "normalized.pdf"
            )

            result = subprocess.run(
                [
                    "qpdf", "--qdf",
                    "--object-streams=disable",
                    pdf_path,
                    normalized_pdf
                ],
                capture_output=True,
                text=True
            )

            if result.returncode == 0:
                pdf_path = normalized_pdf
                status(f"Normalized : {pdf_path}")
            else:
                warning(f"qpdf normalization failed: {result.stderr.strip()}")
                warning("Continuing with original file")

    # ==========================================
    # METADATA
    # ==========================================

    status("Extracting metadata...")

    try:
        metadata = extract_metadata(pdf_path)
    except Exception as e:
        log.error(f"Metadata extraction failed: {e}")
        error(f"Metadata extraction failed: {e}")
        metadata = {}

    print_section("METADATA ANALYSIS")
    print_dictionary(metadata)

    # ==========================================
    # EMBEDDED OBJECT ANALYSIS
    # ==========================================

    status("Analyzing embedded objects...")

    try:
        embedded_results = extract_embedded_objects(pdf_path)
    except Exception as e:
        log.error(f"Embedded extraction failed: {e}")
        error(f"Embedded extraction failed: {e}")
        embedded_results = {}

    print_section("EMBEDDED OBJECT ANALYSIS")
    print_dictionary(embedded_results)

    # ==========================================
    # THREAT ANALYSIS
    # ==========================================

    status("Running threat analysis...")

    try:
        analysis = analyze_results(metadata, embedded_results)
    except Exception as e:
        log.error(f"Analysis failed: {e}")
        error(f"Threat analysis failed: {e}")
        analysis = {
            "Threat Level": "UNKNOWN",
            "Risk Score": 0,
            "Suspicious Findings": [],
            "MITRE ATT&CK": []
        }

    print_section("THREAT ANALYSIS")
    print_dictionary(analysis)

    # ==========================================
    # REPORT
    # ==========================================

    status("Generating report...")

    try:

        report_path = generate_report(
            pdf_path,
            metadata,
            embedded_results,
            analysis
        )

        if report_path:
            status(f"Report saved : {report_path}")
        else:
            warning("Report generation failed — check logs/analyzer.log")

    except Exception as e:
        log.error(f"Report generation failed: {e}")
        warning(f"Report generation failed: {e}")

    # ==========================================
    # FINAL VERDICT
    # ==========================================

    print_section("FINAL VERDICT")

    threat = analysis.get("Threat Level", "UNKNOWN")
    score  = analysis.get("Risk Score", 0)

    print_verdict(threat, score)

    # Print MITRE techniques if any
    mitre = analysis.get("MITRE ATT&CK", [])

    if mitre:
        print(f"\n{Y}  MITRE ATT&CK Techniques Detected:{RS}")
        for technique in mitre:
            print(f"  {R}[*]{RS} {W}{technique}{RS}")

    print(f"\n{G}[✓] Analysis completed{RS}\n")


# ==========================================
# ENTRY POINT
# ==========================================

if __name__ == "__main__":

    import shutil

    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{R}[!] Interrupted by user{RS}")
        sys.exit(0)
    except Exception as e:
        log.error(f"Unhandled exception: {e}", exc_info=True)
        print(f"\n{R}[!] Unexpected error: {e}{RS}")
        print(f"{Y}[!] Check logs/main.log for details{RS}")
        sys.exit(1)