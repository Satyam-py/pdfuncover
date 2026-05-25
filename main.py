#!/usr/bin/env python3

import argparse
import subprocess
import sys

from modules.metadata import extract_metadata
from modules.embedded_extraction import extract_embedded_objects

from modules.analyzer import (
    analyze_results,
    generate_report
)
import os
import random
from colorama import Fore, Style, init
init(autoreset=True)

R  = Fore.RED    + Style.BRIGHT
G  = Fore.GREEN  + Style.BRIGHT
Y  = Fore.YELLOW + Style.BRIGHT
C  = Fore.CYAN   + Style.BRIGHT
W  = Fore.WHITE  + Style.BRIGHT
D  = Fore.WHITE  + Style.DIM
RS = Style.RESET_ALL

ARTS = [

f"""{R}

   ▄▄▄· ·▄▄▄▄  ·▄▄▄
  ▐█ ▀█ ██▪ ██ ▐▄▄·
  ▄█▀▀█ ▐█· ▐█▌██▪
  ▐█ ▪▐▌██. ██ ▐█▌▐▌
   ▀  ▀ ▀▀▀▀▀• .▀▀▀

{RS}""",

f"""{G}

    ____  ____  ______
   / __ \/ __ \/ ____/
  / /_/ / / / / /_
 / ____/ /_/ / __/
/_/    \____/_/

{RS}""",

f"""{C}

   ╔══════════════╗
   ║ {W}PDF MALWARE{C} ║
   ║   {R}ANALYZER{C}   ║
   ╚══════════════╝

{RS}""",

f"""{Y}

   ░▒▓███████▓▒░
   ░▒▓█▓▒░
   ░▒▓█▓▒░
   ░▒▓██████▓▒░
   ░▒▓█▓▒░
   ░▒▓█▓▒░
   ░▒▓█▓▒░

{RS}""",

f"""{R}

  [ {W}PDF{R} ]═══════╗
        ╔══════════╝
        ║ {G}SCAN ACTIVE
        ║ {Y}JS DETECT
        ║ {C}IOC ANALYSIS
        ╚═══════════>

{RS}""",

f"""{G}

     .--------.
    / .------. \\
   / /        \\ \\
   | | {R}PDF{G}  | |
  _| |________| |_
.' |_|        |_| '.
'._____ ____ _____.'

{RS}""",

f"""{C}

   ▄███████▄
  ███{R}█{C}███{R}█{C}███
  ███▄▄▄▄▄███
   ▀▀▀▀▀▀▀▀▀
    PDF SCAN

{RS}""",

f"""{Y}

    ╭━━━╮
    ┃╭━╮┃
    ┃╰━╯┃
    ┃╭━━╯
    ┃┃
    ╰╯

{W} PDF MALWARE TOOLKIT

{RS}""",

f"""{R}

   ___________________
  / {W}PDF ANALYZER{R} /|
 /_________________/ |
 |                 | |
 | {G}[+] JS FOUND {R}| |
 | {Y}[+] URLS     {R}| |
 | {C}[+] EMBEDDED {R}| /
 |_________________|/

{RS}""",

f"""{G}

   ╔═╗╔╦╗╔═╗
   ╠═╝ ║║╠╣
   ╩  ═╩╝╚

 {W}Malicious PDF Scanner

{RS}""",

f"""{C}

         __________
        / ________ \\
       || PDFSCAN ||
       ||_________||
       |  __  __  |
       | |  ||  | |
       | |__||__| |
       |  __  __()|
       | |  ||  | |
       | |  ||  | |
       | |__||__| |
       |__________|

{RS}""",

f"""{C}

        ▄▄▄▄▄▄▄▄▄
      ▄███████████▄
    ▄███▀▀▀▀▀▀▀███▄
   ███  ▄▄▄▄▄▄▄  ███
   ███ ██▀▀▀▀▀██ ███
   ███ ██ PDF ██ ███
   ███ ██SCAN██ ███
   ███ ██▄▄▄▄▄██ ███
    ▀███▄▄▄▄▄███▀
       ▀▀▀▀▀▀▀

{RS}"""
]

# Initialize colorama
init(autoreset=True)


# ==========================================
# COLORS
# ==========================================

RED = Fore.RED
GREEN = Fore.GREEN
YELLOW = Fore.YELLOW
CYAN = Fore.CYAN
BLUE = Fore.BLUE
MAGENTA = Fore.MAGENTA
WHITE = Fore.WHITE

RESET = Style.RESET_ALL
BRIGHT = Style.BRIGHT


# ==========================================
# BANNER
# ==========================================

def banner():
    os.system("clear")
    art = random.choice(ARTS)
    print(art)
    print(f"\n{D}  {'─' * 42}{RS}")
    print(f"  {G}={RS} [ {W}PDF Malware Analysis Toolkit{RS}         ]")
    print(f"  {G}={RS} [ {C}modules{RS} : metadata / ioc / streams   ]")
    print(f"  {G}={RS} [ {C}output{RS}  : embedded / images           ]")
    print(f"  {R}+{RS} -- --=[ {Y}for educational use only{RS}        ]")
    print(f"{D}  {'─' * 42}{RS}\n")

# ==========================================
# SECTION PRINTING
# ==========================================

def print_section(title):

    print(
        f"\n{MAGENTA}{'=' * 70}"
    )

    print(
        f"{YELLOW}{BRIGHT}[ {title} ]"
    )

    print(
        f"{MAGENTA}{'=' * 70}{RESET}"
    )


# ==========================================
# DICTIONARY PRINTING
# ==========================================

def print_dictionary(data, indent=0):

    spacing = " " * indent

    if isinstance(data, dict):

        for key, value in data.items():

            if isinstance(value, dict):

                print(
                    f"{spacing}"
                    f"{CYAN}[+]{RESET} "
                    f"{YELLOW}{key}"
                )

                print_dictionary(
                    value,
                    indent + 4
                )

            elif isinstance(value, list):

                if not value:
                    continue

                print(
                    f"{spacing}"
                    f"{CYAN}[+]{RESET} "
                    f"{YELLOW}{key}"
                )

                for item in value:

                    print(
                        f"{' ' * (indent + 4)}"
                        f"{GREEN}→{RESET} "
                        f"{WHITE}{item}"
                    )

            else:

                print(
                    f"{spacing}"
                    f"{GREEN}{key:<30}"
                    f"{RESET}: "
                    f"{WHITE}{value}"
                )


# ==========================================
# STATUS PRINTING
# ==========================================

def status(message):

    print(
        f"{CYAN}[{GREEN}+{CYAN}] "
        f"{WHITE}{message}"
    )


def warning(message):

    print(
        f"{CYAN}[{YELLOW}!{CYAN}] "
        f"{YELLOW}{message}"
    )


def error(message):

    print(
        f"{CYAN}[{RED}X{CYAN}] "
        f"{RED}{message}"
    )


# ==========================================
# MAIN
# ==========================================

def main():

    parser = argparse.ArgumentParser(

        prog="pdfmal",

        formatter_class=argparse.RawTextHelpFormatter,

        description=f"""{RED}{BRIGHT}

PDF Malware Analysis Toolkit

Examples:
  python main.py sample.pdf
  python main.py malware.pdf --normalize

Features:
  • Metadata Analysis
  • JavaScript Detection
  • IOC Extraction
  • Embedded File Extraction
  • Threat Scoring
  • Report Generation
{RESET}
"""
    )

    parser.add_argument(
        "pdf",
        help="Target PDF file path"
    )

    parser.add_argument(
        "--normalize",
        action="store_true",
        help="Normalize PDF using qpdf"
    )

    args = parser.parse_args()

    banner()

    pdf_path = args.pdf

    status(f"Target PDF : {pdf_path}")

    # ==========================================
    # NORMALIZATION
    # ==========================================

    if args.normalize:

        status("Normalizing PDF using qpdf...")

        os.makedirs(
            "output",
            exist_ok=True
        )

        normalized_pdf = (
            "output/normalized.pdf"
        )

        subprocess.run([
            "qpdf",
            "--qdf",
            "--object-streams=disable",
            pdf_path,
            normalized_pdf
        ])

        pdf_path = normalized_pdf

        status(
            f"Normalized PDF : {pdf_path}"
        )

    # ==========================================
    # METADATA
    # ==========================================

    status("Extracting metadata...")

    metadata = extract_metadata(
        pdf_path
    )

    print_section(
        "METADATA ANALYSIS"
    )

    print_dictionary(metadata)

    # ==========================================
    # EMBEDDED OBJECTS
    # ==========================================

    status(
        "Extracting embedded objects..."
    )

    embedded_results = (
        extract_embedded_objects(
            pdf_path
        )
    )

    print_section(
        "EMBEDDED OBJECT ANALYSIS"
    )

    print_dictionary(
        embedded_results
    )

    # ==========================================
    # THREAT ANALYSIS
    # ==========================================

    status(
        "Running threat analysis..."
    )

    analysis = analyze_results(
        metadata,
        embedded_results
    )

    print_section(
        "THREAT ANALYSIS"
    )

    print_dictionary(
        analysis
    )

    # ==========================================
    # REPORT
    # ==========================================

    status(
        "Generating report..."
    )

    report_path = generate_report(
        pdf_path,
        metadata,
        embedded_results,
        analysis
    )

    status(
        f"Report saved to : {report_path}"
    )

    # ==========================================
    # FINAL VERDICT
    # ==========================================

    print_section(
        "FINAL VERDICT"
    )

    threat = analysis.get(
        "Threat Level",
        "UNKNOWN"
    )

    score = analysis.get(
        "Risk Score",
        0
    )

    if threat == "LOW":

        color = GREEN

    elif threat == "MEDIUM":

        color = YELLOW

    elif threat == "HIGH":

        color = RED

    else:

        color = MAGENTA

    print(
        f"{BRIGHT}"
        f"{color}"
        f"Threat Level : {threat}"
    )

    print(
        f"{BRIGHT}"
        f"{color}"
        f"Risk Score   : {score}/100"
    )

    print(RESET)

    print(
        f"{MAGENTA}{'=' * 70}"
    )

    print(
        f"{GREEN}[✓] Analysis Completed Successfully"
    )

    print(
        f"{MAGENTA}{'=' * 70}{RESET}"
    )


if __name__ == "__main__":

    try:

        main()

    except KeyboardInterrupt:

        print(
            f"\n{RED}[!] Interrupted by user{RESET}"
        )

        sys.exit(0)