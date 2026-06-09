# modules/embedded_extraction.py

import subprocess
import shutil
import os
import re
import math
import zlib
import logging

from collections import Counter


# ==========================================
# LOGGING SETUP
# ==========================================

os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    filename="logs/embedded_extraction.log",
    level=logging.ERROR,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

log = logging.getLogger(__name__)


# ==========================================
# HELPERS
# ==========================================

def run_command(command, timeout=30):
    """
    Runs a shell command safely with timeout.
    Returns stdout+stderr or empty string on failure.
    Logs errors instead of silently swallowing them.
    """

    try:

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        return result.stdout + result.stderr

    except subprocess.TimeoutExpired:

        log.error(f"Command timed out: {command}")
        return ""

    except FileNotFoundError:

        log.error(f"Command not found: {command[0]}")
        return ""

    except OSError as e:

        log.error(f"OS error running {command}: {e}")
        return ""


def decode_pdf_string(text):
    """
    Decode PDF octal-escaped strings.
    Example: \\072 -> :   \\057 -> /   \\056 -> .
    """

    return re.sub(
        r"\\([0-7]{3})",
        lambda x: chr(int(x.group(1), 8)),
        text
    )


def decode_octal_bytes(b):
    """
    Decode octal escapes in raw bytes and return a string.
    Example: b'secret\\056txt' -> 'secret.txt'
    """

    return re.sub(
        rb"\\([0-7]{3})",
        lambda m: bytes([int(m.group(1), 8)]),
        b
    ).decode(errors="replace")


def calculate_entropy(data):
    """
    Calculate Shannon entropy of a byte string.
    Score 0-8. Above 7.2 = likely encrypted/packed payload.
    """

    if not data:
        return 0.0

    counter = Counter(data)
    length = len(data)
    entropy = 0.0

    for count in counter.values():
        p = count / length
        entropy -= p * math.log2(p)

    return round(entropy, 2)


def decompress_stream(data):
    """
    Attempt FlateDecode (zlib) decompression on stream bytes.
    Returns decompressed bytes or None on failure.
    """

    try:
        return zlib.decompress(data)

    except zlib.error:

        try:
            # Some PDF streams omit the zlib header
            return zlib.decompress(data, -15)

        except zlib.error:
            return None


def validate_pdf_header(pdf_path):
    """
    Check that the file starts with %PDF- magic bytes.
    Returns True if valid, False if spoofed/invalid.
    """

    try:

        with open(pdf_path, "rb") as f:
            header = f.read(8)

        return header.startswith(b"%PDF-")

    except OSError as e:

        log.error(f"Could not read PDF header: {e}")
        return False


def detect_shellcode_patterns(data):
    """
    Scan byte data for common shellcode indicators.
    Returns list of findings.
    """

    findings = []

    if isinstance(data, str):
        data = data.encode(errors="replace")

    # NOP sled — common in heap sprays
    if b"\x90\x90\x90\x90" in data:
        findings.append("NOP sled detected (\\x90\\x90\\x90\\x90)")

    # Common shellcode prologue bytes
    shellcode_patterns = [
        (b"\xfc\xe8", "Shellcode prologue (\\xfc\\xe8)"),
        (b"\x31\xc0\x50", "Linux shellcode pattern (\\x31\\xc0\\x50)"),
        (b"\x60\x89\xe5", "Stack frame shellcode (\\x60\\x89\\xe5)"),
        (b"\xeb\xfe",     "Infinite loop / shellcode stub (\\xeb\\xfe)"),
    ]

    for pattern, label in shellcode_patterns:
        if pattern in data:
            findings.append(label)

    return findings


def is_suspicious_filename(fname):
    """
    Check if an embedded filename has a dangerous extension.
    """

    dangerous_extensions = [
        ".exe", ".dll", ".bat", ".cmd",
        ".ps1", ".vbs", ".js", ".scr",
        ".hta", ".jar", ".sh", ".py"
    ]

    lower = fname.lower()

    return any(lower.endswith(ext) for ext in dangerous_extensions)


# ==========================================
# MAIN ANALYZER
# ==========================================

def extract_embedded_objects(pdf_path):
    """
    Full embedded object analysis of a PDF file.
    Returns a structured results dictionary.
    """

    results = {}

    # ==========================================
    # PDF HEADER VALIDATION
    # ==========================================

    header_data = {
        "Valid PDF Header": False,
        "Header Warning": ""
    }

    if validate_pdf_header(pdf_path):

        header_data["Valid PDF Header"] = True

    else:

        header_data["Valid PDF Header"] = False
        header_data["Header Warning"] = (
            "File does not start with %PDF- — "
            "may be spoofed or corrupted"
        )

    results["Header Validation"] = header_data

    # ==========================================
    # COMMON OUTPUTS
    # ==========================================

    strings_output = run_command(["strings", pdf_path])

    parser_output = ""

    if shutil.which("pdf-parser"):
        parser_output = run_command(["pdf-parser", pdf_path])

    # ==========================================
    # STREAM ANALYSIS
    # ==========================================

    stream_data = {
        "Stream Objects Found": False,
        "Compressed Streams": False,
        "Object Count": 0,
        "High Entropy Streams": [],
        "Decompressed Findings": []
    }

    if shutil.which("pdf-parser"):

        # --stats gives clean "Indirect object: N" count
        stats_output = run_command(
            ["pdf-parser", "--stats", pdf_path]
        )

        obj_match = re.search(
            r"Indirect object:\s*(\d+)",
            stats_output
        )

        stream_data["Object Count"] = (
            int(obj_match.group(1)) if obj_match else 0
        )

        if "stream" in parser_output.lower():
            stream_data["Stream Objects Found"] = True

        if "/Filter" in parser_output:
            stream_data["Compressed Streams"] = True

        # Analyze entropy + decompress each stream
        try:

            with open(pdf_path, "rb") as f:
                raw_pdf = f.read()

            stream_pattern = re.compile(
                rb"stream\r?\n(.*?)\r?\nendstream",
                re.DOTALL
            )

            for i, match in enumerate(stream_pattern.finditer(raw_pdf)):

                stream_bytes = match.group(1)

                # Skip very small streams (noise)
                if len(stream_bytes) < 16:
                    continue

                entropy = calculate_entropy(stream_bytes)

                if entropy > 7.2:
                    stream_data["High Entropy Streams"].append(
                        f"Stream {i} — entropy {entropy} "
                        f"(size: {len(stream_bytes)} bytes)"
                    )

                # Try to decompress and scan content
                decompressed = decompress_stream(stream_bytes)

                if decompressed:

                    # Scan decompressed content for shellcode
                    sc_findings = detect_shellcode_patterns(
                        decompressed
                    )

                    for finding in sc_findings:
                        stream_data["Decompressed Findings"].append(
                            f"Stream {i}: {finding}"
                        )

        except OSError as e:
            log.error(f"Stream entropy analysis failed: {e}")

    else:
        stream_data["Error"] = "pdf-parser not installed"

    results["Streams"] = stream_data

    # ==========================================
    # JAVASCRIPT DETECTION
    # ==========================================

    js_data = {
        "JavaScript Detected": False,
        "OpenAction Found": False,
        "Suspicious Keywords": [],
        "Decoded JS Preview": ""
    }

    suspicious_keywords = [
        "eval",
        "unescape",
        "app.launchURL",
        "this.exportDataObject",
        "submitForm",
        "getAnnots",
        "app.alert",
        "util.printf",
        "Collab.collectEmailInfo",
        "fromCharCode"
    ]

    if shutil.which("pdf-parser"):

        js_output = run_command(
            ["pdf-parser", "--search", "JavaScript", pdf_path]
        )

        openaction_output = run_command(
            ["pdf-parser", "--search", "OpenAction", pdf_path]
        )

        combined_js_output = (
            strings_output + js_output + openaction_output
        ).lower()

        if js_output.strip():
            js_data["JavaScript Detected"] = True

        if openaction_output.strip():
            js_data["OpenAction Found"] = True

        for keyword in suspicious_keywords:
            if keyword.lower() in combined_js_output:
                js_data["Suspicious Keywords"].append(keyword)

        # Decode and preview the actual JS content
        if js_data["JavaScript Detected"]:

            decoded_js = decode_pdf_string(js_output)

            js_match = re.search(
                r"/JS\s*\((.{20,200})",
                decoded_js,
                re.DOTALL
            )

            if js_match:
                preview = js_match.group(1)
                preview = re.sub(r"\s+", " ", preview).strip()
                js_data["Decoded JS Preview"] = preview[:200]

    else:
        js_data["Error"] = "pdf-parser not installed"

    results["JavaScript"] = js_data

    # ==========================================
    # IOC EXTRACTION
    # ==========================================

    ioc_data = {
        "URLs": [],
        "Domains": [],
        "IPs": []
    }

    if shutil.which("pdf-parser"):

        # /URI with slash matches Link action dictionaries
        uri_output = run_command(
            ["pdf-parser", "--search", "/URI", pdf_path]
        )

        link_output = run_command(
            ["pdf-parser", "--search", "Link", pdf_path]
        )

    else:
        uri_output = ""
        link_output = ""

    # Decode ALL sources before regex — raw octals won't match
    decoded_strings = decode_pdf_string(strings_output)
    decoded_uri     = decode_pdf_string(uri_output)
    decoded_link    = decode_pdf_string(link_output)

    combined_output = "\n".join([
        decoded_strings,
        decoded_uri,
        decoded_link
    ])

    # URL extraction
    url_pattern = r"https?://[^\s<>()'\"]+"
    urls = re.findall(url_pattern, combined_output)

    clean_urls = []

    for url in urls:

        url = url.strip().rstrip(")]}>,'\"").replace("\\", "")

        if url and url not in clean_urls:
            clean_urls.append(url)

    # Domain extraction
    domain_pattern = (
        r"\b(?:[a-zA-Z0-9-]+\.)+"
        r"(?:com|org|net|edu|gov|io|co|info|biz|ru|cn|in)\b"
    )

    domains = re.findall(
        domain_pattern,
        combined_output,
        re.IGNORECASE
    )

    clean_domains = []

    for domain in domains:

        domain = domain.lower().strip()

        if domain and domain not in clean_domains:
            clean_domains.append(domain)

    # IP extraction with octet validation
    ip_pattern = r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}"
    ips = re.findall(ip_pattern, combined_output)

    clean_ips = []

    for ip in ips:

        parts = ip.split(".")

        try:

            if all(0 <= int(part) <= 255 for part in parts):

                if ip not in clean_ips:
                    clean_ips.append(ip)

        except ValueError:
            continue

    ioc_data["URLs"]    = clean_urls
    ioc_data["Domains"] = clean_domains
    ioc_data["IPs"]     = clean_ips

    results["IOCs"] = ioc_data

    # ==========================================
    # EMBEDDED FILES
    # ==========================================

    embedded_data = {
        "Embedded Files Found": False,
        "Embedded Objects": [],
        "Extracted Files": [],
        "Suspicious Files": [],
        "Extracted To": "None"
    }

    embedded_output_dir = "output/embedded"
    os.makedirs(embedded_output_dir, exist_ok=True)
    extracted_files = []

    # ------------------------------------------
    # STRATEGY 1: pdf-parser object dump
    # Works when embedded file has its own object number
    # ------------------------------------------

    if shutil.which("pdf-parser"):

        embedded_output = run_command(
            ["pdf-parser", "--search", "EmbeddedFile", pdf_path]
        )

        filespec_output = run_command(
            ["pdf-parser", "--search", "Filespec", pdf_path]
        )

        if embedded_output.strip() or filespec_output.strip():

            embedded_data["Embedded Files Found"] = True

            object_matches = list(set(re.findall(
                r"\d+\s+\d+\s+obj",
                embedded_output + filespec_output
            )))

            embedded_data["Embedded Objects"] = object_matches

            for match in object_matches:

                obj_num = match.split()[0]

                dump_path = os.path.join(
                    embedded_output_dir,
                    f"object_{obj_num}.bin"
                )

                run_command([
                    "pdf-parser",
                    "--object", obj_num,
                    "--raw",
                    "--dump", dump_path,
                    pdf_path
                ])

                try:

                    if (
                        os.path.exists(dump_path)
                        and os.path.getsize(dump_path) > 0
                    ):

                        extracted_files.append(dump_path)

                except OSError as e:
                    log.error(f"Could not stat dump file {dump_path}: {e}")

    else:
        embedded_data["Error"] = "pdf-parser not installed"

    # ------------------------------------------
    # STRATEGY 2: Raw byte stream extraction
    # Works for inline embedded files with no separate object number
    # e.g. nested inside /EmbeddedFiles /Names dictionary
    # ------------------------------------------

    try:

        with open(pdf_path, "rb") as f:
            raw_pdf = f.read()

        # Match /F (filename) ... /EmbeddedFile ... stream\n<data>\nendstream
        # Requires BOTH /F and /EmbeddedFile — prevents page content false positives
        embedded_block_pattern = re.compile(
            rb"/F\s*\(([^)]+)\).*?/EmbeddedFile.*?stream\r?\n(.*?)\r?\nendstream",
            re.DOTALL
        )

        for match in embedded_block_pattern.finditer(raw_pdf):

            raw_fname      = match.group(1)
            stream_content = match.group(2)

            fname = decode_octal_bytes(raw_fname)
            fname = os.path.basename(fname).replace("/", "_").replace("\\", "_")

            save_path = os.path.join(embedded_output_dir, fname)

            if save_path not in extracted_files:

                try:

                    with open(save_path, "wb") as out:
                        out.write(stream_content)

                    if os.path.getsize(save_path) > 0:

                        extracted_files.append(save_path)
                        embedded_data["Embedded Files Found"] = True

                        # Flag dangerous file types
                        if is_suspicious_filename(fname):
                            embedded_data["Suspicious Files"].append(
                                f"{fname} — dangerous file type"
                            )

                except OSError as e:
                    log.error(f"Failed to write embedded file {fname}: {e}")

    except OSError as e:
        log.error(f"Strategy 2 raw extraction failed: {e}")
        embedded_data["Stream Extraction Error"] = str(e)

    embedded_data["Extracted Files"] = extracted_files
    embedded_data["Extracted To"] = (
        embedded_output_dir if extracted_files else "None"
    )

    results["Embedded Files"] = embedded_data

    # ==========================================
    # IMAGE EXTRACTION
    # ==========================================

    image_data = {
        "Images Extracted": False,
        "Image Count": 0,
        "Extracted To": "None"
    }

    output_dir = "output/images"
    os.makedirs(output_dir, exist_ok=True)

    if shutil.which("pdfimages"):

        image_prefix = os.path.join(output_dir, "image")

        run_command(["pdfimages", "-all", pdf_path, image_prefix])

        try:

            extracted_images = [
                f for f in os.listdir(output_dir)
                if os.path.isfile(os.path.join(output_dir, f))
            ]

            image_data["Image Count"] = len(extracted_images)
            image_data["Extracted To"] = (
                output_dir if extracted_images else "None"
            )
            image_data["Images Extracted"] = bool(extracted_images)

        except OSError as e:
            log.error(f"Could not list image output dir: {e}")

    else:
        image_data["Error"] = "pdfimages not installed"

    results["Images"] = image_data

    # ==========================================
    # COMPRESSION CHECK
    # ==========================================

    compression_data = {
        "Compressed Objects Found": False,
        "Filters": []
    }

    if shutil.which("pdf-parser"):

        filter_output = run_command(
            ["pdf-parser", "--search", "/Filter", pdf_path]
        )

        compression_filters = [
            "FlateDecode",
            "ASCIIHexDecode",
            "ASCII85Decode",
            "LZWDecode",
            "RunLengthDecode",
            "JBIG2Decode",     # used in CVE-2010-0188
            "CCITTFaxDecode",
            "DCTDecode"
        ]

        found_filters = [
            f for f in compression_filters
            if f in filter_output
        ]

        compression_data["Compressed Objects Found"] = bool(found_filters)
        compression_data["Filters"] = found_filters

        # JBIG2Decode is a known exploit vector — flag it
        if "JBIG2Decode" in found_filters:
            compression_data["JBIG2 Warning"] = (
                "JBIG2Decode detected — associated with CVE-2010-0188"
            )

    else:
        compression_data["Error"] = "pdf-parser not installed"

    results["Compression"] = compression_data

    # ==========================================
    # ENCRYPTION CHECK
    # ==========================================

    encryption_data = {
        "Encrypted": False
    }

    if shutil.which("qpdf"):

        encryption_output = run_command(
            ["qpdf", "--show-encryption", pdf_path]
        )

        encryption_data["Encrypted"] = (
            "R =" in encryption_output
            or "P =" in encryption_output
        )

    else:
        encryption_data["Error"] = "qpdf not installed"

    results["Encryption"] = encryption_data

    # ==========================================
    # ACROFORM / AA DETECTION
    # ==========================================

    acroform_data = {
        "AcroForm Detected": False,
        "Additional Actions Found": False,
        "XFA Form Detected": False
    }

    if shutil.which("pdf-parser"):

        acroform_output = run_command(
            ["pdf-parser", "--search", "AcroForm", pdf_path]
        )

        aa_output = run_command(
            ["pdf-parser", "--search", "/AA", pdf_path]
        )

        xfa_output = run_command(
            ["pdf-parser", "--search", "XFA", pdf_path]
        )

        if acroform_output.strip():
            acroform_data["AcroForm Detected"] = True

        if aa_output.strip():
            acroform_data["Additional Actions Found"] = True

        if xfa_output.strip():
            acroform_data["XFA Form Detected"] = True

    results["AcroForm"] = acroform_data

    # ==========================================
    # SUSPICIOUS FLAGS
    # ==========================================

    suspicious_flags = []

    if not header_data["Valid PDF Header"]:
        suspicious_flags.append("Invalid PDF header — possible spoofed file")

    if js_data["JavaScript Detected"]:
        suspicious_flags.append("Embedded JavaScript detected")

    if js_data["OpenAction Found"]:
        suspicious_flags.append("OpenAction trigger found")

    if js_data["Suspicious Keywords"]:
        suspicious_flags.append(
            f"Suspicious JS keywords: {', '.join(js_data['Suspicious Keywords'])}"
        )

    if embedded_data["Embedded Files Found"]:
        suspicious_flags.append("Embedded files detected")

    if embedded_data["Suspicious Files"]:
        for sf in embedded_data["Suspicious Files"]:
            suspicious_flags.append(f"Dangerous embedded file: {sf}")

    if stream_data["High Entropy Streams"]:
        suspicious_flags.append(
            f"{len(stream_data['High Entropy Streams'])} high-entropy "
            f"stream(s) detected — possible encrypted payload"
        )

    if stream_data["Decompressed Findings"]:
        for finding in stream_data["Decompressed Findings"]:
            suspicious_flags.append(f"Shellcode pattern: {finding}")

    if compression_data["Compressed Objects Found"]:
        suspicious_flags.append("Compressed objects present")

    if compression_data.get("JBIG2 Warning"):
        suspicious_flags.append(compression_data["JBIG2 Warning"])

    if encryption_data["Encrypted"]:
        suspicious_flags.append("Encrypted PDF")

    if ioc_data["URLs"]:
        suspicious_flags.append(
            f"{len(ioc_data['URLs'])} URL(s) found inside PDF"
        )

    if ioc_data["IPs"]:
        suspicious_flags.append(
            f"{len(ioc_data['IPs'])} IP address(es) found inside PDF"
        )

    if acroform_data["AcroForm Detected"]:
        suspicious_flags.append("AcroForm detected — possible data exfiltration")

    if acroform_data["Additional Actions Found"]:
        suspicious_flags.append("/AA trigger found — action on page open/close")

    if acroform_data["XFA Form Detected"]:
        suspicious_flags.append("XFA form detected — used in exploit delivery")

    results["Suspicious Flags"] = suspicious_flags

    return results