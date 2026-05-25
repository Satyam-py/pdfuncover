# modules/embedded_extraction.py

import subprocess
import shutil
import os
import re


# ==========================================
# HELPERS
# ==========================================

def run_command(command):
    """
    Runs shell command safely and returns output.
    """

    try:

        result = subprocess.run(
            command,
            capture_output=True,
            text=True
        )

        return result.stdout + result.stderr

    except Exception as e:

        return str(e)


def decode_pdf_string(text):
    """
    Decode PDF octal escaped strings.

    Example:
    \\072 -> :
    \\057 -> /
    """

    return re.sub(
        r"\\([0-7]{3})",
        lambda x: chr(int(x.group(1), 8)),
        text
    )


# ==========================================
# MAIN ANALYZER
# ==========================================

def extract_embedded_objects(pdf_path):

    results = {}

    # ==========================================
    # COMMON OUTPUTS
    # ==========================================

    strings_output = run_command(
        ["strings", pdf_path]
    )

    parser_output = ""

    if shutil.which("pdf-parser"):

        parser_output = run_command(
            ["pdf-parser", pdf_path]
        )

    # ==========================================
    # STREAM ANALYSIS
    # ==========================================

    stream_data = {
        "Stream Objects Found": False,
        "Compressed Streams": False,
        "Object Count": 0
    }

    if shutil.which("pdf-parser"):

        # Use --stats flag — output contains "Indirect object: N"
        stats_output = run_command(
            ["pdf-parser", "--stats", pdf_path]
        )

        obj_match = re.search(
            r"Indirect object:\s*(\d+)",
            stats_output
        )

        if obj_match:
            stream_data["Object Count"] = int(obj_match.group(1))
        else:
            stream_data["Object Count"] = 0

        if "stream" in parser_output.lower():
            stream_data["Stream Objects Found"] = True

        if "/Filter" in parser_output:
            stream_data["Compressed Streams"] = True

    else:

        stream_data["Error"] = "pdf-parser Not Installed"

    results["Streams"] = stream_data

    # ==========================================
    # JAVASCRIPT DETECTION
    # ==========================================

    js_data = {
        "JavaScript Detected": False,
        "OpenAction Found": False,
        "Suspicious Keywords": []
    }

    suspicious_keywords = [
        "eval",
        "unescape",
        "app.launchURL",
        "this.exportDataObject",
        "submitForm",
        "getAnnots"
    ]

    if shutil.which("pdf-parser"):

        js_output = run_command(
            ["pdf-parser", "--search", "JavaScript", pdf_path]
        )

        openaction_output = run_command(
            ["pdf-parser", "--search", "OpenAction", pdf_path]
        )

        combined_js_output = (
            strings_output +
            js_output +
            openaction_output
        ).lower()

        if js_output.strip():
            js_data["JavaScript Detected"] = True

        if openaction_output.strip():
            js_data["OpenAction Found"] = True

        for keyword in suspicious_keywords:

            if keyword.lower() in combined_js_output:
                js_data["Suspicious Keywords"].append(
                    keyword
                )

    else:

        js_data["Error"] = "pdf-parser Not Installed"

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

        # Search /URI (with slash) to match Link action dictionaries
        uri_output = run_command(
            ["pdf-parser", "--search", "/URI", pdf_path]
        )

        # Also search Link objects where hyperlinks are stored
        link_output = run_command(
            ["pdf-parser", "--search", "Link", pdf_path]
        )

    else:

        uri_output = ""
        link_output = ""

    # Decode ALL outputs before combining — raw octal strings won't match regex
    decoded_strings = decode_pdf_string(strings_output)
    decoded_uri     = decode_pdf_string(uri_output)
    decoded_link    = decode_pdf_string(link_output)

    combined_output = "\n".join([
        decoded_strings,
        decoded_uri,
        decoded_link
    ])

    # ==========================================
    # URL EXTRACTION
    # ==========================================

    url_pattern = r"https?://[^\s<>()'\"]+"

    urls = re.findall(
        url_pattern,
        combined_output
    )

    clean_urls = []

    for url in urls:

        url = url.strip()

        url = url.rstrip(")]}>,'\"")

        url = url.replace("\\", "")

        if url not in clean_urls:
            clean_urls.append(url)

    # ==========================================
    # DOMAIN EXTRACTION
    # ==========================================

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

        if domain not in clean_domains:
            clean_domains.append(domain)

    # ==========================================
    # IP EXTRACTION
    # ==========================================

    ip_pattern = r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}"

    ips = re.findall(
        ip_pattern,
        combined_output
    )

    clean_ips = []

    for ip in ips:

        parts = ip.split(".")

        try:

            if all(
                0 <= int(part) <= 255
                for part in parts
            ):

                if ip not in clean_ips:
                    clean_ips.append(ip)

        except:
            pass

    # ==========================================
    # SAVE IOC RESULTS
    # ==========================================

    ioc_data["URLs"] = clean_urls
    ioc_data["Domains"] = clean_domains
    ioc_data["IPs"] = clean_ips

    results["IOCs"] = ioc_data

    # ==========================================
    # EMBEDDED FILES
    # ==========================================

    embedded_data = {
        "Embedded Files Found": False,
        "Embedded Objects": [],
        "Extracted Files": [],
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

            object_matches = re.findall(
                r"\d+\s+\d+\s+obj",
                embedded_output + filespec_output
            )

            object_matches = list(set(object_matches))
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

                if os.path.exists(dump_path) and os.path.getsize(dump_path) > 0:
                    extracted_files.append(dump_path)

    else:

        embedded_data["Error"] = "pdf-parser Not Installed"

    # ------------------------------------------
    # STRATEGY 2: Raw stream extraction from PDF bytes
    # Works when embedded file is inline (no separate object number)
    # e.g. nested inside /EmbeddedFiles /Names dictionary
    # ------------------------------------------

    try:

        with open(pdf_path, "rb") as f:
            raw_pdf = f.read()

        def decode_octal_bytes(b):
            return re.sub(
                rb"\\([0-7]{3})",
                lambda m: bytes([int(m.group(1), 8)]),
                b
            ).decode(errors="replace")

        # Only extract streams directly associated with a named /F (filename) entry
        # This prevents page content streams from being saved as .bin files
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

                with open(save_path, "wb") as out:
                    out.write(stream_content)

                if os.path.getsize(save_path) > 0:
                    extracted_files.append(save_path)
                    embedded_data["Embedded Files Found"] = True

    except Exception as e:

        embedded_data["Stream Extraction Error"] = str(e)

    embedded_data["Extracted Files"] = extracted_files
    embedded_data["Extracted To"] = embedded_output_dir if extracted_files else "None"

    results["Embedded Files"] = embedded_data

    # ==========================================
    # IMAGE EXTRACTION
    # ==========================================

    image_data = {
        "Images Extracted": False,
        "Image Count": 0
    }

    output_dir = "output/images"

    os.makedirs(output_dir, exist_ok=True)

    if shutil.which("pdfimages"):

        image_prefix = os.path.join(
            output_dir,
            "image"
        )

        run_command(
            ["pdfimages", "-all", pdf_path, image_prefix]
        )

        extracted_images = [
            f for f in os.listdir(output_dir)
            if os.path.isfile(os.path.join(output_dir, f))
        ]

        image_data["Image Count"] = len(extracted_images)
        image_data["Extracted To"] = output_dir if extracted_images else "None"

        if extracted_images:
            image_data["Images Extracted"] = True

    else:

        image_data["Error"] = "pdfimages Not Installed"

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
            "RunLengthDecode"
        ]

        found_filters = []

        for filter_name in compression_filters:

            if filter_name in filter_output:
                found_filters.append(
                    filter_name
                )

        if found_filters:
            compression_data[
                "Compressed Objects Found"
            ] = True

        compression_data["Filters"] = found_filters

    else:

        compression_data["Error"] = "pdf-parser Not Installed"

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

        if (
            "R =" in encryption_output or
            "P =" in encryption_output
        ):

            encryption_data["Encrypted"] = True

    else:

        encryption_data["Error"] = "qpdf Not Installed"

    results["Encryption"] = encryption_data

    # ==========================================
    # SUSPICIOUS FLAGS
    # ==========================================

    suspicious_flags = []

    if js_data["JavaScript Detected"]:

        suspicious_flags.append(
            "Embedded JavaScript Detected"
        )

    if js_data["OpenAction Found"]:

        suspicious_flags.append(
            "OpenAction Trigger Found"
        )

    if embedded_data["Embedded Files Found"]:

        suspicious_flags.append(
            "Embedded Files Detected"
        )

    if compression_data["Compressed Objects Found"]:

        suspicious_flags.append(
            "Compressed Objects Present"
        )

    if encryption_data["Encrypted"]:

        suspicious_flags.append(
            "Encrypted PDF"
        )

    if ioc_data["URLs"]:

        suspicious_flags.append(
            "URLs Found Inside PDF"
        )

    results["Suspicious Flags"] = suspicious_flags

    return results