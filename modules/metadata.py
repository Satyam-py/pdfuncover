# modules/metadata.py

import subprocess
import hashlib
import os
import shutil


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

        return result.stdout

    except Exception as e:
        return str(e)


def calculate_hash(file_path):
    """
    Calculate MD5, SHA1, SHA256 hashes.
    """

    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:

        while chunk := f.read(4096):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return {
        "MD5": md5.hexdigest(),
        "SHA1": sha1.hexdigest(),
        "SHA256": sha256.hexdigest()
    }


def parse_output(output):
    """
    Converts command output into dictionary.
    """

    data = {}

    for line in output.splitlines():

        if ":" in line:

            key, value = line.split(":", 1)

            data[key.strip()] = value.strip()

    return data


def extract_metadata(pdf_path):

    metadata = {}

    # ==========================================
    # BASIC FILE INFO
    # ==========================================

    metadata["File Name"] = os.path.basename(pdf_path)
    metadata["File Size"] = f"{os.path.getsize(pdf_path)} bytes"

    # ==========================================
    # HASHES
    # ==========================================

    hashes = calculate_hash(pdf_path)

    metadata.update(hashes)

    # ==========================================
    # PDFINFO
    # ==========================================

    if shutil.which("pdfinfo"):

        pdfinfo_output = run_command(
            ["pdfinfo", pdf_path]
        )

        pdfinfo_data = parse_output(pdfinfo_output)

        important_fields = [
            "Title",
            "Author",
            "Creator",
            "Producer",
            "CreationDate",
            "ModDate",
            "Pages",
            "Encrypted",
            "JavaScript",
            "PDF version",
            "Tagged",
            "Optimized"
        ]

        for field in important_fields:

            if field in pdfinfo_data:
                metadata[field] = pdfinfo_data[field]

    else:

        metadata["pdfinfo"] = "Not Installed"

    # ==========================================
    # EXIFTOOL
    # ==========================================

    if shutil.which("exiftool"):

        exif_output = run_command(
            ["exiftool", pdf_path]
        )

        exif_data = parse_output(exif_output)

        important_exif_fields = [
            "File Type",
            "MIME Type",
            "PDF Version",
            "Linearized",
            "Warning"
        ]

        for field in important_exif_fields:

            if field in exif_data:
                metadata[field] = exif_data[field]

    else:

        metadata["exiftool"] = "Not Installed"

    # ==========================================
    # SUSPICIOUS CHECKS
    # ==========================================

    suspicious_flags = []

    if metadata.get("JavaScript", "").lower() == "yes":
        suspicious_flags.append("Embedded JavaScript Detected")

    if metadata.get("Encrypted", "").lower() == "yes":
        suspicious_flags.append("Encrypted PDF")

    if "Warning" in metadata:
        suspicious_flags.append(metadata["Warning"])

    if not metadata.get("Author"):
        suspicious_flags.append("Missing Author Metadata")

    if not metadata.get("Creator"):
        suspicious_flags.append("Missing Creator Metadata")

    metadata["Suspicious Flags"] = suspicious_flags

    return metadata