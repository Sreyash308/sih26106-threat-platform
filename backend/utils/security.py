"""
Security utilities: HTML sanitization, hashing, path validation, and SSRF prevention.
Never executes untrusted content or visits arbitrary remote endpoints.
"""
import re
import hashlib
import os
import html
from typing import Dict, Any, Optional
from bs4 import BeautifulSoup

# Dangerous extensions that warrant immediate high-risk alerts
DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".pif", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
    ".ps1", ".psm1", ".bat", ".cmd", ".com", ".cpl", ".hta", ".iso", ".img",
    ".jar", ".msi", ".msp", ".reg", ".dll", ".sys", ".drv"
}

MACRO_EXTENSIONS = {
    ".docm", ".dotm", ".xlsm", ".xltm", ".xlam", ".pptm", ".potm", ".ppam", ".ppsm", ".sldm"
}

SUSPICIOUS_ARCHIVE_EXTENSIONS = {
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".iso", ".img", ".cab"
}

# Dangerous HTML tags and attributes for sanitization
DISALLOWED_TAGS = {
    "script", "iframe", "object", "embed", "applet", "form", "input",
    "button", "textarea", "select", "option", "base", "link", "meta",
    "frame", "frameset"
}

DANGEROUS_ATTRIBUTES = {
    "onload", "onerror", "onclick", "onmouseover", "onfocus", "onblur",
    "onchange", "onsubmit", "onreset", "onkeydown", "onkeypress", "onkeyup",
    "formaction", "action", "data", "dynsrc", "lowsrc"
}


def sanitize_email_html(raw_html: str) -> str:
    """
    Sanitizes untrusted email HTML for secure analyst preview.
    Strips scripts, iframes, executable elements, event handlers, and data/javascript URIs.
    """
    if not raw_html or not raw_html.strip():
        return "<p class='text-slate-400 italic'>No HTML body present in email.</p>"

    try:
        soup = BeautifulSoup(raw_html, "html.parser")

        # Strip disallowed dangerous tags completely
        for tag in soup.find_all(DISALLOWED_TAGS):
            tag.decompose()

        # Clean all remaining tags
        for tag in soup.find_all(True):
            attrs = dict(tag.attrs)
            for attr_name, attr_value in attrs.items():
                lower_attr = attr_name.lower()

                # Remove JavaScript event handlers
                if lower_attr.startswith("on") or lower_attr in DANGEROUS_ATTRIBUTES:
                    del tag.attrs[attr_name]
                    continue

                # Inspect URI attributes (href, src)
                if lower_attr in ("href", "src", "xlink:href"):
                    val_str = str(attr_value).strip().lower()
                    if val_str.startswith("javascript:") or val_str.startswith("vbscript:"):
                        del tag.attrs[attr_name]
                    elif val_str.startswith("data:") and not val_str.startswith("data:image/"):
                        del tag.attrs[attr_name]

            # Neutralize target attribute to prevent window hijacking
            if tag.name == "a":
                tag.attrs["target"] = "_blank"
                tag.attrs["rel"] = "noopener noreferrer nofollow"

        return str(soup)
    except Exception as e:
        # Fallback to escaped HTML if parsing fails
        return f"<pre class='text-xs text-slate-300'>{html.escape(raw_html)}</pre>"


def calculate_hashes(data: bytes) -> Dict[str, str]:
    """
    Computes deterministic SHA-256, SHA-1, and MD5 hashes for binary payloads.
    """
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),
    }


def sanitize_filename(filename: Optional[str]) -> str:
    """
    Strips directory traversal characters and unsafe characters from filenames.
    """
    if not filename:
        return "unnamed_attachment"
    
    # Strip path separators
    cleaned = os.path.basename(filename.strip().replace("\\", "/"))
    # Remove null bytes and non-printable chars
    cleaned = re.sub(r'[\x00-\x1f\x7f]', '', cleaned)
    # Avoid empty string after cleaning
    return cleaned if cleaned else "attachment"


def detect_double_extension(filename: str) -> bool:
    """
    Detects deceptive double extensions, e.g., 'invoice.pdf.exe' or 'document.docx.vbs'.
    """
    parts = filename.lower().split(".")
    if len(parts) >= 3:
        last_ext = "." + parts[-1]
        second_last_ext = "." + parts[-2]
        common_doc_exts = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".csv", ".jpg", ".png"}
        if last_ext in DANGEROUS_EXTENSIONS and second_last_ext in common_doc_exts:
            return True
    return False
