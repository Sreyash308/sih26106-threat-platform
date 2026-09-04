"""
Attachment Forensic Analyzer.
Calculates deterministic cryptographic hashes (SHA-256, SHA-1, MD5),
detects dangerous extensions, macro-enabled files, double extensions, and MIME discrepancies
without executing or unpacking untrusted binaries.
"""
import os
import mimetypes
from typing import List, Dict, Any

from ..utils.security import (
    calculate_hashes,
    detect_double_extension,
    DANGEROUS_EXTENSIONS,
    MACRO_EXTENSIONS,
    SUSPICIOUS_ARCHIVE_EXTENSIONS,
)
from ..schemas.analysis import AttachmentItem


class AttachmentAnalyzer:
    """Forensic attachment parser and signature analyzer."""

    def __init__(self, raw_attachments: List[Dict[str, Any]]):
        self.attachments = raw_attachments

    def analyze(self) -> List[AttachmentItem]:
        """Inspects all extracted email attachments."""
        results: List[AttachmentItem] = []

        for att in self.attachments:
            filename = att.get("filename", "unnamed_attachment")
            data = att.get("data", b"")
            declared_mime = att.get("content_type", "application/octet-stream")
            size_bytes = len(data)

            # Cryptographic Hashes
            hashes = calculate_hashes(data)

            # Extension analysis
            _, ext = os.path.splitext(filename.lower())

            # Double extension detection (e.g. invoice.pdf.exe)
            has_double_ext = detect_double_extension(filename)

            # Dangerous executable check
            is_dangerous_exec = ext in DANGEROUS_EXTENSIONS

            # Macro-enabled document check
            is_macro = ext in MACRO_EXTENSIONS

            # Suspicious archive check
            is_suspicious_archive = ext in SUSPICIOUS_ARCHIVE_EXTENSIONS

            # MIME mismatch detection
            expected_mime, _ = mimetypes.guess_type(filename)
            mime_mismatch = False
            if expected_mime and declared_mime:
                # If declared as image or pdf, but extension is binary or executable
                if ("pdf" in declared_mime and ext != ".pdf") or ("image" in declared_mime and ext in DANGEROUS_EXTENSIONS):
                    mime_mismatch = True

            # Risk calculation
            risk_reasons: List[str] = []
            suspicious = False

            if is_dangerous_exec:
                suspicious = True
                risk_reasons.append(f"High-risk executable extension ({ext})")
            if has_double_ext:
                suspicious = True
                risk_reasons.append(f"Deceptive double-extension detected ({filename})")
            if is_macro:
                suspicious = True
                risk_reasons.append(f"Macro-enabled Office document ({ext}) — vector for malicious VBA payloads")
            if is_suspicious_archive:
                suspicious = True
                risk_reasons.append(f"Compressed archive container ({ext}) frequently used to bypass email security gateways")
            if mime_mismatch:
                suspicious = True
                risk_reasons.append(f"MIME mismatch: Header declares '{declared_mime}', but extension indicates '{ext}'")

            if is_dangerous_exec or has_double_ext:
                risk_level = "CRITICAL"
            elif is_macro:
                risk_level = "HIGH"
            elif is_suspicious_archive or mime_mismatch:
                risk_level = "MEDIUM"
            else:
                risk_level = "SAFE"

            reason = "; ".join(risk_reasons) if risk_reasons else "Standard document format, no heuristic anomalies detected"

            results.append(AttachmentItem(
                filename=filename,
                extension=ext or "none",
                mime_type=declared_mime,
                size_bytes=size_bytes,
                sha256=hashes["sha256"],
                sha1=hashes["sha1"],
                md5=hashes["md5"],
                suspicious=suspicious,
                risk_level=risk_level,
                reason=reason,
                double_extension=has_double_ext,
                macro_enabled=is_macro,
                dangerous_executable=is_dangerous_exec
            ))

        return results
