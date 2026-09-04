"""
Forensic Email Parser: Parses RFC 2822/5322 and MIME emails.
Extracts all headers, decoded metadata, plain-text body, sanitized HTML,
and attachments without executing untrusted data.
"""
import email
from email import policy
from email.message import EmailMessage
from typing import Dict, Any, List, Optional, Tuple

from ..utils.security import sanitize_email_html, sanitize_filename
from ..utils.helpers import decode_rfc2047, normalize_date


class EmailParser:
    """Robust forensic parser for raw email files and strings."""

    def __init__(self, raw_input: bytes | str):
        if isinstance(raw_input, str):
            self.raw_bytes = raw_input.encode("utf-8", errors="replace")
        else:
            self.raw_bytes = raw_input

    def parse(self) -> Dict[str, Any]:
        """Parses the email and returns a comprehensive structured forensic dict."""
        try:
            msg: EmailMessage = email.message_from_bytes(self.raw_bytes, policy=policy.default)
        except Exception:
            # Fallback to compat32 policy if default policy fails on corrupted MIME
            msg = email.message_from_bytes(self.raw_bytes, policy=policy.compat32)

        # 1. Extract and preserve raw headers
        raw_headers_list: List[Tuple[str, str]] = []
        headers_dict: Dict[str, List[str]] = {}
        raw_headers_str_lines: List[str] = []

        for key, val in msg.items():
            decoded_val = decode_rfc2047(str(val))
            raw_headers_list.append((key, decoded_val))
            raw_headers_str_lines.append(f"{key}: {decoded_val}")
            k_lower = key.lower()
            if k_lower not in headers_dict:
                headers_dict[k_lower] = []
            headers_dict[k_lower].append(decoded_val)

        raw_headers_str = "\n".join(raw_headers_str_lines)

        # 2. Extract standard identity headers
        subject = decode_rfc2047(msg.get("Subject", "(No Subject)"))
        from_hdr = decode_rfc2047(msg.get("From", ""))
        to_hdr = decode_rfc2047(msg.get("To", ""))
        cc_hdr = decode_rfc2047(msg.get("Cc", ""))
        bcc_hdr = decode_rfc2047(msg.get("Bcc", ""))
        reply_to_hdr = decode_rfc2047(msg.get("Reply-To", ""))
        return_path_hdr = decode_rfc2047(msg.get("Return-Path", ""))
        sender_hdr = decode_rfc2047(msg.get("Sender", ""))
        date_hdr = decode_rfc2047(msg.get("Date", ""))
        message_id = decode_rfc2047(msg.get("Message-ID", ""))
        content_type = decode_rfc2047(msg.get("Content-Type", ""))
        user_agent = decode_rfc2047(msg.get("User-Agent", msg.get("X-Mailer", "")))

        # 3. Walk message parts to extract text, HTML, and attachments
        plain_text_parts: List[str] = []
        html_parts: List[str] = []
        raw_attachments: List[Dict[str, Any]] = []

        if msg.is_multipart():
            for part in msg.walk():
                # Skip container multipart items
                if part.is_multipart():
                    continue

                fn = part.get_filename()
                cd = str(part.get("Content-Disposition", ""))
                is_attachment = bool(fn) or ("attachment" in cd.lower())

                if is_attachment:
                    try:
                        payload = part.get_payload(decode=True)
                        if payload is None:
                            payload = b""
                        raw_attachments.append({
                            "filename": sanitize_filename(fn or "unnamed_attachment"),
                            "content_type": part.get_content_type(),
                            "data": payload,
                            "size": len(payload)
                        })
                    except Exception as e:
                        raw_attachments.append({
                            "filename": sanitize_filename(fn or "malformed_attachment"),
                            "content_type": part.get_content_type(),
                            "data": b"",
                            "size": 0,
                            "error": f"Failed to decode attachment: {str(e)}"
                        })
                else:
                    ctype = part.get_content_type()
                    try:
                        charset = part.get_content_charset() or "utf-8"
                        payload = part.get_payload(decode=True)
                        if payload:
                            text_content = payload.decode(charset, errors="replace")
                            if ctype == "text/plain":
                                plain_text_parts.append(text_content)
                            elif ctype == "text/html":
                                html_parts.append(text_content)
                    except Exception:
                        pass
        else:
            # Single-part message
            ctype = msg.get_content_type()
            try:
                charset = msg.get_content_charset() or "utf-8"
                payload = msg.get_payload(decode=True)
                if payload:
                    text_content = payload.decode(charset, errors="replace")
                    if ctype == "text/html":
                        html_parts.append(text_content)
                    else:
                        plain_text_parts.append(text_content)
            except Exception:
                text_content = str(msg.get_payload() or "")
                plain_text_parts.append(text_content)

        raw_plain_text = "\n\n".join(plain_text_parts).strip()
        raw_html = "\n\n".join(html_parts).strip()
        sanitized_html = sanitize_email_html(raw_html) if raw_html else ""

        # If no plain text extracted, create a text representation from HTML if available
        if not raw_plain_text and raw_html:
            from bs4 import BeautifulSoup
            try:
                soup = BeautifulSoup(raw_html, "html.parser")
                raw_plain_text = soup.get_text(separator="\n").strip()
            except Exception:
                raw_plain_text = ""

        return {
            "metadata": {
                "subject": subject,
                "from": from_hdr,
                "to": to_hdr,
                "cc": cc_hdr,
                "bcc": bcc_hdr,
                "reply_to": reply_to_hdr,
                "return_path": return_path_hdr,
                "sender": sender_hdr,
                "date": date_hdr,
                "normalized_date": normalize_date(date_hdr),
                "message_id": message_id,
                "content_type": content_type,
                "user_agent": user_agent,
            },
            "headers_dict": headers_dict,
            "raw_headers_list": raw_headers_list,
            "raw_headers_str": raw_headers_str,
            "plain_text": raw_plain_text,
            "raw_html": raw_html,
            "sanitized_html": sanitized_html,
            "raw_attachments": raw_attachments,
        }
