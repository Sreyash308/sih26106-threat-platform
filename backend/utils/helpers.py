"""
Helper utilities: RFC 2047 header decoding, IP address classification,
distance calculation, and date normalization.
"""
import ipaddress
import math
from typing import Dict, Any, Optional, Tuple
from email.header import decode_header, make_header
from dateutil import parser as date_parser


def decode_rfc2047(header_value: Optional[str]) -> str:
    """
    Decodes RFC 2047 encoded email headers (e.g. '=?UTF-8?B?...?=').
    Safely handles malformed strings and multiple encoding blocks.
    """
    if not header_value:
        return ""
    try:
        decoded_chunks = decode_header(header_value)
        parts = []
        for chunk, encoding in decoded_chunks:
            if isinstance(chunk, bytes):
                enc = encoding or "utf-8"
                try:
                    parts.append(chunk.decode(enc, errors="replace"))
                except (LookupError, UnicodeDecodeError):
                    parts.append(chunk.decode("latin-1", errors="replace"))
            else:
                parts.append(str(chunk))
        return " ".join(parts).strip()
    except Exception:
        # Fallback to string representation if header parser fails
        return str(header_value).strip()


def classify_ip(ip_str: str) -> Dict[str, Any]:
    """
    Classifies an IP address into forensic categories:
    - public
    - private (RFC 1918)
    - loopback (RFC 1122 / 4291)
    - cgnat (RFC 6598)
    - multicast (RFC 5771 / 4291)
    - reserved (RFC 1112 / 6890)
    - documentation (RFC 5737 / 3849 - test nets 192.0.2.0/24, etc.)
    - link_local (RFC 3927)
    - invalid
    """
    if not ip_str:
        return {"ip": "", "version": 0, "type": "invalid", "is_public": False, "description": "Empty IP"}

    clean_ip = ip_str.strip().strip("[]").split(":")[0] if ("." in ip_str and ":" in ip_str and not ip_str.startswith("[")) else ip_str.strip().strip("[]")

    try:
        ip_obj = ipaddress.ip_address(clean_ip)
    except ValueError:
        return {"ip": ip_str, "version": 0, "type": "invalid", "is_public": False, "description": "Unparseable IP format"}

    version = ip_obj.version

    # Documentation / Test IPs (RFC 5737 / RFC 3849)
    doc_ranges = [
        ipaddress.ip_network("192.0.2.0/24"),
        ipaddress.ip_network("198.51.100.0/24"),
        ipaddress.ip_network("203.0.113.0/24"),
        ipaddress.ip_network("2001:db8::/32")
    ]
    is_doc = any(ip_obj in net for net in doc_ranges if net.version == version)

    if is_doc:
        ip_type = "documentation"
        is_public = False
        desc = "RFC 5737/3849 Test & Documentation Net (Synthetic/Demo)"
    elif ip_obj.is_loopback:
        ip_type = "loopback"
        is_public = False
        desc = "Loopback address (localhost)"
    elif ip_obj.is_private:
        ip_type = "private"
        is_public = False
        desc = "RFC 1918 Private Internal Network"
    elif ip_obj.is_link_local:
        ip_type = "link_local"
        is_public = False
        desc = "RFC 3927 Link-Local address"
    elif ip_obj.is_multicast:
        ip_type = "multicast"
        is_public = False
        desc = "Multicast address"
    elif ip_obj.is_reserved:
        ip_type = "reserved"
        is_public = False
        desc = "IETF Reserved address"
    elif version == 4 and ip_obj in ipaddress.ip_network("100.64.0.0/10"):
        ip_type = "cgnat"
        is_public = False
        desc = "RFC 6598 Carrier-Grade NAT"
    else:
        ip_type = "public"
        is_public = True
        desc = "Routable Public Internet Address"

    return {
        "ip": str(ip_obj),
        "version": version,
        "type": ip_type,
        "is_public": is_public,
        "description": desc
    }


def calculate_haversine_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """
    Computes approximate great-circle distance between two geographic coordinates in kilometers.
    """
    R = 6371.0  # Earth's mean radius in km
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = math.sin(dlat / 2.0) ** 2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2.0) ** 2
    c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
    return round(R * c, 2)


def normalize_date(date_str: Optional[str]) -> Optional[str]:
    """
    Normalizes RFC 2822 / ISO date strings into standard ISO 8601 UTC string.
    """
    if not date_str:
        return None
    try:
        dt = date_parser.parse(date_str)
        return dt.isoformat()
    except Exception:
        return date_str.strip()
