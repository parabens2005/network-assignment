import ipaddress
from datetime import datetime, timezone

import requests


RIPESTAT_API = "https://stat.ripe.net/data/network-info/data.json"


def investigate_ip(ip_address):
    """Retrieve public routing information for a global IP address."""

    try:
        ip = ipaddress.ip_address(ip_address)
    except ValueError:
        return {
            "status": "invalid",
            "message": "Invalid IP address."
        }

    if not ip.is_global:
        return {
            "status": "not_queried",
            "message": "Non-global IP addresses are not sent to external providers.",
            "verdict": "unknown"
        }

    timestamp = datetime.now(timezone.utc).isoformat()

    try:
        response = requests.get(
            RIPESTAT_API,
            params={"resource": str(ip)},
            timeout=8
        )
        response.raise_for_status()

        payload = response.json()

        if payload.get("status") != "ok":
            return {
                "status": "unavailable",
                "message": "The intelligence provider did not return a successful result.",
                "verdict": "unknown"
            }

        data = payload.get("data") or {}

        return {
            "status": "completed",
            "indicator": str(ip),
            "network": {
                "prefix": data.get("prefix"),
                "asns": data.get("asns", [])
            },
            "source": {
                "provider": "RIPEstat",
                "endpoint": RIPESTAT_API
            },
            "queried_at_utc": timestamp,
            "verdict": "unknown",
            "message": (
                "Public network routing metadata retrieved. "
                "This information does not establish whether the IP is malicious."
            )
        }

    except (requests.RequestException, ValueError, TypeError):
        return {
            "status": "unavailable",
            "message": "Network intelligence could not be retrieved.",
            "verdict": "unknown"
        }


GOOGLE_DNS_API = "https://dns.google/resolve"

DNS_RECORD_TYPES = {
    "A": 1,
    "AAAA": 28,
    "MX": 15
}


def investigate_domain(domain):
    """Retrieve DNS records using Google's public DNS API."""

    import re

    if (
        not isinstance(domain, str)
        or len(domain) > 253
        or not re.fullmatch(
            r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}",
            domain
        )
    ):
        return {
            "status": "invalid",
            "message": "Invalid domain name.",
            "verdict": "unknown"
        }

    domain = domain.lower()
    records = {"A": [], "AAAA": [], "MX": []}
    errors = []

    for record_name, record_type in DNS_RECORD_TYPES.items():
        try:
            response = requests.get(
                GOOGLE_DNS_API,
                params={
                    "name": domain,
                    "type": record_type
                },
                timeout=8
            )
            response.raise_for_status()

            payload = response.json()

            if payload.get("Status") != 0:
                errors.append(
                    f"{record_name}: DNS response status {payload.get('Status')}"
                )
                continue

            for answer in payload.get("Answer", []):
                if answer.get("type") == record_type:
                    records[record_name].append(answer.get("data"))

        except (requests.RequestException, ValueError, TypeError):
            errors.append(f"{record_name}: lookup unavailable")

    completed = len(errors) == 0

    return {
        "status": "completed" if completed else "partial",
        "indicator": domain,
        "dns": records,
        "errors": errors,
        "source": {
            "provider": "Google Public DNS",
            "endpoint": GOOGLE_DNS_API
        },
        "queried_at_utc": datetime.now(timezone.utc).isoformat(),
        "verdict": "unknown",
        "message": (
            "DNS information retrieved. DNS records do not establish "
            "whether a domain is malicious."
            if completed
            else "Some DNS lookups were unsuccessful. Results may be incomplete."
        )
    }


def investigate_hash(sha256):
    """Retrieve an existing VirusTotal file report by SHA-256 hash."""

    import os
    import re

    if not isinstance(sha256, str) or not re.fullmatch(
        r"[a-fA-F0-9]{64}", sha256
    ):
        return {
            "status": "invalid",
            "verdict": "unknown",
            "message": "Invalid SHA-256 hash."
        }

    sha256 = sha256.lower()
    api_key = os.environ.get("VIRUSTOTAL_API_KEY")

    if not api_key:
        return {
            "status": "not_configured",
            "indicator": sha256,
            "verdict": "unknown",
            "message": (
                "VirusTotal API key is not configured. "
                "The hash format was validated, but reputation was not checked."
            )
        }

    endpoint = f"https://www.virustotal.com/api/v3/files/{sha256}"

    try:
        response = requests.get(
            endpoint,
            headers={"x-apikey": api_key},
            timeout=10
        )

        if response.status_code == 404:
            return {
                "status": "not_found",
                "indicator": sha256,
                "verdict": "unknown",
                "message": "No existing VirusTotal report was found for this hash."
            }

        if response.status_code == 429:
            return {
                "status": "rate_limited",
                "indicator": sha256,
                "verdict": "unknown",
                "message": "VirusTotal API rate limit reached."
            }

        response.raise_for_status()

        payload = response.json()
        attributes = payload.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        return {
            "status": "completed",
            "indicator": sha256,
            "reputation": {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0)
            },
            "source": {
                "provider": "VirusTotal",
                "report_url": f"https://www.virustotal.com/gui/file/{sha256}"
            },
            "queried_at_utc": datetime.now(timezone.utc).isoformat(),
            "verdict": "unknown",
            "message": (
                "VirusTotal analysis statistics retrieved. "
                "Detection counts are third-party assessments, "
                "not definitive proof of maliciousness or safety."
            )
        }

    except (requests.RequestException, ValueError, TypeError, AttributeError):
        return {
            "status": "unavailable",
            "indicator": sha256,
            "verdict": "unknown",
            "message": "VirusTotal intelligence could not be retrieved."
        }
