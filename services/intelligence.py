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
