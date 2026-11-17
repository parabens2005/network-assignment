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
