import ipaddress
import re


def validate_indicator(value, indicator_type):
    if not isinstance(value, str):
        return {
            "valid": False,
            "reason": "Indicator must be a string."
        }

    value = value.strip()

    if not value:
        return {
            "valid": False,
            "reason": "Indicator cannot be empty."
        }

    if indicator_type == "ip":
        try:
            address = ipaddress.ip_address(value)
            return {
                "valid": True,
                "type": "ip",
                "value": str(address),
                "version": address.version,
                "public": address.is_global
            }
        except ValueError:
            return {
                "valid": False,
                "reason": "Invalid IP address."
            }

    if indicator_type == "domain":
        if len(value) > 253:
            return {
                "valid": False,
                "reason": "Domain is too long."
            }

        labels = value.rstrip(".").split(".")

        label_pattern = re.compile(
            r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
        )

        if (
            len(labels) < 2
            or not all(label_pattern.fullmatch(label) for label in labels)
            or labels[-1].isdigit()
        ):
            return {
                "valid": False,
                "reason": "Invalid domain format."
            }

        return {
            "valid": True,
            "type": "domain",
            "value": value.rstrip(".").lower()
        }

    if indicator_type == "sha256":
        if not re.fullmatch(r"[a-fA-F0-9]{64}", value):
            return {
                "valid": False,
                "reason": "SHA-256 must contain exactly 64 hexadecimal characters."
            }

        return {
            "valid": True,
            "type": "sha256",
            "value": value.lower()
        }

    return {
        "valid": False,
        "reason": "Unsupported indicator type."
    }
