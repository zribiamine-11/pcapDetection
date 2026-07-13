DNS_MAX_PACKET_SIZE = 4096


def check_dns_rules(packet):

    alerts = []

    if packet["protocol"] != "DNS":
        return alerts


    # DNS-001: Oversized DNS packet
    if packet["length"] > DNS_MAX_PACKET_SIZE:

        alerts.append({

            "rule_id": "DNS-001",

            "severity": "Medium",

            "title": "Oversized DNS Packet",

            "description": (
                f"DNS packet length ({packet['length']} bytes) "
                f"exceeds the expected maximum of "
                f"{DNS_MAX_PACKET_SIZE} bytes."
            )

        })


    # DNS-002: DNS traffic on non-standard port
    if packet["default_port"] is False:

        alerts.append({

            "rule_id": "DNS-002",

            "severity": "Medium",

            "title": "DNS Non Default Port",

            "description": (
                f"DNS traffic detected on "
                f"non standard port {packet['dst_port']}."
            )

        })


    return alerts