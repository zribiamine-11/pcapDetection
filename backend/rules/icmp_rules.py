ICMP_MAX_PACKET_SIZE = 10


def check_icmp_rules(packet):
    alerts = []

    if packet["protocol"] != "ICMP":
        return alerts

    if packet["length"] > ICMP_MAX_PACKET_SIZE:

        alerts.append({

            "rule_id": "ICMP-001",

            "severity": "Medium",

            "title": "Oversized ICMP Packet",

            "description": (
                f"ICMP packet length ({packet['length']} bytes) "
                f"exceeds the expected maximum of "
                f"{ICMP_MAX_PACKET_SIZE} bytes."
            ),

           

        })

    return alerts