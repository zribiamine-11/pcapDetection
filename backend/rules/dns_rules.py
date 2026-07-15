DNS_MAX_PACKET_SIZE = 4096
DNS_WINDOW_SIZE = 10
DNS_WINDOW_THRESHOLD = 100


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

def check_dns_window_rules(conversation):

    alerts = []

    # Ignore non-DNS conversations
    if "DNS" not in conversation["protocols_seen"]:
        return alerts

    # Keep only DNS packets
    dns_packets = []

    for packet in conversation["packets"]:

        if packet["protocol"] == "DNS":
            dns_packets.append(packet)

    if len(dns_packets) == 0:
        return alerts

    # Sliding window
    for i in range(len(dns_packets)):

        window_start = dns_packets[i]["timestamp"]
        window_end = window_start + DNS_WINDOW_SIZE

        packet_count = 0

        for packet in dns_packets:

            if window_start <= packet["timestamp"] <= window_end:
                packet_count += 1

        if packet_count > DNS_WINDOW_THRESHOLD:

            alerts.append({

                "rule_id": "DNS-003",

                "severity": "High",

                "title": "High DNS Query Rate",

                "description": (
                    f"{packet_count} DNS packets were detected "
                    f"within {DNS_WINDOW_SIZE} seconds between "
                    f"{conversation['ip_a']} and {conversation['ip_b']}."
                )

            })

            break

    return alerts