UDP_FLOOD_WINDOW = 10
UDP_FLOOD_THRESHOLD = 500
UDP_PORT_SCAN_THRESHOLD = 20
UDP_MAX_PACKET_SIZE = 4096

def check_udp_rules(packet):

    alerts = []

    if packet["protocol"] != "UDP":
        return alerts

    if packet["length"] > UDP_MAX_PACKET_SIZE:

        alerts.append({

            "rule_id": "UDP-001",

            "severity": "Medium",

            "title": "Oversized UDP Packet",

            "description": (
                f"UDP packet size ({packet['length']} bytes) "
                f"exceeds the allowed limit "
                f"({UDP_MAX_PACKET_SIZE} bytes)."
            )

        })

    return alerts


def check_udp_flood(conversation):

    alerts = []

    # Ignore non-UDP conversations
    if "UDP" not in conversation["protocols_seen"]:
        return alerts

    # Keep only UDP packets
    udp_packets = []

    for packet in conversation["packets"]:

        if packet["protocol"] == "UDP":
            udp_packets.append(packet)

    if len(udp_packets) == 0:
        return alerts

    # Sliding window
    for i in range(len(udp_packets)):

        window_start = udp_packets[i]["timestamp"]
        window_end = window_start + UDP_FLOOD_WINDOW

        packet_count = 0

        for packet in udp_packets:

            if window_start <= packet["timestamp"] <= window_end:
                packet_count += 1

        if packet_count > UDP_FLOOD_THRESHOLD:

            alerts.append({

                "rule_id": "UDP-002",

                "severity": "High",

                "title": "UDP Flood Detected",

                "description": (
                    f"{packet_count} UDP packets were detected "
                    f"within {UDP_FLOOD_WINDOW} seconds between "
                    f"{conversation['ip_a']} and {conversation['ip_b']}."
                )

            })

            break

    return alerts

def check_udp_port_scan(conversation):

    alerts = []

    # Ignore non-UDP conversations
    if "UDP" not in conversation["protocols_seen"]:
        return alerts

    destination_ports = set()

    for packet in conversation["packets"]:

        if packet["protocol"] == "UDP":

            dst_port = packet.get("dst_port")

            if dst_port is not None:
                destination_ports.add(dst_port)

    if len(destination_ports) > UDP_PORT_SCAN_THRESHOLD:

        alerts.append({

            "rule_id": "UDP-003",

            "severity": "High",

            "title": "UDP Port Scan Detected",

            "description": (
                f"{conversation['ip_a']} scanned "
                f"{len(destination_ports)} different UDP destination ports "
                f"on {conversation['ip_b']}."
            )

        })

    return alerts