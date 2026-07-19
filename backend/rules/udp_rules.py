UDP_FLOOD_WINDOW = 10
UDP_FLOOD_THRESHOLD = 500

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