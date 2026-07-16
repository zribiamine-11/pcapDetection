ICMP_MAX_PACKET_SIZE = 1024
ICMP_WINDOW_SIZE = 10          # seconds
ICMP_WINDOW_THRESHOLD = 100 
ICMP_SWEEP_WINDOW_SIZE = 10          # seconds
ICMP_SWEEP_THRESHOLD = 20    # Echo Requests


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

def check_excessive_icmp_echo(conversation):

    alerts = []

    # Ignore conversations without ICMP
    if "ICMP" not in conversation["protocols_seen"]:
        return alerts

    # Keep only ICMP Echo Request packets (Type 8)
    echo_packets = []

    for packet in conversation["packets"]:

        if (
            packet["protocol"] == "ICMP"
            and packet["icmp_type"] == "8"
        ):
            echo_packets.append(packet)

    if len(echo_packets) == 0:
        return alerts

    # Sliding window
    for i in range(len(echo_packets)):

        window_start = echo_packets[i]["timestamp"]
        window_end = window_start + ICMP_WINDOW_SIZE

        packet_count = 0

        for packet in echo_packets:

            if window_start <= packet["timestamp"] <= window_end:
                packet_count += 1

        if packet_count > ICMP_WINDOW_THRESHOLD:

            alerts.append({

                "rule_id": "ICMP-002",

                "severity": "High",

                "title": "Excessive ICMP Echo Requests",

                "description": (
                    f"{packet_count} ICMP Echo Request packets were detected "
                    f"within {ICMP_WINDOW_SIZE} seconds between "
                    f"{conversation['ip_a']} and {conversation['ip_b']}."
                )

            })

            break

    return alerts




def check_icmp_ping_sweep(conversations):

    alerts = []

    # Store every ICMP Echo Request in the capture
    echo_requests = []

    # Iterate over all conversations
    for conversation in conversations:

        # Ignore conversations without ICMP
        if "ICMP" not in conversation["protocols_seen"]:
            continue

        # Keep only ICMP Echo Requests
        for packet in conversation["packets"]:

            if (
                packet["protocol"] == "ICMP"
                and packet["icmp_type"] == "8"
            ):

                echo_requests.append({

                    "src_ip": packet["src_ip"],

                    "dst_ip": packet["dst_ip"],

                    "timestamp": packet["timestamp"]

                })

    if len(echo_requests) == 0:
        return alerts


    # -------------------------------------------------
    # Group Echo Requests by source IP
    # -------------------------------------------------

    grouped = {}

    for packet in echo_requests:

        src = packet["src_ip"]

        if src not in grouped:
            grouped[src] = []

        grouped[src].append(packet)


    # -------------------------------------------------
    # Analyze each source independently
    # -------------------------------------------------

    for src_ip, packets in grouped.items():

        # Sort by timestamp
        packets.sort(key=lambda p: p["timestamp"])

        # Sliding window
        for i in range(len(packets)):

            window_start = packets[i]["timestamp"]
            window_end = window_start + ICMP_SWEEP_WINDOW_SIZE

            # Unique destination IPs
            destinations = set()

            for packet in packets:

                if window_start <= packet["timestamp"] <= window_end:

                    destinations.add(packet["dst_ip"])

            if len(destinations) > ICMP_SWEEP_THRESHOLD:

                alerts.append({

                    "rule_id": "ICMP-003",

                    "severity": "High",

                    "title": "ICMP Ping Sweep Detected",

                    "description": (
                        f"Host {src_ip} sent ICMP Echo Requests "
                        f"to {len(destinations)} different destination IPs "
                        f"within {ICMP_SWEEP_WINDOW_SIZE} seconds."
                    )

                })

                break

    return alerts