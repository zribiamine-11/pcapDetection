def check_tcp_rules(conversation):
    """
    Analyze TCP conversation-level rules.

    Checks:
    - TCP 3-way handshake completion
    """

    alerts = []


    handshake = conversation.get("handshake")


    # No TCP in this conversation
    if not handshake or not handshake.get("has_tcp"):
        return alerts


    streams = handshake.get("streams", {})


    for stream_id, stream in streams.items():

        if not stream["completed"]:

            if (
                stream["syn_seen"]
                and not stream["syn_ack_seen"]
            ):
                reason = (
                    "SYN packet was observed "
                    "but no SYN-ACK response was received."
                )


            elif (
                stream["syn_seen"]
                and stream["syn_ack_seen"]
                and not stream["ack_seen"]
            ):
                reason = (
                    "SYN-ACK response was observed "
                    "but final ACK was not received."
                )


            else:
                reason = (
                    "TCP 3-way handshake was not completed."
                )


            alerts.append({

                "rule_id": "TCP-001",

                "severity": "Medium",

                "title": "Incomplete TCP Handshake",

                "description": (
                    f"TCP stream {stream_id}: {reason}"
                ),

                "stream_id": stream_id,

                "syn_seen": stream["syn_seen"],

                "syn_ack_seen": stream["syn_ack_seen"],

                "ack_seen": stream["ack_seen"]

            })


    return alerts

def check_tcp_null_scan(packet):

    alerts = []

    if packet.get("protocol") != "TCP":
        return alerts

    # TCP packet with no flags set
    if (
        packet.get("tcp_syn") is False
        and packet.get("tcp_ack") is False
        and packet.get("tcp_fin") is False
        and packet.get("tcp_rst") is False
        and packet.get("tcp_psh") is False
        and packet.get("tcp_urg") is False
    ):
        alerts.append({
            "rule_id": "TCP-002",
            "severity": "Medium",
            "message": "TCP NULL Scan detected.",
            "description": (
                "A TCP packet with no flags set was detected. "
                "This behavior is commonly associated with Nmap NULL scans."
            )
        })

    return alerts

def check_tcp_scan_rules(conversation):

    alerts = []

    tcp_packets = [
        p for p in conversation["packets"]
        if p.get("protocol") == "TCP"
    ]

    if not tcp_packets:
        return alerts


    # Group packets by TCP stream
    streams = {}

    for packet in tcp_packets:

        stream_id = packet.get("tcp_stream")

        if stream_id is None:
            continue

        if stream_id not in streams:
            streams[stream_id] = []

        streams[stream_id].append(packet)


    # Analyze each TCP stream
    for stream_id, packets in streams.items():

        # Sort by time
        packets.sort(key=lambda x: x["timestamp"])

        first_packet = packets[0]


        # Ignore normal TCP connections
        if first_packet.get("tcp_syn"):
            continue


        # FIN Scan
        if (
            first_packet.get("tcp_fin")
            and not first_packet.get("tcp_psh")
            and not first_packet.get("tcp_urg")
            and not first_packet.get("tcp_rst")
            and not first_packet.get("tcp_ack")
        ):
            alerts.append({
                "rule_id": "TCP-003",
                "severity": "Medium",
                "message": "TCP FIN Scan detected.",
                "description": (
                    f"TCP stream {stream_id} started with a FIN packet "
                    "without a SYN handshake."
                )
            })


        # Xmas Scan
        elif (
            first_packet.get("tcp_fin")
            and first_packet.get("tcp_psh")
            and first_packet.get("tcp_urg")
            and not first_packet.get("tcp_syn")
        ):
            alerts.append({
                "rule_id": "TCP-004",
                "severity": "Medium",
                "message": "TCP Xmas Scan detected.",
                "description": (
                    f"TCP stream {stream_id} started with FIN+PSH+URG "
                    "flags without a SYN handshake."
                )
            })


    return alerts