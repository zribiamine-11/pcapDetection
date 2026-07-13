SSH_MAX_CONNECTIONS = 3
SSH_TIME_WINDOW = 60  # seconds


# ---------------------------------------------------------------------------
# Packet-level SSH rules
# ---------------------------------------------------------------------------
def check_ssh_rules(packet):

    alerts = []

    if packet["protocol"] != "SSH":
        return alerts

    # SSH-001: Non-default port
    if packet["default_port"] is False:

        alerts.append({

            "rule_id": "SSH-001",

            "severity": "Low",

            "title": "SSH Non Default Port",

            "description": (
                f"SSH traffic detected on "
                f"non standard port {packet['dst_port']}."
            )

        })

    return alerts


# ---------------------------------------------------------------------------
# Conversation-level SSH rules
# ---------------------------------------------------------------------------
def check_ssh_bruteforce(conversation):

    alerts = []

    packets = conversation["packets"]

    # Keep only SSH packets
    ssh_packets = [
        p for p in packets
        if p["protocol"] == "SSH"
    ]

    if not ssh_packets:
        return alerts

    # Count unique TCP streams (each stream = one SSH connection)
    streams = set()

    timestamps = []

    for packet in ssh_packets:

        if packet["tcp_stream"] is not None:
            streams.add(packet["tcp_stream"])

        if packet["timestamp"] is not None:
            timestamps.append(packet["timestamp"])

    if not timestamps:
        return alerts

    connection_count = len(streams)

    duration = max(timestamps) - min(timestamps)

    if (
        connection_count > SSH_MAX_CONNECTIONS
        and duration <= SSH_TIME_WINDOW
    ):

        alerts.append({

            "rule_id": "SSH-002",

            "severity": "High",

            "title": "Possible SSH Brute Force",

            "description": (
                f"{connection_count} SSH connections were "
                f"detected within {duration:.2f} seconds."
            )

        })

    return alerts