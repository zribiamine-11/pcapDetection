TLS_WINDOW_SIZE = 10
TLS_CONNECTION_THRESHOLD = 50

def check_https_rules(packet):

    alerts = []

    if packet["protocol"] != "HTTPS":
        return alerts


    if packet["default_port"] is False:

        alerts.append({

            "rule_id": "HTTPS-001",

            "severity": "Low",

            "title": "HTTPS Non Default Port",

            "description": (
                f"HTTPS traffic detected on "
                f"non standard port {packet['dst_port']}."
            )

        })


    return alerts

def check_tls_connection_rate(conversation):

    alerts = []

    # Ignore non HTTPS/TLS conversations
    if not any(
        "HTTPS" in protocol or "TLS" in protocol
        for protocol in conversation["protocols_seen"]
    ):
        return alerts


    tls_handshakes = []


    # Keep only TLS Client Hello packets
    for packet in conversation["packets"]:

        if packet.get("tls_handshake_type") == "1":
            tls_handshakes.append(packet)


    if len(tls_handshakes) == 0:
        return alerts


    # Sliding window detection
    for i in range(len(tls_handshakes)):

        window_start = tls_handshakes[i]["timestamp"]

        window_end = (
            window_start + TLS_WINDOW_SIZE
        )


        connection_count = 0


        for packet in tls_handshakes:

            if (
                window_start <= packet["timestamp"]
                <= window_end
            ):
                connection_count += 1


        if connection_count > TLS_CONNECTION_THRESHOLD:

            alerts.append({

                "rule_id": "HTTPS-002",

                "severity": "High",

                "title": "Excessive TLS Connections",

                "description": (
                    f"{connection_count} TLS Client Hello messages "
                    f"were detected within "
                    f"{TLS_WINDOW_SIZE} seconds between "
                    f"{conversation['ip_a']} and "
                    f"{conversation['ip_b']}."
                )

            })

            break


    return alerts