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