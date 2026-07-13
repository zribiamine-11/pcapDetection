def check_http_rules(packet):

    alerts = []

    if packet["protocol"] != "HTTP":
        return alerts


    if packet["default_port"] is False:

        alerts.append({

            "rule_id": "HTTP-001",

            "severity": "Low",

            "title": "HTTP Non Default Port",

            "description": (
                f"HTTP traffic detected on "
                f"non standard port {packet['dst_port']}."
            )

        })


    return alerts