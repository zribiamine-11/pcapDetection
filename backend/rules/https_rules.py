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