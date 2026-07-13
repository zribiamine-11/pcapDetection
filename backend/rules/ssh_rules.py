def check_ssh_rules(packet):

    alerts = []

    if packet["protocol"] != "SSH":
        return alerts


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


    return alertss