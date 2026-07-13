def check_ftp_rules(packet):

    alerts = []

    if packet["protocol"] != "FTP":
        return alerts


    if packet["default_port"] is False:

        alerts.append({

            "rule_id": "FTP-001",

            "severity": "Low",

            "title": "FTP Non Default Port",

            "description": (
                f"FTP traffic detected on "
                f"non standard port {packet['dst_port']}."
            )

        })


    return alerts