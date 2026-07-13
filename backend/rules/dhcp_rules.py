def check_dhcp_rules(packet):

    alerts = []

    if packet["protocol"] != "DHCP":
        return alerts


    if packet["default_port"] is False:

        alerts.append({

            "rule_id": "DHCP-001",

            "severity": "Medium",

            "title": "DHCP Non Default Port",

            "description": (
                f"DHCP traffic detected on "
                f"ports {packet['src_port']} -> {packet['dst_port']}."
            )

        })


    return alerts