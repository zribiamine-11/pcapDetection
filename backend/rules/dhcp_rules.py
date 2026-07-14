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

def check_multiple_dhcp_servers(conversations):

    alerts = []

    dhcp_servers = set()


    for conversation in conversations:

        # Check only conversations containing DHCP
        if "DHCP" not in conversation["protocols_seen"]:
            continue


        for packet in conversation["packets"]:

            # DHCP server -> client
            if (
                packet["protocol"] == "DHCP"
                and packet["src_port"] == "67"
                and packet["dst_port"] == "68"
            ):

                src_mac = packet.get("src_mac")

                if src_mac:
                    dhcp_servers.add(src_mac)



    if len(dhcp_servers) > 1:

        alerts.append({

            "rule_id": "DHCP-002",

            "severity": "High",

            "title": "Multiple DHCP Servers Detected",

            "description": (
                f"Detected {len(dhcp_servers)} DHCP servers: "
                f"{', '.join(dhcp_servers)}"
            )

        })


    return alerts