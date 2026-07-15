DHCP_WINDOW_SIZE = 10          # seconds
DHCP_DISCOVER_THRESHOLD = 10   # Discover packets
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

def check_excessive_dhcp_discover(conversation):

    alerts = []

    # Ignore non DHCP conversations
    if "DHCP" not in conversation["protocols_seen"]:
        return alerts


    # Get only DHCP Discover packets
    discover_packets = []

    for packet in conversation["packets"]:

        if packet["protocol"] != "DHCP":
            continue


        if packet.get("dhcp_type") == "1":

            discover_packets.append(packet)



    if len(discover_packets) == 0:
        return alerts



    # Sliding window
    for packet in discover_packets:

        window_start = packet["timestamp"]

        window_end = (
            window_start + DHCP_WINDOW_SIZE
        )


        discover_count = 0


        for discover in discover_packets:

            if (
                window_start
                <= discover["timestamp"]
                <= window_end
            ):
                discover_count += 1



        if discover_count > DHCP_DISCOVER_THRESHOLD:


            mac = packet.get("src_mac")


            alerts.append({

                "rule_id": "DHCP-003",

                "severity": "High",

                "title": "Excessive DHCP Discover Requests",

                "description": (
                    f"MAC address {mac} sent "
                    f"{discover_count} DHCP Discover packets "
                    f"within {DHCP_WINDOW_SIZE} seconds. "
                    "Possible DHCP starvation or abnormal DHCP behavior."
                )

            })


            break


    return alerts