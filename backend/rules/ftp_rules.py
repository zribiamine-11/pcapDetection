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



FTP_MEDIUM_TRANSFER_THRESHOLD = 500 * 1024 * 1024      # 500 MB
FTP_HIGH_TRANSFER_THRESHOLD = 1024 * 1024 * 1024       # 1 GB


def check_excessive_ftp_transfer(conversation):

    alerts = []

    # Ignore non-FTP conversations
    if "FTP" not in conversation["protocols_seen"]:
        return alerts

    ftp_bytes = 0

    # Count only FTP packet bytes
    for packet in conversation["packets"]:
        if packet["protocol"] == "FTP":
            ftp_bytes += int(packet["length"])

    # High severity alert
    if ftp_bytes >= FTP_HIGH_TRANSFER_THRESHOLD:
        alerts.append({
            "rule_id": "FTP-002",
            "severity": "High",
            "message": (
                f"Excessive FTP data transfer detected "
                f"({ftp_bytes / (1024 * 1024):.2f} MB transferred)."
            ),
            "description": (
                "The FTP conversation transferred more than 1 GB of data, "
                "which may indicate bulk data exfiltration or unauthorized file transfer."
            )
        })

    # Medium severity alert
    elif ftp_bytes >= FTP_MEDIUM_TRANSFER_THRESHOLD:
        alerts.append({
            "rule_id": "FTP-002",
            "severity": "Medium",
            "message": (
                f"Large FTP data transfer detected "
                f"({ftp_bytes / (1024 * 1024):.2f} MB transferred)."
            ),
            "description": (
                "The FTP conversation transferred more than 500 MB of data, "
                "which may indicate suspicious file transfer activity."
            )
        })

    return alerts