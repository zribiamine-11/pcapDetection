HIGH_RISK_USER_AGENTS = {

    "sqlmap": "SQL Injection Tool",
    "nikto": "Web Vulnerability Scanner",
    "gobuster": "Directory Enumeration Tool",
    "dirbuster": "Directory Enumeration Tool",
    "ffuf": "Web Fuzzer",
    "feroxbuster": "Directory Fuzzer",
    "wfuzz": "Web Fuzzer",
    "burpsuite": "Web Proxy Tool",
    "zap": "OWASP ZAP Scanner",
    "acunetix": "Web Vulnerability Scanner",
    "nessus": "Vulnerability Scanner",
    "openvas": "Vulnerability Scanner",
    "netsparker": "Web Vulnerability Scanner",
    "arachni": "Web Scanner",
    "skipfish": "Web Scanner",
    "masscan": "Network Scanner",
    "metasploit": "Exploitation Framework",
    "beef": "Browser Exploitation Framework",
    "commix": "Command Injection Tool",
    "nmap": "Network Scanner"

}


AUTOMATION_USER_AGENTS = {

    "curl": "Command Line HTTP Client",
    "wget": "Command Line Downloader",
    "python-requests": "Python HTTP Library",
    "python-urllib": "Python HTTP Library",
    "go-http-client": "Go HTTP Client",
    "libwww-perl": "Perl HTTP Library",
    "powershell": "PowerShell HTTP Client",
    "httpclient": "HTTP Client Library",
    "okhttp": "Java HTTP Client",
    "apache-httpclient": "Apache HTTP Client",
    "aiohttp": "Python Async HTTP Client",
    "postmanruntime": "Postman API Client",
    "insomnia": "Insomnia API Client",
    "httpie": "HTTP Command Line Client",
    "axios": "JavaScript HTTP Client"

}


HTTP_WINDOW_SIZE = 10          # seconds
HTTP_REQUEST_THRESHOLD = 100


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

HTTP_WINDOW_SIZE = 10
HTTP_REQUEST_THRESHOLD = 100


def check_http_window_rules(conversation):

    alerts = []

    # Ignore non-HTTP conversations
    if "HTTP" not in conversation["protocols_seen"]:
        return alerts

    # Keep only HTTP requests
    http_packets = []

    for packet in conversation["packets"]:

        if packet["http_request_method"]:
            http_packets.append(packet)

    if len(http_packets) == 0:
        return alerts

    # Sliding window
    for i in range(len(http_packets)):

        window_start = http_packets[i]["timestamp"]
        window_end = window_start + HTTP_WINDOW_SIZE

        packet_count = 0

        for packet in http_packets:

            if window_start <= packet["timestamp"] <= window_end:
                packet_count += 1

        if packet_count > HTTP_REQUEST_THRESHOLD:

            alerts.append({

                "rule_id": "HTTP-002",

                "severity": "High",

                "title": "High HTTP Request Rate",

                "description": (
                    f"{packet_count} HTTP requests were detected "
                    f"within {HTTP_WINDOW_SIZE} seconds between "
                    f"{conversation['ip_a']} and {conversation['ip_b']}."
                )

            })

            break

    return alerts


def check_http_user_agent_rule(packet):

    alerts = []

    # Only analyze HTTP packets
    if packet.get("protocol") != "HTTP":
        return alerts


    user_agent = packet.get("http_user_agent", "")


    # No User-Agent header
    if not user_agent:
        return alerts


    user_agent_lower = user_agent.lower()


    # Check high-risk tools
    for agent, description in HIGH_RISK_USER_AGENTS.items():

        if agent in user_agent_lower:

            alerts.append({

                "rule_id": "HTTP-003",

                "severity": "High",

                "title": "High Risk HTTP User-Agent",

                "description": (
                    f"Detected suspicious User-Agent: "
                    f"{user_agent}. "
                    f"Identified as {description}."
                )

            })

            return alerts


    # Check automation tools
    for agent, description in AUTOMATION_USER_AGENTS.items():

        if agent in user_agent_lower:

            alerts.append({

                "rule_id": "HTTP-003",

                "severity": "Medium",

                "title": "Suspicious HTTP User-Agent",

                "description": (
                    f"Detected automated HTTP client: "
                    f"{user_agent}. "
                    f"Identified as {description}."
                )

            })

            return alerts


    return alerts