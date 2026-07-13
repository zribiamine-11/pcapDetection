from rules.tcp_rules import check_tcp_rules

from rules.udp_rules import check_udp_rules
from rules.icmp_rules import check_icmp_rules
from rules.dns_rules import check_dns_rules
from rules.dhcp_rules import check_dhcp_rules
from rules.http_rules import check_http_rules
from rules.https_rules import check_https_rules
from rules.ftp_rules import check_ftp_rules
from rules.ssh_rules import check_ssh_rules



def analyze_packet(packet):
    """
    Run packet-level rules.

    Used during packet extraction.
    """

    alerts = []


    alerts.extend(check_udp_rules(packet))
    alerts.extend(check_icmp_rules(packet))
    alerts.extend(check_dns_rules(packet))
    alerts.extend(check_dhcp_rules(packet))
    alerts.extend(check_http_rules(packet))
    alerts.extend(check_https_rules(packet))
    alerts.extend(check_ftp_rules(packet))
    alerts.extend(check_ssh_rules(packet))


    return alerts



def analyze_conversation(conversation):
    """
    Run conversation-level rules.

    Used after grouping packets and creating TCP streams.
    """

    alerts = []


    alerts.extend(
        check_tcp_rules(conversation)
    )


    return alerts