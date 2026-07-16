from rules.tcp_rules import check_tcp_rules

from rules.udp_rules import check_udp_rules
from rules.icmp_rules import (
    check_icmp_rules,
    check_excessive_icmp_echo,
    check_icmp_ping_sweep
)
from rules.dns_rules import (
    check_dns_rules,
    check_dns_window_rules
)
from rules.dhcp_rules import (
    check_dhcp_rules,
    check_multiple_dhcp_servers,
    check_excessive_dhcp_discover
)
from rules.http_rules import check_http_rules
from rules.https_rules import check_https_rules
from rules.ftp_rules import check_ftp_rules
from rules.ssh_rules import (
    check_ssh_rules,
    check_ssh_bruteforce
)



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
    alerts.extend(
        check_ssh_bruteforce(conversation)
    )
    alerts.extend(
        check_dns_window_rules(conversation)
    )

    alerts.extend(
        check_excessive_dhcp_discover(conversation)
    )
    alerts.extend(
        check_excessive_icmp_echo(conversation)
        )


    return alerts


def analyze_capture(conversations):

    alerts = []


    alerts.extend(
        check_multiple_dhcp_servers(conversations)
    )
    
    alerts.extend(
        check_icmp_ping_sweep(conversations)
        )


    


    return alerts