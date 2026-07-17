import subprocess
from datetime import datetime, timezone
from rules.rule_engine import (
    analyze_packet,
    analyze_conversation,
    analyze_capture
)

# ---------------------------------------------------------------------------
# STEP 1: Extract raw packets from the pcap using tshark
# ---------------------------------------------------------------------------
def extract_packets(filepath):
    """
    Runs tshark once and extracts:
    - timestamps
    - IP addresses
    - packet length
    - protocols
    - TCP/UDP ports
    - TCP flags
    - TCP stream id
    """

    cmd = [
        "tshark",
        "-r", filepath,
        "-T", "fields",
        "-E", "separator=|",
        "-E", "occurrence=f",
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "frame.len",
        "-e", "frame.protocols",
        "-e", "tcp.srcport",
        "-e", "tcp.dstport",
        "-e", "udp.srcport",
        "-e", "udp.dstport",
        "-e", "tcp.flags",
        "-e", "tcp.stream",
        "-e", "eth.src",
        "-e", "eth.dst",
        "-e", "bootp.option.dhcp",
        "-e", "icmp.type",
        "-e", "http.request.method",
        "-e", "http.user_agent",
        "-e", "tls.handshake.type"
    ]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"tshark failed: {result.stderr.strip()}"
        )

    packets = []

    lines = result.stdout.strip().split("\n")

    NUM_FIELDS = 18


    def flag_to_bool(flags, bit):
        """
        Convert TCP flag hexadecimal value to boolean.
        
        SYN = 0x02
        ACK = 0x10
        """
        if not flags:
            return False

        try:
            value = int(flags, 16)
            return bool(value & bit)

        except ValueError:
            return False


    for line in lines:

        if not line:
            continue


        fields = line.split("|")


        if len(fields) < NUM_FIELDS:
            fields += [""] * (NUM_FIELDS - len(fields))


        (
            ts,
            src_ip,
            dst_ip,
            length,
            protocols,
            tcp_sport,
            tcp_dport,
            udp_sport,
            udp_dport,
            tcp_flags,
            tcp_stream,
            src_mac,
            dst_mac,
            dhcp_type,
            icmp_type,
            http_request_method,
            http_user_agent,
            tls_handshake_type

        ) = fields[:NUM_FIELDS]


        if not src_ip or not dst_ip:
            continue


        protocol = detect_protocol(
            protocols,
            tcp_sport,
            tcp_dport,
            udp_sport,
            udp_dport
        )
        packet_time = float(ts) if ts else None

        packet = {
        "timestamp": packet_time,
        "captured": epoch_to_iso(packet_time),

        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_mac": src_mac,
        "dst_mac": dst_mac,

        "length": int(length) if length else 0,

        "protocol": protocol,

        "src_port": tcp_sport or udp_sport or None,
        "dst_port": tcp_dport or udp_dport or None,

        "default_port": is_default_port(
        protocol,
        tcp_sport or udp_sport,
        tcp_dport or udp_dport
        ),
        "dhcp_type": dhcp_type,
        "icmp_type": icmp_type,
        "http_request_method": http_request_method,
        "http_user_agent": http_user_agent,
        "tls_handshake_type": tls_handshake_type,
        

        "tcp_syn": flag_to_bool(tcp_flags, 0x02),
        "tcp_ack": flag_to_bool(tcp_flags, 0x10),
        "tcp_syn_ack": (
        flag_to_bool(tcp_flags, 0x02)
        and flag_to_bool(tcp_flags, 0x10)
    ),
        "tcp_stream": (
        int(tcp_stream)
        if tcp_stream != ""
        else None
    )

}
        packet["alerts"] = analyze_packet(packet)
        packets.append(packet)
        


    return packets

def detect_protocol(protocols, tcp_sport, tcp_dport, udp_sport, udp_dport):
    protocols = (protocols or "").lower()

    if "dns" in protocols:
        return "DNS"
    if "icmp" in protocols:
        return "ICMP"
    if "http" in protocols:
        return "HTTP"
    if "tls" in protocols:
        return "HTTPS"
    if "ssh" in protocols:
        return "SSH"
    if "dhcp" in protocols:
        return "DHCP"
    if "ftp" in protocols:
        return "FTP"

    if tcp_sport or tcp_dport:
        return "TCP"
    if udp_sport or udp_dport:
        return "UDP"

    return "OTHER"





DEFAULT_PORTS = {
    "HTTP": {80},
    "HTTPS": {443},
    "DNS": {53},
    "SSH": {22},
    "FTP": {21},
    "DHCP": {67, 68},
}


def is_default_port(protocol, src_port, dst_port):
    """
    Check whether the packet uses the default port
    of the detected application protocol.
    """

    if protocol not in DEFAULT_PORTS:
        return None

    try:
        src = int(src_port) if src_port else None
        dst = int(dst_port) if dst_port else None
    except ValueError:
        return False

    return (
        src in DEFAULT_PORTS[protocol]
        or
        dst in DEFAULT_PORTS[protocol]
    )


# ---------------------------------------------------------------------------
# STEP 2: Group packets into conversations between IP pairs
# ---------------------------------------------------------------------------
def group_by_ip_pair(packets):
    """
    Groups all packets exchanged between two IPs into one bucket,
    regardless of direction (A->B and B->A go into the same group).
    """
    conversations = {}

    for pkt in packets:
        key = tuple(sorted([pkt["src_ip"], pkt["dst_ip"]]))

        if key not in conversations:
            conversations[key] = {
                "ip_a": key[0],
                "ip_b": key[1],
                "packets": [],
            }

        conversations[key]["packets"].append(pkt)

    return conversations


# ---------------------------------------------------------------------------
# STEP 3: Check the TCP 3-way handshake for each conversation
# ---------------------------------------------------------------------------
def check_handshake(packets):
    """
    Groups packets by tcp.stream (tshark's per-connection id) so multiple
    TCP connections between the same two IPs are checked independently.
    Looks for the sequence SYN -> SYN+ACK -> ACK in time order.
    """
    streams = {}
    for pkt in packets:
        if pkt["tcp_stream"] is None:
            continue
        streams.setdefault(pkt["tcp_stream"], []).append(pkt)

    stream_results = {}

    for stream_id, pkts in streams.items():
        pkts_sorted = sorted(pkts, key=lambda p: p["timestamp"] or 0)

        got_syn = False
        got_syn_ack = False
        got_ack = False

        for pkt in pkts_sorted:
            syn, ack = pkt["tcp_syn"], pkt["tcp_ack"]

            if syn and not ack and not got_syn:
                got_syn = True
            elif syn and ack and got_syn and not got_syn_ack:
                got_syn_ack = True
            elif ack and not syn and got_syn_ack and not got_ack:
                got_ack = True
                break  # handshake fully observed for this stream

        stream_results[stream_id] = {
            "syn_seen": got_syn,
            "syn_ack_seen": got_syn_ack,
            "ack_seen": got_ack,
            "completed": got_syn and got_syn_ack and got_ack,
        }

    return stream_results


# ---------------------------------------------------------------------------
# STEP 4: Tie it all together
# ---------------------------------------------------------------------------
def epoch_to_iso(ts):
    if ts is None:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def build_conversation_summary(convo):
    packets = convo["packets"]

    timestamps = [
        p["timestamp"]
        for p in packets
        if p["timestamp"] is not None
    ]

    start_ts = min(timestamps) if timestamps else None
    end_ts = max(timestamps) if timestamps else None


    # Check TCP streams and handshake
    handshake_streams = check_handshake(packets)

    any_tcp = len(handshake_streams) > 0

    all_completed = (
        all(s["completed"] for s in handshake_streams.values())
        if any_tcp
        else None
    )

    any_completed = (
        any(s["completed"] for s in handshake_streams.values())
        if any_tcp
        else None
    )


    # Data needed for conversation-level rules
    conversation_data = {
    "ip_a": convo["ip_a"],
    "ip_b": convo["ip_b"],

    "protocols_seen": sorted(
        set(p["protocol"] for p in packets)
    ),

    "start_time": start_ts,

    "end_time": end_ts,

    "duration_seconds": (
        end_ts - start_ts
        if start_ts is not None and end_ts is not None
        else None
    ),

    "handshake": {
        "has_tcp": any_tcp,
        "all_streams_completed": all_completed,
        "any_stream_completed": any_completed,
        "streams": handshake_streams,
    },

    "packets": packets
}


    # Run TCP/conversation rules
    conversation_alerts = analyze_conversation(
        conversation_data
    )


    return {

        "ip_a": convo["ip_a"],

        "ip_b": convo["ip_b"],

        "total_packets": len(packets),

        "total_bytes": sum(
            p["length"] for p in packets
        ),

        "protocols_seen": sorted(
            set(p["protocol"] for p in packets)
        ),

        "start_time_iso": epoch_to_iso(start_ts),

        "end_time_iso": epoch_to_iso(end_ts),

        "duration_seconds": (
            end_ts - start_ts
            if start_ts is not None and end_ts is not None
            else None
        ),


        "handshake": {
            "has_tcp": any_tcp,

            "all_streams_completed": all_completed,

            "any_stream_completed": any_completed,

            "streams": handshake_streams,
        },


        # New field for conversation-level anomalies
        "alerts": conversation_alerts,


        "packets": packets,
    }

def parse_pcap(filepath):
    packets = extract_packets(filepath)
    grouped = group_by_ip_pair(packets)

    conversations = [build_conversation_summary(convo) for convo in grouped.values()]
    # sort biggest conversations first, often the most "interesting"
    conversations.sort(key=lambda c: c["total_packets"], reverse=True)
    # Capture-level rules
    capture_alerts = analyze_capture(
    conversations
)

    return {
        "total_packets": len(packets),
        "total_conversations": len(conversations),
        "capture_alerts": capture_alerts,
        "conversations": conversations,
    }