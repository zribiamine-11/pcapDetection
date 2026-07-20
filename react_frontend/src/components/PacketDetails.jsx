function PacketDetails({ packet }) {

    if (!packet) {

        return null;

    }

    return (

        <div className="packet-details-card">

            <h2>🔍 Packet Details</h2>

            {/* ================= GENERAL ================= */}

            <div className="details-section">

                <h3>General Information</h3>

                <div className="details-grid">

                    <div className="detail-item">
                        <span>Timestamp</span>
                        <strong>{packet.timestamp}</strong>
                    </div>

                    <div className="detail-item">
                        <span>Captured</span>
                        <strong>{packet.captured}</strong>
                    </div>

                    <div className="detail-item">
                        <span>Protocol</span>
                        <strong>{packet.protocol}</strong>
                    </div>

                    <div className="detail-item">
                        <span>Length</span>
                        <strong>{packet.length} Bytes</strong>
                    </div>

                </div>

            </div>



            {/* ================= NETWORK ================= */}

            <div className="details-section">

                <h3>Network Information</h3>

                <div className="details-grid">

                    <div className="detail-item">
                        <span>Source IP</span>
                        <strong>{packet.src_ip || "N/A"}</strong>
                    </div>

                    <div className="detail-item">
                        <span>Destination IP</span>
                        <strong>{packet.dst_ip || "N/A"}</strong>
                    </div>

                    <div className="detail-item">
                        <span>Source MAC</span>
                        <strong>{packet.src_mac || "N/A"}</strong>
                    </div>

                    <div className="detail-item">
                        <span>Destination MAC</span>
                        <strong>{packet.dst_mac || "N/A"}</strong>
                    </div>

                </div>

            </div>



            {/* ================= PORTS ================= */}

            <div className="details-section">

                <h3>Ports</h3>

                <div className="details-grid">

                    <div className="detail-item">
                        <span>Source Port</span>
                        <strong>{packet.src_port || "N/A"}</strong>
                    </div>

                    <div className="detail-item">
                        <span>Destination Port</span>
                        <strong>{packet.dst_port || "N/A"}</strong>
                    </div>

                    <div className="detail-item">
                        <span>Default Port</span>
                        <strong>

                            {

                                packet.default_port === null

                                    ? "N/A"

                                    : packet.default_port.toString()

                            }

                        </strong>
                    </div>

                </div>

            </div>



            {/* ================= TCP FLAGS ================= */}

            <div className="details-section">

                <h3>TCP Flags</h3>

                <div className="details-grid">

                    <div className="detail-item">
                        <span>TCP Stream</span>
                        <strong>{packet.tcp_stream ?? "N/A"}</strong>
                    </div>

                    <div className="detail-item">
                        <span>SYN</span>
                        <strong>{packet.tcp_syn ? "🟢 Yes" : "🔴 No"}</strong>
                    </div>

                    <div className="detail-item">
                        <span>SYN ACK</span>
                        <strong>{packet.tcp_syn_ack ? "🟢 Yes" : "🔴 No"}</strong>
                    </div>

                    <div className="detail-item">
                        <span>ACK</span>
                        <strong>{packet.tcp_ack ? "🟢 Yes" : "🔴 No"}</strong>
                    </div>

                    <div className="detail-item">
                        <span>FIN</span>
                        <strong>{packet.tcp_fin ? "🟢 Yes" : "🔴 No"}</strong>
                    </div>

                    <div className="detail-item">
                        <span>RST</span>
                        <strong>{packet.tcp_rst ? "🟢 Yes" : "🔴 No"}</strong>
                    </div>

                    <div className="detail-item">
                        <span>PSH</span>
                        <strong>{packet.tcp_psh ? "🟢 Yes" : "🔴 No"}</strong>
                    </div>

                    <div className="detail-item">
                        <span>URG</span>
                        <strong>{packet.tcp_urg ? "🟢 Yes" : "🔴 No"}</strong>
                    </div>

                </div>

            </div>



            {/* ================= APPLICATION ================= */}

            <div className="details-section">

                <h3>Application Fields</h3>

                <div className="details-grid">

                    <div className="detail-item">
                        <span>DHCP Type</span>
                        <strong>{packet.dhcp_type || "N/A"}</strong>
                    </div>

                    <div className="detail-item">
                        <span>ICMP Type</span>
                        <strong>{packet.icmp_type || "N/A"}</strong>
                    </div>

                    <div className="detail-item">
                        <span>HTTP Method</span>
                        <strong>{packet.http_request_method || "N/A"}</strong>
                    </div>

                    <div className="detail-item">
                        <span>HTTP User Agent</span>
                        <strong>{packet.http_user_agent || "N/A"}</strong>
                    </div>

                    <div className="detail-item">
                        <span>TLS Handshake</span>
                        <strong>{packet.tls_handshake_type || "N/A"}</strong>
                    </div>

                </div>

            </div>



            {/* ================= ALERTS ================= */}

            <div className="details-section">

                <h3>Packet Alerts</h3>

                {

                    packet.alerts && packet.alerts.length > 0

                        ?

                        packet.alerts.map(

                            (alert, index) => (

                                <div

                                    className="packet-alert-card"

                                    key={index}

                                >

                                    <h4>

                                        {alert.rule_id}

                                    </h4>

                                    <p>

                                        <strong>Severity:</strong>

                                        {" "}

                                        {alert.severity}

                                    </p>

                                    <p>

                                        <strong>Message:</strong>

                                        {" "}

                                        {alert.message}

                                    </p>

                                    <p>

                                        <strong>Description:</strong>

                                        {" "}

                                        {alert.description}

                                    </p>

                                </div>

                            )

                        )

                        :

                        <div className="empty-alerts">

                            ✅ No packet alerts detected.

                        </div>

                }

            </div>

        </div>

    );

}

export default PacketDetails;