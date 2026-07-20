import { useParams } from "react-router-dom";
import { useContext } from "react";

import { AnalysisContext } from "../context/AnalysisContext";
import PacketTable from "../components/PacketTable";

import "../styles/conversationDetails.css";

function ConversationDetails() {

    const { id } = useParams();

    const { analysis } = useContext(AnalysisContext);

    if (!analysis) {

        return (
            <div className="conversation-page">
                <h1>Upload a PCAP first</h1>
            </div>
        );

    }

    const conversation = analysis.conversations[id];

    if (!conversation) {

        return (
            <div className="conversation-page">
                <h1>Conversation not found</h1>
            </div>
        );

    }

    return (

        <div className="conversation-page">

            {/* ================= HEADER ================= */}

            <div className="conversation-header">

                <h1>💬 Conversation Details</h1>

                <p>

                    <strong>{conversation.ip_a}</strong>

                    <span className="conversation-arrow">

                        ↔

                    </span>

                    <strong>{conversation.ip_b}</strong>

                </p>

            </div>



            {/* ================= GENERAL INFORMATION ================= */}

            <div className="conversation-card">

                <h2>General Information</h2>

                <div className="info-grid">

                    <div className="info-item">
                        <span>IP A</span>
                        <strong>{conversation.ip_a}</strong>
                    </div>

                    <div className="info-item">
                        <span>IP B</span>
                        <strong>{conversation.ip_b}</strong>
                    </div>

                    <div className="info-item">
                        <span>Protocols</span>
                        <strong>{conversation.protocols_seen.join(", ")}</strong>
                    </div>

                    <div className="info-item">
                        <span>Total Packets</span>
                        <strong>{conversation.total_packets}</strong>
                    </div>

                    <div className="info-item">
                        <span>Total Bytes</span>
                        <strong>{conversation.total_bytes}</strong>
                    </div>

                    <div className="info-item">
                        <span>Duration</span>
                        <strong>{conversation.duration_seconds.toFixed(3)} sec</strong>
                    </div>

                    <div className="info-item">
                        <span>Start Time</span>
                        <strong>{conversation.start_time_iso}</strong>
                    </div>

                    <div className="info-item">
                        <span>End Time</span>
                        <strong>{conversation.end_time_iso}</strong>
                    </div>

                </div>

            </div>



            {/* ================= TCP HANDSHAKE ================= */}

            {

                conversation.handshake && (

                    <div className="conversation-card">

                        <h2>TCP Handshake</h2>

                        <div className="handshake-summary">

                            <div className="status-card">

                                <span>Has TCP</span>

                                <strong>

                                    {

                                        conversation.handshake.has_tcp

                                            ? "🟢 Yes"

                                            : "🔴 No"

                                    }

                                </strong>

                            </div>

                            <div className="status-card">

                                <span>Any Stream Completed</span>

                                <strong>

                                    {

                                        conversation.handshake.any_stream_completed

                                            ? "🟢 Yes"

                                            : "🔴 No"

                                    }

                                </strong>

                            </div>

                            <div className="status-card">

                                <span>All Streams Completed</span>

                                <strong>

                                    {

                                        conversation.handshake.all_streams_completed

                                            ? "🟢 Yes"

                                            : "🔴 No"

                                    }

                                </strong>

                            </div>

                        </div>

                        <h3>Streams</h3>

                        <div className="streams-grid">

                            {

                                Object.entries(conversation.handshake.streams).map(

                                    ([streamId, stream]) => (

                                        <div

                                            className="stream-card"

                                            key={streamId}

                                        >

                                            <h4>

                                                Stream {streamId}

                                            </h4>

                                            <p>

                                                SYN

                                                <strong>

                                                    {

                                                        stream.syn_seen

                                                            ? " 🟢"

                                                            : " 🔴"

                                                    }

                                                </strong>

                                            </p>

                                            <p>

                                                SYN ACK

                                                <strong>

                                                    {

                                                        stream.syn_ack_seen

                                                            ? " 🟢"

                                                            : " 🔴"

                                                    }

                                                </strong>

                                            </p>

                                            <p>

                                                ACK

                                                <strong>

                                                    {

                                                        stream.ack_seen

                                                            ? " 🟢"

                                                            : " 🔴"

                                                    }

                                                </strong>

                                            </p>

                                            <p>

                                                Completed

                                                <strong>

                                                    {

                                                        stream.completed

                                                            ? " 🟢"

                                                            : " 🔴"

                                                    }

                                                </strong>

                                            </p>

                                        </div>

                                    )

                                )

                            }

                        </div>

                    </div>

                )

            }



            {/* ================= CONVERSATION ALERTS ================= */}

            <div className="conversation-card">

                <h2>Conversation Alerts</h2>

                {

                    conversation.alerts.length > 0 ? (

                        <table>

                            <thead>

                                <tr>

                                    <th>Severity</th>

                                    <th>Rule</th>

                                    <th>Title</th>

                                    <th>Description</th>

                                </tr>

                            </thead>

                            <tbody>

                                {

                                    conversation.alerts.map(

                                        (alert, index) => (

                                            <tr key={index}>

                                                <td>{alert.severity}</td>

                                                <td>{alert.rule_id}</td>

                                                <td>{alert.title || alert.message}</td>

                                                <td>{alert.description}</td>

                                            </tr>

                                        )

                                    )

                                }

                            </tbody>

                        </table>

                    ) : (

                        <div className="empty-alerts">

                            ✅ No conversation alerts detected.

                        </div>

                    )

                }

            </div>



            {/* ================= PACKETS ================= */}

            <div className="conversation-card">

                <h2>Packets</h2>

                <PacketTable

                    packets={conversation.packets}

                />

            </div>

        </div>

    );

}

export default ConversationDetails;