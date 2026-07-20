import { useState } from "react";

import PacketDetails from "./PacketDetails";

function PacketTable({ packets }) {

    const [selectedPacket, setSelectedPacket] = useState(null);

    return (

        <div className="packet-table-container">

            <h2>

                📦 Packets

            </h2>

            <p className="table-description">

                Click on any packet to display its complete information.

            </p>

            <table className="packet-table">

                <thead>

                    <tr>

                        <th>#</th>

                        <th>Timestamp</th>

                        <th>Source IP</th>

                        <th>Destination IP</th>

                        <th>Protocol</th>

                        <th>Ports</th>

                        <th>Length</th>

                        <th>Alerts</th>

                    </tr>

                </thead>

                <tbody>

                    {

                        packets.map(

                            (packet, index) => (

                                <tr

                                    key={index}

                                    className="packet-row"

                                    onClick={() => setSelectedPacket(packet)}

                                >

                                    <td>

                                        {index + 1}

                                    </td>

                                    <td>

                                        {packet.captured}

                                    </td>

                                    <td>

                                        {packet.src_ip || "-"}

                                    </td>

                                    <td>

                                        {packet.dst_ip || "-"}

                                    </td>

                                    <td>

                                        <span className={`protocol-badge protocol-${packet.protocol.toLowerCase()}`}>

                                            {packet.protocol}

                                        </span>

                                    </td>

                                    <td>

                                        {packet.src_port || "-"}

                                        {" → "}

                                        {packet.dst_port || "-"}

                                    </td>

                                    <td>

                                        {packet.length} Bytes

                                    </td>

                                    <td>

                                        {

                                            packet.alerts && packet.alerts.length > 0

                                                ?

                                                <span className="alert-badge">

                                                    🚨 {packet.alerts.length}

                                                </span>

                                                :

                                                <span className="no-alert">

                                                    ✅

                                                </span>

                                        }

                                    </td>

                                </tr>

                            )

                        )

                    }

                </tbody>

            </table>

            {

                selectedPacket && (

                    <PacketDetails

                        packet={selectedPacket}

                    />

                )

            }

        </div>

    );

}

export default PacketTable;