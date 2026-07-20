import { useContext } from "react";

import { AnalysisContext } from "../context/AnalysisContext";

import AlertTable from "../components/AlertTable";

import "../styles/alerts.css";


function Alerts(){


    const { analysis } = useContext(AnalysisContext);



    if(!analysis){

        return (

            <div className="alerts-container">

                <h1>
                    Upload a PCAP first
                </h1>

            </div>

        );

    }



    // ==========================
    // Conversation Alerts
    // ==========================


    let conversationAlerts = [];



    analysis.conversations.forEach(

        (conversation)=>{


            if(conversation.alerts){


                conversation.alerts.forEach(

                    (alert)=>{


                        conversationAlerts.push({

                            ...alert,

                            source:
                            conversation.ip_a,

                            destination:
                            conversation.ip_b

                        });


                    }

                );


            }


        }

    );





    // ==========================
    // Packet Alerts
    // ==========================


    let packetAlerts = [];



    analysis.conversations.forEach(

        (conversation)=>{


            if(conversation.packets){


                conversation.packets.forEach(

                    (packet,index)=>{


                        if(packet.alerts){


                            packet.alerts.forEach(

                                (alert)=>{


                                    packetAlerts.push({

                                        ...alert,

                                        packet:
                                        index + 1,

                                        source:
                                        packet.src_ip,

                                        destination:
                                        packet.dst_ip

                                    });


                                }

                            );


                        }


                    }

                );


            }


        }

    );





    return (


        <div className="alerts-container">


            <h1>

                🚨 Security Alerts

            </h1>



            <div className="alert-section">


                <AlertTable

                    title="Capture Alerts"

                    alerts={
                        analysis.capture_alerts || []
                    }

                />


            </div>




            <div className="alert-section">


                <AlertTable

                    title="Conversation Alerts"

                    alerts={
                        conversationAlerts
                    }

                />


            </div>




            <div className="alert-section">


                <AlertTable

                    title="Packet Alerts"

                    alerts={
                        packetAlerts
                    }

                />


            </div>



        </div>


    );


}



export default Alerts;