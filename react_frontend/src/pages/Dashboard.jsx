import { useContext } from "react";


import UploadPCAP from "../components/UploadPCAP";

import StatCard from "../components/StatCard";

import { AnalysisContext } from "../context/AnalysisContext";

import "../styles/dashboard.css";



function Dashboard(){


    const { analysis } = useContext(AnalysisContext);



    return (


        <div className="dashboard-container">


            <h1>
                PCAP IDS Dashboard
            </h1>



            <UploadPCAP />



            {

                analysis && (


                    <div className="dashboard-cards">



                        <StatCard

                            title="Total Packets"

                            value={
                                analysis.total_packets
                            }

                        />



                        <StatCard

                            title="Conversations"

                            value={
                                analysis.total_conversations
                            }

                        />



                        <StatCard

                            title="Alerts"

                            value={
                                analysis.capture_alerts.length
                            }

                        />



                    </div>


                )

            }



        </div>


    );


}


export default Dashboard;