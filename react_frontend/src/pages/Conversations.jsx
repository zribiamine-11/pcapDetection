import { useContext } from "react";


import { AnalysisContext } from "../context/AnalysisContext";


import ConversationCard from "../components/ConversationCard";


import "../styles/conversations.css";



function Conversations(){



    const {analysis} = useContext(AnalysisContext);



    if(!analysis){


        return (

            <h1>
                Upload a PCAP first
            </h1>

        )


    }



    return (


        <div className="conversations-container">


            <h1>
                Conversations
            </h1>



            {

                analysis.conversations.map(

                    (conversation,index)=>(


                        <ConversationCard

                            key={index}

                            conversation={conversation}

                            index={index}

                        />


                    )

                )

            }



        </div>


    )


}


export default Conversations;