import { useNavigate } from "react-router-dom";


function ConversationCard({conversation,index}){


    const navigate = useNavigate();



    return (

        <div className="conversation-card">


            <h3>
                Conversation {index + 1}
            </h3>



            <p>
                <strong>
                    Source:
                </strong>

                {" "}

                {conversation.ip_a}

            </p>



            <p>
                <strong>
                    Destination:
                </strong>

                {" "}

                {conversation.ip_b}

            </p>



            <p>
                <strong>
                    Protocols:
                </strong>

                {" "}

                {
                    conversation.protocols_seen.join(", ")
                }

            </p>



            <p>
                <strong>
                    Packets:
                </strong>

                {" "}

                {
                    conversation.total_packets
                }

            </p>



            <p>
                <strong>
                    Alerts:
                </strong>

                {" "}

                {
                    conversation.alerts
                    ?
                    conversation.alerts.length
                    :
                    0
                }

            </p>



            <button

                onClick={()=>

                    navigate(
                        `/conversation/${index}`
                    )

                }

            >

                View Details

            </button>



        </div>

    )


}


export default ConversationCard;