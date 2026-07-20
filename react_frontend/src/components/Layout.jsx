import { Link } from "react-router-dom";
import "../styles/layout.css";


function Layout({children}){

    return (

        <div className="container">


            <aside className="sidebar">

                <h2>
                    PCAP IDS
                </h2>


                <Link to="/">
                    Dashboard
                </Link>


                <Link to="/alerts">
                    Alerts
                </Link>


                <Link to="/conversations">
                    Conversations
                </Link>


                <Link to="/statistics">
                    Statistics
                </Link>


                <Link to="/about">
                    About
                </Link>


            </aside>



            <main className="content">

                {children}

            </main>


        </div>

    )

}


export default Layout;