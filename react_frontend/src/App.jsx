import {
    BrowserRouter,
    Routes,
    Route
} from "react-router-dom";


import Layout from "./components/Layout";

import { AnalysisProvider } from "./context/AnalysisContext";

import Dashboard from "./pages/Dashboard";
import Alerts from "./pages/Alerts";
import Conversations from "./pages/Conversations";
import ConversationDetails from "./pages/ConversationDetails";
import Statistics from "./pages/Statistics";
import About from "./pages/About";



function App(){

    return (

        <AnalysisProvider>

            <BrowserRouter>

                <Layout>

                    <Routes>

                        <Route
                            path="/"
                            element={<Dashboard />}
                        />


                        <Route
                            path="/alerts"
                            element={<Alerts />}
                        />


                        <Route
                            path="/conversations"
                            element={<Conversations />}
                        />


                        <Route
                            path="/conversation/:id"
                            element={<ConversationDetails />}
                        />


                        <Route
                            path="/statistics"
                            element={<Statistics />}
                        />


                        <Route
                            path="/about"
                            element={<About />}
                        />

                    </Routes>

                </Layout>

            </BrowserRouter>

        </AnalysisProvider>

    )

}


export default App;