import { useState, useContext } from "react";

import api from "../services/api";

import { AnalysisContext } from "../context/AnalysisContext";


function UploadPCAP(){

    const [file, setFile] = useState(null);

    const { setAnalysis } = useContext(AnalysisContext);



    const uploadFile = async () => {


        if(!file){

            alert("Please select a PCAP file");

            return;

        }



        const formData = new FormData();


        formData.append(
            "file",
            file
        );



        try{


            const response = await api.post(

                "/upload",

                formData,

                {

                    headers:{

                        "Content-Type":"multipart/form-data"

                    }

                }

            );



            console.log("PCAP Analysis:", response.data);



            // Save analysis globally
            setAnalysis(response.data);



            alert("PCAP uploaded successfully");


        }

        catch(error){


            console.error(
                "Upload error:",
                error
            );


            alert("Upload failed");


        }


    };



    return (

        <div>


            <h3>
                Upload PCAP File
            </h3>



            <input

                type="file"

                accept=".pcap,.pcapng"

                onChange={
                    (e)=>setFile(e.target.files[0])
                }

            />



            <button

                onClick={uploadFile}

            >

                Upload PCAP

            </button>


        </div>

    );


}


export default UploadPCAP;