function AlertTable({ title, alerts }) {


    return (


        <div className="alert-table-container">


            <h2>

                {title}

            </h2>



            {

                alerts.length === 0 ?


                (

                    <div className="no-alerts">

                        ✅ No alerts detected

                    </div>


                )


                :


                (


                    <table className="alert-table">


                        <thead>


                            <tr>


                                <th>
                                    Severity
                                </th>


                                <th>
                                    Rule
                                </th>


                                <th>
                                    Title
                                </th>


                                <th>
                                    Description
                                </th>


                            </tr>


                        </thead>




                        <tbody>


                        {


                            alerts.map(

                                (alert,index)=>(


                                    <tr key={index}>


                                        <td>


                                            <span

                                                className={
                                                    `severity severity-${alert.severity.toLowerCase()}`
                                                }

                                            >

                                                {alert.severity}

                                            </span>


                                        </td>





                                        <td>


                                            <span className="rule-id">


                                                {alert.rule_id}


                                            </span>


                                        </td>





                                        <td>


                                            {alert.title}


                                        </td>





                                        <td className="alert-description">


                                            {alert.description}


                                        </td>



                                    </tr>


                                )


                            )


                        }


                        </tbody>


                    </table>


                )


            }


        </div>


    );


}


export default AlertTable;