Date: 13/07/2026
 Tasks completed: adding the ssh  brute force detection rule
 Challenges: it is hard to test because ai models can not guive me a code to generate a pcap file with an ssh connection so i cretaed a pcap file with a real brut force attack with virtual machine
 Next steps: testing the shh rule

date: 14/07/2026
 tasks: adding the dhcp multiple servers rule
 next step : adding the Excessive DHCP Discover messages rule 


date: 14/07/2026
 tasks: adding the the Excessive DHCP Discover messages rule 
 next step: adding other dns ruls

date: 15/07/2026
 tasks: -adding dns high query rate
        -modify the excessive dhcp discovery from capture level to conversation level rule
 challenges: adding a window of 10s because calculing the query rate can not be for all the conversation duration and adding also this window to the excessive dhcp discovery rule 

 date: 16/07/2026
 tasks: -adding Excessive ICMP Echo Requests rule 
        -adding  ICMP Ping Sweep Detected
challenges: i aded a conversation level rule whish is excessive icmp echo requests rule(ICMP Ping Flood) that calculate the number of echo requests sent in 10 seconds and then i aded the icmp ping sweep detection rule (ICMP Host Discovery Scan) that is a capture level rule that calculate the number of echo requests sent by an ip to different ips in 10s

date: 17/07/2026
tasks: -adding the HTTP Request Flood rule
        -adding the http Suspicious User-Agent rule
        -adding the https flood tls hello packet(connection)
next tasks: adding the https rules 

date: 18/07/2026
tasks: -adding the ftp large transfer rule


rules: 
 capture level rules: Multiple DHCP Servers / ICMP Host Discovery Scan
 conversation level rules : Incomplete TCP Handshake /high dns quey rate (adding window per 10s)/ Excessive DHCP Discovery/Excessive ICMP Echo Requests/ HTTP Request Flood/ https tls connections flood/ ftp large transfer
 packet level rules: port-default rules/ http Suspicious User-Agent
