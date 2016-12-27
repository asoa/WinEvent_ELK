# WinEvent_ELK
PowerShell Remoting to Get-WinEvent Logs and Ingest into the Elastic Stack

Why does this repo exist? The problem this repo aims to provide a solution for is: How to aggregate widows event logs across an enterprise to detect cyber threat actor lateral movement activity?  This problem is expounded on in the following resources:
http://www.deer-run.com/~hal/IREventLogAnalysis.pdf
https://www.rapid7.com/resources/using-windows-event-logs-to-detect-lateral-movement/

This repo contains scripts and configurations files to create a docker Elastic Stack (formerly ELK) single node deployment to ingest windows event logs used for security auditing.
The docker-compose.yml file and Elastic Stack conf files were derived from "https://github.com/deviantony/docker-elk.git"; this repo contains an excellent README to walk 
you through deploying a docker-compose Elastic Stack environment.

The PowerShell script uses PowerShell Remoting to distributively conduct parrallel "Invoke-Command" commands on remote computers to run the PowerShell cmdlet "Get-WinEvent" to get Windows Logs->Security, and
Application and Services Logs->TaskScheduler.  The PowerShell script requires PS-Remoting to be enabled in the windows environment; See PowerShell help file "get-help about_Remote_Requirements" for more information about
the requirements to enable PowerShell Remoting.  In summary, you have to enable PS-Remoting on all computers that the script will run on.  The easiest way to do this is to create a GPO that enables the WinRM service and 
corresponding firewall rules to allow the traffic.  Another way is to use Psexec to programmatically run "winrm.cmd quickconfig -q" on remote computers.

Again, this repo provides a docker-compose.yml file to quickly deploy an Elastic Stack using the official Elasticsearch,Logstash,and Kibana images hosted on https://hub.docker.com.  The requirements to deploy the Elastic Stack using the
docker-compose.yml are:
1. Install Docker
2. Install Docker-compose version >= 1.6
3. Clone this repository

Test data resides in ~/logstash/testData/ and will copied to your Elastic Stack docker instance after you install docker, docker-compose, and run the command "docker-compose up" from the path the docker-compose.yml resides

Running docker-compose up will build your Elastic Stack and expose Kibana on http://localhost:5601.  You can analyze the test data logs in Kibana by setting the Kibana absolute time range from 23 Dec 16 - 25 Dec 16.  You can add your own event logs
by running "get-eventLogs_v6.ps1" in your windows environment and adding the csv files to ~/logstash/testData/.

The Elastic Stack (Logstash) currently is capable of parsing the following windows event logs retrieved using the repo's PowerShell script "get-eventLogs_v6.ps1":
(4624) logon
(4634) logoff
(4688) new process creation
(4648) runas command
(4672) admin rights
(106) task scheduled
(200) task executed
(201) task completed
(141) task removed

The logstash conf files are in ~/logstash/conf and are mapped (docker volumes) from your local host to the Elastic Stack docker container at runtime

