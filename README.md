# WinEvent_ELK
## PowerShell Remoting to Get-WinEvent Logs and Ingest into the Elastic Stack

### Why does this repo exist? 
The problem this repo aims to provide a solution for is: How to aggregate widows event logs across an enterprise to detect cyber threat actor lateral movement activity?  This problem is expounded on in the following resources:
* http://www.deer-run.com/~hal/IREventLogAnalysis.pdf
* https://www.rapid7.com/resources/using-windows-event-logs-to-detect-lateral-movement/

### Summary
This repo contains scripts and configurations files to create a docker Elastic Stack (formerly ELK) single node deployment to ingest windows event logs used for security auditing.
The docker-compose.yml file and Elastic Stack conf files were derived from "https://github.com/deviantony/docker-elk.git"; this repo contains an excellent README to walk 
you through deploying a docker-compose Elastic Stack environment.

### PowerShell
The PowerShell script uses PowerShell Remoting to distributively conduct "Invoke-Command" commands on remote computers to run the PowerShell cmdlet "Get-WinEvent" to get Windows Logs->Security, and
Application and Services Logs->TaskScheduler. 

### Usage
Again, this repo provides a docker-compose.yml file to quickly deploy an Elastic Stack using the official Elasticsearch,Logstash,and Kibana images hosted on https://hub.docker.com.  The requirements to deploy the Elastic Stack using the
docker-compose.yml are:
* Install Docker
* Install Docker-compose version >= 1.6
* Clone this repository
* Run this command on docker host: sudo sysctl -w vm.max_map_count=262144

Test data resides in ~/logstash/testData/ and will copied from your localhost to your Elastic Stack docker instance (/data) after you install docker, docker-compose, and run the command "docker-compose up" from the path the docker-compose.yml resides.  Please note that additions to 
your Elastic Stack configuration Dockerfiles, or changes to content of build directory(i.e. add your own logs to ~/testData) will be applied only when running "docker-compose build \<image\>" i.e. docker-compose build logstash

Running "docker-compose up" will build your Elastic Stack and expose Kibana on http://localhost:5601.  You can analyze the test data logs in Kibana by setting the Kibana absolute time range from 23 Dec 16 - 25 Dec 16.  You can add your own event logs
by running "get-eventLogs.ps1" in your windows environment and adding the csv files to ~/logstash/testData/.

Running "docker-compose down" destroys your environment and all volumes (docker storage).  This is what makes developing in docker so powerful--you can build/test/destroy an Elastic Stack in literally seconds.

The Elastic Stack (Logstash) currently is capable of parsing the following windows event logs retrieved using the repo's PowerShell script "get-eventLogs.ps1":
- (4624) logon
- (4625) failed logon
- (4634) logoff
- (4688) new process creation
- (4648) runas command
- (4672) admin rights
- (106) task scheduled
- (200) task executed
- (201) task completed
- (141) task removed
- (7045) service created

The logstash conf files to parse the event logs listed above are in ~/logstash/conf and are mapped (docker volumes) from your local host to the Elastic Stack docker container at runtime

### Elasticsearch-py Library

From the docs: "Official low-level client for Elasticsearch. Its goal is to provide common ground for all Elasticsearch-related code in Python; because of this it tries to be opinion-free and very extendable.
For a more high level client library with more limited scope, have a look at elasticsearch-dsl - it is a more pythonic library sitting on top of elasticsearch-py."

How this project uses elasticsearch-py: to programmatically query data in the elasticsearch database using Apache Lucene syntax to "find all the things." 

### Troubleshooting


