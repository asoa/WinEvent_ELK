# WinEvent_ELK
PowerShell Remoting to Get-WinEvent Logs and Ingest into the Elastic Stack

Why does this repo exist:  The problem this repo aims to solve is to provide a windows organic way to collect winodows event logs that are indicative of cyber threat actor malicious activity outlined in this article:
<placeholder>

This repo contains scripts and configurations files to create a docker Elastic Stack (formerly ELK) single node deployment to ingest windows event logs used for security auditing.
The docker-compose.yml file and Elastic Stack conf files were derived from "https://github.com/deviantony/docker-elk.git"; this repo contains an excellent README to walk 
you through deploying a docker-compose Elastic Stack environment.

The powershell script uses PowerShell Remoting to distibutively conduct parrallel "Invoke-Command" on remote computers to run the PowerShell cmdlet "Get-WinEvent" to get Windows Logs->Security, and
Application and Services Logs->TaskScheduler.  The powershell script requires PS-Remoting to be enabled in the windows environment; See PowerShell help file "get-help about_Remote_Requirements" for more information about 
the requirements to enable PowerShell Remoting.  In summary, you have to enable PS-Remoting on all computers that the script will run on.  The easiest way to do this is to create a GPO that enables the WinRM service and 
corresponding firewall rules to allow the traffic.  Another way is to use Psexec to programmatically run "winrm.cmd quickconfig -q" on remote computers.
