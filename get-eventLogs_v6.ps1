function Get-LogsWorker {
    #param([string]$computername)
    Param (
        [Parameter(Position=0)]
        [string]$computer,
        [Parameter(Position=1)]
        [int[]]$ID,
        [Parameter(Position=2)]
        [string]$time
    )

    $secArray = @(4624,4634,4688,4648,4672)
    if ($secArray -like $ID) {
        Try { 
            if ($time -like "hours") {
                $hours = (Get-Date).AddHours(-1)  # AddHours function subtracts X hour from current time
                $filter = @{Logname="Security";Id=$ID;StartTime=$hours}  
            } else {
                $days = (Get-Date).AddDays(-1)  # AddDays function subtracs X days from current time
                $filter = @{Logname="Security";Id=$ID;StartTime=$days}
            }
        
            $Events = Get-WinEvent -ComputerName $computer -FilterHashtable $filter -ErrorAction Stop            
            
            ForEach ($Event in $Events) {            
                # Convert the event to XML            
                $eventXML = [xml]$Event.ToXml()            
                # Iterate through each one of the XML message properties            
                For ($i=0; $i -lt $eventXML.Event.EventData.Data.Count; $i++) {            
                    # Append these as object properties            
                    Add-Member -InputObject $Event -MemberType NoteProperty -Force -Name $eventXML.Event.EventData.Data[$i].name -Value $eventXML.Event.EventData.Data[$i].'#text'           
                }            
            }            
 
            if ($ID -eq 4624) {
                $Global:log_ID["log"] = "logon"
                $Events | Select-Object -Property TargetUserSid,TargetUserName,TargetDomainName,TargetLogonId,LogonType,Id,Version,Level,Task,Opcode,Keywords,RecordId,ProviderName,ProviderId,LogName,ProcessId,ThreadId,MachineName,TimeCreated,ActivityId,RelatedActivityId,ContainerLog,LevelDisplayName,OpcodeDisplayName,TaskDisplayName  # Only selects specified attributes
                LogWrite_success "$computer logon scan completed"
                #Write-Host $Global:log_ID["log"]
            } elseif ($ID -eq [int]4634) {
                $Global:log_ID["log"] = "logoff"
                $Events | Select-Object -Property TargetUserSid,TargetUserName,TargetDomainName,TargetLogonId,LogonType,Id,Version,Level,Task,Opcode,Keywords,RecordId,ProviderName,ProviderId,LogName,ProcessId,ThreadId,MachineName,TimeCreated,ActivityId,RelatedActivityId,ContainerLog,LevelDisplayName,OpcodeDisplayName,TaskDisplayName  # Only selects specified attributes
                LogWrite_success "$computer logoff scan completed"
                #Write-Host $Global:log_ID["log"]
            } elseif ($ID -eq [int]4688) {
                $Global:log_ID["log"] = "process"
                $Events | Select-Object -Property SubjectUserSid,SubjectUserName,SubjectDomainName,SubjectLogonId,NewProcessId,NewProcessName,TokenElevationType,ProcessId,CommandLine,Id,Version,Level,Task,Opcode,Keywords,RecordId,ProviderName,ProviderId,LogName,ThreadId,MachineName,UserId,TimeCreated,ActivityId,RelatedActivityId,ContainerLog,LevelDisplayName,OpcodeDisplayName,TaskDisplayName
                LogWrite_success "$computer process scan completed"
                #Write-Host $Global:log_ID["log"]
            } elseif ($ID -eq "4648") {
                $Global:log_ID["log"] = "runas"
                $Events | Select-Object -Property SubjectUserSid,SubjectUserName,SubjectDomainName,SubjectLogonId,LogonGuid,TargetUserName,TargetDomainName,TargetLogonGuid,TargetServerName,TargetInfo,ProcessId,ProcessName,IpAddress,IpPort,Id,Version,Qualifiers,Level,Task,Opcode,Keywords,RecordId,ProviderName,ProviderId,LogName,ThreadId,MachineName,UserId,TimeCreated,ActivityId,RelatedActivityId,ContainerLog,LevelDisplayName,OpcodeDisplayName,TaskDisplayName
                LogWrite_success "$computer runas scan completed"
                #Write-Host $Global:log_ID["runas"]
            } elseif ($ID -eq "4672") {
                $Global:log_ID["log"] = "admin"
                foreach ($event in $Events) {
                    $privs = $event.PrivilegeList -replace '[\t\t\t]',''
                    #Write-Host $privs
                    #Write-Host $Events.GetType()
                    $parsedPrivs = ParseAdminLogs $event $privs
                    $parsedPrivs | Select-Object *
                    #Write-Host $event.PrivilegeList 
                }
                #$Events | Select-Object -Property SubjectUserSid,SubjectUserName,SubjectDomainName,SubjectLogonId,PrivilegeList,Id,Version,Qualifiers,Level,Task,Opcode,Keywords,RecordId,ProviderName,ProviderId,LogName,ProcessId,ThreadId,MachineName,UserId,TimeCreated,ActivityId,RelatedActivityId,ContainerLog,MatchedQueryIds,Bookmark,LevelDisplayName,OpcodeDisplayName,TaskDisplayName,KeywordsDisplayNames,Properties
                LogWrite_success "$computer admin scan completed"
                #Write-Host $Global:log_ID["admin"]
            } else {
                $Events | Select-Object *
                LogWrite_success "$computer $ID scan completed"
                Write-Host "You selected an event ID that has not been normalized (i.e. the columns are jacked up)"
            }

            #$Events | Select-Object *  # selects all properties of object; use this to develop what fields (Properties) to select     
        }            
        Catch {            
            if ($_.Exception -like "*No events were found that match criteria*") {           
                Write-Warning "[$computer] $_" # TODO: create log file with failed event ID, computername, time, etc           
                LogWrite_failure "[$computer]: no events found" 
            } else {            
                Write-Warning "[$computer] Event ID:$ID $_"  # Something bad happened
                LogWrite_failure "$computer EventID:$ID $_"         
            }            
        }
        Return            
    }

    $taskArray = @(106,200,201,141)
    if ($taskArray -like $ID) {
        Try { 
            if ($time -like "hours") {
                $hours = (Get-Date).AddHours(-1)  # AddHours function subtracts X hour from current time
                $filter = @{Logname="Microsoft-Windows-TaskScheduler/Operational";Id=$ID;StartTime=$hours}  
            } else {
                $days = (Get-Date).AddDays(-1)  # AddDays function subtracs X days from current time
                $filter = @{Logname="Microsoft-Windows-TaskScheduler/Operational";Id=$ID;StartTime=$days}
            }

            $Events = Get-WinEvent -ComputerName $computer -FilterHashtable $filter -ErrorAction Stop   
                     
            ForEach ($Event in $Events) {  
                # Convert the event to XML            
                $eventXML = [xml]$Event.ToXml()            
                # Iterate through each one of the XML message properties            
                For ($i=0; $i -lt $eventXML.Event.EventData.Data.Count; $i++) {            
                    # Append these as object properties            
                    Add-Member -InputObject $Event -MemberType NoteProperty -Force -Name $eventXML.Event.EventData.Data[$i].name -Value $eventXML.Event.EventData.Data[$i].'#text'           
                }            
            }
            
            if ($ID -eq 106) {
                $Global:log_ID["log"] = "taskCreated"
                $Events | Select-Object TaskName,UserContext,Id,Version,Level,Task,Opcode,Keywords,RecordId,ProviderName,ProviderId,LogName,ProcessId,ThreadId,MachineName,UserId,TimeCreated,ActivityId,RelatedActivityId,ContainerLog,LevelDisplayName,OpcodeDisplayName,TaskDisplayName
                LogWrite_success "$computer taskCreated scan completed"
                #Write-Host $Global:log_ID["log"]
            } elseif ($ID -eq 200) {
                $Global:log_ID["log"] = "taskStarted"
                $Events | Select-Object -Property TaskName,ActionName,TaskInstanceId,EnginePID,Id,Version,Level,Task,Opcode,Keywords,RecordId,ProviderName,ProviderId,LogName,ProcessId,ThreadId,MachineName,UserId,TimeCreated,ActivityId,RelatedActivityId,ContainerLog,LevelDisplayName,OpcodeDisplayName,TaskDisplayName
                LogWrite_success "$computer taskStarted scan completed"
                #Write-Host $Global:log_ID["log"]
            } elseif ($ID -eq 201) {
                $Global:log_ID["log"] = "taskCompleted"
                $Events | Select-Object -Property TaskName,TaskInstanceId,ActionName,ResultCode,EnginePID,Id,Version,Level,Task,Opcode,Keywords,RecordId,ProviderName,ProviderId,LogName,ProcessId,ThreadId,MachineName,UserId,TimeCreated,ActivityId,RelatedActivityId,ContainerLog,LevelDisplayName,OpcodeDisplayName,TaskDisplayName
                LogWrite_success "$computer taskCompleted scan completed"
            } elseif ($ID -eq 141) {
                $Global:log_ID["log"] = "taskDeleted"
                $Events | Select-Object -Property TaskName,UserName,Id,Version,Level,Task,Opcode,Keywords,RecordId,ProviderName,ProviderId,LogName,ProcessId,ThreadId,MachineName,UserId,TimeCreated,ActivityId,RelatedActivityId,ContainerLog,LevelDisplayName,OpcodeDisplayName,TaskDisplayName 
                LogWrite_success "$computer taskDeleted scan completed"
            } else {
               $Events | Select-Object *
               LogWrite_success "$computer $ID scan completed"
               Write-Host "You selected an event ID that has not been normalized (i.e. the columns are jacked up)" 
            }   
        }

        Catch {
            if ($_.Exception -like "*No events were found that match criteria*") {           
                Write-Warning "[$computer] $_" # TODO: create log file with failed event ID, computername, time, etc           
                LogWrite_failure "[$computer]: no events found" 
            } else {            
                Write-Warning "[$computer] Event ID:$ID $_"  # Something bad happened
                LogWrite_failure "$computer EventID:$ID $_"         
            }  
        }
    }
    
    else {
        Write-Host "I don't know how to process that Event-ID; Use Event ID-4624,4634,4688,4648,4672,106,200,201,or 141"
        LogWrite_failure "[$computer]: I don't know how to process EventID:$ID"
    }
}


$log_ID = @{} 
$log_name = $log_ID["log"]    


Function ParseAdminLogs {  # this function creates new admin log (4672) object with privilige attribute seperated by '-'
    [CmdletBinding()]
    param (
        [PsObject]$event,
        [string]$Privs
    )
    BEGIN {
        $oldProps = $event | Select-Object -Property SubjectUserSid,SubjectUserName,SubjectDomainName,SubjectLogonId,Id,Version,Qualifiers,Level,Task,Opcode,Keywords,RecordId,ProviderName,ProviderId,LogName,ProcessId,ThreadId,MachineName,UserId,TimeCreated,ActivityId,RelatedActivityId,ContainerLog,LevelDisplayName,OpcodeDisplayName,TaskDisplayName
        #Write-Host $oldProps
        $privArray = New-Object System.Collections.ArrayList
        #Write-Host $privs
        foreach ($priv in $Privs) {
            #Write-Host $priv
            #Write-Host "\n"
            $parsedPrivs = $privs -replace '\n','-'
            #Write-Host $parsedPrivs
            #$privArray.Add($priv)
        }
    }
    PROCESS {
        $oldProps | Add-Member -MemberType NoteProperty -Name Privileges -Value $parsedPrivs
    }
    END {
    
        $obj = New-Object -TypeName PsObject
        #foreach ($Value in $oldProps.GetEnumerator()) {
        foreach ($Value in $oldProps) {
                        
            $obj | Add-Member -MemberType NoteProperty -Force -Name TimeCreated -Value $Value.TimeCreated 
            $obj | Add-Member -MemberType NoteProperty -Force -Name MachineName -Value $Value.MachineName
            $obj | Add-Member -MemberType NoteProperty -Force -Name UserName -Value $Value.SubjectUserName
            $obj | Add-Member -MemberType NoteProperty -Force -Name UserSid -Value $Value.SubjectUserSid
            $obj | Add-Member -MemberType NoteProperty -Force -Name Privileges -Value $Value.Privileges
            $obj | Add-Member -MemberType NoteProperty -Force -Name DomainName -Value $Value.SubjectDomainName
            $obj | Add-Member -MemberType NoteProperty -Force -Name LogonID -Value $Value.SubjectLogonId
            $obj | Add-Member -MemberType NoteProperty -Force -Name ID -Value $Value.ID
            $obj | Add-Member -MemberType NoteProperty -Force -Name ProviderName -Value $Value.ProviderName
            $obj | Add-Member -MemberType NoteProperty -Force -Name TaskDisplayName -Value $Value.TaskDisplayName
            $obj | Add-Member -MemberType NoteProperty -Force -Name OpcodeDisplayName -Value $Value.OpcodeDisplayName
            return $obj | Select-Object *
            
        }    
    }
}

Function Copy-Property {
    [CmdletBinding()]
    param (
        [PsObject]$from,
        [PsObject]$to
    )

}


Function LogWrite_success
{
   Param ([string]$logstring)

   $computername = $computer
   $stamp = (Get-Date).ToString("yyyy/MM/dd HH:mm:ss")
   $log_entry = $logstring + " " + $stamp
   Add-content $LogfileSuccess -value $log_entry
}

Function LogWrite_failure
{
   Param ([string]$logstring)

   $computername = $computer
   $stamp = (Get-Date).ToString("yyyy/MM/dd HH:mm:ss")
   $log_entry = $logstring + " " + $stamp
   Add-content $LogfileFailure -value $log_entry
}
 
function Get-Logs {
param([string[]]$computernames,[int[]]$Event_ID,[string]$time,[bool]$test,[string]$cred)

# create logfile to log computername, timestamp and 
$USER = [Environment]::UserName 
$LogfileSuccess = "C:\Users\$USER\Desktop\success.log"
$LogfileFailure = "C:\Users\$USER\Desktop\failure.log"


$hash_table = @{
    logon = 4624
    logoff = 4634
    process = 4688
    runas = 4648
    admin = 4672
    taskScheduled = 106
    taskExecuted = 200
    taskCompleted = 201
    taskDeleted = 141
}

foreach ($log_type in $hash_table.GetEnumerator()) {
    if ($log_type.Value -like $Event_ID) {
        $log_name = $log_type.Key
    }
}

$USER = [Environment]::UserName  
    foreach ($computer in $computernames) {
        if ((Test-Connection -ComputerName $computer -Count 1 -ea 0) -and ($test -ne $true)) {
            #Invoke-Command -ScriptBlock ${function:Get-LogsWorker} -ArgumentList $computer, $Event_ID, $time| Out-GridView  # use this for testing; prints output to excel like grid output
            Invoke-Command -ScriptBlock ${function:Get-LogsWorker} -ArgumentList $computer,$Event_ID, $time | Export-Csv C:\Users\$USER\Desktop\$computer-$log_name-$Event_ID.csv  
        } elseif ((Test-Connection -ComputerName $computer -Count 1 -ea 0) -and ($test = $true)) {
            Invoke-Command -ScriptBlock ${function:Get-LogsWorker} -ArgumentList $computer, $Event_ID, $time | Out-GridView   # use this for testing; prints output to excel like grid output
        } else {
            Write-Warning "$computer could not be contacted"
            LogWrite_failure "$computer could not be contacted"
        }
    }  
}

## USAGE ##

# Open up powershell as user with admin creds, hit the play button, and then enter option 1 | 2 into the powershell terminal

#$creds = Get-Credential -Credential \<domain>\<adminAccount>
#[option 1] Get-Logs -computernames $computers -Event_ID <ID> -time [hours | days] [-creds] [-test [$true]]  # creds argument is optional, must uncommen $creds variable
#[option 2] same as option 1, but uncomment computers variable with path to computers.txt
#$computers = "localhost"  # use this to test script on localhost
#$computers = Get-Content C:\<path>\computers.txt # creats array from list of computers from file; TODO: consider using Get-ADComputer
#[note]: hours | days argument is hard coded to 1 hour in the past or 1 day in the past

## Windows Event IDs to detect SMB lateral movement ##

#(4624) Logon
#(4634) Logoff
#(4688) New process creation
#(4648) runas command
#(4672) admin rights
#(106) task scheduled
#(200) task executed
#(201) task completed
#(141) task removed

# TODO (have not completed yet)
#(601,4697) # service creation 
#(5140) # network share 