<#
.SYNOPSIS
Performs infrastructure health checks across multiple enterprise services.

.DESCRIPTION
The SystemHealthChecks module provides a collection of functions used to
evaluate the operational health of core infrastructure components including:

• Active Directory Domain Controllers
• Windows Servers
• SQL Servers
• SCVMM Servers
• Network Load Balancing Clusters
• Windows Failover Clusters
• DFS Namespaces

The module can return results as PowerShell objects for automation or
generate formatted HTML reports for operational monitoring.

This module is designed for system administrators and infrastructure
engineers responsible for maintaining enterprise environments.

.NOTES
Author: Darrell Nielsen
Version: 1.07
Initial Release: 01.07.2016

This module collects system health data and may require administrative
privileges to access remote systems and services.

Tags:
asfd
health
monitor

.LINK
Get-Help Check-ADHealth
Get-Help Check-GeneralWindows
Get-Help Check-SQL
Get-Help Check-SCVMM
Get-Help Check-NLB
Get-Help Check-FailoverCluster
Get-Help Check-DFSNameSpace

.EXAMPLE
Import-Module SystemHealthChecks

Loads the health check module.

.EXAMPLE
Check-ADHealth

Runs health checks against all domain controllers in the forest.

.EXAMPLE
Check-GeneralWindows -Computers Server01,Server02

Runs general Windows health checks on the specified servers.

.EXAMPLE
Check-GeneralWindows -Computers Server01 -Report

Runs checks and generates an HTML report.

.EXAMPLE
Check-SQL -SqlServerAndInstance SQL01\PROD

Runs SQL Server health checks against the specified instance.

.EXAMPLE
Check-FailoverCluster -FailoverClusters Cluster01 -Report

Runs cluster health checks and outputs an HTML report.

#>
function formatStringStatus
{
	param([string[]]$StringArray, $RemovePart)

	$returnString = ""
	for ($count=0; $count -lt $StringArray.Length; $count++)
	{
		$currentString = $StringArray[$count]
		If ($RemovePart -ne $null)
		{
			$currentString = $currentString.Replace($RemovePart, "")
		}
		If ($count -eq 0)
		{
			$returnString = $currentString
		}
		else 
		{
			$returnString = $returnString +  ", " + $currentString
		}
	}
	return $returnString
}
#------------------------------------------------#
#endregion

Function Get-CheckSystemHealthVersion
{
	return "01.07.2016"

	<#

	01.07.2016
	-initial version with initial checks

	#>
}

function Begin-HTML {
    Param (
        [Parameter(ValueFromPipelineByPropertyName=$true,
                   ValueFromPipeline=$true,
                   Position=0)]
        [string]$ReportPath="$env:USERPROFILE\Desktop\HealthCheck_Report.html"
    )

    if((test-path $reportpath) -like $false) {
        
        new-item $reportpath -type file

    }
	$report = $ReportPath

        Clear-Content $report 
        Add-Content $report "<html>" 
        Add-Content $report "<head>" 
        Add-Content $report "<meta http-equiv='Content-Type' content='text/html; charset=iso-8859-1'>" 
        Add-Content $report '<title>AD Status Report</title>' 
        add-content $report '<STYLE TYPE="text/css">' 
        add-content $report  "<!--" 
        add-content $report  "td {" 
        add-content $report  "font-family: Tahoma;" 
        add-content $report  "font-size: 11px;" 
        add-content $report  "border-top: 1px solid #999999;" 
        add-content $report  "border-right: 1px solid #999999;" 
        add-content $report  "border-bottom: 1px solid #999999;" 
        add-content $report  "border-left: 1px solid #999999;" 
        add-content $report  "padding-top: 0px;" 
        add-content $report  "padding-right: 0px;" 
        add-content $report  "padding-bottom: 0px;" 
        add-content $report  "padding-left: 0px;" 
        add-content $report  "}" 
        add-content $report  "body {" 
        add-content $report  "margin-left: 5px;" 
        add-content $report  "margin-top: 5px;" 
        add-content $report  "margin-right: 0px;" 
        add-content $report  "margin-bottom: 10px;" 
        add-content $report  "" 
        add-content $report  "table {" 
        add-content $report  "border: thin solid #000000;" 
        add-content $report  "}" 
        add-content $report  "-->" 
        add-content $report  "</style>" 
        Add-Content $report "</head>" 
        Add-Content $report "<body>" 
    
}

function End-HTML {
     Param (
        [Parameter(ValueFromPipelineByPropertyName=$true,
                   ValueFromPipeline=$true,
                   Position=0)]
        [string]$ReportPath="$env:USERPROFILE\Desktop\HealthCheck_Report.html"
     )
    $report = $ReportPath
    ###### CLOSE REPORT #####
    Add-Content $report "</body>" 
    Add-Content $report "</html>" 
}

function Build-HTML
{

    Param
    (
        # Param1 help description
        [Parameter(ValueFromPipelineByPropertyName=$true,
                   ValueFromPipeline=$true,
                   Position=0)]
        $Object,

        [Parameter(ValueFromPipelineByPropertyName=$true,
                   ValueFromPipeline=$true,
                   Position=1)]
        [string]$Header,

        [Parameter(ValueFromPipelineByPropertyName=$true,
                   ValueFromPipeline=$true,
                   Position=2)]
        [string]$ReportPath="$env:USERPROFILE\Desktop\HealthCheck_Report.html"


    )

    $goodWords = "Success","Online","OK","Up","Running", "Connected", "Plenty", "Healthy", "LowUtilization", "Passed", "Pass"
    $badWords = "Fail","Offline","Down","Failed","NotRunning", "Stopped", "Disconnected", "VeryLow", "Unhealthy", "HighUtilization"
	$mehWords = "Caution", "Warning", "Partial", "Yellow", "Suspect", "Unable to obtain", "GettingLow"

	function isKeyword
	{
		param([String[]]$word)

		$allkeywords = $goodWords + $badWords + $mehWords
		$result = $false 
		foreach ($keyword in $allkeywords)
		{
			foreach ($w in $word)
			{
				if ($w -match $keyword)
				{
					$result = $true 
				}
			}

		}

		return $result
	}

	function isGoodWord
	{
		param([String[]]$word)

		$goodWords  = $goodWords
		$result = $false 
		foreach ($keyword in $goodWords)
		{
			foreach ($w in $word)
			{
				if ($w -match $keyword)
				{
					$result = $true 
				}
			}

		}

		return $result
	}

	function isBadWord
	{
		param([String[]]$word)

		$badwords =  $badWords
		$result = $false 
		foreach ($keyword in $badwords)
		{
			foreach ($w in $word)
			{
				if ($w -match $keyword)
				{
					$result = $true 
				}
			}

		}

		return $result
	}

	function isMehWord
	{
		param([String[]]$word)

		$mehwords =  $mehWords
		$result = $false 
		foreach ($keyword in $mehwords)
		{
			foreach ($w in $word)
			{
				if ($w -match $keyword)
				{
					$result = $true 
				}
			}

		}

		return $result

	}

    $report = $reportPath



    add-content $report  "<table width='100%'>" 
    add-content $report  "<tr bgcolor='Lavender'>" 
    add-content $report  "<td colspan='7' height='25' align='center'>" 
    add-content $report  "<font face='tahoma' color='#003399' size='4'><strong>$header</strong></font>" 
    add-content $report  "</td>" 
    add-content $report  "</tr>" 
    add-content $report  "</table>" 

	$colTitles = @()
	$colTitles = $object[0].PSObject.Properties.Name
	foreach ($obj in $Object)
	{
		foreach ($title in $Obj.psobject.properties.name)
		{
			If ($title -notin $colTitles) {$colTitles += $title}
		}
	}


    $reportColTitles = @()

    foreach ($colTitle in $colTitles) {

        if ($colTitle -eq $colTitles[0]) { $reportColTitles += $colTitle; Continue }
        
        #if ( ($goodWords -contains $object.$colTitle[0]) -or ($badWords -contains $object.$colTitle[0] )) {
		if  (isKeyword($Object.$colTitle)) {

            $reportColTitles += $colTitle

        }

    }

    $colTitlesCount = $reportColTitles.Count

    add-content $report  "<table width='100%'>" 
    Add-Content $report  "<tr bgcolor='IndianRed'>"


    foreach ($colTitle in $reportColTitles){

       Add-Content $report "<td width='5%' align='center'><B>$colTitle</B></td>" 

    }


        foreach ($obj in $object) {
            add-content $report  "<tr>"  

			$cObjColTitles = $Obj.psobject.properties.name

            for($i = 0; $i -lt $reportColTitles.Count; $i++) {
                
                $text = $obj.$($reportColTitles[$i])

                if ($i -eq 0) { add-content $report "<td bgcolor= 'GainsBoro' align=center>  <B>$text</B></td>" }

				elseif (!($cObjColTitles[$i] -notmatch $text)) {continue}
                
                elseif (isGoodWord($text)) { Add-Content $report "<td bgcolor= 'Aquamarine' align=center><B>$text</B></td>" }
                
                elseif (isBadWord($text)) { Add-Content $report "<td bgcolor= 'LightPink' align=center><B>$text</B></td>" } 
				
				elseif (isMehWord($text)) { Add-Content $report "<td bgcolor= 'CornYellow' align=center><B>$test</B></td>"}          

            }


            add-content $report  "</tr>" 

        }
    
}



<# Old Functions
function Check-ConnectionStatus {
    Param (

        [Parameter(ValueFromPipelineByPropertyName=$true,
                   ValueFromPipeline=$true,
                   Position=0)]
        $serverList      
    )

    Write-Host ""
    Write-Host "----------------------------------------------------------"
    Write-Host " Checking connection status of servers.."
    Write-Host "----------------------------------------------------------"
    Write-Host ""

    $colObjs = @()

    foreach ($server in $serverList) {

        Write-Host "$server .." -NoNewline


        $test = Test-Connection -ComputerName $server -Count 2 -Quiet

        if ($test -eq $true) {
            Write-Host "on" -ForegroundColor Green
            $HealthCheckStatus = "Online"

        }
        else {
            Write-Host "off" -ForegroundColor Red
            $HealthCheckStatus = "Offline"

            $continue = $false
        }


        $props = [Ordered]@{Server=$server; HealthCheckStatus=$HealthCheckStatus;}
        $colObjs += (New-Object -TypeName psobject -Property $props)
    }

    return $colObjs
}

function Check-AutoServices {
    Param (

        [Parameter(ValueFromPipelineByPropertyName=$true,
                   ValueFromPipeline=$true,
                   Position=0)]
        $serverList      
    )

    Write-Host ""
    Write-Host "----------------------------------------------------------"
    Write-Host " Checking services on servers.."
    Write-Host "----------------------------------------------------------"
    Write-Host ""

    $colObjs = @()

    foreach ($server in $serverList) {

        
        Write-Host "$server .." -NoNewline
        
        
        try{
            $services = Get-CimInstance win32_service -Filter "StartMode = 'Auto' AND state != 'Running' AND ExitCode != '0' AND Name != 'iphlpsvc'" -ComputerName $server -ErrorAction SilentlyContinue
        }
        catch{
            Write-Host "failed" -ForegroundColor Red
            continue
        }

        if ($services) {
            Write-Host "found: " -NoNewline

                foreach ($service in $services) {
                    Write-Host "$($service.Name) ($($service.ExitCode)) " -ForegroundColor Yellow -NoNewline


                } 

            $HealthCheckStatus = "Failed"
            $Details += "$($service.Name) ($($service.ExitCode)) "
            
            Write-Host ""
        }
        else{
            Write-Host "OK" -ForegroundColor Green
            $HealthCheckStatus = "OK"
        }

        $props = [Ordered]@{Server=$server; HealthCheckStatus=$HealthCheckStatus; Details=$Details;}
        $colObjs += (New-Object -TypeName psobject -Property $props)

    }

    return $colObjs
}
#>


function Check-DFSNameSpace {


    Write-Host ""
    Write-Host "----------------------------------------------------------"
    Write-Host " Checking DFS Namespaces.."
    Write-Host "----------------------------------------------------------"
    Write-Host ""

    $colObjs = @()
    
    $DFSRs = Get-DfsnRoot -ErrorAction SilentlyContinue

    foreach ($dfsr in $DFSRs) {

        Write-Host "$($dfsr.Path) .." -NoNewline


        if ($dfsr.State -eq "Online"){
            $HealthCheckStatus = "Online"
            Write-Host "OK" -ForegroundColor Green
        }
        else{
            $HealthCheckStatus = "failed"
             Write-Host "failed" -ForegroundColor Red
        }
        $props = [Ordered]@{DFSRPath=$dfsr.path; HealthCheckStatus=$HealthCheckStatus;}
        $colObjs += (New-Object -TypeName psobject -Property $props)
    }
    return $colObjs
}

function Check-ADHealth {

Write-Host ""
Write-Host "----------------------------------------------------------"
Write-Host " Starting Active Directory Health Check.."
Write-Host "----------------------------------------------------------"
Write-Host ""


###### BEGIN AD HEALTH CHECK ######

##### Clean up aliases ########
	$timeout = 180
	If (get-module virtualmachinemanager)
	{
		If (Get-Alias stop-job -ErrorAction SilentlyContinue) {remove-item alias:stop-job}
		If (Get-Alias restart-job -ErrorAction SilentlyContinue) { remove-item alias:restart-job}
		If (Get-Alias get-job -ErrorAction SilentlyContinue) {remove-item alias:get-job}
	}
 
 

#####################################Get ALL DC Servers#################################
$getForest = [system.directoryservices.activedirectory.Forest]::GetCurrentForest()

$DCServers = $getForest.domains | ForEach-Object {$_.DomainControllers} | ForEach-Object {$_.Name} 

$colObjs = @()

################Ping Test######

foreach ($DC in $DCServers){
$Identity = $DC

if ( Test-Connection -ComputerName $DC -Count 1 -ErrorAction SilentlyContinue ) {
Write-Host $DC `t $DC `t Ping Success -ForegroundColor Green
 
$PingStatus = "Passed"

                ##############Netlogon Service Status################
		$serviceStatus = start-job -scriptblock {get-service -ComputerName $($args[0]) -Name "Netlogon" -ErrorAction SilentlyContinue} -ArgumentList $DC
                [void](wait-job $serviceStatus -timeout $timeout)
                if($serviceStatus.state -like "Running")
                {
                 Write-Host $DC `t Netlogon Service TimeOut -ForegroundColor Yellow
                 stop-job $serviceStatus
                }
                else
                {
                $serviceStatus1 = Receive-job $serviceStatus
                 if ($serviceStatus1.status -eq "Running") {
 		   Write-Host $DC `t $serviceStatus1.name `t $serviceStatus1.status -ForegroundColor Green 
         	   $svcName = $serviceStatus1.name 
         	   $svcState = $serviceStatus1.status          
         	  $NetlogonService = "Passed"
                  }
                 else 
                  { 
       		  Write-Host $DC `t $serviceStatus1.name `t $serviceStatus1.status -ForegroundColor Red 
         	  $svcName = $serviceStatus1.name 
         	  $svcState = $serviceStatus1.status          
         	  $NetlogonService = "Failed"
                  } 
                }
               ######################################################
                ##############NTDS Service Status################
		$serviceStatus = start-job -scriptblock {get-service -ComputerName $($args[0]) -Name "NTDS" -ErrorAction SilentlyContinue} -ArgumentList $DC
                [void](wait-job $serviceStatus -timeout $timeout)
                if($serviceStatus.state -like "Running")
                {
                 Write-Host $DC `t NTDS Service TimeOut -ForegroundColor Yellow
                 stop-job $serviceStatus
                }
                else
                {
                $serviceStatus1 = Receive-job $serviceStatus
                 if ($serviceStatus1.status -eq "Running") {
 		   Write-Host $DC `t $serviceStatus1.name `t $serviceStatus1.status -ForegroundColor Green 
         	   $svcName = $serviceStatus1.name 
         	   $svcState = $serviceStatus1.status          
         	   $NTDSService = "Passed"
                  }
                 else 
                  { 
       		  Write-Host $DC `t $serviceStatus1.name `t $serviceStatus1.status -ForegroundColor Red 
         	  $svcName = $serviceStatus1.name 
         	  $svcState = $serviceStatus1.status          
         		$NTDSService = "Failed"
                  } 
                }
               ######################################################
                ##############DNS Service Status################
		$serviceStatus = start-job -scriptblock {get-service -ComputerName $($args[0]) -Name "DNS" -ErrorAction SilentlyContinue} -ArgumentList $DC
                [void](wait-job $serviceStatus -timeout $timeout)
                if($serviceStatus.state -like "Running")
                {
                 Write-Host $DC `t DNS Server Service TimeOut -ForegroundColor Yellow
                 stop-job $serviceStatus
                }
                else
                {
                $serviceStatus1 = Receive-job $serviceStatus
                 if ($serviceStatus1.status -eq "Running") {
 		   Write-Host $DC `t $serviceStatus1.name `t $serviceStatus1.status -ForegroundColor Green 
         	   $svcName = $serviceStatus1.name 
         	   $svcState = $serviceStatus1.status          
					$DNSService = "Passed"
                  }
                 else 
                  { 
       		  Write-Host $DC `t $serviceStatus1.name `t $serviceStatus1.status -ForegroundColor Red 
         	  $svcName = $serviceStatus1.name 
         	  $svcState = $serviceStatus1.status          
					$DNSService = "Failed"
                  } 
                }
               ######################################################

               ####################Netlogons status##################
               add-type -AssemblyName microsoft.visualbasic 
               $cmp = "microsoft.visualbasic.strings" -as [type]
               $sysvol = start-job -scriptblock {dcdiag /test:netlogons /s:$($args[0])} -ArgumentList $DC
               [void](wait-job $sysvol -timeout $timeout)
               if($sysvol.state -like "Running")
               {
               Write-Host $DC `t Netlogons Test TimeOut -ForegroundColor Yellow
               stop-job $sysvol
               }
               else
               {
               $sysvol1 = Receive-job $sysvol
               if($cmp::instr($sysvol1, "passed test NetLogons"))
                  {
                  Write-Host $DC `t Netlogons Test passed -ForegroundColor Green
					$NetLogonTest = "Passed"
                  }
               else
                  {
                  Write-Host $DC `t Netlogons Test Failed -ForegroundColor Red
					$NetLogonTest = "Failed"
                  }
                }
               ########################################################
               ####################Replications status##################
               add-type -AssemblyName microsoft.visualbasic 
               $cmp = "microsoft.visualbasic.strings" -as [type]
               $sysvol = start-job -scriptblock {dcdiag /test:Replications /s:$($args[0])} -ArgumentList $DC
               [void](wait-job $sysvol -timeout $timeout)
               if($sysvol.state -like "Running")
               {
               Write-Host $DC `t Replications Test TimeOut -ForegroundColor Yellow
               stop-job $sysvol
               }
               else
               {
               $sysvol1 = Receive-job $sysvol
               if($cmp::instr($sysvol1, "passed test Replications"))
                  {
                  Write-Host $DC `t Replications Test passed -ForegroundColor Green
                  $ReplTest = "Passed"
                  }
               else
                  {
                  Write-Host $DC `t Replications Test Failed -ForegroundColor Red
                  $ReplTest = "Failed"
                  }
                }
               ########################################################
	       ####################Services status##################
               add-type -AssemblyName microsoft.visualbasic 
               $cmp = "microsoft.visualbasic.strings" -as [type]
               $sysvol = start-job -scriptblock {dcdiag /test:Services /s:$($args[0])} -ArgumentList $DC
               [void](wait-job $sysvol -timeout $timeout)
               if($sysvol.state -like "Running")
               {
               Write-Host $DC `t Services Test TimeOut -ForegroundColor Yellow
               stop-job $sysvol
               }
               else
               {
               $sysvol1 = Receive-job $sysvol
               if($cmp::instr($sysvol1, "passed test Services"))
                  {
                  Write-Host $DC `t Services Test passed -ForegroundColor Green
					$ServicesTest = "Passed"
                  }
               else
                  {
                  Write-Host $DC `t Services Test Failed -ForegroundColor Red
					$ServicesTest = "Failed"
                  }
                }
               ########################################################
	       ####################Advertising status##################
               add-type -AssemblyName microsoft.visualbasic 
               $cmp = "microsoft.visualbasic.strings" -as [type]
               $sysvol = start-job -scriptblock {dcdiag /test:Advertising /s:$($args[0])} -ArgumentList $DC
               [void](wait-job $sysvol -timeout $timeout)
               if($sysvol.state -like "Running")
               {
               Write-Host $DC `t Advertising Test TimeOut -ForegroundColor Yellow
               stop-job $sysvol
               }
               else
               {
               $sysvol1 = Receive-job $sysvol
               if($cmp::instr($sysvol1, "passed test Advertising"))
                  {
                  Write-Host $DC `t Advertising Test passed -ForegroundColor Green
				  $AdvertisingTest = "Passed"
                  }
               else
                  {
                  Write-Host $DC `t Advertising Test Failed -ForegroundColor Red
				  $AdvertisingTest = "Failed"
                  }
                }
               ########################################################
	       ####################FSMOCheck status##################
               add-type -AssemblyName microsoft.visualbasic 
               $cmp = "microsoft.visualbasic.strings" -as [type]
               $sysvol = start-job -scriptblock {dcdiag /test:FSMOCheck /s:$($args[0])} -ArgumentList $DC
               [void](wait-job $sysvol -timeout $timeout)
               if($sysvol.state -like "Running")
               {
               Write-Host $DC `t FSMOCheck Test TimeOut -ForegroundColor Yellow
               stop-job $sysvol
               }
               else
               {
               $sysvol1 = Receive-job $sysvol
               if($cmp::instr($sysvol1, "passed test FsmoCheck"))
                  {
                  Write-Host $DC `t FSMOCheck Test passed -ForegroundColor Green
                  $FSMOCheckTest = "Passed"
                  }
               else
                  {
                  Write-Host $DC `t FSMOCheck Test Failed -ForegroundColor Red

				  $FSMOCheckTest = "Failed"
                  }
                }
               ########################################################
		$props = [Ordered]@{Server=$DC; PingStatus=$PingStatus; NetLogonService=$NetLogonService; NTDSService=$NTDSService; DNSService=$DNSService; NetlogonTest=$NetlogonTest; ReplTest=$ReplTest; ServicesTest=$ServicesTest; AdvertisingTest=$AdvertisingTest; FSMOCheckTest=$FSMOCheckTest; }
                
} 
else
              {
Write-Host $DC `t $DC `t Ping Fail -ForegroundColor Red
		$PingStatus = "Failed"

        $props = [Ordered]@{Server=$DC; PingStatus=$PingStatus; NetLogonService=$NetLogonService; NTDSService=$NTDSService; DNSService=$DNSService; NetlogonTest=$NetlogonTest; ReplTest=$ReplTest; ServicesTest=$ServicesTest; AdvertisingTest=$AdvertisingTest; FSMOCheckTest=$FSMOCheckTest; }

}         
        $colObjs += (New-Object -TypeName psobject -Property $props)      
} 




return $colObjs


###### END AD HEALTH CHECK
}

function Check-GeneralWindows
{
	[CmdletBinding()]

	param
	(
		[Parameter(Mandatory, ValueFromPipeline=$true)]
		[String[]]$Computers,

		[Parameter()]
		[switch]$Report,

		[Parameter()]
		[switch]$NoOutput
	)

	$retObjs = @()
	$i = 0

	If (!$NoOutput)
	{
		Write-Host "`n-------------------------------------------------"
		Write-Host " Running General Windows health checks"
		Write-Host "-------------------------------------------------"
	}

	foreach ($computer in $computers)
	{
		$computer = $Computer.ToUpper()
		$i++
		$pingResult = $false 
		$wsmanResult = $false
		Write-Progress -Activity "Checking general Windows health of $computer" -Status "Checking $computer ($i of $($computers.count))" -PercentComplete ($i / $computers.Count * 100)
		$obj = New-Object -TypeName psobject 
		Add-Member -InputObject $obj -MemberType NoteProperty -Name "Computer" -Value $computer
		If (!$NoOutput)
		{
			Write-Host "`n$computer"
			Write-Host "--Ping Test .. " -NoNewline 
		}

		# test ping
		If (Test-Connection -Quiet -ComputerName $computer) 
		{
			Add-Member -InputObject $obj -MemberType NoteProperty -Name "Ping" -Value "Success"
			If (!$NoOutput) { Write-Host "Success" -ForegroundColor Green }
			$pingResult = $true
		}
		Else 
		{
			Add-Member -InputObject $obj -MemberType NoteProperty -Name "Ping" -Value "Failed"
			If (!$NoOutput) { Write-Host "Failed" -ForegroundColor Red }
		}

		# test remote management
		If (!$NoOutput) {Write-Host "--Remote Management Test .. " -NoNewline}
		If (Test-WSMan -ComputerName $computer -ErrorAction SilentlyContinue) 
		{
			Add-Member -InputObject $obj -MemberType NoteProperty -Name "Remote Management" -Value "Success"
			$wsmanResult = $true
			If (!$NoOutput) {Write-Host "Success" -ForegroundColor Green}
		}
		Else 
		{
			Add-Member -InputObject $obj -MemberType NoteProperty -Name "Remote Management" -Value "Failed"
			If (!$NoOutput) { Write-Host "Failed"  -ForegroundColor Red} 
		}
		If ($pingResult -eq $false -and $wsmanResult -eq $false) {write-host "--$computer is unreachable; skipping" -ForegroundColor Yellow; continue}
		

		# cpu average
		If (!$NoOutput) {Write-Host "--CPU Usage .. " -NoNewline}
		$cpuAvg = (Get-CimInstance -ComputerName $computer -ClassName win32_processor  | Measure-Object -Property loadpercentage -Average).average

		If ($cpuAvg -gt 85)
		{
			Add-Member -InputObject $obj -MemberType NoteProperty -Name "CPU" -Value "HighUtilization ($cpuAvg%)"
			If (!$NoOutput) {Write-Host "High Utilization, $cpuAvg%" -ForegroundColor Red }
		}
		ElseIf($cpuAvg -eq $null)
		{
			Add-Member -InputObject $obj -MemberType NoteProperty -Name "CPU" -Value "Unavailable"
			If (!$NoOutput) {Write-Host "Unavailable" }
		}
		Else
		{
			Add-Member -InputObject $obj -MemberType NoteProperty -Name "CPU" -Value "LowUtilization ($cpuAvg%)"
			If (!$NoOutput) {Write-Host "Low Utilization, $cpuAvg" -ForegroundColor Green }
		}

		# ram average
		If (!$NoOutput) {Write-Host "--Memory Availability .. " -NoNewline }
		$totalRamMB = "\Memory\Available MBytes"
		try
		{
			$availableRAM = (get-counter -ComputerName $computer "\Memory\Available Bytes" -ErrorAction Stop).countersamples.Cookedvalue / 1GB
			$usedRAM = (get-counter -ComputerName $computer  "\Memory\Committed Bytes" -ErrorAction Stop).countersamples.cookedvalue / 1GB
			$totalRam = $availableRAM + $usedRAM
			$unusedRam = $totalRAM - $usedRAM
			$percentRamFree = [Math]::Round($unusedRam / $totalRam * 100, 1)
			If ($percentRamFree -lt 10)
			{
				Add-Member -InputObject $obj -MemberType NoteProperty -Name "RAM" -Value "VeryLow ($percentRamFree% free)"
				If (!$NoOutput) {Write-Host "Very Low, $percentRamFree% free" -ForegroundColor Green }
			}
			ElseIf ($percentRamFree -lt 20)
			{
				Add-Member -InputObject $obj -MemberType NoteProperty -Name "RAM" -Value "GettingLow ($percentRamFree% free)"
				If (!$NoOutput) { Write-Host "Getting Low, $percentRamFree% free" -ForegroundColor Yellow }
			}
			ElseIf ($percentRamFree -gt 20)
			{
				Add-Member -InputObject $obj -MemberType NoteProperty -Name "RAM" -Value "Plenty ($percentRamFree% free)"
				If (!$NoOutput) { Write-Host "Pleny, $percentRamFree% free" -ForegroundColor Green }
			}
		}
		catch
		{
			Add-Member -InputObject $obj -MemberType NoteProperty -Name "RAM" -Value "Unavailable"
			If (!$NoOutput) { Write-Host "Unavailable"  }
		}


		# disk space
		If (!$NoOutput) {Write-Host "--Disk Space .. " -NoNewline}

		try
		{
			$session = New-PSSession -ComputerName $computer -ErrorAction Stop
			$driveResults = Invoke-Command -Session $session -ScriptBlock  {
			$drives = Get-PSDrive -PSProvider FileSystem | where Free -ne $null
			$driveObjs = @()
			foreach ($drive in $drives)
			{
				$totalSpace = [Math]::Round(($drive.Used + $drive.Free) / 1GB, 1)
				$usedSpace = [Math]::Round($drive.Used / 1GB, 1)
				$freeSpace = [Math]::Round($drive.Free / 1GB, 1)
				$percentFree = [Math]::Round($freeSpace / $totalSpace * 100, 1)
				$props = [Ordered]@{Drive="$($drive.root)"; TotalSpaceGB=$totalSpace; UsedSpaceGB=$usedSpace; FreeSpaceGB=$freeSpace; PercentFree=$percentFree}
				$driveObjs += (New-Object -TypeName psobject -Property $props)
			}
			return $driveObjs
		}
		}
		catch
		{
			If (!$NoOutput) {Write-Host "Unreachable" -ForegroundColor Yellow}
			Add-Member -InputObject $obj -MemberType NoteProperty -Name "Disk Drives" -Value "Unreachable"
		}

		$driveCount = 0
		foreach ($driveResult in $driveResults)
		{
			$driveName = $driveresult.Drive + " Drive"
			$percentFree = $driveResult.PercentFree
			$totalSpace = $driveResult.TotalSpaceGB
			$usedSpace = $driveResult.UsedSpaceGB
			$freeSpace = $driveResult.freeSpaceGb
			If ($driveResult.Percentfree -lt 10)
			{
				Add-Member -InputObject $obj -MemberType NoteProperty -Name $driveName -Value "VeryLow: $percentFree% Free ($freespace/$totalSpace GB)"
				If (!$NoOutput) {Write-Host "$driveName ($freespace/$totalspace GB)" -NoNewline -ForegroundColor Red }
			}
			ElseIf ($percentFree -lt 20)
			{
				Add-Member -InputObject $obj -MemberType NoteProperty -Name $driveName -Value "GettingLow: $percentFree% Free ($freespace/$totalSpace GB)"
				If (!$NoOutput) {Write-Host "$driveName ($freespace/$totalspace GB)" -NoNewline -ForegroundColor Yellow }
			}
			ElseIf ($percentFree -gt 20)
			{
				Add-Member -InputObject $obj -MemberType NoteProperty -Name $driveName -Value "Plenty: $percentFree% Free ($freespace/$totalSpace GB)"
				If (!$NoOutput) {Write-Host "$driveName ($freespace/$totalspace GB)" -NoNewline -ForegroundColor Green }
			}
			$driveCount++ 
			if ($driveCount -lt $driveResults.Count) 
			{
				If (!$NoOutput) {Write-Host " | " -NoNewline}
			}
			#Add-Member -InputObject $obj -MemberType NoteProperty -Name $driveName 
		}

		# automatic services check
		If (!$NoOutput) {Write-Host "`n--Automatic Services .. " -NoNewline}
		$autoServices = Get-CimInstance win32_service -Filter "StartMode = 'Auto' AND state != 'Running' AND Name != 'iphlpsvc' AND ExitCode != '0'" -ComputerName $computer -ErrorAction SilentlyContinue
		If ( (!$autoServices) -or $autoServices -eq $null)
		{
			Add-Member -InputObject $obj -MemberType NoteProperty -Name "AutomaticServices" -Value "Healthy" 
			If (!$NoOutput) {Write-Host "Healthy" -ForegroundColor Green}
		}
		Else
		{
			$failedServies = formatStringStatus -StringArray $autoServices.Name
			Add-Member -InputObject $obj -MemberType NoteProperty -Name "AutomaticServices" -Value "NotRunning ($failedServies)"
			If (!$NoOutput) {Write-Host "Failed ($failedServies)" -ForegroundColor Red}
		}

		# latest windows update install
		If (!$NoOutput) {Write-Host "--Latest Update Installed .. " -NoNewline }
		#Get most recently installed update/hotfix date
		$LatestUpdate = Get-date (get-hotfix -ComputerName $computer | sort installedon -Descending | select -First 1).InstalledOn -Format "MMM dd, yyyy" -ErrorAction SilentlyContinue
		If($LatestUpdate -eq $null) {$LatestUpdate = "Unavailable"}
		Add-Member -InputObject $obj -MemberType NoteProperty -Name "Latest Update Install" -Value $LatestUpdate
		If (!$NoOutput) {Write-Host "$LatestUpdate" }


		# system up time
		If (!$NoOutput) {Write-Host "--System Uptime .. " -NoNewline }
		#Get System up time
		$uptime = (Get-date) - (Get-CimInstance -ComputerName $computer -ClassName win32_operatingSystem | select lastbootuptime).lastbootuptime
		If ($uptime -eq $null) {$uptime = "Unavailable"; $fUpTime = "Unavailable"}
		$fUpTime = ""
		If ($uptime.days -gt 0)
		{
			$fUpTime = $uptime.days.Tostring() + " days " + $uptime.Hours + " hours " + $uptime.minutes.tostring() + " minutes"
		}
		ElseIf ($uptime.hours -gt 0)
		{
			$fUpTime = $uptime.hours.toString() + " hours " + $uptime.minutes.toString() + " minutes"
		}
		Else
		{
			$fUpTime = $uptime.minutes.toString() + " minutes " + $uptime.seconds.toString() + " seconds"
		}
		Add-Member -InputObject $obj -MemberType NoteProperty -Name "SystemUptime" -Value $fUpTime
		If (!$NoOutput) {Write-Host $fUpTime}

		$retObjs += $obj 
		If ($session -ne $null)
		{
			Remove-PSSession $session | Out-Null
		}
		
	
	}


	If ($Report) {Build-HTML -Object $retObjs -Header "General Windows Health Checks"}
	return $retObjs
}

function Check-SCVMM
{
	[CmdletBinding()]

	param
	(
		[Parameter(Mandatory=$true, ValueFromPipeline=$true)]
		[String[]]$ScvmmName,

		[Parameter()]
		[switch]$Report
	)

	$retObjs = @()

	foreach ($vmmName in $ScvmmName)
	{
		$obj = New-Object -TypeName psobject
		$obj | Add-Member -MemberType NoteProperty -Name "SCVMM Server" -Value $vmmName

		If (Test-Connection -Quiet -ComputerName $vmmName) {Add-Member -InputObject $obj -MemberType NoteProperty -Name "PingResult" -Value "Success"} 
		Else {Add-Member -InputObject $obj -MemberType NoteProperty -Name "PingResult" -Value "Failed"}

		$vmmService = Get-Service -ComputerName $vmmName -Name SCVMMService 
		If ($vmmService.Status -like "Running") {Add-Member -InputObject $obj -MemberType NoteProperty -Name "VMM Service" -Value "Running"}
		ElseIf ($vmmService.status -like "Stopped") {Add-Member -InputObject $obj -MemberType NoteProperty -Name "VMM Service" -Value "Stopped"}
		Else {Add-Member -InputObject $obj -MemberType NoteProperty -Name "VMM Service" -Value $($vmmService.Status)}

		$vmmAgentService = Get-Service -ComputerName $vmmName -Name SCVMMAgent 
		If ($vmmAgentService.Status -like "Running") {Add-Member -InputObject $obj -MemberType NoteProperty -Name "VMM Agent Service" -Value "Running"}
		ElseIf ($vmmAgentService.status -like "Stopped") {Add-Member -InputObject $obj -MemberType NoteProperty -Name "VMM Agent Service" -Value "Stopped"}
		Else {Add-Member -InputObject $obj -MemberType NoteProperty -Name "VMM Service" -Value $($vmmAgentService.Status)}

		try
		{
			Import-Module virtualmachinemanager -ErrorAction Stop
			$SCVMM = Get-SCVMMServer $vmmName
			If ($SCVMM -ne $null)
			{
				If ($Scvmm.IsConnected -eq $true) {Add-Member -InputObject $obj -MemberType NoteProperty -Name "Connectivity Status" -Value "Connected" }
				Else {Add-Member -InputObject $obj -MemberType NoteProperty -Name "Connectivity Status" -Value "Disconnected"}
			} 
		}
		catch
		{
			Add-Member -InputObject $obj -MemberType NoteProperty -Name "Connectivity Status" -Value "Unable to obtain"
			continue
		}
	}
	$retObjs += $obj 

	If ($Report)
	{
		Build-HTML -Object $retObjs -Header "SCVMM Health Check" 
	}
	return $retObjs
	 
}

Function Check-SQL
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory)]
        [String[]]$SqlServerAndInstance,

        [Parameter()]
        [switch]$Report
    )

	$retObjs = @()

	foreach ($si in $sqlServerAndInstance)
	{
		If ($si.Contains("\"))
		{
			$sqlServer = $si.Split("\")[0]
			$sqlInstance = $si.Split("\")[1]
		}
		else
		{
			$SqlServer = $si
			$sqlInstance = "MSSQLSERVER"
		}

		$userDbCount = 0
		$servicesQLCount = 0
		$serviceSQLAgentCount = 0
		$statusQuery = "select name, state from sys.databases"
		$logQuery = "DBCC SQLPERF(logspace)"
		$dbs = (Invoke-Sqlcmd -ServerInstance $si -Query $statusQuery) # | where name -eq $DatabaseName).state
		$sqlLogs = (Invoke-Sqlcmd -ServerInstance $si -Query $logQuery)
		$props = [Ordered]@{SQLServerAndInstance=$si}
		$retObj = New-Object -TypeName psobject -Property $props

		$sqlServices = Get-Service -ComputerName $sqlServer | where {$_.DisplayName -Like "SQL Server ($sqlInstance)"}
		$sqlAgentServices = Get-Service -ComputerName $sqlServer | where {$_.DisplayName -Like "sql server agent ($sqlInstance)"}

		foreach ($service in $sqlservices)
		{
			++$serviceSQLAgentCount
			$serviceName = $service.Name
			$serviceStatus = $service.Status
			$columnName = "SQLService" + $serviceCount
			$fieldName = "$serviceStatus" + " ($serviceName)"
			#$props.add("$serviceName", "$serviceStatus")
			$retObj | Add-Member -MemberType NoteProperty -Name $columnName -Value $fieldName
		}
		foreach ($service in $sqlagentservices)
		{
			++$serviceSQLCount
			$serviceName = $service.Name
			$serviceStatus = $service.Status
			$columnName = "SQLAgentService" + $serviceCount
			$fieldName = "$serviceStatus" + " ($serviceName)"
			#$props.add("$serviceName", "$serviceStatus")
			$retObj | Add-Member -MemberType NoteProperty -Name $columnName -Value $fieldName
		}

		foreach ($db in $dbs)
		{

			#$dbName = $db.Name
			$state = $db.State
			$dbName = $db.name
			switch ($state)
			{
				0 {$status = "Online"; break}
				1 {$status = "Restoring"; break}
				2 {$status = "Recovering"; break}
				3 {$status = "Recovery_Pending"; break}
				4 {$status = "Suspect"; break}
				5 {$status = "Emergency"; break}
				6 {$status = "Offline"; break}
				7 {$status = "Copying"; break}
				10 {$status = "OFFLINE_SECONDARY"; break}
				Default { $staus = $null}
			}

			If($db.name -notmatch "master|msdb|tempdb|model")
			{
				++$userDbCount
				$dbName = "UserDatabase" + $userDbCount
				$status = $status + " ($($db.name))"
				$logSizeMB = ($sqlLogs | where {$_."database name" -eq $($db.name)})."Log Size (MB)"
				$logSpaceUsed = ($sqlLogs | where {$_."database name" -eq $($db.name)})."Log Space Used (%)"
				$percentFree = [Math]::Round( (100 - $logSpaceUsed), 1)
				$logSizeColumn = "Log size of " + $($db.Name)
				$logSizeMB = $logSizeMB.ToSTring() + " ($percentFree% free space)"
				$retObj | Add-Member -MemberType NoteProperty -Name $logSizeColumn -Value $logSizeMB

			}
			else 
			{
				$dbName = $db.name
			}
			$retObj | Add-Member -MemberType NoteProperty -Name $dbName -Value $status 
			#$props.add("$dbName", "$status")	
		}
		$retObjs += $retObj

	}

	If ($Report)
	{
		Build-HTML -Object $retObjs -Header "SQL Server Health Check" 
	}

	return $retObjs
	
}


function Check-NLB {

	[CmdletBinding()]
    Param
    (
        [Parameter(Mandatory)]
        [String[]]$NLBServerList,

        [Parameter()]
        [switch]$Report,

		[Parameter()]
        [switch]$NoOutput
    )

	$retObjs = @()

	if (!$NoOutput) {
		Write-Host ""
		Write-Host "----------------------------------------------------------"
		Write-Host " Starting Active Directory Health Check.."
		Write-Host "----------------------------------------------------------"
		Write-Host ""
	}

	foreach ($server in $NLBServerList) {
		try{
			if (!$NoOutput){ Write-Host "$server .." }	
			$NodeStatus = Get-WmiObject -Class MicrosoftNLB_Node -ComputerName $server -Namespace root\MicrosoftNLB | Select-Object __Server, statuscode
		}
		catch {
			if (!$NoOutput){ Write-Host "failed getting node status." -ForegroundColor Red }	
			$HealthCheckStatus = "Fail"
			$props = [Ordered]@{Server=$server; HealthCheckStatus=$HealthCheckStatus;}
		    $retObjs += (New-Object -TypeName psobject -Property $props)
			continue
		}

		$Status = ($NodeStatus.statuscode -match 1008) -or ($NodeStatus.statuscode -match 1007)

		if ($Status -eq "True") {
			if (!$NoOutput){ Write-Host "OK" -ForegroundColor Green }	
			$HealthCheckStatus = "Pass"

		}
		else {
			if (!$NoOutput){ Write-Host "failed" -ForegroundColor Red }	
			$HealthCheckStatus = "Fail"
		}

	$props = [Ordered]@{Server=$server; HealthCheckStatus=$HealthCheckStatus; StatusCodes=$NodeStatus.StatusCode}
    $retObjs += (New-Object -TypeName psobject -Property $props)

	}

	if ($Report) {

		Build-HTML -Object $retObjs -Header "NLB Status Check"

	}

	return $retObjs

}

Function Check-FailoverCluster
{
	[CmdletBinding()]

	Param
	(
		[Parameter(Mandatory)]
		[String[]]$FailoverClusters,

		[Parameter()]
		[switch]$Report
	)

	$retObjs = @()
	$i = 0

	foreach ($failoverCluster in $FailoverClusters)
	{
		$failoverCluster = $failoverCluster.ToUpper()
		$i++
		Write-Progress -Activity "Checking Failover Cluster Health of $failoverCluster" -Status "Checking $failoverCluster ($i of $($FailoverClusters.count))" -PercentComplete ($i / $FailoverClusters.Count * 100)

		$obj = New-Object -TypeName psobject 
		$name = (Get-Cluster -Name $failoverCluster -ErrorAction SilentlyContinue).name
		If (!$name) {$name -eq $failoverCluster}
		Add-Member -InputObject $obj -MemberType NoteProperty -Name "Cluster" -Value "$name"

		$pingTest = ""
		$wsManTest = ""
		If (Test-Connection -Quiet -ComputerName $failoverCluster) {$pingTest = "Passed"} Else {$pingTest = "Failed"}
		If (Test-WSMan -ComputerName $failoverCluster) {$wsManTest = "Passed"} Else {$wsManTest = "Failed"}
		Add-Member -InputObject $obj -MemberType NoteProperty -Name "PingTest" -Value $pingTest
		Add-Member -InputObject $obj -MemberType NoteProperty -Name "RemoteManagementTest" -Value $wsManTest
		If ($pingTest -eq "Failed" -and $wsManTest -eq "Failed") {continue}

		$resources = Get-ClusterResource -Cluster $failoverCluster | where resourceType -NotMatch "Virtual Machine"
		# cluster resource checks
		# cluster names
		$clusterNamesStatus = ""
		$clusterNames = $resources | where resourcetype -eq "Network Name"
		$clusterNamesOnline = $clusterNames | where state -EQ "online"
		$clusterNamesOffline = $clusterNames | where state -NE "online" 
		If ($clusterNamesOffline.Count -eq 0) {$clusterNamesStatus = "Up (All)"}
		ElseIf ($clusterNamesOnline.Count -eq 0) {$clusterNamesStatus = "Down (All)"}
		ElseIf ($clusterNamesOffline -gt 0) {$clusterNamesStatus = "Partially Down ($($clusterNamesOffline.Name)"}
		Add-Member -InputObject $obj -MemberType NoteProperty -Name "ClusterNetworkNames" -Value $clusterNamesStatus

		# IP Addresses
		$ipStatus = ""
		$IPs = $resources | ? resourceType -like "IP Address"
		$onlineIPs = $IPs | ? state -eq "online" 
		$offlineIPs = $IPs | ? state -ne "online" 
		$offlineIPsFormatted = formatStringStatus -StringArray $offlineIPs.Name -RemovePart "IP Address "
		if($onlineIPs.Count -eq 0) {$ipStatus = "Down (All)"}
		elseif ($offlineIPs.Count -eq 0) {$ipStatus = "Up (All)" }
		elseif ($offlineIPs.Count -gt 0) {$ipStatus = "Down ($offlineIPsFormatted)"}
		Add-Member -InputObject $obj -MemberType NoteProperty -Name "IP Status" -Value $ipStatus

		# CSVs
		$csvStatus = ""
		$CSVs = Get-ClusterSharedVolume -Cluster $failoverCluster 
		$onlineCSVs = $csvs | ? state -eq "online" 
		$offlineCSVs = $CSVs | ? state -NE "online"
		If ($offlineCSVs.Count -eq 0)
		{
			$csvStatus = "Online (All)"
		}
		ElseIf ($onlineCSVs.Count -eq 0)
		{
			$csvStatus = "Offline (All)"
		}
		ElseIf ($offlineCSVs.Count -gt 0 )
		{
			$csvNamesF = formatStringStatus -StringArray $offlineCSVs.name
			$csvStatus = "Offline ($csvNamesF)"
		}
		If ($CSVs.count -gt 0)
		{
			Add-Member -InputObject $obj -MemberType NoteProperty -Name "CSVs" -Value $csvStatus
		}

		# physical disks
		$pDiskStatus = ""
		$clusterDisks = $resources | where resourcetype -Like "Physical Disk"
		$onlinePdisks = $clusterDisks | where state -eq "Online" 
		$offlinePdisks = $clusterDisks | where state -NE "online"
		If ($offlinePdisks.Count -eq 0)
		{
			$pDiskStatus = "Online (All)"
		}
		ElseIf ($onlinePdisks.Count -eq 0)
		{
			$pDiskStatus = "Offline (All)"
		}
		ElseIf ($offlinePdisks.Count -gt 0)
		{
			$offlineDisksF = formatStringStatus -StringArray $offlinePdisks.name 
			$pDiskStatus = "Offline ($offlineDisksF)"
		}
		If ($clusterDisks.Count -gt 0)
		{
			Add-Member -InputObject $obj -MemberType NoteProperty -Name "Cluster Disks" -Value $pDiskStatus
		}
		

		$retObjs += $obj 
	}
	If ($Report)
	{
		Build-HTML -Object $retObjs -Header "Failover Cluster Health Checks" 
	}
	return $retObjs
}