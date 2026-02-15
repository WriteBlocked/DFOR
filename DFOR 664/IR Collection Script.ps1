<#
.SYNOPSIS

This script retrives forensically important information from a computer for IR triaging.
Made by Hiller Hoover for DFOR 664 on 4/29/2025.

.DESCRIPTION

This script uses native Powershell commands and WMI to retireve the following data:
- Process information
- Services
- Port-to-process maps for established connections
- List of scheduled tasks
- Network Share information
- List of executables in a user profile
- List of user accounts
- List of specific events from security log within a specified time period
- System clock time
- DNS and ARP cache
- Prefetech files
- Information about the computer
- Autoruns
- Installed Hotfixes
#>

#region test for admin
#I need to make this script seperate out admin and non-admin tasks so it can still run without admin.

if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Script starting as Administrator..."
}
else {
    Write-Host "No Administrator session detected. Please run the script as an Administrator"
    Read-Host -Prompt "`nPlease press enter to exit."
    Exit

    #Didn't finish this, want to make it so that script re-runs as admin after asking for UAC elevation.
    #Start-Process powershell.exe -Verb RunAs -ArgumentList ('-elevated -noexit -file "{0}"')
}
#endregion

#region Introduction
    Clear
    Write-Host "This Script is designed to collect important forensic information from a computer."
    Write-Host "It will create files in the specified directory with the output of various modules."
    $Collector = Read-Host -Prompt "What is the name or ID of the investigator responsible for the collection? "
    $DateAndTime = Read-Host -Prompt @"
What is the Date and time?
(Do not use the target computer to get this.)
(mm/dd/yyyy HH:MM)
"@
    $IncidentNumber = Read-Host -Prompt "What is the Incident Number? "
    do {
    $OutputDestination = Read-Host -Prompt "What is the path to the folder for the output? (This path must end with a \)"
    if (-not (Test-Path -Path $OutputDestination)) {
        Write-Host "The path does not exist."
        do {
            $create = Read-Host -Prompt "Do you want to create it? (y/n)"
            } 
            until ($create -match '^[yYnN]$')
            if ($create -match '^[yY]$') {
                try {
                    New-Item -ItemType Directory -Path $OutputDestination -Force | Out-Null
                    Write-Host "Directory created."
                } catch {
                    Write-Host "Failed to create directory: $_"
                }
            }
            else {
                $OutputDestination = $null
            }
        }
    } 
    until (-not [string]::IsNullOrWhiteSpace($OutputDestination) -and (Test-Path -Path $OutputDestination))
    $daysBack = Read-Host -Prompt "How many days back should the security log be checked for events? (0 will skip search) "
    if ( $daysBack -eq 0) {
        Write-Host "`nSecurity event logs will not be searched" -ForegroundColor DarkYellow 
    }
    else{
    #This part sanitizes the user input for event IDs. If there aren't any, it leaves defaults
        $daySearch = (Get-Date).AddDays(- $daysBack)
        $defaultEventIDs = 4624,4625,4634,4672,4688,4698,1102,4719,4720,4722,4723,4724,4725,4726
        $input = Read-Host "Enter event IDs (comma- or space-separated, or press Enter for defaults)"
        $eventIDs = if ([string]::IsNullOrWhiteSpace($input)) {
            $defaultEventIDs
        } else {
            $input -split '[,\s]+' | Where-Object { $_ -match '^\d+$' } | ForEach-Object { [int]$_ }
        }
    }
    $daysBackEx = Read-Host -Prompt "How many days back should user folders be checked for new executables? (0 will skip search) "
    if ($daysBackEx0 -eq 0) {
        Write-Host "`nUser Profiles will not be searched for executables." -ForegroundColor DarkYellow
    }
    else{
        Write-Host "Gathering user executables will take some time. Please be patient."
    }
    Write-Host "Thank you for your input. The script will begin now."
    Start-Sleep -Seconds 3
    Clear
#endregion

#region functions
function Show-Complete {
    Write-Host "[COMPLETE]" -ForegroundColor Yellow
    }

function output {

    #Used to standardize output to files. Use -Top to add header.
    #Takes -FileName as input, and accepts piped input.
    #Takes -Header as the header for the section
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$FileName,

        [Parameter(ValueFromPipeline = $true)]
        [PSObject]$InputObject,

        [switch]$Top,

        [String]$Header
    )
    begin {
        $fullPath = Join-Path -Path $OutputDestination -ChildPath $FileName
        if ($Top) {
            $heading = @"
========================================
Investigator  : $Collector
Case Number   : $IncidentNumber
Date          : $DateAndTime
========================================
"@
            $heading | Out-File -FilePath $fullPath -Append
        }
        if ($Header) {
            $header = @"

----------------------------------------
$Header
----------------------------------------
"@
            $header | Out-File -FilePath $fullPath -Append
        }
        $outputData = @()
    }
    process {
        $outputData += $InputObject
    }
    end {
       $outputData | Out-File -FilePath $fullPath -Append
    }
}
#endregion

#region System Info
    $os = Get-CimInstance Win32_OperatingSystem
    $cs = Get-CimInstance Win32_ComputerSystem
    $bios = Get-CimInstance Win32_BIOS
    $cpu = Get-CimInstance Win32_Processor

    $SystemInfo = [PSCustomObject]@{
        "Host Name"             = $env:COMPUTERNAME
        "OS Name"               = $os.Caption
        "OS Version"            = "$($os.Version) $($os.BuildNumber)"
        "Original Install Date" = $os.InstallDate
        "System Boot Time"      = $os.LastBootUpTime
        "System Manufacturer"   = $cs.Manufacturer
        "System Model"          = $cs.Model
        "Processor(s)"          = $cpu.Name
        "BIOS Version"          = $bios.SMBIOSBIOSVersion
        "Boot Device"           = $os.BootDevice
        "Total Physical Memory" = "{0:N2} GB" -f ($cs.TotalPhysicalMemory / 1GB)
        "System Time"           = Get-Date -Format "MM/dd/yyyy HH:mm"
        "Investigator time"     =$DateAndTime
    }
    $SystemInfo | output -FileName "System Info.txt" -Top -Header "System Info"
    Get-HotFix | output -FileName "System Info.txt" -Header "Installed Hotfixes"
    Get-LocalUser | Select-Object -Property Name,Enabled,LastLogon,SID | output -FileName "Users.txt" -Top -Header "Local Users"
#endregion

#region Networking data
    Write-Host "Collecting DNS and ARP Cache...." -ForegroundColor DarkYellow
    Get-DnsClientCache | output -FileName "Networking.txt" -Top -Header "DNS Cache"
    Get-NetNeighbor -AddressFamily IPv4 | output -FileName "Networking.txt"-Header "ARP Cache"
    #only choosing IPv4 ARP cache for output size considerations
    Show-Complete

    Write-Host "Getting IP Config and SMB Shares...." -ForegroundColor DarkYellow
    ipconfig /all | output -FileName "Networking.txt" -Header "IPConfig"
    Get-FileShare | Select-Object -Property `
        Name,Description,UniqueId,FileSharingProtocol,OperationalStatus | 
        output -FileName "Networking.txt" -Header "File Shares"

    #checking if SMB shares exist
    if ($smbFiles = Get-SmbOpenFile | Where-Object { $_ }) {
    $smbFiles | Select-Object ClientUserName, FileId, Path, SessionId |
        output -FileName "Networking.txt" -Header "SMB Shares"
    }
    else {
        Write-Host "No SMB Shares Found!" -ForegroundColor DarkYellow | output -FileName "Networking.txt" -Header "SMB Shares"
    }
    Show-Complete
#endregion

#region Security Logs
    Write-Host "Collecting Security Logs...." -ForegroundColor DarkYellow
    Get-WinEvent -FilterHashtable @{ logName='Security'; StartTime=$daySearch; Id=$EventIDs } -ErrorAction SilentlyContinue |
    Select-Object -Property TimeCreated, Id |
    output -FileName "Security Logs.txt" -Top -Header "Security Events"
    Show-Complete
#endregion

#region Firewall Rules
<#

Commented out because I am not sure if this is helpful info.
If I was going to collect all firewall rules, it would probably be best to do pre- and post- incident
additionally this collection can take some time, depending on how many rules the person has

Get-NetFirewallRule | Where-Object { $_.Profile -eq 'Public' } | ForEach-Object {
    $rule = $_
    $addressFilter = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule
    $portFilter = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule
    [PSCustomObject]@{
        Name          = $rule.DisplayName
        Direction     = $rule.Direction
        Enabled       = $rule.Enabled
        Description   = $rule.Description
        Action        = $rule.Action
        LocalAddress  = $addressFilter.LocalAddress
        LocalPort     = $portFilter.LocalPort
        RemoteAddress = $addressFilter.RemoteAddress
        RemotePort    = $portFilter.RemotePort
    }
} | output -Top -FileName "Firewall rules.txt" -Header "Firewall rules - Public"

Get-NetFirewallRule | Where-Object { $_.Profile -eq 'Private' } | ForEach-Object {
    $rule = $_
    $addressFilter = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule 
    $portFilter = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule
    [PSCustomObject]@{
        Name          = $rule.DisplayName
        Direction     = $rule.Direction
        Enabled       = $rule.Enabled
        Description   = $rule.Description
        Action        = $rule.Action
        LocalAddress  = $addressFilter.LocalAddress
        LocalPort     = $portFilter.LocalPort
        RemoteAddress = $addressFilter.RemoteAddress
        RemotePort    = $portFilter.RemotePort
    }
} | output -FileName "Firewall rules.txt" -Header "Firewall rules - Private"
#>
#endregion

#region Process and service collection
    Write-Host "Recording Services...." -ForegroundColor DarkYellow
    Get-service | Format-Table -Wrap -AutoSize | output "ServiceList.txt" -Top -Header "Service List"
    Show-Complete

    Write-Host "Recording Running Processes...." -ForegroundColor DarkYellow
    #This part joing together the Process Name, ID, and start time from Get-Process with the Command Line options from WMI
    $procData = Get-Process | ForEach-Object {
        try {
            [PSCustomObject]@{
                ProcessName = $_.ProcessName
                Id          = $_.Id
                SessionId   = $_.SessionId
                StartTime   = $_.StartTime
            }
        } catch {
            Write-Warning "Failed to Retrieve full info for Process ID $($_.Id)"
        }
    }
    $wmiData = Get-WmiObject -Class Win32_Process | Select-Object ProcessId, CommandLine
    $combined = foreach ($p in $procData) {
        $cmd = $wmiData | Where-Object { $_.ProcessId -eq $p.Id } | Select-Object -First 1
        [PSCustomObject]@{
            ProcessName = $p.ProcessName
            Id          = $p.Id
            StartTime   = $p.StartTime
            CommandLine = $cmd.CommandLine
        }
    }
    $combined | Format-table -wrap -autosize | output -Filename "Running Processes.txt" -top -Header "Running Processes"
    Show-Complete

    Write-Host "Collecting Startup Services and scheduled tasks...." -ForegroundColor DarkYellow
    Get-CimInstance Win32_StartupCommand | 
        Select-Object Name, command, Location, User | 
        Format-table -Wrap -AutoSize | 
        output -FileName "Startup Items.txt" -Top -Header "Startup Items"

    Get-ScheduledTask |Where-Object state -eq Ready |
    Select-Object -Property TaskName,TaskPath |
    Format-Table -Wrap -AutoSize | output -FileName "Scheduled Tasks.txt" -Top -Header "Scheduled Tasks"
    Show-Complete

    if ($daysBackEx -gt 0) {
    Write-Host "Collecting User Executables from the past $($daysBackEx) days...." -ForegroundColor DarkYellow
    #I've noticed this process was very slow with -include so I use -filter, which can only take one input.
    #I might want to repeat this section and add a part for DLLs?
    #In general, this part is a little clunky and needs some fine tuning (possibly for each loop?)
    Get-ChildItem -Path C:\Users -Filter *.exe -Recurse -ErrorAction SilentlyContinue -Force  |
    Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-$daysBackEx)} | 
        output -Top -Filename "User Executables.txt" -Header "User executables from the last $($daysBackEx) days."
    Show-Complete
    }
    else{
    Write-Host -ForegroundColor DarkYellow "Skipping executable check in user profiles." 
    }
#endregion

#region Port to Process map
    Write-Host "Collecting a Port to Process Map...." -ForegroundColor DarkYellow
    $PortToProcessMap = 
    Get-NetTCPConnection -State Established |
    Select-Object -Property `
    LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess,CreationTime,
    @{name='Path'; expression={(Get-Process -Id $_.OwningProcess).Path}}
    $PortToProcessMap | Format-Table -Wrap | output -FileName "PortToProcessMap.txt" -Top -Header "Port to Process Map"
    Show-Complete
#endregion

#region Enumerate Prefetech Files
    Write-Host "Collecting Prefetch Files...." -ForegroundColor DarkYellow
    $PrefetchFiles = @()
    Get-ChildItem -Path C:\Windows\Prefetch\*.pf |
    select Name,LastAccessTime,CreationTime |
    sort LastAccessTime |
    output -Filename "PrefetechFiles.txt" -Top -Header "Prefetch Files"
    Show-Complete
#endregion

#region Loaded DLLs
    Write-Host "Copying Process Dependencies...." -ForegroundColor DarkYellow
    Get-Process | select ProcessName -expand Modules -ea 0 | 
    Format-Table Processname, modulename, filename -Groupby Processname |
    output -filename "ProcessDependencies.txt" -Top -Header "Loaded Modules"
    Show-Complete
#endregion

#region Recent Documents
<#
This never ended up returning output for me. Possibly a problem with my computer, needs more testing.

Get-ChildItem -Path "$env:HOMEPATH\AppData\Roaming\Microsoft\Windows\Recent\*.*" |
    Select-Object -Property Name,CreationTime,LastWriteTime
#>
#endregion

#region Hashing
    Write-Host "Hashing output files." -ForegroundColor DarkYellow
    Get-ChildItem -Path "$OutputDestination\*.txt" | ForEach-Object {
    Get-FileHash -Path $_.FullName | Out-File -FilePath "$OutputDestination\Hashes.txt" -Append
    }
    Show-complete
#endregion

Read-Host -Prompt "Collection Completed. Press Enter to close the window..."