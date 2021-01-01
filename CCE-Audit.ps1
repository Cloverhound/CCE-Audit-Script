Set-Location -Path $PSScriptRoot
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

#$CredsSql

#Note: This Script looks for two files, Servers.txt (Required) and Creds.csv (Optional) in the same folder where the script is.
#region Initial Setup Vars
$InputServerList = ".\Servers.txt"
$ResultsFolder = "\AuditResults"
$global:ResultsPath = "$PSScriptRoot$($ResultsFolder)"
$global:CredCheckCount = 1
$CredsCsv = ".\Creds.csv"
$HTMLFile = "Initial.htm"
$CsvFile = "Initial.csv"

$CredsValid = $false
$global:HTMLOuputStart = "<html><body><br><b>UCCE/PCCE Server Audit Report.</b></body><html>
<html><body>"
$global:HTMLOuputEnd = "</body></html>"
#endregion Initial Setup Vars

#region Functions
#Write results to CSV, html file and PowerShell window
#To use function, send it the Color of the message and up to 2 strings and a Pass/Fail/Warning string to write to audit result to files and console
Function WriteResults ($Color,$String1,$String2,$PassFail){
    if ($Color -eq "Green") {$HtmlColor = "008000"; $ConsColor = "Green"}
    elseif ($Color -eq "Red") {$HtmlColor = "F00000"; $ConsColor = "Red"}
    elseif ($Color -eq "Yellow") {$HtmlColor = "FFC000"; $ConsColor = "Yellow"}
    else {$HtmlColor = "000000"; $ConsColor = "White"}
    Add-Content "$ResultsPath\$HTMLFile" "<br><font color =`"#$HtmlColor`">$String1 $String2 $PassFail</font>"
    Add-Content -Path "$ResultsPath\$CsvFile" "$String1,$String2,$PassFail"
    Write-Host -ForegroundColor $ConsColor $String1 $String2 $PassFail
}

#Write Page file notice for malconfigured page files
Function WritePFNotice($Color){
    WriteResults $Color "- It is recommended to configure the Swap File with an Inital and Max size of 1.5 x Memory" "" ""
    WriteResults $Color "- Use the below sizes to set the Swap File accordingly " "" ""
    WriteResults $Color "-  - 16GB RAM = 24576MB Page File | 12GB RAM = 18432MB Page File | 8GB RAM =  12288MB Page File" "" ""
    WriteResults $Color "-  -  6GB RAM =  9216MB Page File |  4GB RAM =  6144MB Page File | 2GB RAM =  3072MB Page File" "" ""
    WriteResults $Color "-  -  Note that a change to the Page File may require a reboot" "" ""
}

#Make Web Request
Function MakeWebRequest ($Url){
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
    $global:WebReq = [System.Net.WebRequest]::Create($Url)
    $global:WebReq.Method ="GET"
    $global:WebReq.ContentLength = 0
    $global:WebReq.Timeout = 15000
    $global:WebReq.Credentials = $CredsWin.GetNetworkCredential()
}

<#
function Get-ServerICMInstance()
{
    $url = "https://$($server):7890/icm-dp/rest/DiagnosticPortal/ListConfigurationCategories"
    Write-Host "Getting Configuration Categories From: $($url)"
    $resultXml = Get-XmlFromUrl -url $url

    $configs = $resultXml.ListConfigurationCategoriesReply.ConfigurationCategoryList.ConfigurationCategory
    $instance = $null
    foreach ($config in $configs)
    {
        $instance = ($config.Description | select-string -pattern "Instance=(?<instance>[^\s]+)").Matches[0].Groups['instance'].Value
        if ($instance -ne $null -and $instance -ne '') { break }
    }
    
    if ($instance -eq $null -or $instance -eq '') { $instance = 'none' }
    return $instance
}
#>
#Get Windows/ICM Admin credentials
Function GetCredsWin {
    $global:CredsWin = Get-Credential -Message "Enter Windows/ICM Admin Credentials"
    $global:CredCheckCount++
}

#Write closing tags for HTML file
Function CloseHtml {
    Add-Content "$ResultsPath\$HTMLFile" $HTMLOuputEnd
}

#Read Registry Data for a Specific Value function
Function ReadReg ($RegHive,$RegPath,$ValueName,$Computer){
    $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($RegHive,$Computer)
    $RegKey = $reg.OpenSubKey($RegPath)
    $global:ValueData = $RegKey.GetValue($ValueName)
}

#Read Registry SubKeys for a Specific Path function
Function ReadRegKey ($RegHive,$RegPath,$Computer){
    $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($RegHive,$Computer)
    $global:RegKey = $reg.OpenSubKey($RegPath)
    $global:RegSbuKeys = $RegKey.GetSubKeyNames()
}

Function CloseScript {
    CloseHtml
    $endvar = [Console]::ReadKey()
    Exit
}
#endregion Functions

#region File, Folder and Credential Checks
#Check to see if the Audit Results folder is present
Write-Host "Checking to see if the Audit Results folder is present"
if (Test-Path -Path $ResultsPath){
    WriteResults "Green" "- Audit Results folder found, proceeding" "" "Pass"
}
else{
    Write-Host "Audit Results folder NOT Found, creating one"
    New-Item $ResultsPath -ItemType "Directory"
}

Set-Content -Path "$ResultsPath\$HTMLFile" $HTMLOuputStart
Set-Content -Path "$ResultsPath\$CsvFile" ""

#Check to see if the Server list is present
WriteResults "Default" "Checking to see if the Server list is present" "" ""
if (Test-Path -Path $InputServerList){
    WriteResults "Green" "- Server list file found, proceeding" "" "Pass"
    if (("" -eq ($global:TestServer = Get-Content $InputServerList))-or($null -eq ($global:TestServer = Get-Content $InputServerList))){
        WriteResults "Red" "- No Servers in List File - Nothing to check." "" ""
        WriteResults "Red" "- Exiting, press any key to exit script" "" ""
        CloseScript
    }
}
else{
    WriteResults "Red" "- File NOT Found - Nothing to check." "" ""
    WriteResults "Red" "- Exiting, press any key to exit script" "" ""
    CloseScript
}

#Check to see if the Credentials CSV file is present
WriteResults "Default" "Checking to see if the Credentials CSV File is present" "" ""
if (Test-Path -Path $CredsCsv){
    #check to see if credentials are present in CSV file
    $UserCreds = Import-Csv -Path $CredsCsv
    if (($null -ne $UserCreds.username)-and($null -ne $UserCreds.pass)){
        #Read Windows and Portico credentials from CSV file
        WriteResults "Green" "- Loading Credentials from CSV, proceeding" "" ""
        $password = ConvertTo-SecureString $UserCreds.pass -AsPlainText -Force
        $global:CredsWin = New-Object System.Management.Automation.PSCredential ($UserCreds.username, $password)
    }
    else{
        WriteResults "Red" "- Credentials not found in CSV, prompting for credentials"
        GetCredsWin
    }
}
else{
    WriteResults "Red" "- Credentials CSV file NOT Found, prompting for credentials" "" ""
    GetCredsWin
}

#Check if credentials are valid
WriteResults "Default" "Cechking credentials against the first server in the list to see if credentials are valid"
While ($CredsValid -eq $false){
    Try {
        $LoginError = $false
        $CredCheck = Invoke-Command -ComputerName $global:TestServer[0] -Credential $CredsWin -ErrorAction Stop {Get-WmiObject -Class win32_operatingsystem}
    }
    Catch {
        $LoginError = $true
    }
    if (($LoginError -eq $true)-and ($global:CredCheckCount -lt 4)){
        WriteResults "Red" "- Credentials not valid or don't have proper privileges, prompting for credentials" "" ""
        WriteResults "Red" "- Note: this error may also occur if the fist server in the list is invalid or not reachable" "" ""
        GetCredsWin
    }
    elseif (($LoginError -eq $true)-and($global:CredCheckCount -ge 3)) {
        WriteResults "Red" "- Credentials not valid or don't have proper privileges, prompting for credentials" "" ""
        WriteResults "Red" "- Note: this error may also occur if the fist server in the list is invalid or not reachable" "" ""
        Write-Host ""
        WriteResults "Red" "- No more attemmpts remaining, exiting, press any key to exit script" "" ""
        CloseScript
    }
    else{
        WriteResults "Green" "- Credentials are valid, continuing" "" ""
        $CredsValid = $true
    }
}
#endregion File, Folder and Credential Checks

WriteResults "Default" "Starting Audit Checks for list of servers" "" ""
Get-Content $InputServerList | ForEach-Object {
    #region Setup Vars
    $global:Server = $_
    $HTMLFile = "$Server.htm"
    $CsvFile = "$Server.csv"
    $IcmInstalled=$PorticoRunning=$PrivateNic=$Router=$Logger=$Awhds=$Pg=$Cg=$CTIOS=$Dialer=$False
    $LoggerSide=$LoggerDb=$AwDb=$HdsDb=""
    Set-Content -Path "$ResultsPath\$HTMLFile" $HTMLOuputStart
    Set-Content -Path "$ResultsPath\$CsvFile" ""
    #endregion Setup Vars

    #region TempVars
    $global:TwoNICs = $true
    #endregion TempVars

    #Write Server name to results
    WriteResults "Default" "Server - $($Server)" "" ""

    #Check that the server is reachable
    WriteResults "Default" "Checking to see if $Server is online" "" ""
    if (Test-Connection -Count 2 -Quiet $Server){
        WriteResults "Green" "Server $Server Online - Continuing with health chek items" "" "Pass"
        
        #Get OS version
        WriteResults "Default" "Getting OS version" "" ""
        $OS =  Invoke-Command -ComputerName $Server -Credential $CredsWin {Get-WmiObject -Class win32_operatingsystem} | Select-Object @{Name="OS"; Expression={"$($_.Caption)$($_.CSDVersion) $($_.OSArchitecture)"}} | Select-Object -expand OS
        WriteResults "Default" "- " $OS ""
        
        #region Check that Portico is installed and running
        WriteResults "Default" "Checking if Portico/ICM is installed and Running" "" ""
        $PorticoService = Invoke-Command -ComputerName $Server -Credential $CredsWin {Get-WmiObject -Class Win32_Service} | Select-Object -property DisplayName,State | Where-Object {$_.DisplayName -eq "Cisco ICM Diagnostic Framework"} | Select-Object -expand State
        if ($null -ne $PorticoService){
            $global:IcmInstalled = $true
            WriteResults "Green" "- Portico/ICM is installed - Checking if it is Running" "" "Pass"
            if ($PorticoService -eq "Running"){
                $global:PorticoRunning = $true
                WriteResults "Green" "- - Portico/ICM is installed and Running" "" "Pass"
            }
            else{
                $PorticoRunning = $false
                WriteResults "Red" "- - Portico/ICM is installed - But NOT Running" "" "Fail"
            }
        }
        else{
            WriteResults "Red" "- Unable to find Portico Service Ensure that servername in list is correct" "" "Fail"
            WriteResults "Red" "- - ICM must be installed on the server to be audited, only a limited audit will be run" "" "Fail"
            $IcmInstalled = $false
        }
        #endregion Check that Portico is installed and running

        #region Get ICM Instance(s)
        WriteResults "Default" "Fetching ICM Inatance(s)"
        ReadRegKey "LocalMachine" "SOFTWARE\Cisco Systems, Inc.\ICM" $Server
        $InstancesFound = $RegSbuKeys | where {($_ -notmatch '\d\d\.\d')-and($_ -notin 'ActiveInstance','Performance','Serviceability','SNMP','SystemSettings','CertMon','Cisco SSL Configuration')}
        If ($InstancesFound.Count -gt 0){
            ForEach ($Instance in $InstancesFound){
                WriteResults "Green" "- Instance $($Instance) Found" "" "Pass"
            }   
        }
        else{WriteResults "Red" "No Instance Found" "" "Fail"}
        #endregion Get ICM Instance(s)

        #region Get Installed ICM Components
        WriteResults "Default" "Checking to see what ICM Components are installed"
        ForEach ($Instance in $InstancesFound){
            MakeWebRequest "https://$Server`:7890/icm-dp/rest/DiagnosticPortal/ListAppServers?InstanceName=$Instance"
            try {$Resp = $WebReq.GetResponse()}
            catch {$Resp = "error"}
            if ($Resp -eq "error")
            {
                WriteResults "Red" "Unable to Fetch ICM Instance from Portico" "" "Fail"
            }
            else {
                $Reader = new-object System.IO.StreamReader($resp.GetResponseStream())
                [xml]$ResultXml = $Reader.ReadToEnd()
                $Services = @($ResultXml.ListAppServersReply.AppServerList.AppServer | Where-Object {$_.ProductComponentType -notin "Cisco ICM Diagnostic Framework","Administration Client"} | Select-Object -expand ProductComponentType)
                ForEach ($Service in $Services){
                    WriteResults "Green" "- $($Instance) - $($Service) Found" "" "Pass"
                    if ($Service -like "Router*"){
                        $Router = $true
                    }
                    if ($Service -like "Logger*"){
                        $Logger = $true
                        $LoggerSide = $Service.Substring(7,1)
                        $LoggerDb = "$($Instance)_side$($LoggerSide)"
                    }
                    if ($Service -like "Administration and Data Server*"){
                        $Awhds = $true
                        $AwDb="$($Instance)_awdb"
                        $HdsDb="$($Instance)_hds"
                    }
                    if ($Service -like "Peripheral Gateway*"){
                        $Pg = $true
                    }
                    if ($Service -like "CTI Server*"){
                        $Cg = $true
                    }
                    if ($Service -like "CTI OS Server*"){
                        $CTIOS = $true
                    }
                    if ($Service -like "Outbound Option Dialer*"){
                        $Dialer = $true
                    }
                }
                $reader.Close()
                $resp.Close()
            }
        }
        $Router
        $Logger
        $LoggerDb
        $Pg
        $Cg
        $CTIOS
        $Dialer
        $Awhds
        $AwDb
        $HdsDb
        #endregion Get Installed ICM Components

        #Exit

        #Check if IPv6 is globally disabled
        WriteResults "Default" "Checking if IPv6 is globally disabled in the registry" "" ""
        ReadReg "LocalMachine" "SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters" "DisabledComponents" $Server
        if ($ValueData -eq 255){
            WriteResults "Green" "IPv6 has been globally disabled in the registry" "" "Pass"
            $Ipv6DisReg = $true
        }
        elseif ($ValueData -eq -1){
            WriteResults "Yellow" "IPv6 has been globally disabled in the registry" "" "Pass"
            WriteResults "Yellow" "The following registry value should be set to 0x000000ff not 0xffffffff" "" ""
            WriteResults "Yellow" "HKLM:SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters\DisabledComponents" "" ""
            WriteResults "Yellow" "Using 0xffffffff will cause the server to take longer to boot up during restarts" "" ""
            $Ipv6DisReg = $true
        }
        else{
            WriteResults "Yellow" "IPv6 NOT globally disabled in the registry, must check that it's disabled on NIC's" "" ""
            $Ipv6DisReg = $false
        }
        
        #region Get Advanced NIC Properties
        WriteResults "Default" "Check to see if TCP Offload and Speed/Duplex setting are configured properly" "" ""
        Invoke-Command -ComputerName $Server -Credential $CredsWin {Get-NetAdapterAdvancedProperty} | ForEach-Object {
            if ((($_.DisplayName -like "*Off*") -and ($_.DisplayValue -like "*Disabled*")) -or (($_.DisplayName -like "Speed*") -and ($_.DisplayValue -like "*1.0 Gbps Full*"))){
                WriteResults "Green" "- $($_.Name) $($_.DisplayName)  $($_.DisplayValue)" "" "Pass"
            }
            elseif ((($_.DisplayName -like "*Off*") -and ($_.DisplayValue -notlike "*Disabled*"))-or(($_.DisplayName -like "Speed*") -and ($_.DisplayValue -notlike "*1.0 Gbps Full*"))){
                WriteResults "Red" "- $($_.Name) $($_.DisplayName) $($_.DisplayValue)" "" "Fail"
            }
        }
        #endregion Get Advanced NIC Properties
    
        #region Get Cisco ICM Services and Startup Type
        WriteResults "Default" "Checking to see what ICM services are installed and their Startup Type" "" ""
         Invoke-Command -ComputerName $_ -Credential $CredsWin {Get-WmiObject -Class Win32_Service} | Select-Object -property DisplayName,StartMode,State | ForEach-Object {
            if (($_.DisplayName -like "Cisco*")-and($_.StartMode -like "Auto*")-and($_.State -like "Running")){
                WriteResults "Green" "- $($_.DisplayName) - $($_.State) - $($_.StartMode)" "" "Pass"
            }
            elseif (($_.DisplayName -like "Cisco*")-and(($_.StartMode -notlike "Auto*")-or($_.State -notlike "Running"))) {
                WriteResults "Red" "- $($_.DisplayName) - $($_.State) - $($_.StartMode)" "" "Fail"
            }
        }
        #endregion Get Cisco ICM Services and Startup Type
    
        #region Check if RDP is enabled
        WriteResults "Default" "Checking to see RDP Services are enabled" "" ""
        if ((Invoke-Command -ComputerName $_ -Credential $CredsWin {Get-WmiObject -name "root\cimv2\TerminalServices" Win32_TerminalServiceSetting} | Select-Object -expand AllowTSConnections)-eq 1){
            WriteResults "Green" "- Remote Desktop Enabled" "" "Pass"
        }
        else {WriteResults "Red" "- Remote Desktop DISABLED" "" "Fail"}
        #enddregion Check if RDP is enabled
    
        #Check if CD Rom drive is assigned to Z:
        WriteResults "Default" "Checking to see if CD Rom has been reassigned to Z:" "" ""
        $CdRomDrive = Invoke-Command -ComputerName $_ -Credential $CredsWin {Get-WmiObject win32_logicaldisk} | Where-Object {$_.DriveType -eq 5} |Select-Object -expand DeviceID
        if($CdRomDrive -eq "z:"){
            WriteResults "Green" "- CD Drive Assigned to Z:" "" "Pass"
        }
        else {WriteResults "Red" "- CD Drive Assigned to $CdRomDrive - Should be reassigned to Z:" "" "Fail"}

        #Check if WMI SNMP Provider is installed
        WriteResults "Default" "Checking to see if WMI SNMP Provider is installed" "" ""
        if ((Invoke-Command -ComputerName $_ -Credential $CredsWin {Get-WmiObject win32_optionalfeature} | Where-Object {$_.Name -eq 'WMISnmpProvider'} | Select-Object -expand InstallState) -eq "1"){
            WriteResults "Green" "- WMI SNMP Provider Installed" "" "Pass"
        }
        else {WriteResults "Red" "- WMI SNMP Provider NOT Installed - Should be installed" "" "Fail"}

        #region Check Page file is hard set to 1.5x RAM size
        WriteResults "Default" "Checking to see if Page file is configured to MS best practices" "" ""
        $MemSzMB = Invoke-Command -ComputerName $_ -Credential $CredsWin {[Math]::Ceiling((Get-WmiObject win32_computersystem | Select-Object -ExpandProperty TotalPhysicalMemory) / 1048576 )}
        if ((Invoke-Command -ComputerName $_ -Credential $CredsWin {Get-WmiObject win32_computersystem} | Select-Object -expand AutomaticManagedPagefile) -eq "True"){
            WriteResults "Red" "- Page File Configred to be managed by system" "" "Fail"
            WritePFNotice "Red"
        }
        else{
            $PfSettings = Invoke-Command -ComputerName $_ -Credential $CredsWin {Get-WmiObject -Class Win32_PageFileSetting}
            $PfRangeLow = $MemSzMB*1.4 ; $PfRangeHigh = $MemSzMB*1.6
            #Write-Host $PfSettings.InitialSize $PfSettings.MaximumSize
            if ($PfSettings.InitialSize -eq $PfSettings.MaximumSize){
                if (($PfSettings.MaximumSize -gt $PfRangeLow) -and ($PfSettings.MaximumSize -lt $PfRangeHigh)){
                    WriteResults "Green" "- Page File Configred to best practices" "" "Pass"
                }
                elseif($PfSettings.MaximumSize -gt $PfRangeHigh){
                    WriteResults "Yellow" "- Page File Configred larger than typical installs" "" "Warning"
                    WritePFNotice "Yellow"
                }
                else{
                    WriteResults "Red" "- Page File Size Should be increased" "" "Fail"
                    WritePFNotice "Red"
                }
            }
            elseif($PfSettings.InitialSize -lt $PfRangeLow){
                WriteResults "Red" "- Page File Size Should be increased and both Initial and Max Values shoufl be the same" "" "Fail"
                WritePFNotice "Red"
            }
            else{
                WriteResults "Yellow" "- Page File Size is large enough but both Initial and Max Values shoufl be the same" "" "Warning"
                WritePFNotice "Yellow"
            }
        }
        #endregion Check Page file is hard set to 1.5x RAM size

        #region Check to see if Updates are Set to Manual
        WriteResults "Default" "Checking to see if Windows Updates are set to Manual" "" ""
        if ($OS -like "*2016*"){
            $reg = Invoke-Command -ComputerName $_ -Credential $CredsWin -ScriptBlock {(Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU").NoAutoUpdate}
            if ($UpdateStatus -eq 1){
                WriteResults "Green" "- Windows Updates Set to manual" "" "Pass"
            }
            else{WriteResults "Yellow" "- Windows Updates enabled" "" "Warning"}
        }
        elseif($OS -like "*2012*"){
            $reg = Invoke-Command -ComputerName $_ -Credential $CredsWin -ScriptBlock {(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update").AUOptions}
            if ($reg -eq 1){
                WriteResults "Green" "- Windows Updates Set to manual" "" "Pass"
            }
            else{WriteResults "Yellow" "- Windows Updates enabled" "" "Warning"}
        }
        #endregion Check to see if Updates are Set to Manual

        #region Check for recently installed updates
        WriteResults "Default" "Checking to see if Windows Updates have been installed in the last 60 days" "" ""
        $Hotfixes = Invoke-Command -ComputerName $_ -Credential $CredsWin {Get-WmiObject win32_quickfixengineering}
        $LastUpdate = $Hotfixes.item(($Hotfixes.length - 1)).InstalledOn
        $Today = Get-Date ; $DateDif = $Today - $LastUpdate
        if ($DateDif.Days -lt 60){
            WriteResults "Green" "- Windows Updates have been installed in the last 60 days" "" "Pass"
        }
        else{WriteResults "Red" "- NO Windows Updates have been installed in the last 60 days" "" "Fail"}
        #endregion Check for recently installed updates

        #region Check NIC Priority
        if($TwoNICs -eq $true){
            WriteResults "Default" "Checking to see if NIC Binding Order/Interface Metric is configured properly" "" ""
            #2016 NIC Metric Check
            if ($OS -like "*2016*"){
                WriteResults "Default" "- Server 2016 Found Checking Interface Metric" "" ""
                $pubMetric = Invoke-Command -ComputerName $_ -Credential $CredsWin -ScriptBlock {get-netipinterface -interfacealias *public* | Select-Object -expand interfacemetric}
                $priMetric = Invoke-Command -ComputerName $_ -Credential $CredsWin -ScriptBlock {get-netipinterface -interfacealias *private* | Select-Object -expand interfacemetric}
                if ($pubMetric -lt $priMetric){
                    WriteResults "Green" "- NIC Metric Priority correctly configured Public - NIC = $pubMetric and Private NIC = $priMetric" "" "Pass"
                }
                else{
                   WriteResults "Red" "- NIC Metric Priority NOT correctly configured - Public NIC = $pubMetric and Private NIC = $priMetric" "" "Fail"
                    WriteResults "Red" "- - Public NIC should have a lower Metric value than the Priate NIC" "" "Fail"
                }
            }

            #2012 R2 Binding Order Check
            else{
                WriteResults "Default" "- Server 2012 Found Checking Binding Order" "" ""
                $Binding = Invoke-Command -ComputerName $_ -Credential $CredsWin -ScriptBlock {Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Linkage"} | Select-Object -expand Bind
                $BindingOrder = @()
                ForEach ($Bind in $Binding)
                {
                    $DeviceId = $Bind.Split("\")[2]
                    $Adapter = Invoke-Command -ComputerName $_ -Credential $CredsWin {Get-WmiObject Win32_Networkadapter} | Where-Object {$_.GUID -like "$DeviceId" } | Select-Object -expand NetConnectionId
                    if (($Adapter -like '*public*')-or($Adapter -like '*private*')){
                        $BindingOrder += $Adapter
                    }
                }
                if (($BindingOrder[0] -like '*public*')-and($BindingOrder[1] -like '*private*')){
                    WriteResults "Green" "- Binding Order correctly configured - $($BindingOrder[0]) above $($BindingOrder[1])" "" "Pass"
                }
                else {
                    WriteResults "Red" "- Binding Order NOT correctly configured - $($BindingOrder[1]) above $($BindingOrder[0])" "" "Fail"
                    WriteResults "Red" "- - the Public NIC should be listed above the Private NIC in the Binding Order" "" "Fail"
                }
            }
        }
        #endregion Check NIC Priority
    }

    #If Server not Reachable NOT continuing with Audit Checks
    Else{
        WriteResults "Red" "Server $_ is not reachable - Ensure server is online and attempt to audit again." "" "Fail"
    }
}

Write-Host "" ; Write-Host "Audit Complete, resluts have been written to the following folder" ; Write-Host ""
Write-Host $ResultsPath ; Write-Host ""
Write-Host "Press any key to close this script"
CloseScript