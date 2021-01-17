Set-Location -Path $PSScriptRoot
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

#$CredsSql

#Note: This Script looks for two files, Servers.txt (Required) and Creds.csv (Optional) in the same folder where the script is.
#region Initial Setup Vars
$InputServerList = ".\Servers.txt"
$ResultsFolder = "\AuditResults"
$global:ResultsPath = "$PSScriptRoot$($ResultsFolder)"
$global:CredCheckCount = 1
$WinCredsCsv = ".\WinCreds.csv"
$SqlCredsCsv = ".\SqlCreds.csv"
$HTMLFile = "InitAudit.htm"
$CsvFile = "InitAudit.csv"
#$integratedSqlLogin=$true
$CredsValid = $false
$ShwResMsg = $true
$global:HTMLOuputStart = "<html><body><br><b>UCCE/PCCE Server Audit Report.</b></body><html>
<html><body>"
$global:HTMLOuputEnd = "</body></html>"

while ($SqlCredType -notin "Y","N"){
    Write-Host "Enter " -NoNewline; Write-Host -ForegroundColor Yellow "Y" -NoNewline; Write-Host " to use Integrated authentication for SQL, or enter " -NoNewline
    Write-Host -ForegroundColor Yellow "N" -NoNewline; Write-Host " to use SQL authentication"
    $SqlCredType = Read-Host
    if ($SqlCredType -in "Y","N"){
        if ($SqlCredType -eq "Y"){
            $integratedSqlLogin=$true
        }
        else{
            $integratedSqlLogin=$false
        }
    }
    else {
        Write-Host "You must enter " -ForegroundColor Yellow -NoNewline; Write-Host "Y" -ForegroundColor Red -NoNewline;Write-Host " or " -ForegroundColor Yellow -NoNewline
        Write-Host "N" -ForegroundColor Red -NoNewline; Write-Host " to continue" -ForegroundColor Yellow
    }
}
#endregion Initial Setup Vars

#region Functions
#Write results to CSV, html file and PowerShell window
#To use function, send it the Color of the message and up to 2 strings and a Pass/Fail/Warning string to write to audit result to files and console
Function WriteResults ($msgStatus,$String1,$String2,$ShwResMsg){
    if ($msgStatus -eq "Pass") {$HtmlColor = "008000"; $ConsColor = "Green"}
    elseif ($msgStatus -eq "Fail") {$HtmlColor = "F00000"; $ConsColor = "Red"}
    elseif ($msgStatus -eq "Warning") {$HtmlColor = "FFC000"; $ConsColor = "Yellow"}
    else {$HtmlColor = "000000"; $ConsColor = "White"}
    if ($ShwResMsg) {
        Add-Content "$ResultsPath\$HTMLFile" "<br><font color =`"#$HtmlColor`">$String1 $String2 $msgStatus</font>"
        Add-Content -Path "$ResultsPath\$CsvFile" "$String1,$String2,$msgStatus"
        Write-Host -ForegroundColor $ConsColor $String1 $String2 $msgStatus
    }
    else {
        Add-Content "$ResultsPath\$HTMLFile" "<br><font color =`"#$HtmlColor`">$String1 $String2</font>"
        Add-Content -Path "$ResultsPath\$CsvFile" "$String1,$String2,"
        Write-Host -ForegroundColor $ConsColor $String1 $String2
    }
}

#Write notice for malconfigured Page-files
Function WritePFNotice($msgStatus){
    WriteResults $msgStatus "- It is recommended to configure the Swap File with an Inital and Max size of 1.5 x Memory" ""
    WriteResults $msgStatus "- Use the below sizes to set the Swap File accordingly " ""
    WriteResults $msgStatus "-  - 16GB RAM = 24576MB Page File | 12GB RAM = 18432MB Page File | 8GB RAM =  12288MB Page File" ""
    WriteResults $msgStatus "-  -  6GB RAM =  9216MB Page File |  4GB RAM =  6144MB Page File | 2GB RAM =  3072MB Page File" ""
    WriteResults $msgStatus "-  -  Note that a change to the Page File may require a reboot" ""
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

#Get Windows/ICM Admin credentials
Function GetCredsWin {
    $global:CredsWin = Get-Credential -Message "Enter Windows/ICM Admin Credentials"
    $global:CredCheckCount++
}

Function GetCredsSql {
    $global:CredsSql = Get-Credential -Message "Enter SQL Credentials"
}

#Write closing tags for HTML file
Function CloseHtml {
    Add-Content "$ResultsPath\$HTMLFile" $HTMLOuputEnd
}
#------------------------

#Invocke Coammand to remote or local computer(s)
Function InvCmd ($command){
    Invoke-Command -ComputerName $global:Server -Credential $global:CredsWin $command
}

function ExecuteSql($sql) {
    $user = $CredsSql.Username
    $pass = $CredsSql.GetNetworkCredential().Password
    
    if ($integratedSqlLogin)
    {
        $connection = new-object system.data.SqlClient.SQLConnection("Server=$($Server);Integrated Security=SSPI");
    }
    else 
    {
        $connection = new-object system.data.SqlClient.SQLConnection("Server=$($Server);User Id=$($user);Password=$($pass)")
    }
    $adapter = new-object System.Data.SqlClient.SqlDataAdapter ($sql, $connection)
    $table = new-object System.Data.DataTable
    $rowCount = $adapter.fill($table)
    return ($table | Select-Object *)
}

Function CloseScript {
    CloseHtml
    $endvar = Read-Host
    Exit
}
#endregion Functions

#region File, Folder and Credential Checks
#Check to see if the Audit Results folder is present
Write-Host "Checking to see if the Audit Results folder is present"
if (Test-Path -Path $ResultsPath){
    WriteResults "Pass" "- Audit Results folder found, proceeding" "" $ShwResMsg
}
else{
    Write-Host "Audit Results folder NOT Found, creating one"
    New-Item $ResultsPath -ItemType "Directory"
}

Set-Content -Path "$ResultsPath\$HTMLFile" $HTMLOuputStart
Set-Content -Path "$ResultsPath\$CsvFile" ""

#Check to see if the Server list is present
WriteResults "Default" "Checking to see if the Server list is present" ""
if (Test-Path -Path $InputServerList){
    WriteResults "Pass" "- Server list file found, proceeding" "" $ShwResMsg
    if (("" -eq ($global:TestServer = Get-Content $InputServerList))-or($null -eq ($global:TestServer = Get-Content $InputServerList))){
        WriteResults "Fail" "- No Servers in List File - Nothing to check." "" $ShwResMsg
        WriteResults "Fail" "- Exiting, press any key to exit script" ""
        CloseScript
    }
}
else{
    WriteResults "Fail" "- File NOT Found - Nothing to check." "" $ShwResMsg
    WriteResults "Fail" "- Exiting, press any key to exit script" ""
    CloseScript
}

#Check to see if the Windows/ICM Credentials CSV file is present
WriteResults "Default" "Checking to see if the Windows/ICM credentials CSV file is present" ""
if (Test-Path -Path $WinCredsCsv){
    #check to see if credentials are present in CSV file
    $UserCreds = Import-Csv -Path $WinCredsCsv
    if (($null -ne $UserCreds.username)-and($null -ne $UserCreds.pass)){
        #Read Windows and Portico credentials from CSV file
        WriteResults "Pass" "- Loading Windows/ICM credentials from CSV, proceeding" "" $ShwResMsg
        $password = ConvertTo-SecureString $UserCreds.pass -AsPlainText -Force
        $global:CredsWin = New-Object System.Management.Automation.PSCredential ($UserCreds.username, $password)
    }
    else{
        WriteResults "Fail" "- Windows/ICM credentials not found in CSV, prompting for credentials" $ShwResMsg
        GetCredsWin
    }
}
else{
    WriteResults "Fail" "- Windows/ICM credentials CSV file NOT found, prompting for credentials" "" $ShwResMsg
    GetCredsWin
}

WriteResults "Default" "Checking to see if the SQL credentials CSV file is present" ""
if (Test-Path -Path $SqlCredsCsv){
    #check to see if credentials are present in CSV file
    $UserCreds = Import-Csv -Path $SqlCredsCsv
    if (($null -ne $UserCreds.username)-and($null -ne $UserCreds.pass)){
        #Read Windows and Portico credentials from CSV file
        WriteResults "Pass" "- Loading SQL credentials from CSV, proceeding" "" $ShwResMsg
        $password = ConvertTo-SecureString $UserCreds.pass -AsPlainText -Force
        $global:CredsSql = New-Object System.Management.Automation.PSCredential ($UserCreds.username, $password)
    }
    else{
        WriteResults "Fail" "- SQL credentials not found in CSV, prompting for credentials" $ShwResMsg
        GetCredsSql
    }
}
else{
    WriteResults "Fail" "- SQL credentials CSV file NOT found, prompting for credentials" "" $ShwResMsg
    GetCredsSql
}

#Check if credentials are valid
WriteResults "Default" "Cechking credentials against the first server in the list to see if credentials are valid" ""
While ($CredsValid -eq $false){
    Try {
        $LoginError = $false
        $CredCheck = Invoke-Command -ComputerName $global:TestServer[0] -Credential $CredsWin -ErrorAction Stop {Get-WmiObject -Class win32_operatingsystem}
    }
    Catch {
        $LoginError = $true
    }
    if (($LoginError -eq $true)-and ($global:CredCheckCount -lt 4)){
        WriteResults "Fail" "- Credentials not valid or don't have proper privileges, prompting for credentials" "" $ShwResMsg
        WriteResults "Fail" "- Note: this error may also occur if the fist server in the list is invalid or not reachable" ""
        GetCredsWin
    }
    elseif (($LoginError -eq $true)-and($global:CredCheckCount -ge 3)) {
        WriteResults "Fail" "- Credentials not valid or don't have proper privileges, prompting for credentials" "" $ShwResMsg
        WriteResults "Fail" "- Note: this error may also occur if the fist server in the list is invalid or not reachable" ""
        Write-Host ""
        WriteResults "Fail" "- No more attemmpts remaining, exiting, press any key to exit script" "" $ShwResMsg
        CloseScript
    }
    else{
        WriteResults "Pass" "- Credentials are valid, continuing" "" $ShwResMsg
        $CredsValid = $true
    }
}
#endregion File, Folder and Credential Checks

#region ---------------------------------------Start Audit---------------------------------------
WriteResults "Default" "Starting Audit Checks for list of servers" ""
Get-Content $InputServerList | ForEach-Object {
    #region Audit Setup vars and Check for Server
    #Setup Audit Vars
    $global:Server = $_
    $HTMLFile = "$Server.htm"
    $CsvFile = "$Server.csv"
    $IcmInstalled=$PorticoRunning=$PrivateNic=$Router=$Logger=$Awhds=$Pg=$Cg=$CTIOS=$Dialer=$False
    $LoggerSide=$LoggerDb=$AwDb=$HdsDb=""
    $PubNicErr=$PrivNicErr=$false
    Set-Content -Path "$ResultsPath\$HTMLFile" $HTMLOuputStart
    Set-Content -Path "$ResultsPath\$CsvFile" ""

    #Write Server name to results
    WriteResults "Default" "Server - `'$Server`'" ""

    #Check that the server is reachable
    WriteResults "Default" "Checking to see if `'$Server`' is online" ""
    if (Test-Connection -Count 2 -Quiet $Server){
        WriteResults "Pass" "- Server `'$Server`' Online - Continuing with health chek items" "" $ShwResMsg
        
        

        #Get OS version
        WriteResults "Default" "Getting OS version" ""
        $OS = InvCmd {Get-WmiObject -Query "select * from win32_operatingsystem"} | Select-Object @{Name="OS"; Expression={"$($_.Caption)$($_.CSDVersion) $($_.OSArchitecture)"}} | Select-Object -expand OS
        WriteResults "Pass" "- $OS" ""

        #Get OS License Status
        WriteResults "Default" "Getting OS License Status" ""
        $OSLic = InvCmd {(Get-WmiObject -Query "select * from SoftwareLicensingProduct"| Select-Object -expand LicenseStatus) -contains 1}
        if ($OSLic -eq "True"){
            WriteResults "Pass" "- This copy if Windows is successfully activated" "" $ShwResMsg
        }
        else {
            WriteResults "Fail" "- This copy if Windows is NOT activated" "" $ShwResMsg
        }

        #Get the Servers Time Zone
        WriteResults "Default" "Getting Server Time Zone" ""
        $timeZone = InvCmd {Get-WmiObject -Query "select * from win32_timezone"} | Select-Object -expand Caption
        WriteResults "Pass" "- $timeZone" ""
        
        #Get the server that provides time synchronization for this server
        WriteResults "Default" "Getting Time Server" ""
        $timeServer = InvCmd {cmd /c $env:WINDIR\system32\w32tm.exe /query /source}
        WriteResults "Pass" "- $timeServer" ""
        
        #Get Processor Information
        WriteResults "Default" "Getting Processor Type and Core Count" ""
        $Cpu = InvCmd {Get-WmiObject -Query "select * from win32_processor"}
        WriteResults "Pass" "- $($Cpu.Name) with $($Cpu.NumberOfCores) cores" ""
        
        #Get RAM size
        WriteResults "Default" "Getting RAM amount" ""
        $Ram = InvCmd {"{0:N2}" -f ((Get-WmiObject -Query "select * from win32_computersystem" | Select-Object -expand TotalPhysicalMemory) / 1GB)}
        WriteResults "Pass" "- $($Ram)GB of RAM" ""

        #Check Page file is hard set to 1.5x RAM size
        WriteResults "Default" "Checking to see if Page file is configured to MS best practices" ""
        $MemSzMB = InvCmd {[Math]::Ceiling((Get-WmiObject win32_computersystem | Select-Object -ExpandProperty TotalPhysicalMemory) / 1048576 )}
        $sysManPgFil = InvCmd {Get-WmiObject win32_computersystem} | Select-Object -expand AutomaticManagedPagefile
        if ($sysManPgFil -eq "True"){
            WriteResults "Fail" "- Page File Configred to be managed by system" "" $ShwResMsg
            WritePFNotice "Fail"
        }
        else{
            $PfSettings = InvCmd {Get-WmiObject -Class Win32_PageFileSetting}
            $PfRangeLow = $MemSzMB*1.4 ; $PfRangeHigh = $MemSzMB*1.6
            #Write-Host $PfSettings.InitialSize $PfSettings.MaximumSize
            if ($PfSettings.InitialSize -eq $PfSettings.MaximumSize){
                if (($PfSettings.MaximumSize -gt $PfRangeLow) -and ($PfSettings.MaximumSize -lt $PfRangeHigh)){
                    WriteResults "Pass" "- Page File Configred to best practices" "" $ShwResMsg
                }
                elseif($PfSettings.MaximumSize -gt $PfRangeHigh){
                    WriteResults "Warning" "- Page File Configred larger than typical installs" "" "Warning" $ShwResMsg
                    WritePFNotice "Warning"
                }
                else{
                    WriteResults "Fail" "- Page File Size Should be increased" "" $ShwResMsg
                    WritePFNotice "Fail"
                }
            }
            elseif($PfSettings.InitialSize -lt $PfRangeLow){
                WriteResults "Fail" "- Page File Size Should be increased and both Initial and Max Values shoufl be the same" "" $ShwResMsg
                WritePFNotice "Fail"
            }
            else{
                WriteResults "Warning" "- Page File Size is large enough but both Initial and Max Values shoufl be the same" "" "Warning" $ShwResMsg
                WritePFNotice "Warning"
            }
        }

        #Check if CD Rom drive is assigned to Z:
        WriteResults "Default" "Checking to see if CD Rom has been reassigned to Z:" ""
        $CdRomDrive = InvCmd {Get-WmiObject Win32_CDROMDrive} | Select-Object -ExpandProperty Drive
        if ($CdRomDrive.Count -eq 1){
            if ($CdRomDrive -eq "z:"){
                WriteResults "Pass" "- CD Drive Assigned to Z:" "" $ShwResMsg
            }
            else {
                WriteResults "Fail" "- CD Drive Assigned to $CdRomDrive - Should be reassigned to Z:" "" $ShwResMsg
            }
        }
        elseif ($CdRomDrive.Count -eq 0) {
            WriteResults "Fail" "- Virtual CD Drive MISSING, should have one assigned to Z:" "" $ShwResMsg
        }
        else {
            WriteResults "Fail" "- MULTIPLE Virtual CD Drives present - $CdRomDrive, should have one assigned to Z:" "" $ShwResMsg
        }

        #Check if WMI SNMP Provider is installed
        WriteResults "Default" "Checking to see if WMI SNMP Provider is installed" ""
        $snmpInst = InvCmd {Get-WmiObject -Query "select * from win32_optionalfeature where Name='WMISnmpProvider'"} | Select-Object -expand InstallState
        if ($snmpInst -eq "1"){
            WriteResults "Pass" "- WMI SNMP Provider Installed" "" $ShwResMsg
        }
        else {
            WriteResults "Fail" "- WMI SNMP Provider NOT Installed - Should be installed" "" $ShwResMsg
        }

        #Check if RDP is enabled
        WriteResults "Default" "Checking to see RDP Services are enabled" ""
        $RdpEnabled = InvCmd {Get-WmiObject Win32_TerminalServiceSetting -name "root\cimv2\TerminalServices"} | Select-Object -expand AllowTSConnections
        if ($RdpEnabled -eq 1){
            WriteResults "Pass" "- Remote Desktop Enabled" "" $ShwResMsg
        }
        else {
            WriteResults "Fail" "- Remote Desktop DISABLED" "" $ShwResMsg
        }
    
        #Get Windows Firewall status
        if ($OS -like "*2008*"){
            WriteResults "Default" "Getting Windows Firewall Status - Server 2008R2" ""
            $fwService = InvCmd {Get-WmiObject -Query "select * from win32_service where DisplayName like '%Windows Firewall%'"} | Select-Object -ExpandProperty Started
            if ($fwService){
                $fwNetworks = @("Domain","Private","Public")
                WriteResults "Pass" "- Windows Firewall service is Running" "" $ShwResMsg
                foreach ($fwNetwork in $fwNetworks) {
                    $fwNetCmd = "(cmd /c $env:WINDIR\system32\netsh.exe advfirewall show $fwNetwork | select-string -pattern `"State[ \t]*(?<state>.+)`" ).Matches[0].Groups['state'].Value"
                    $fwNetworkStatus = InvCmd {$fwNetCmd}
                    if ($fwNetworkStatus -eq "ON"){
                        WriteResults "Fail" "- $($fwNetwork) Firewall Network is ON" ""  $ShwResMsg
                    }
                    else {
                        WriteResults "Pass" "- - $($fwNetwork) Firewall Network is OFF" "" $ShwResMsg
                    }
                }
            }
            else {
                WriteResults "Pass" "- Windows Firewall service is not running" "" $ShwResMsg
            }
        }
        else {
            WriteResults "Default" "Getting Windows Firewall Status" ""
            $fwService = InvCmd {Get-WmiObject -Query "select * from win32_service where DisplayName like '%Windows Firewall%'"} | Select-Object -ExpandProperty Started
            if ($fwService){
                $fwProfiles = InvCmd {Get-NetFirewallProfile}
                $fwProfNames = @("Domain","Private","Public")
                WriteResults "Pass" "- Windows Firewall service is Running" "" $ShwResMsg
                foreach ($fwProfName in $fwProfNames) {
                    $fwProfStatus = $fwProfiles| Where-Object -eq Name $fwProfName | Select-Object -ExpandProperty Enabled
                    if ($fwProfStatus){
                        WriteResults "Fail" "- - $fwProfName` Firewall Profile is ON" "" $ShwResMsg
                    }
                    else {
                        WriteResults "Pass" "- - $fwProfName` Firewall Profile is OFF" "" $ShwResMsg
                    }
                }
            }
            else {
                WriteResults "Pass" "- Windows Firewall service is not running" "" $ShwResMsg
            }
        }

        #Check to see if Updates are Set to Manual
        WriteResults "Default" "Checking to see if Windows Updates are set to Manual" ""
        if ($OS -like "*2016*"){
            $reg = InvCmd {(Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU").NoAutoUpdate}
            if ($UpdateStatus -eq 1){
                WriteResults "Pass" "- Windows Updates Set to manual" "" $ShwResMsg
            }
            else{
                WriteResults "Warning" "- Windows Updates enabled" "" $ShwResMsg
            }
        }
        elseif($OS -like "*2012*"){
            $reg = InvCmd {(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update").AUOptions}
            if ($reg -eq 1){
                WriteResults "Pass" "- Windows Updates Set to manual" "" $ShwResMsg
            }
            else{
                WriteResults "Warning" "- Windows Updates enabled" "" "Warning" $ShwResMsg
            }
        }

        #Check for recently installed updates
        WriteResults "Default" "Checking to see if Windows Updates have been installed in the last 60 days" ""
        $Hotfixes = InvCmd {Get-WmiObject win32_quickfixengineering}
        $LastUpdate = $Hotfixes.item(($Hotfixes.length - 1)).InstalledOn
        $Today = Get-Date ; $DateDif = $Today - $LastUpdate
        if ($DateDif.Days -lt 60){
            WriteResults "Pass" "- Windows Updates have been installed in the last 60 days" "" $ShwResMsg
        }
        else{
            WriteResults "Fail" "- NO Windows Updates have been installed in the last 60 days" "" $ShwResMsg
        }

        #Check if IPv6 is globally disabled
        WriteResults "Default" "Checking if IPv6 is globally disabled in the registry" ""
        try {$Ipv6RegData = InvCmd {Get-ItemProperty -PSPath 'HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters\'} | Select-Object -ExpandProperty DisabledComponents -ErrorAction Stop}
        catch {$Ipv6RegData=$null}
        if ($Ipv6RegData -eq 255){
            WriteResults "Pass" "- IPv6 has been globally disabled in the registry" "" $ShwResMsg
            $Ipv6DisReg = $true
        }
        elseif ($Ipv6RegData -eq -1){
            WriteResults "Warning" "- IPv6 has been globally disabled in the registry" "" $ShwResMsg
            WriteResults "Warning" "- The following registry value should be set to 0x000000ff not 0xffffffff" ""
            WriteResults "Warning" "- HKLM:SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters\DisabledComponents" ""
            WriteResults "Warning" "- Using 0xffffffff will cause the server to take longer to boot up during restarts" ""
            $Ipv6DisReg = $true
        }
        else{
            WriteResults "Warning" "- IPv6 NOT globally disabled in the registry, must check that it's disabled on NIC's" "" $ShwResMsg
            $Ipv6DisReg = $false
        }
        
        #Check that TCP offload is Disabled and NIC speed is set to 1Gb Full Duplex
        WriteResults "Default" "Check to see if TCP Offload and Speed/Duplex setting are configured properly" ""
        #Offload settings
        InvCmd {Get-NetAdapterAdvancedProperty -DisplayName "*offload*"} | ForEach-Object {
            if ($_.DisplayValue -like "*Disabled*"){
                WriteResults "Pass" "- $($_.Name) $($_.DisplayName)  $($_.DisplayValue)" "" $ShwResMsg
            }
            else {
                WriteResults "Fail" "- $($_.Name) $($_.DisplayName) $($_.DisplayValue)" "" $ShwResMsg
            }
        }
        #Speed-Duplex setting(s)
        InvCmd {Get-NetAdapterAdvancedProperty -DisplayName "*speed*"} | ForEach-Object {
            if ($_.DisplayValue -like "*1.0 Gbps Full*"){
                WriteResults "Pass" "- $($_.Name) $($_.DisplayName)  $($_.DisplayValue)" "" $ShwResMsg
            }
            else {
                WriteResults "Fail" "- $($_.Name) $($_.DisplayName) $($_.DisplayValue)" "" $ShwResMsg
            }
        }

    #endregion
        
        #region Get ICM info
        #Check that Portico is installed and running
        WriteResults "Default" "Checking if Portico/ICM is installed and Running" ""
        $PorticoService = InvCmd {Get-WmiObject -Query "select * from win32_service where DisplayName='Cisco ICM Diagnostic Framework'"} | Select-Object -property State
        if ($PorticoService){
            $global:IcmInstalled = $true
            WriteResults "Pass" "- Portico/ICM is installed - Checking if it is Running" ""
            if ($PorticoService.State -eq "Running"){
                $global:PorticoRunning = $true
                WriteResults "Pass" "- - Portico/ICM is installed and Running" "" $ShwResMsg
            }
            else{
                $PorticoRunning = $false
                WriteResults "Fail" "- - Portico/ICM is installed - But NOT Running" "" $ShwResMsg
            }
        }
        else{
            WriteResults "Fail" "- Unable to find Portico Service Ensure that servername in list is correct" "" $ShwResMsg
            WriteResults "Fail" "- - ICM must be installed on the server to be audited, only a limited audit will be run" ""
            $IcmInstalled = $false
        } 

        #Get ICM Instance(s)
        WriteResults "Default" "Fetching ICM Inatance(s)"
        $IcmRegKeys = InvCmd {Get-ChildItem -PSPath 'HKLM:\SOFTWARE\Cisco Systems, Inc.\ICM\' -Name}
        $InstancesFound = $IcmRegKeys | Where-Object {($_ -notmatch '\d\d\.\d')-and($_ -notin 'ActiveInstance','Performance','Serviceability','SNMP','SystemSettings','CertMon','Cisco SSL Configuration')}
        If ($InstancesFound.Count -gt 0){
            ForEach ($Instance in $InstancesFound){
                WriteResults "Pass" "- Instance $($Instance) Found" "" $ShwResMsg
            }   
        }
        else{
            WriteResults "Fail" "No Instance Found" "" $ShwResMsg
        }

        #Get ICM Version
        WriteResults "Default" "Fetching ICM Version(s)"
        ForEach ($Instance in $InstancesFound){
            MakeWebRequest "https://$Server`:7890/icm-dp/rest/DiagnosticPortal/GetProductVersion?InstanceName=$Instance"
            try {$Resp = $WebReq.GetResponse()}
            catch {$Resp = "error"}
            if ($Resp -eq "error")
            {
                WriteResults "Fail" "Unable to Fetch ICM Version from Portico" "" $ShwResMsg
            }
            else {
                $Reader = new-object System.IO.StreamReader($resp.GetResponseStream())
                [xml]$ResultXml = $Reader.ReadToEnd()
                $Products = @($ResultXml.GetProductVersionReply |  Select-Object -expand ProductVersion)                
                ForEach ($Product in $Products){
                    WriteResults "Pass" "- $Instance` - $($Product.Name) $($Product.VersionString) Found" "" $ShwResMsg
                    #Read-Host
                }
                $reader.Close()
                $resp.Close()
            }
        }
        $MajorIcmVer = $Products.Major
        $MinorIcmVer = $Products.Minor


        #Get Installed ICM Components
        WriteResults "Default" "Checking to see what ICM Components are installed"
        ForEach ($Instance in $InstancesFound){
            MakeWebRequest "https://$Server`:7890/icm-dp/rest/DiagnosticPortal/ListAppServers?InstanceName=$Instance"
            try {$Resp = $WebReq.GetResponse()}
            catch {$Resp = "error"}
            if ($Resp -eq "error")
            {
                WriteResults "Fail" "Unable to Fetch ICM Components from Portico" "" $ShwResMsg
            }
            else {
                $Reader = new-object System.IO.StreamReader($resp.GetResponseStream())
                [xml]$ResultXml = $Reader.ReadToEnd()
                $Services = @($ResultXml.ListAppServersReply.AppServerList.AppServer | Where-Object {$_.ProductComponentType -notin "Cisco ICM Diagnostic Framework","Administration Client"} | Select-Object -expand ProductComponentType)
                ForEach ($Service in $Services){
                    WriteResults "Pass" "- $($Instance) - $($Service) Found" "" $ShwResMsg
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
        <#$Router
        $Logger
        $LoggerDb
        $Pg
        $Cg
        $CTIOS
        $Dialer
        $Awhds
        $AwDb
        $HdsDb#>
        #endregion Get ICM info

        #Get Cisco ICM Services and Startup Type
        WriteResults "Default" "Checking to see what ICM services are installed and their Startup Type" ""
        InvCmd {Get-WmiObject -Query "select * from win32_service where DisplayName like 'Cisco%'"}  | ForEach-Object {
            if (($_.StartMode -like "Auto*")-and($_.State -like "Running")){
                WriteResults "Pass" "- $($_.DisplayName) - $($_.State) - $($_.StartMode)" "" $ShwResMsg
            }
            elseif (($_.StartMode -notlike "Auto*")-or($_.State -notlike "Running")) {
                WriteResults "Fail" "- $($_.DisplayName) - $($_.State) - $($_.StartMode)" "" $ShwResMsg
            }
        }
    
        #Get SQL version for Servers that use SQL
        if (($Logger -eq $true)-or($Awhds -eq $true)){
            WriteResults "Default" "Gettin SQL version" ""
            $SqlVerInfo = ExecuteSql("SELECT SERVERPROPERTY('productversion') AS Version, SERVERPROPERTY ('productlevel') AS ServicePack, SERVERPROPERTY ('edition') AS Edition")
            $SqlVer = "- $($SqlVerInfo.Version) $($SqlVerInfo.ServicePack) $($SqlVerInfo.Edition)"
            $SqlVer = $SqlVer -replace "14.0.[\.\d]*", "SQL Server 2016"
            $SqlVer = $SqlVer -replace "12.0.[\.\d]*", "SQL Server 2014"
            $SqlVer = $SqlVer -replace "11.[\.\d]*", "SQL Server 2012"
            $SqlVer = $SqlVer -replace "10.50.[\.\d]*", "SQL Server 2008 R2"
            $SqlVer = $SqlVer -replace "10.00.[\.\d]*", "SQL Server 2008"
            $SqlVer = $SqlVer -replace "9.00.[\.\d]*", "SQL Server 2005"
            $SqlVer = $SqlVer -replace "8.00.[\.\d]*", "SQL Server 2000"
            WriteResults "Pass" $SqlVer "" "" $ShwResMsg
        }


        #Get Disk(s) and Disk size(s)
        WriteResults "Default" "Getting Disk(s) and Disk size(s)" ""
        $drives = InvCmd {Get-WmiObject -Query "select * from win32_logicaldisk where DriveType=3"}
        $driveDetails = @();
        $drives | ForEach-Object {$driveDetails += "$($_.DeviceID) $("{0:N2}" -f ($_.FreeSpace / 1GB)) GB Free / $("{0:N2}" -f ($_.Size / 1GB)) GB Total"}
        foreach ($drive in $driveDetails){
            if ($drive -like "*C:*") {
                WriteResults "Pass" "- $drive" "" $ShwResMsg
            }
            elseif (($Logger)-or($Awhds)) {
                WriteResults "Pass" "- $drive" "" $ShwResMsg
            }
            else {
                WriteResults "Warning" "- $drive - This server does not have ICM components that require additional disks" "" $ShwResMsg
            }
        }

        #Get Data drive (D:) Volume name for AW-HDS and Logger servers
        if (($Awhds)-or($Logger)){
            WriteResults "Default" "Getting Data Drive (D:) Volume Name" ""
            $dataDrive = InvCmd {Get-WmiObject win32_logicaldisk} | Where-Object {($_.DeviceID -eq 'D:')-and($_.DriveType -eq 3)}
            if (!$dataDrive) {
                WriteResults "Fail" "- NO data volume with drive letter D: found" "" $ShwResMsg
            } 
            else {
                if ($dataDrive.VolumeName -eq $null -or $dataDrive.VolumeName -eq "") {
                    WriteResults "Warning" "- No name for data volume with drive letter D: found" "" "Warning" $ShwResMsg
                }
                else {
                    WriteResults "Pass" "- Volume '$($dataDrive.VolumeName)' with drive letter D: found" "" $ShwResMsg
                }
            }
        } #>


        #Getting non-loopback nics for following NIC checks
        $Nics = InvCmd {Get-NetIPInterface} | Where-Object {($_.InterfaceAlias -notlike 'Loopback*')-and($_.InterfaceAlias -notlike 'isatap*')}
        #Check if IPv6 is Disabled on all NIC's if not disabled globally
        if (!$Ipv6DisReg) {
            $Ipv6Nics = $Nics | Where-Object {$_.AddressFamily -eq 23}
            WriteResults "Default" "Checking to see IPv6 is disabled on the NIC's" ""
            if ($Ipv6Nics.count -eq 0) {
                WriteResults "Pass" "- IPv6 is Disabled on all present NIC's" "" $ShwResMsg
            }
            else {
                WriteResults "Fail" "- IPv6 is enabled on the followng NIC's" "" $ShwResMsg
                foreach ($Ipv6Nic in $Ipv6Nics){
                    WriteResults "Fail" "- - $($Ipv6Nic.InterfaceAlias)" ""
                }
            }
        }

        #Check for proper number of Public NIC's
        WriteResults "Default" "Checking for the proper number of interfaces named 'Public'" ""
        $Ipv4Nics = $Nics | Where-Object -FilterScript {$_.AddressFamily -eq 2}
        $PubNic = $Ipv4Nics | Where-Object {$_.InterfaceAlias -like '*public*'}
        $PrivNic = $Ipv4Nics | Where-Object {$_.InterfaceAlias -like '*private*'}
        if ($PubNic){
            if (!$PubNic.count) {
                WriteResults "Pass" "- One interface named `'Public`' found" "" $ShwResMsg
            }
            else {
                WriteResults "Fail" "- $($PubNic.count) interfaces named `'Public`' found" "" $ShwResMsg
                $PubNicErr = $true
            }
        }
        else {
            WriteResults "Fail" "- No interface named `'Public`' found" "" $ShwResMsg
            $PubNicErr = $true
        }    

        if($Router -or $Logger -or $Pg){
            WriteResults "Default" "Checking for the proper number of interfaces named 'Private'" ""
            if ($PrivNic){
                if (!$PrivNic.count) {
                    WriteResults "Pass" "- One interface named `'Private`' found" "" $ShwResMsg
                }
                else {
                    WriteResults "Fail" "- $($PrivNic.count) interfaces named `'Private`' found" "" $ShwResMsg
                    $PrivNicErr = $true
                }
            }
            else {
                WriteResults "Fail" "- No interface named `'Private`' found" "" $ShwResMsg
                $PrivNicErr = $true
            }    
        }

        #Check for proper number of IP Addresses for Public NIC
        WriteResults "Default" "Checking for proper number of IP Addresses for Public NIC" ""
        if(!$PubNicErr){
            $PubNicIps = InvCmd {Get-NetIPAddress} | Where-Object {$_.InterfaceAlias -eq $PubNic.InterfaceAlias}
            if ($Router -or $Pg) {
                WriteResults "Default" "- Server has PG or Router present and should have 2 Public IP addresses" ""
                if ($PubNicIps.count -eq 2) {
                    WriteResults "Pass" "- - Found 2 IP addresses assigned to the Public Interface" "" $ShwResMsg
                    WriteResults "Pass" "- - $($PubNicIps.IPAddress)" ""
                }
                else {
                    if (!$PubNicIps.count) {
                        WriteResults "Fail" "- - Found only 1 IP addresses assigned to the Public Interface" "" $ShwResMsg
                        WriteResults "Fail" "- - $($PubNicIps.IPAddress)" ""
                    }
                    else {
                        WriteResults "Fail" "- - Found more than 2 IP addresses assigned to the Public Interface" "" $ShwResMsg
                        WriteResults "Fail" "- - $($PubNicIps.IPAddress)" ""
                    }
                    
                }
            }
            else {
                WriteResults "Default" "- Server has does not have PG or Router present and should have 1 Public IP addresses" ""
                if (!$PubNicIps.count) {
                    WriteResults "Pass" "- - Found 1 IP addresses assigned to the Public Interface" "" $ShwResMsg
                    WriteResults "Pass" "- - $($PubNicIps.IPAddress)" ""
                }
                else {
                    WriteResults "Fail" "- - Found more than 1 IP addresses assigned to the Public Interface" "" $ShwResMsg
                    WriteResults "Fail" "- - $($PubNicIps.IPAddress)" ""
                }
            }
        }
        else {
            WriteResults "Fail" "- Public NIC count or Public NIC naming not configured correctly." "" $ShwResMsg
            WriteResults "Fail" "- Cannot check for proper number of IP Addresse" ""
        }

        #Check for proper number of IP Addresses for Private NIC
        if ($Router -or $Logger -or $Pg -or $Cg) {
            WriteResults "Default" "Checking for proper number of IP Addresses for Private NIC" ""
            if(!$PrivNicErr){
                $PrivNicIps = InvCmd {Get-NetIPAddress} | Where-Object {$_.InterfaceAlias -eq $PrivNic.InterfaceAlias}
                if ($Router -or $Pg) {
                    WriteResults "Default" "- Server has PG or Router present and should have 2 Private IP addresses" ""
                    if ($PrivNicIps.count -eq 2) {
                        WriteResults "Pass" "- - Found 2 IP addresses assigned to the Private Interface" "" $ShwResMsg
                        WriteResults "Pass" "- - $($PrivNicIps.IPAddress)" ""
                    }
                    else {
                        if (!$PrivNicIps.count) {
                            WriteResults "Fail" "- - Found only 1 IP addresses assigned to the Private Interface" "" $ShwResMsg
                            WriteResults "Fail" "- - $($PrivNicIps.IPAddress)" ""
                        }
                        else {
                            WriteResults "Fail" "- - Found more than 2 IP addresses assigned to the Private Interface" "" $ShwResMsg
                            WriteResults "Fail" "- - $($PrivNicIps.IPAddress)" ""
                        }
                        
                    }
                }
                else {
                    WriteResults "Default" "- Server has does not have PG or Router present and should have 1 Private IP addresses" ""
                    if (!$PrivNicIps.count) {
                        WriteResults "Pass" "- - Found 1 IP addresses assigned to the Private Interface" "" $ShwResMsg
                        WriteResults "Pass" "- - $($PrivNicIps.IPAddress)" ""
                    }
                    else {
                        WriteResults "Fail" "- - Found more than 1 IP addresses assigned to the Private Interface" "" $ShwResMsg
                        WriteResults "Fail" "- - $($PrivNicIps.IPAddress)" ""
                    }
                }
            }
            else {
                WriteResults "Fail" "- Private NIC count or Private NIC naming not configured correctly." "" $ShwResMsg
                WriteResults "Fail" "- Cannot check for proper number of IP Addresse" ""
            }
        }
        else {
            #server does not have component that reqires private NIC
        }

        #lsits static routes for Private NIC
        if($Router -or $Logger -or $Pg -or $Cg){
            WriteResults "Default" "Checking to see Persistent Static Route for Prive NIC is present" ""
            try {$PrivRoute = InvCmd {Get-NetRoute} | Where-Object {($_.InterfaceAlias -eq $PrivNic.InterfaceAlias) -and ($_.Protocol -eq 'NetMgmt')} -ErrorAction Stop}
            catch{$PrivRoute = "error"}
        }
        #try {$PrivRoute = Get-NetRoute -InterfaceAlias $PrivNic.InterfaceAlias -Protocol NetMgmt -ErrorAction Stop}
        #catch {$PrivRoute = "error"}
        #$PrivNic.InterfaceAlias

        #Check NIC/Interface Priority for Router, Logger and PG servers
        if($Router -or $Logger -or $Pg -or $Cg){
            WriteResults "Default" "Checking to see if NIC Binding Order/Interface Metric is configured properly" ""
            if ($PubNicErr -or $PrivNicErr) {
                WriteResults "Fail" "- NIC count or NIC naming not configured correctly." "" $ShwResMsg
                WriteResults "Fail" "- Cannot check for Binding Order or Interface Metric" ""
            }
            else {
                #2016 NIC Metric Check
                if ($OS -like "*2016*"){
                    WriteResults "Default" "- Server 2016 Found Checking Interface Metric" ""
                    if ($PubNic.InterfaceMetric -lt $PrivNic.InterfaceMetric){
                        WriteResults "Pass" "- NIC Metric Priority correctly configured Public - NIC = $($PubNic.InterfaceMetric) and Private NIC = $($PrivNic.InterfaceMetric)" "" $ShwResMsg
                    }
                    
        
                    else{
                    WriteResults "Fail" "- NIC Metric Priority NOT correctly configured - Public NIC = $($PubNic.InterfaceMetric) and Private NIC = $($PrivNic.InterfaceMetric)" "" $ShwResMsg
                        WriteResults "Fail" "- - Public NIC should have a lower Metric value than the Priate NIC" ""
                    }
                }

                #2012 R2 Binding Order Check
                else{
                    WriteResults "Default" "- Server 2012 Found Checking Binding Order" ""
                    $Binding = InvCmd {Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Linkage"} | Select-Object -expand Bind
                    $BindingOrder = @()
                    ForEach ($Bind in $Binding)
                    {
                        $DeviceId = $Bind.Split("\")[2]
                        $Adapter = InvCmd {Get-WmiObject Win32_Networkadapter} | Where-Object {$_.GUID -like "$DeviceId" } | Select-Object -expand NetConnectionId
                        if (($Adapter -like '*public*')-or($Adapter -like '*private*')){
                            $BindingOrder += $Adapter
                        }
                    }
                    if (($BindingOrder[0] -like '*public*')-and($BindingOrder[1] -like '*private*')){
                        WriteResults "Pass" "- Binding Order correctly configured - $($BindingOrder[0]) above $($BindingOrder[1])" "" $ShwResMsg
                    }
                    else {
                        WriteResults "Fail" "- Binding Order NOT correctly configured - $($BindingOrder[1]) above $($BindingOrder[0])" "" $ShwResMsg
                        WriteResults "Fail" "- - the Public NIC should be listed above the Private NIC in the Binding Order" ""
                    }
                }
            }
        }
        else{
            WriteResults "Pass" "- Server only requires 1 NIC, not checking binding order" "" $ShwResMsg
        }
    }

    #If Server not Reachable NOT continuing with Audit Checks
    Else{
        WriteResults "Fail" "- Server `'$Server`' is not reachable - Ensure server is online and attempt to audit again." "" $ShwResMsg
    }
}
#endregion

Write-Host "" ; Write-Host "Audit Complete, resluts have been written to the following folder" ; Write-Host ""
Write-Host $ResultsPath ; Write-Host ""
Write-Host "Press Enter to close this script"
CloseScript