#Written by Mike Jezierski - Cloverhound, Inc.
#Work in progress

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
    #$SqlCredType = Read-Host
    #testing with auto setting sql auth
    $SqlCredType = 'n'
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
#To use function, send it the message status (Pass, Fail, Warning or Default) then the string to write to audit result to files
#and lastly the variable $ShwResMsg if you want the message status to be displayed at the end of the message line
Function WriteResults ($msgStatus,$String,$ShwResMsg){
    if ($msgStatus -eq "Pass") {$HtmlColor = "008000"; $ConsColor = "Green"}
    elseif ($msgStatus -eq "Fail") {$HtmlColor = "F00000"; $ConsColor = "Red"}
    elseif ($msgStatus -eq "Warning") {$HtmlColor = "FFC000"; $ConsColor = "Yellow"}
    else {$HtmlColor = "000000"; $ConsColor = "White"}
    if ($ShwResMsg) {
        if ($ConsColor -eq "White") {
            Add-Content "$ResultsPath\$HTMLFile" "<br><font color =`"#$HtmlColor`"></font>"
            Add-Content "$ResultsPath\$HTMLFile" "<br><font color =`"#$HtmlColor`">$String - $msgStatus</font>"
            Add-Content -Path "$ResultsPath\$CsvFile" ""
            Add-Content -Path "$ResultsPath\$CsvFile" "`'$String`',`'- $msgStatus`'"
            Write-Host -ForegroundColor $ConsColor "`n$String - $msgStatus"
        }else {
            Add-Content "$ResultsPath\$HTMLFile" "<br><font color =`"#$HtmlColor`">$String - $msgStatus</font>"
            Add-Content -Path "$ResultsPath\$CsvFile" "`'$String`',`'- $msgStatus`'"
            Write-Host -ForegroundColor $ConsColor "$String - $msgStatus"
        }
        
    }
    else {
        if ($ConsColor -eq "White") {
            Add-Content "$ResultsPath\$HTMLFile" "<br><font color =`"#$HtmlColor`"></font>"
            Add-Content "$ResultsPath\$HTMLFile" "<br><font color =`"#$HtmlColor`">$String</font>"
            Add-Content -Path "$ResultsPath\$CsvFile" ""
            Add-Content -Path "$ResultsPath\$CsvFile" "`'$String`',"
            Write-Host -ForegroundColor $ConsColor "`n$String"
        }else {
            Add-Content "$ResultsPath\$HTMLFile" "<br><font color =`"#$HtmlColor`">$String</font>"
            Add-Content -Path "$ResultsPath\$CsvFile" "`'$String`',"
            Write-Host -ForegroundColor $ConsColor "$String"
        }
    }
}

#Write notice for malconfigured Page-files
Function WritePFNotice($msgStatus){
    WriteResults $msgStatus "- It is recommended to configure the Swap File with an Inital and Max size of 1.5 x Memory"
    WriteResults $msgStatus "- Use the below sizes to set the Swap File accordingly "
    WriteResults $msgStatus "-  - 16GB RAM = 24576MB Page File | 12GB RAM = 18432MB Page File | 8GB RAM =  12288MB Page File"
    WriteResults $msgStatus "-  -  6GB RAM =  9216MB Page File |  4GB RAM =  6144MB Page File | 2GB RAM =  3072MB Page File"
    WriteResults $msgStatus "-  -  Note that a change to the Page File may require a reboot"
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
    Write-Host "Press Enter to close this script"
    $endvar = Read-Host
    Exit
}
#endregion Functions

#region File, Folder and Credential Checks
#Check to see if the Audit Results folder is present
Write-Host "Checking to see if the Audit Results folder is present"
if (Test-Path -Path $ResultsPath){
    WriteResults "Pass" "- Audit Results folder found, proceeding" $ShwResMsg
}
else{
    Write-Host "Audit Results folder NOT Found, creating one"
    New-Item $ResultsPath -ItemType "Directory"
}

Set-Content -Path "$ResultsPath\$HTMLFile" $HTMLOuputStart
Set-Content -Path "$ResultsPath\$CsvFile" $null


#Check to see if the Server list is present
WriteResults "Default" "Checking to see if the Server list is present"
if (Test-Path -Path $InputServerList){
    WriteResults "Pass" "- Server list file found, proceeding" $ShwResMsg
    if (("" -eq ($global:TestServer = Get-Content $InputServerList))-or($null -eq ($global:TestServer = Get-Content $InputServerList))){
        WriteResults "Fail" "- No Servers in List File - Nothing to check." $ShwResMsg
        WriteResults "Fail" "- Exiting, press any key to exit script"
        CloseScript
    }
}
else{
    WriteResults "Fail" "- File NOT Found - Nothing to check." $ShwResMsg
    WriteResults "Fail" "- Exiting, press any key to exit script"
    CloseScript
}

#Check to see if the Windows/ICM Credentials CSV file is present
WriteResults "Default" "Checking to see if the Windows/ICM credentials CSV file is present"
if (Test-Path -Path $WinCredsCsv){
    #check to see if credentials are present in CSV file
    $UserCreds = Import-Csv -Path $WinCredsCsv
    if (($null -ne $UserCreds.username)-and($null -ne $UserCreds.pass)){
        #Read Windows and Portico credentials from CSV file
        WriteResults "Pass" "- Loading Windows/ICM credentials from CSV, proceeding" $ShwResMsg
        $password = ConvertTo-SecureString $UserCreds.pass -AsPlainText -Force
        $global:CredsWin = New-Object System.Management.Automation.PSCredential ($UserCreds.username, $password)
    }
    else{
        WriteResults "Fail" "- Windows/ICM credentials not found in CSV, prompting for credentials" $ShwResMsg
        GetCredsWin
    }
}
else{
    WriteResults "Fail" "- Windows/ICM credentials CSV file NOT found, prompting for credentials" $ShwResMsg
    GetCredsWin
}

WriteResults "Default" "Checking to see if the SQL credentials CSV file is present"
if (Test-Path -Path $SqlCredsCsv){
    #check to see if credentials are present in CSV file
    $UserCreds = Import-Csv -Path $SqlCredsCsv
    if (($null -ne $UserCreds.username)-and($null -ne $UserCreds.pass)){
        #Read Windows and Portico credentials from CSV file
        WriteResults "Pass" "- Loading SQL credentials from CSV, proceeding" $ShwResMsg
        $password = ConvertTo-SecureString $UserCreds.pass -AsPlainText -Force
        $global:CredsSql = New-Object System.Management.Automation.PSCredential ($UserCreds.username, $password)
    }
    else{
        WriteResults "Fail" "- SQL credentials not found in CSV, prompting for credentials" $ShwResMsg
        GetCredsSql
    }
}
else{
    WriteResults "Fail" "- SQL credentials CSV file NOT found, prompting for credentials" $ShwResMsg
    GetCredsSql
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
        WriteResults "Fail" "- Credentials not valid or don't have proper privileges, prompting for credentials" $ShwResMsg
        WriteResults "Fail" "- Note: this error may also occur if the fist server in the list is invalid or not reachable"
        GetCredsWin
    }
    elseif (($LoginError -eq $true)-and($global:CredCheckCount -ge 3)) {
        WriteResults "Fail" "- Credentials not valid or don't have proper privileges, prompting for credentials" $ShwResMsg
        WriteResults "Fail" "- Note: this error may also occur if the fist server in the list is invalid or not reachable"
        Write-Host ""
        WriteResults "Fail" "- No more attemmpts remaining, exiting, press any key to exit script" $ShwResMsg
        CloseScript
    }
    else{
        WriteResults "Pass" "- Credentials are valid, continuing" $ShwResMsg
        $CredsValid = $true
    }
}
#endregion File, Folder and Credential Checks

#region ---------------------------------------Start Audit---------------------------------------
WriteResults "Default" "Starting Audit Checks for list of servers"
Get-Content $InputServerList | ForEach-Object {
    #region Audit Setup vars and Check for Server
    #Setup Audit Vars
    $global:Server = $_
    $HTMLFile = "$Server.htm"
    $CsvFile = "$Server.csv"
    $IcmInstalled=$PorticoRunning=$PrivateNic=$Router=$Logger=$Awhds=$Pg=$Cg=$CTIOS=$Dialer=$False
    $LoggerSide=$LoggerDb=$AwDb=$HdsDb=$null
    $PubNicErr=$PrivNicErr=$false
    $OS=$PrivNetProf=$null
    Set-Content -Path "$ResultsPath\$HTMLFile" $HTMLOuputStart
    Set-Content -Path "$ResultsPath\$CsvFile" $null

    #Write Server name to results
    WriteResults "Default" "Server - `'$Server`'"

    #Check that the server is reachable
    WriteResults "Default" "Checking to see if `'$Server`' is online"
    if (Test-Connection -Count 2 -Quiet $Server){
        WriteResults "Pass" "- Server `'$Server`' Online - Continuing with health chek items" $ShwResMsg

        #Get OS version
        WriteResults "Default" "Getting OS version"
        $OS = InvCmd {Get-WmiObject -Query "select * from win32_operatingsystem"} | Select-Object @{Name="OS"; Expression={"$($_.Caption)$($_.CSDVersion) $($_.OSArchitecture)"}} | Select-Object -expand OS
        WriteResults "Pass" "- $OS"

        #Get OS License Status 
        WriteResults "Default" "Getting OS License Status"
        $OSLic = InvCmd {(Get-WmiObject -Query "select * from SoftwareLicensingProduct"| Select-Object -expand LicenseStatus) -contains 1}
        if ($OSLic -eq "True"){
            WriteResults "Pass" "- This copy if Windows is successfully activated" $ShwResMsg
        }
        else {
            WriteResults "Fail" "- This copy if Windows is NOT activated" $ShwResMsg
        }

        #Get the Servers Time Zone
        WriteResults "Default" "Getting Server Time Zone"
        $timeZone = InvCmd {Get-WmiObject -Query "select * from win32_timezone"} | Select-Object -expand Caption
        WriteResults "Pass" "- $timeZone"
        
        #Get the server that provides time synchronization for this server
        WriteResults "Default" "Getting Time Server"
        $timeServer = InvCmd {cmd /c $env:WINDIR\system32\w32tm.exe /query /source}
        WriteResults "Pass" "- $timeServer"
        
        #Get Processor Information
        WriteResults "Default" "Getting Processor Type and Core Count"
        $Cpu = InvCmd {Get-WmiObject -Query "select * from win32_processor"}
        if ((!$Cpu.count)-and($Cpu)){
            WriteResults "Pass" "- $($Cpu.name) with $($Cpu.NumberOfCores) cores"
        }
        elseif (($Cpu.count)-and($Cpu)) {
            WriteResults "Pass" "- $($Cpu[0].Name) with $($Cpu.count) cores"
        }
        
        
        #Get RAM size
        WriteResults "Default" "Getting RAM amount"
        $Ram = InvCmd {"{0:N2}" -f ((Get-WmiObject -Query "select * from win32_computersystem" | Select-Object -expand TotalPhysicalMemory) / 1GB)}
        WriteResults "Pass" "- $($Ram)GB of RAM"

        #Check Page file is hard set to 1.5x RAM size
        WriteResults "Default" "Checking to see if Page file is configured to MS best practices"
        $MemSzMB = InvCmd {[Math]::Ceiling((Get-WmiObject win32_computersystem | Select-Object -ExpandProperty TotalPhysicalMemory) / 1048576 )}
        $sysManPgFil = InvCmd {Get-WmiObject win32_computersystem} | Select-Object -expand AutomaticManagedPagefile
        if ($sysManPgFil -eq "True"){
            WriteResults "Fail" "- Page File Configred to be managed by system" $ShwResMsg
            WritePFNotice "Fail"
        }
        else{
            $PfSettings = InvCmd {Get-WmiObject -Class Win32_PageFileSetting}
            $PfRangeLow = $MemSzMB*1.4 ; $PfRangeHigh = $MemSzMB*1.6
            #Write-Host $PfSettings.InitialSize $PfSettings.MaximumSize
            if ($PfSettings.InitialSize -eq $PfSettings.MaximumSize){
                if (($PfSettings.MaximumSize -gt $PfRangeLow) -and ($PfSettings.MaximumSize -lt $PfRangeHigh)){
                    WriteResults "Pass" "- Page File Configred to best practices" $ShwResMsg
                }
                elseif($PfSettings.MaximumSize -gt $PfRangeHigh){
                    WriteResults "Warning" "- Page File Configred larger than typical installs" "Warning" $ShwResMsg
                    WritePFNotice "Warning"
                }
                else{
                    WriteResults "Fail" "- Page File Size Should be increased" $ShwResMsg
                    WritePFNotice "Fail"
                }
            }
            elseif($PfSettings.InitialSize -lt $PfRangeLow){
                WriteResults "Fail" "- Page File Size Should be increased and both Initial and Max Values shoufl be the same" $ShwResMsg
                WritePFNotice "Fail"
            }
            else{
                WriteResults "Warning" "- Page File Size is large enough but both Initial and Max Values shoufl be the same" "Warning" $ShwResMsg
                WritePFNotice "Warning"
            }
        }

        #Check if CD Rom drive is assigned to Z:
        WriteResults "Default" "Checking to see if CD Rom has been reassigned to Z:"
        $CdRomDrive = InvCmd {Get-WmiObject Win32_CDROMDrive} | Select-Object -ExpandProperty Drive
        if ($CdRomDrive.Count -eq 1){
            if ($CdRomDrive -eq "z:"){
                WriteResults "Pass" "- CD Drive Assigned to Z:" $ShwResMsg
            }
            else {
                WriteResults "Fail" "- CD Drive Assigned to $CdRomDrive - Should be reassigned to Z:" $ShwResMsg
            }
        }
        elseif ($CdRomDrive.Count -eq 0) {
            WriteResults "Fail" "- Virtual CD Drive MISSING, should have one assigned to Z:" $ShwResMsg
        }
        else {
            WriteResults "Fail" "- MULTIPLE Virtual CD Drives present - $CdRomDrive, should have one assigned to Z:" $ShwResMsg
        }

        #Check if WMI SNMP Provider is installed
        WriteResults "Default" "Checking to see if WMI SNMP Provider is installed"
        $snmpInst = InvCmd {Get-WmiObject -Query "select * from win32_optionalfeature where Name='WMISnmpProvider'"} | Select-Object -expand InstallState
        if ($snmpInst -eq "1"){
            WriteResults "Pass" "- WMI SNMP Provider Installed" $ShwResMsg
        }
        else {
            WriteResults "Fail" "- WMI SNMP Provider NOT Installed - Should be installed" $ShwResMsg
        }

        #Check if RDP is enabled
        WriteResults "Default" "Checking to see RDP Services are enabled"
        $RdpEnabled = InvCmd {Get-WmiObject Win32_TerminalServiceSetting -name "root\cimv2\TerminalServices"} | Select-Object -expand AllowTSConnections
        if ($RdpEnabled -eq 1){
            WriteResults "Pass" "- Remote Desktop Enabled" $ShwResMsg
        }
        else {
            WriteResults "Fail" "- Remote Desktop DISABLED" $ShwResMsg
        }
    
        #Get Windows Firewall status
        if ($OS -like "*2008*"){
            WriteResults "Default" "Getting Windows Firewall Status - Server 2008R2"
            $fwService = InvCmd {Get-WmiObject -Query "select * from win32_service where DisplayName like '%Windows Firewall%'"} | Select-Object -ExpandProperty Started
            if ($fwService){
                $fwNetworks = @("Domain","Private","Public")
                WriteResults "Pass" "- Windows Firewall service is Running" $ShwResMsg
                foreach ($fwNetwork in $fwNetworks) {
                    $fwNetCmd = "(cmd /c $env:WINDIR\system32\netsh.exe advfirewall show $fwNetwork | select-string -pattern `"State[ \t]*(?<state>.+)`" ).Matches[0].Groups['state'].Value"
                    $fwNetworkStatus = InvCmd {$fwNetCmd}
                    if ($fwNetworkStatus -eq "ON"){
                        WriteResults "Fail" "- $($fwNetwork) Firewall Network is ON"  $ShwResMsg
                    }
                    else {
                        WriteResults "Pass" "- - $($fwNetwork) Firewall Network is OFF" $ShwResMsg
                    }
                }
            }
            else {
                WriteResults "Pass" "- Windows Firewall service is not running" $ShwResMsg
            }
        }
        else {
            WriteResults "Default" "Getting Windows Firewall Status"
            $fwService = InvCmd {Get-WmiObject -Query "select * from win32_service where DisplayName like '%Windows Firewall%'"} | Select-Object -ExpandProperty Started
            if ($fwService){
                $fwProfiles = InvCmd {Get-NetFirewallProfile}
                $fwProfNames = @("Domain","Private","Public")
                WriteResults "Pass" "- Windows Firewall service is Running" $ShwResMsg
                foreach ($fwProfName in $fwProfNames) {
                    $fwProfStatus = $fwProfiles| Where-Object -eq Name $fwProfName | Select-Object -ExpandProperty Enabled
                    if ($fwProfStatus){
                        WriteResults "Fail" "- - $fwProfName` Firewall Profile is ON" $ShwResMsg
                    }
                    else {
                        WriteResults "Pass" "- - $fwProfName` Firewall Profile is OFF" $ShwResMsg
                    }
                }
            }
            else {
                WriteResults "Pass" "- Windows Firewall service is not running" $ShwResMsg
            }
        }

        #Check to see if Updates are Set to Manual
        WriteResults "Default" "Checking to see if Windows Updates are set to Manual"
        if ($OS -like "*2016*"){
            $reg = InvCmd {(Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU").NoAutoUpdate}
            if ($UpdateStatus -eq 1){
                WriteResults "Pass" "- Windows Updates Set to manual" $ShwResMsg
            }
            else{
                WriteResults "Warning" "- Windows Updates enabled" $ShwResMsg
            }
        }
        elseif($OS -like "*2012*"){
            $reg = InvCmd {(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update").AUOptions}
            if ($reg -eq 1){
                WriteResults "Pass" "- Windows Updates Set to manual" $ShwResMsg
            }
            else{
                WriteResults "Warning" "- Windows Updates enabled" "Warning" $ShwResMsg
            }
        }

        #Check for recently installed updates
        WriteResults "Default" "Checking to see if Windows Updates have been installed in the last 60 days"
        $Hotfixes = InvCmd {Get-WmiObject win32_quickfixengineering}
        $LastUpdate = $Hotfixes.item(($Hotfixes.length - 1)).InstalledOn
        $Today = Get-Date ; $DateDif = $Today - $LastUpdate
        if ($DateDif.Days -lt 60){
            WriteResults "Pass" "- Windows Updates have been installed in the last 60 days" $ShwResMsg
        }
        else{
            WriteResults "Fail" "- NO Windows Updates have been installed in the last 60 days" $ShwResMsg
        } 
        
        #Check that TCP offload is Disabled and NIC speed is set to 1Gb Full Duplex
        WriteResults "Default" "Check to see if TCP Offload and Speed/Duplex setting are configured properly"
        #Offload settings
        InvCmd {Get-NetAdapterAdvancedProperty -DisplayName "*offload*"} | Where-Object {($_.DisplayName -notlike "*IPv6*")} | ForEach-Object {
            if ($_.DisplayValue -like "*Disabled*"){
                WriteResults "Pass" "- $($_.Name) $($_.DisplayName)  $($_.DisplayValue)" $ShwResMsg
            }
            else {
                WriteResults "Fail" "- $($_.Name) $($_.DisplayName) $($_.DisplayValue)" $ShwResMsg
            }
        }
        #Speed-Duplex setting(s)
        InvCmd {Get-NetAdapterAdvancedProperty -DisplayName "*speed*"} | ForEach-Object {
            if ($_.DisplayValue -like "*1.0 Gbps Full*"){
                WriteResults "Pass" "- $($_.Name) $($_.DisplayName)  $($_.DisplayValue)" $ShwResMsg
            }
            else {
                WriteResults "Fail" "- $($_.Name) $($_.DisplayName) $($_.DisplayValue)" $ShwResMsg
            }
        } 

    #endregion
        
        #region Get ICM info
        #Check that Portico is installed and running
        WriteResults "Default" "Checking if Portico/ICM is installed and Running"
        $PorticoService = InvCmd {Get-WmiObject -Query "select * from win32_service where DisplayName='Cisco ICM Diagnostic Framework'"} | Select-Object -property State
        if ($PorticoService){
            $global:IcmInstalled = $true
            WriteResults "Pass" "- Portico/ICM is installed - Checking if it is Running"
            if ($PorticoService.State -eq "Running"){
                $global:PorticoRunning = $true
                WriteResults "Pass" "- - Portico/ICM is installed and Running" $ShwResMsg
            }
            else{
                $PorticoRunning = $false
                WriteResults "Fail" "- - Portico/ICM is installed - But NOT Running" $ShwResMsg
            }
        }
        else{
            WriteResults "Fail" "- Unable to find Portico Service Ensure that servername in list is correct" $ShwResMsg
            WriteResults "Fail" "- - ICM must be installed on the server to be audited, only a limited audit will be run"
            $IcmInstalled = $false
        }

        #Get ICM Instance(s)
        WriteResults "Default" "Fetching ICM Inatance(s)"
        $IcmRegKeys = InvCmd {Get-ChildItem -PSPath 'HKLM:\SOFTWARE\Cisco Systems, Inc.\ICM\' -Name}
        $InstancesFound = $IcmRegKeys | Where-Object {($_ -notmatch '\d\d\.\d')-and($_ -notin 'ActiveInstance','Performance','Serviceability','SNMP','SystemSettings','CertMon','Cisco SSL Configuration')}
        If ($InstancesFound.Count -gt 0){
            ForEach ($Instance in $InstancesFound){
                $InstNum = InvCmd  {Get-ItemProperty -PSPath "HKLM:\SOFTWARE\Cisco Systems, Inc.\ICM\$using:Instance\CurrentVersion\" | Select-Object -ExpandProperty InstanceNumber}
                WriteResults "Pass" "- Found Instance`:$Instance Instance Number`:$InstNum" $ShwResMsg
            }   
        }
        else{
            WriteResults "Fail" "No Instance Found" $ShwResMsg
        }

        #Get ICM Install Path
        WriteResults "Default" "Getting Installed Cisco Products"
        $IcmPath = InvCmd {Get-ItemProperty -PSPath "HKLM:\SOFTWARE\Cisco Systems, Inc.\ICM\SystemSettings\" | Select-Object -ExpandProperty InstallPath}
        WriteResults "Pass" "- ICM is installed in `'$IcmPath`'"

        #Get Installed Cisco Products
        WriteResults "Default" "Getting Installed Cisco Products"
        $InstalledCiscoProds = InvCmd {Get-ItemProperty "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Where-Object {$_.Publisher -like "*cisco*"}}
        foreach ($InstalledCiscoProd in $InstalledCiscoProds){
            $CiscoProdPub = $InstalledCiscoProd.Publisher
            $CiscoProdPub = $CiscoProdPub -replace ",","."
            WriteResults "Pass" "- Application`:$($InstalledCiscoProd.DisplayName) - Version`:$($InstalledCiscoProd.DisplayVersion) - Publisher`:$CiscoProdPub - Install Date`:$($InstalledCiscoProd.InstallDate)"
        }
        

        #Get ICM Version
        WriteResults "Default" "Fetching ICM Version(s)"
        ForEach ($Instance in $InstancesFound){
            MakeWebRequest "https://$Server`:7890/icm-dp/rest/DiagnosticPortal/GetProductVersion?InstanceName=$Instance"
            try {$Resp = $WebReq.GetResponse()}
            catch {$Resp = "error"}
            if ($Resp -eq "error")
            {
                WriteResults "Fail" "Unable to Fetch ICM Version from Portico" $ShwResMsg
            }
            else {
                $Reader = new-object System.IO.StreamReader($resp.GetResponseStream())
                [xml]$ResultXml = $Reader.ReadToEnd()
                $Products = @($ResultXml.GetProductVersionReply |  Select-Object -expand ProductVersion)                
                ForEach ($Product in $Products){
                    WriteResults "Pass" "- $Instance` - $($Product.Name) $($Product.VersionString) Found" $ShwResMsg
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
                WriteResults "Fail" "Unable to Fetch ICM Components from Portico" $ShwResMsg
            }
            else {
                $Reader = new-object System.IO.StreamReader($resp.GetResponseStream())
                [xml]$ResultXml = $Reader.ReadToEnd()
                $Services = @($ResultXml.ListAppServersReply.AppServerList.AppServer | Where-Object {$_.ProductComponentType -notin "Cisco ICM Diagnostic Framework","Administration Client"} | Select-Object -expand ProductComponentType)
                ForEach ($Service in $Services){
                    WriteResults "Pass" "- $($Instance) - $($Service) Found" $ShwResMsg
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
        WriteResults "Default" "Checking to see what ICM services are installed and their Startup Type"
        InvCmd {Get-WmiObject -Query "select * from win32_service where DisplayName like 'Cisco%'"}  | ForEach-Object {
            if (($_.StartMode -like "Auto*")-and($_.State -like "Running")){
                WriteResults "Pass" "- $($_.DisplayName) - $($_.State) - $($_.StartMode)" $ShwResMsg
            }
            elseif (($_.StartMode -notlike "Auto*")-or($_.State -notlike "Running")) {
                WriteResults "Fail" "- $($_.DisplayName) - $($_.State) - $($_.StartMode)" $ShwResMsg
            }
        }
    
        #Get SQL version for Servers that use SQL
        if (($Logger -eq $true)-or($Awhds -eq $true)){
            WriteResults "Default" "Gettin SQL version"
            $SqlVerInfo = ExecuteSql("SELECT SERVERPROPERTY('productversion') AS Version, SERVERPROPERTY ('productlevel') AS ServicePack, SERVERPROPERTY ('edition') AS Edition")
            $SqlVer = "- $($SqlVerInfo.Version) $($SqlVerInfo.ServicePack) $($SqlVerInfo.Edition)"
            $SqlVer = $SqlVer -replace "14.0.[\.\d]*", "SQL Server 2016"
            $SqlVer = $SqlVer -replace "12.0.[\.\d]*", "SQL Server 2014"
            $SqlVer = $SqlVer -replace "11.[\.\d]*", "SQL Server 2012"
            $SqlVer = $SqlVer -replace "10.50.[\.\d]*", "SQL Server 2008 R2"
            $SqlVer = $SqlVer -replace "10.00.[\.\d]*", "SQL Server 2008"
            $SqlVer = $SqlVer -replace "9.00.[\.\d]*", "SQL Server 2005"
            $SqlVer = $SqlVer -replace "8.00.[\.\d]*", "SQL Server 2000"
            WriteResults "Pass" $SqlVer "" $ShwResMsg
        }


        #Get Disk(s) and Disk size(s)
        WriteResults "Default" "Getting Disk(s) and Disk size(s)"
        $drives = InvCmd {Get-WmiObject -Query "select * from win32_logicaldisk where DriveType=3"}
        $driveDetails = @();
        $drives | ForEach-Object {$driveDetails += "$($_.DeviceID) $("{0:N2}" -f ($_.FreeSpace / 1GB)) GB Free / $("{0:N2}" -f ($_.Size / 1GB)) GB Total"}
        foreach ($drive in $driveDetails){
            if ($drive -like "*C:*") {
                WriteResults "Pass" "- $drive"
            }
            elseif (($Logger)-or($Awhds)) {
                WriteResults "Pass" "- $drive"
            }
            else {
                WriteResults "Warning" "- $drive - This server does not have ICM components that require additional disks"
            }
        }

        #Get Data drive (D:) Volume name for AW-HDS and Logger servers
        if (($Awhds)-or($Logger)){
            WriteResults "Default" "Getting Data Drive (D:) Volume Name"
            $dataDrive = InvCmd {Get-WmiObject win32_logicaldisk} | Where-Object {($_.DeviceID -eq 'D:')-and($_.DriveType -eq 3)}
            if (!$dataDrive) {
                WriteResults "Fail" "- NO data volume with drive letter D: found" $ShwResMsg
            } 
            else {
                if ($dataDrive.VolumeName -eq $null -or $dataDrive.VolumeName -eq "") {
                    WriteResults "Warning" "- No name for data volume with drive letter D: found" $ShwResMsg
                }
                else {
                    WriteResults "Pass" "- Volume '$($dataDrive.VolumeName)' with drive letter D: found" $ShwResMsg
                }
            }
        }

        #Check if IPv6 is globally disabled
        WriteResults "Default" "Checking if IPv6 is globally disabled in the registry"
        try {$Ipv6RegData = InvCmd {Get-ItemProperty -PSPath 'HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters\'} | Select-Object -ExpandProperty DisabledComponents -ErrorAction Stop}
        catch {$Ipv6RegData=$null}
        if ($Ipv6RegData -eq 255){
            WriteResults "Pass" "- IPv6 has been globally disabled in the registry" $ShwResMsg
            $Ipv6DisReg = $true
        }
        elseif ($Ipv6RegData -eq -1){
            WriteResults "Warning" "- IPv6 has been globally disabled in the registry" $ShwResMsg
            WriteResults "Warning" "- The following registry value should be set to 0x000000ff not 0xffffffff"
            WriteResults "Warning" "- HKLM:SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters\DisabledComponents"
            WriteResults "Warning" "- Using 0xffffffff will cause the server to take longer to boot up during restarts"
            $Ipv6DisReg = $true
        }
        else{
            WriteResults "Warning" "- IPv6 NOT globally disabled in the registry - must check that it's disabled on NIC's" $ShwResMsg
            $Ipv6DisReg = $false
        }

        #Check for proper number of Public NIC's
        WriteResults "Default" "Checking for the proper number of interfaces named 'Public'"
        $Nics = InvCmd {Get-NetIPInterface}
        $Ipv4Nics = $Nics | Where-Object -FilterScript {$_.AddressFamily -eq 2}
        $PubNic = $Ipv4Nics | Where-Object {$_.InterfaceAlias -like '*public*'}
        $PrivNic = $Ipv4Nics | Where-Object {$_.InterfaceAlias -like '*private*'}
        if ($PubNic){
            if (!$PubNic.count) {
                WriteResults "Pass" "- One interface named `'Public`' found" $ShwResMsg
            }
            else {
                WriteResults "Fail" "- $($PubNic.count) interfaces named `'Public`' found" $ShwResMsg
                $PubNicErr = $true
            }
        }
        else {
            WriteResults "Fail" "- No interface named `'Public`' found" $ShwResMsg
            $PubNicErr = $true
        }    

        if($Router -or $Logger -or $Pg -or $Cg){
            WriteResults "Default" "Checking for the proper number of interfaces named 'Private'"
            if ($PrivNic){
                if (!$PrivNic.count) {
                    WriteResults "Pass" "- One interface named `'Private`' found" $ShwResMsg
                }
                else {
                    WriteResults "Fail" "- $($PrivNic.count) interfaces named `'Private`' found" $ShwResMsg
                    $PrivNicErr = $true
                }
            }
            else {
                WriteResults "Fail" "- No interface named `'Private`' found" $ShwResMsg
                $PrivNicErr = $true
            }    
        }


        #Getting Network Properties for following checks
        if (!$PubNicErr -or !$PrivNicErr) {
            $DnsClient = InvCmd {Get-DnsClient}
            $NetIpConfig = InvCmd {Get-NetIPConfiguration}
            $NetIpAdd = InvCmd {Get-NetIPAddress}
            $NetBindings = InvCmd {Get-NetAdapterBinding}
            $DnsSvrCnt = 1
        }

        #Verify that only one Public NIC exists
        if (!$PubNicErr) {
            #Check if IPv6 is Disabled on Public NIC
            WriteResults "Default" "Checking to see if IPv6 is disabled on the Public NIC"
            $PubIpv6En = $NetBindings | Where-Object {($_.Name -eq $PubNic.InterfaceAlias)-and($_.ComponentID -eq 'ms_tcpip6')} | Select-Object -ExpandProperty Enabled
            if ($PubIpv6En -eq $false) {
                WriteResults "Pass" "- TCP IP v6 disabled on 'Public' Interface" $ShwResMsg
            }
            else {
                if ($Ipv6DisReg) {
                    WriteResults "Warning" "- IPv6 is ENABLED on 'Public' Interface" $ShwResMsg
                    WriteResults "Warning" "- however IPv6 is disabled globally in the registry"
                }
                else {
                    WriteResults "Fail" "- TCP IP v6 ENABLED on 'Public' Interface and in the registry" $ShwResMsg
                }
            }

            #Check for proper number of IP Addresses for Public NIC and show Subnet Mask
            WriteResults "Default" "Checking for proper number of IP Addresses for Public NIC"
            $PubNicIps = $NetIpAdd | Where-Object {$_.InterfaceAlias -eq $PubNic.InterfaceAlias}
            if ($Router -or $Pg) {
                WriteResults "Default" "- Server has PG or Router present and should have 2 Public IP addresses"
                if ($PubNicIps.count -eq 2) {
                    WriteResults "Pass" "- - Found 2 IP addresses assigned to the Public Interface" $ShwResMsg
                    foreach ($PubNicIp in $PubNicIps){
                        WriteResults "Pass" "- - IP:$($PubNicIp.IPAddress)/$($PubNicIp.PrefixLength)"
                    }
                }
                else {
                    if (!$PubNicIps.count) {
                        WriteResults "Fail" "- - Found only 1 IP addresses assigned to the Public Interface" $ShwResMsg
                        WriteResults "Fail" "- - IP:$($PubNicIps.IPAddress)/$($PubNicIps.PrefixLength)"
                    }
                    else {
                        WriteResults "Fail" "- - Found more than 2 IP addresses assigned to the Public Interface" $ShwResMsg
                        foreach ($PubNicIp in $PubNicIps){
                            WriteResults "Pass" "- - IP:$($PubNicIp.IPAddress)/$($PubNicIp.PrefixLength)"
                        }
                    }
                    
                }
            }
            else {
                WriteResults "Default" "- Server has does not have PG or Router present and should have 1 Public IP addresses"
                if (!$PubNicIps.count) {
                    WriteResults "Pass" "- - Found 1 IP addresses assigned to the Public Interface" $ShwResMsg
                    WriteResults "Pass" "- - IP:$($PubNicIp.IPAddress)/$($PubNicIp.PrefixLength)"
                }
                else {
                    WriteResults "Fail" "- - Found more than 1 IP addresses assigned to the Public Interface" $ShwResMsg
                    foreach ($PubNicIp in $PubNicIps){
                        WriteResults "Pass" "- - IP:$($PubNicIp.IPAddress)/$($PubNicIp.PrefixLength)"
                    }
                }
            }

            #Check for Default Gateway for Public NIC and NO Default gateway on Private (if applicable)
            WriteResults "Default" "Checking for Default Gateway for Public NIC"
            $PubDefGw = $NetIpConfig | Where-Object {$_.InterfaceAlias -eq $PubNic.InterfaceAlias} | Select-Object -ExpandProperty IPv4DefaultGateway
            if ($PubDefGw) {
                WriteResults "Pass" "- Default Gateway for Public Network" $ShwResMsg
                WriteResults "Pass" "- - NIC:`'$($PubDefGw.InterfaceAlias)`' Default Gateway:$($PubDefGw.NextHop)"
            }
            else {
                WriteResults "Fail" "- NO Default Gateway Configured for Public Network" $ShwResMsg
            }

            #Check to see if Public NIC has DNS Servers configured
            WriteResults "Default" "Checking to see if Public NIC has DNS Servers configured"
            $PubDnsSvrs = $NetIpConfig | Where-Object {$_.InterfaceAlias -eq $PubNic.InterfaceAlias} | Select-Object -ExpandProperty DNSServer | Where-Object {$_.AddressFamily -eq 2} | Select-Object -ExpandProperty ServerAddresses
            if ($PubDnsSvrs) {
                WriteResults "Pass" "- The following DNS servers have been configured" $ShwResMsg
                foreach ($PubDnsSvr in $PubDnsSvrs){
                    WriteResults "Pass" "- - DNS Server $DnsSvrCnt`: $PubDnsSvr"
                    $DnsSvrCnt++
                }
            }
            else {
                WriteResults "Fail" "- DNS Servers NOT found for Public NIC" $ShwResMsg
            }

            #Check to see if Public NIC is configured to register with DNS
            WriteResults "Default" "Checking to see if Public NIC is configured to register with DNS"
            $PubDnsReg = $DnsClient | Where-Object {$_.InterfaceAlias -eq $PubNic.InterfaceAlias} | Select-Object -ExpandProperty RegisterThisConnectionsAddress
            if ($PubDnsReg -eq 'True') {
                WriteResults "Pass" "- The Public interface is configured to register with DNS" $ShwResMsg
            }
            else {
                WriteResults "Fail" "- The Public interface is NOT configured to register with DNS" $ShwResMsg
            }

            #Check to see if Public NIC is configured with DNS Suffix
            WriteResults "Default" "Checking to see if Public NIC is configured with DNS Suffix"
            $PubDnsSuf = $DnsClient | Where-Object {$_.InterfaceAlias -eq $PubNic.InterfaceAlias} | Select-Object -ExpandProperty ConnectionSpecificSuffix
            if ($PubDnsSuf) {
                WriteResults "Pass" "- The Public interface is configured with DNS Suffix" $ShwResMsg
                WriteResults "Pass" "- DNS Suffix`: $PubDnsSuf"
            }
            else {
                WriteResults "Fail" "- The Public interface is NOT configured with DNS Suffix" $ShwResMsg
            }
        }
        else {
            WriteResults "Fail" "- Public NIC count or Public NIC naming not configured correctly." $ShwResMsg
            WriteResults "Fail" "- Cannot check for Public NIC configurations"
        }

        #Check IP Settings for Private NIC on applicable 
        if($Router -or $Logger -or $Pg -or $Cg){
            #Verify that there's only One NIC Named Private
            if(!$PrivNicErr){
                #Check if IPv6 is Disabled on Private NIC
                WriteResults "Default" "Checking to see if IPv6 is disabled on the Private NIC"
                $PrivIpv6En = $NetBindings | Where-Object {($_.Name -eq $PrivNic.InterfaceAlias)-and($_.ComponentID -eq 'ms_tcpip6')} | Select-Object -ExpandProperty Enabled
                if (!$PrivIpv6En) {
                    WriteResults "Pass" "- TCP IP v6 disabled on 'Private' Interface" $ShwResMsg
                }
                else {
                    if ($Ipv6DisReg) {
                        WriteResults "Warning" "- IPv6 is ENABLED on 'Private' Interface" $ShwResMsg
                        WriteResults "Warning" "- however IPv6 is disabled globally in the registry"
                    }
                    else {
                        WriteResults "Fail" "- TCP IP v6 ENABLED on 'Private' Interface and in the registry" $ShwResMsg
                    }
                }

                #Check for proper number of IP Addresses for Private NIC
                WriteResults "Default" "Checking for proper number of IP Addresses for Private NIC"
                $PrivNicIps = $NetIpAdd | Where-Object {$_.InterfaceAlias -eq $PrivNic.InterfaceAlias}
                if ($Router -or $Pg) {
                    WriteResults "Default" "- Server has PG or Router present and should have 2 Private IP addresses"
                    if ($PrivNicIps.count -eq 2) {
                        WriteResults "Pass" "- - Found 2 IP addresses assigned to the Private Interface" $ShwResMsg
                        foreach ($PrivNicIp in $PrivNicIps){
                            WriteResults "Pass" "- - IP:$($PrivNicIp.IPAddress)/$($PrivNicIp.PrefixLength)"
                        }
                    }
                    else {
                        if (!$PrivNicIps.count) {
                            WriteResults "Fail" "- - Found only 1 IP addresses assigned to the Private Interface" $ShwResMsg
                            WriteResults "Fail" "- - IP:$($PrivNicIps.IPAddress)/$($PrivNicIps.PrefixLength)"
                        }
                        else {
                            WriteResults "Fail" "- - Found more than 2 IP addresses assigned to the Private Interface" $ShwResMsg
                            foreach ($PrivNicIp in $PrivNicIps){
                                WriteResults "Pass" "- - IP:$($PrivNicIp.IPAddress)/$($PrivNicIp.PrefixLength)"
                            }
                        }
                    }
                }
                else {
                    WriteResults "Default" "- Server has does not have PG or Router present and should have 1 Private IP addresses"
                    if (!$PrivNicIps.count) {
                        WriteResults "Pass" "- - Found 1 IP addresses assigned to the Private Interface" $ShwResMsg
                        WriteResults "Pass" "- - $($PrivNicIps.IPAddress)"
                    }
                    else {
                        WriteResults "Fail" "- - Found more than 1 IP addresses assigned to the Private Interface" $ShwResMsg
                        foreach ($PrivNicIp in $PrivNicIps){
                            WriteResults "Pass" "- - IP:$($PrivNicIp.IPAddress)/$($PrivNicIp.PrefixLength)"
                        }
                    }
                }

                #Check to see if 'Client for MS Networks' is disabled on Private NIC
                WriteResults "Default" "Check to see if 'Client for MS Networks' is disabled on Private NIC"
                $PrivMsCliBind = $NetBindings | Where-Object {($_.Name -eq $PrivNic.InterfaceAlias)-and($_.ComponentID -eq 'ms_msclient')} | Select-Object -ExpandProperty Enabled
                if (!$PrivMsCliBind) {
                    WriteResults "Pass" "- 'Client for MS Networks' is disabled on Private NIC" $ShwResMsg
                }
                else {
                    WriteResults "Fail" "- 'Client for MS Networks' is ENABLED on Private NIC" $ShwResMsg
                }

                #Check to see if 'File and Printer Sharing for MS Networks' is disabled on Private NIC
                WriteResults "Default" "Check to see if 'File and Printer Sharing for MS Networks' is disabled on Private NIC"
                $PrivMsSrvBind = $NetBindings | Where-Object {($_.Name -eq $PrivNic.InterfaceAlias)-and($_.ComponentID -eq 'ms_server')} | Select-Object -ExpandProperty Enabled
                if (!$PrivMsSrvBind) {
                    WriteResults "Pass" "- 'File and Printer Sharing for MS Networks' is disabled on Private NIC" $ShwResMsg
                }
                else {
                    WriteResults "Fail" "- 'File and Printer Sharing for MS Networks' is ENABLED on Private NIC" $ShwResMsg
                }

                #Check for NO Default Gateway on Private NIC
                WriteResults "Default" "Checking for NO Default Gateway on Private NIC"
                $PrivDefGw = $NetIpConfig | Where-Object {$_.InterfaceAlias -eq $PrivNic.InterfaceAlias} | Select-Object -ExpandProperty IPv4DefaultGateway
                if (!$PrivDefGw) {
                    WriteResults "Pass" "- No Default Gateway found for Private Network" $ShwResMsg
                }
                else {
                    WriteResults "Fail" "- Foun a Default Gateway on Private NIC, this should NOT be configured" $ShwResMsg
                    WriteResults "Fail" "- - NIC:`'$($PrivDefGw.InterfaceAlias)`' Default Gateway:$($PrivDefGw.NextHop)"
                }

                #Check for Static Route entry for Private NIC
                WriteResults "Default" "Checking to see Persistent Static Route for Prive NIC is present"
                $PrivRoutes = InvCmd {Get-NetRoute} | Where-Object {($_.InterfaceAlias -eq $PrivNic.InterfaceAlias) -and ($_.Protocol -eq 'NetMgmt')}
                if (($PrivRoutes)-and(!$PrivRoutes.count)) {
                    WriteResults "Pass" "- One Static Route found for Private Network" $ShwResMsg
                    WriteResults "Pass" "- - NIC:`'$($PrivRoutes.InterfaceAlias)`' Destination:$($PrivRoutes.DestinationPrefix) Next Hop:$($PrivRoutes.NextHop)"
                }
                else {
                    if (!$PrivRoutes) {
                        WriteResults "Fail" "- NO Route found for Private Network, expecting one" $ShwResMsg
                    }
                    else {
                        WriteResults "Fail" "- Multiple Static Routes found for Private Network, expecting one" $ShwResMsg
                        foreach ($PrivRoute in $PrivRoutes){
                            WriteResults "Fail" "- - NIC:`'$($PrivRoute.InterfaceAlias)`' Destination:$($PrivRoute.DestinationPrefix) Next Hop:$($PrivRoute.NextHop)" 
                        }
                    }
                }

                #Check to see if Private NIC has DNS Servers configured
                $DnsSvrCnt=1
                WriteResults "Default" "Checking to see if Private NIC has DNS Servers configured"
                $PrivDnsSvrs = $NetIpConfig | Where-Object {$_.InterfaceAlias -eq $PrivNic.InterfaceAlias} | Select-Object -ExpandProperty DNSServer | Where-Object {$_.AddressFamily -eq 2} | Select-Object -ExpandProperty ServerAddresses
                if ($PrivDnsSvrs) {
                    WriteResults "Fail" "- The following DNS servers have been configured" $ShwResMsg
                    foreach ($PrivDnsSvr in $PrivDnsSvrs){
                        WriteResults "Fail" "- - DNS Server $DnsSvrCnt`: $PrivDnsSvr"
                        $DnsSvrCnt++
                    }
                }
                else {
                    WriteResults "Pass" "- DNS Servers not found for Private NIC" $ShwResMsg
                }

                #Check to see if Private NIC is configured to register with DNS
                WriteResults "Default" "Checking to see if Private NIC is configured to register with DNS"
                $PrivDnsReg = $DnsClient | Where-Object {$_.InterfaceAlias -eq $PrivNic.InterfaceAlias} | Select-Object -ExpandProperty RegisterThisConnectionsAddress
                if ($PrivDnsReg -eq 'True') {
                    WriteResults "Fail" "- The Private interface IS configured to register with DNS" $ShwResMsg
                }
                else {
                    WriteResults "Pass" "- The Private interface is not configured to register with DNS" $ShwResMsg
                }

                #Check to see if Private NIC is configured with DNS Suffix
                WriteResults "Default" "Checking to see if Private NIC is configured with DNS Suffix"
                $PrivDnsSuf = $DnsClient | Where-Object {$_.InterfaceAlias -eq $PrivNic.InterfaceAlias} | Select-Object -ExpandProperty ConnectionSpecificSuffix
                if ($PrivDnsSuf) {
                    WriteResults "Fail" "- The Private interface IS configured with DNS Suffix" $ShwResMsg
                    WriteResults "Fail" "- DNS Suffix`: $PrivDnsSuf"
                }
                else {
                    WriteResults "Pass" "- The Private interface is not configured with DNS Suffix" $ShwResMsg
                }

                #Check to see if 'Unidentified network' is set as a 'Private' network
                WriteResults "Default" "Checking to see if 'Unidentified network' is set as a 'Private' network"
                $PrivNetProf = InvCmd {Get-NetConnectionProfile} | Where-Object {$_.InterfaceAlias -eq $PrivNic.InterfaceAlias}
                $PrivNetProfCat = $PrivNetProf.NetworkCategory
                if ($PrivNetProfCat -eq 'Private') {
                    WriteResults "Pass" "- The 'Unidentified network' is set as a `'$PrivNetProfCat`' network" $ShwResMsg
                }
                else {
                    WriteResults "Fail" "- The 'Unidentified network' is NOT set as a 'Private' network" $ShwResMsg
                    WriteResults "Fail" "- It is set to use the `'$PrivNetProfCat`' profile" $ShwResMsg
                }
            }
            else {
                WriteResults "Fail" "- Private NIC count or Private NIC naming not configured correctly." $ShwResMsg
                WriteResults "Fail" "- Cannot check Private NIC configurations"
            }
        }
        else {
            #No components installed that reqire a Private interface
        }

        #Check NIC/Interface Priority for Router, Logger and PG servers
        if($Router -or $Logger -or $Pg -or $Cg){
            WriteResults "Default" "Checking to see if NIC Binding Order/Interface Metric is configured properly"
            if ($PubNicErr -or $PrivNicErr) {
                WriteResults "Fail" "- NIC count or NIC naming not configured correctly." $ShwResMsg
                WriteResults "Fail" "- Cannot check for Binding Order or Interface Metric"
            }
            else {
                #2016 NIC Metric Check
                if ($OS -like "*2016*"){
                    WriteResults "Default" "- Server 2016 Found Checking Interface Metric"
                    if ($PubNic.InterfaceMetric -lt $PrivNic.InterfaceMetric){
                        WriteResults "Pass" "- NIC Metric Priority correctly configured - Public NIC:$($PubNic.InterfaceMetric) and Private NIC:$($PrivNic.InterfaceMetric)" $ShwResMsg
                    }
                    
        
                    else{
                    WriteResults "Fail" "- NIC Metric Priority NOT correctly configured - Public NIC:$($PubNic.InterfaceMetric) and Private NIC:$($PrivNic.InterfaceMetric)" $ShwResMsg
                        WriteResults "Fail" "- - Public NIC should have a lower Metric value than the Priate NIC"
                    }
                }

                #2012 R2 Binding Order Check
                elseif ($OS -like "*2012*"){
                    WriteResults "Default" "- Server 2012 Found Checking Binding Order"
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
                        WriteResults "Pass" "- Binding Order correctly configured - $($BindingOrder[0]) above $($BindingOrder[1])" $ShwResMsg
                    }
                    else {
                        WriteResults "Fail" "- Binding Order NOT correctly configured - $($BindingOrder[1]) above $($BindingOrder[0])" $ShwResMsg
                        WriteResults "Fail" "- - the Public NIC should be listed above the Private NIC in the Binding Order"
                    }
                }
                else {
                    WriteResults "Fail" "- OS not Server 2012 or 2016" $ShwResMsg
                    WriteResults "Fail" "- - OS Found`:$OS" $ShwResMsg
                }
            }
        }
        else{
            WriteResults "Pass" "- Server only requires 1 NIC, not checking binding order" $ShwResMsg
        }
    }

    #If Server not Reachable NOT continuing with Audit Checks
    Else{
        WriteResults "Fail" "- Server `'$Server`' is not reachable - Ensure server is online and attempt to audit again." $ShwResMsg
    }
}
#endregion

Write-Host "`nAudit Complete, resluts have been written to the following folder `n`n$ResultsPath`n"
CloseScript