[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

#$CredsSql

#region Initial Setup Vars
$InputServerList = "C:\Temp\Servers.txt"
$TempFolder = "C:\Temp"
$ResultsPath = "C:\Temp\AuditResults"
$CredsCsv = "C:\Temp\Creds2.csv"
$HTMLFile = "Initial.htm"
$CsvFile = "Initial.csv"
$HTMLOuputStart = "<html><body><br><b>UCCE/PCCE Server Audit Report.</b></body><html>
<html><body>"
$global:HTMLOuputEnd = "</body></html>"
#endregion Initial Setup Vars

#region Functions
#region Write results to CSV, html file and PowerShell window
#To use function, send it the Color of the message and up to 3 strings to write to audit result files and console
Function WriteResults ($Color,$String1,$String2,$String3){
    if ($Color -eq "Green") {$HtmlColor = "008000"; $ConsColor = "Green"}
    elseif ($Color -eq "Red") {$HtmlColor = "F00000"; $ConsColor = "Red"}
    elseif ($Color -eq "Yellow") {$HtmlColor = "FFC000"; $ConsColor = "Yellow"}
    else {$HtmlColor = "000000"; $ConsColor = "White"}
    Add-Content "$ResultsPath\$HTMLFile" "<br><font color =`"#$HtmlColor`">$String1 $String2 $String3</font>"
    Add-Content -Path "$ResultsPath\$CsvFile" "$String1,$String2,$String3"
    Write-Host -ForegroundColor $ConsColor $String1 $String2 $String3
}
#endregion Write results to CSV, html file and PowerShell window

#region Write Page file notice for malconfigured page files
Function WritePFNotice($Color){
    WriteResults $Color "- It is recommended to configure the Swap File with an Inital and Max size of 1.5 x Memory" "" ""
    WriteResults $Color "- Use the below sizes to set the Swap File accordingly " "" ""
    WriteResults $Color "-  - 16GB RAM = 24576MB Page File | 12GB RAM = 18432MB Page File | 8GB RAM =  12288MB Page File" "" ""
    WriteResults $Color "-  -  6GB RAM =  9216MB Page File |  4GB RAM =  6144MB Page File | 2GB RAM =  3072MB Page File" "" ""
    WriteResults $Color "-  -  Note that a change to the Page File may require a reboot" "" ""
}
#endregion Write Page file notice for malconfigured page files

#region Make Web Request
Function MakeWebRequest ($Url){
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
    $global:WebReq = [System.Net.WebRequest]::Create($Url)
    $global:WebReq.Method ="GET"
    $global:WebReq.ContentLength = 0
    $global:WebReq.Timeout = 15000
    $global:WebReq.Credentials = $CredsWin.GetNetworkCredential()
}
#endregion Make Web Request

#Get Windows/ICM Admin credentials
Function GetCredsWin {
    $global:CredsWin = Get-Credential -Message "Enter Windows/ICM Admin Credentials"
}

#Write closing tags for HTML file
Function CloseHtml {
    Add-Content "$ResultsPath\$HTMLFile" $HTMLOuputEnd
}
#endregion Functions

#Check to see if the Temp folder is present in c:
Write-Host "Checking to see if the Temp folder is present in c:"
if (Test-Path -Path $TempFolder){
    Write-Host "Temp folder found, proceeding"
}
else{
    Write-Host "Temp folder NOT Found, creating one"
    New-Item $TempFolder -ItemType "Directory"
}

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
}
else{
    WriteResults "Red" "File NOT Found - Nothing to check, exiting" "" ""
    CloseHtml
    Exit
}

#Check to see if the Credentials CSV file is present
WriteResults "Default" "Checking to see if the Credentials CSV File is present" "" ""
if (Test-Path -Path $CredsCsv){
    #check to see if credentials are present in CSV file
    $UserCreds = Import-Csv -Path $CredsCsv
    if (($null -ne $UserCreds.username)-and($null -ne $UserCreds.pass)){
        #Read Windows and Portico credentials from CSV file
        WriteResults "Green" "Loading Credentials from CSV, proceeding" "" ""
        $password = ConvertTo-SecureString $UserCreds.pass -AsPlainText -Force
        $global:CredsWin = New-Object System.Management.Automation.PSCredential ($UserCreds.username, $password)
    }
    else{
        WriteResults "Red" "Credentials not found in CSV, prompting for credentials"
        GetCredsWin
    }
}
else{
    WriteResults "Red" "Credentials CSV file NOT Found, prompting for credentials" "" ""
    GetCredsWin
}



Get-Content $InputServerList | ForEach-Object {
    #region Setup Vars
    $ResultsPath = "C:\Temp\AuditResults"
    $HTMLFile = "$_.htm"
    $CsvFile = "$_.csv"
    $HTMLOuputStart = "<html><body><br><b>UCCE/PCCE Server Audit Report.</b></body><html>
    <html><body>"
    $global:HTMLOuputEnd = "</body></html>"
    $IcmInstalled = $false
    $PorticoRunning = $false
    Set-Content -Path "$ResultsPath\$HTMLFile" $HTMLOuputStart
    Set-Content -Path "$ResultsPath\$CsvFile" ""
    #endregion Setup Vars

    #region TempVars
    $global:TwoNICs = $true
    #endregion TempVars

    #Write Server name to results
    WriteResults "Default" "Server -" $_ ""

    #Check that the server is reachable
    WriteResults "Default" "Checking to see if $_ is online" "" ""
    if (Test-Connection -Count 1 -Quiet $_){
        WriteResults "Green" "Server $_ Online - Continuing with health chek items" "" "Pass"
        
        #Get OS version
        WriteResults "Default" "Getting OS version" "" ""
        $OS =  Invoke-Command -ComputerName $_ -Credential $CredsWin {Get-WmiObject -Class win32_operatingsystem} | Select-Object @{Name="OS"; Expression={"$($_.Caption)$($_.CSDVersion) $($_.OSArchitecture)"}} | Select-Object -expand OS
        WriteResults "Default" "- " $OS ""
        
        #region Check that Portico is installed and running
        WriteResults "Default" "Checking if Portico/ICM is installed and Running" "" ""
        $PorticoService = Invoke-Command -ComputerName $_ -Credential $CredsWin {Get-WmiObject -Class Win32_Service} | Select-Object -property DisplayName,State | Where-Object {$_.DisplayName -eq "Cisco ICM Diagnostic Framework"} | Select-Object -expand State
        if ($PorticoService -ne $null){
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

        #region Get Installed ICM Components
        WriteResults "Default" "Checking to see what ICM Components are installed"
        MakeWebRequest "https://$_`:7890/icm-dp/rest/DiagnosticPortal/ListAppServers"
        try {$Resp = $WebReq.GetResponse()}
        catch {$Resp = "error"}
        if ($Resp -eq "error")
        {
            Write-Host "Unable to fetch $Url - Page"
            return @()
            $Resp.Close()
        }
        else {
            $Reader = new-object System.IO.StreamReader($resp.GetResponseStream())
            [xml]$ResultXml = $Reader.ReadToEnd()
            $Services = @($ResultXml.ListAppServersReply.AppServerList.AppServer | Where-Object {$_.ProductComponentType -ne "Cisco ICM Diagnostic Framework"} | Where-Object {$_.ProductComponentType -ne "Administration Client"} | Select-Object -expand ProductComponentType)
            ForEach ($Service in $Services){
                WriteResults "Green" "- "$Service " Found"
            }
            $reader.Close()
            $resp.Close()
        }
        #endregion Get Installed ICM Components

        #region Get Advanced NIC Properties
        WriteResults "Default" "Check to see if TCP Offload and Speed/Duplex setting are configured properly" "" ""
        Invoke-Command -ComputerName $_ -Credential $CredsWin {Get-NetAdapterAdvancedProperty} | ForEach-Object {
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


        #region Check for AntiVirus
        <#Get-WmiObject win32_product -ComputerName $_ | where {$_.Name -eq 'Microsoft Security Client'} | select -expand Name | ForEach-Object {
            if ($_ -ne ""){
                WriteResults "Green" "AntiVirus Installed" "" ""
            }
            else {WriteResults "Red" "NO AntiVirus Installed" "" ""}
        }#>
        #endregion
    
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
	        #$regKey=$reg.OpenSubKey("SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU")
            #$UpdateStatus = $regKey.GetValue('NoAutoUpdate')
            if ($UpdateStatus -eq 1){
                WriteResults "Green" "- Windows Updates Set to manual" "" "Pass"
            }
            else{WriteResults "Yellow" "- Windows Updates enabled" "" "Warning"}
        }
        elseif($OS -like "*2012*"){
            $reg = Invoke-Command -ComputerName $_ -Credential $CredsWin -ScriptBlock {(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update").AUOptions}
            #$regKey=$reg.OpenSubKey("SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update")
            #$UpdateStatus = $regKey.GetValue('AUOptions')
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

        CloseHtml
    }

    #If Server not Reachable NOT continuing with Audit Checks
    Else{
        WriteResults "Red" "Server $_ is not reachable - Ensure server is online and attempt to audit again." "" "Fail"
        CloseHtml
    }
}
