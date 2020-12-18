[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

<#
#Prompt for Windows and Portico Credentials, 
$CredsWin = Get-Credential -Message "test"
#>

#Read Windows and Portico credentials from CSV file
$UserCreds = Import-Csv -Path "C:\Temp\Creds.csv"
$password = ConvertTo-SecureString $UserCreds.pass -AsPlainText -Force
$global:CredsWin = New-Object System.Management.Automation.PSCredential ($UserCreds.username, $password)
#>

#$CredsSql

function GetComponents()
{
    $url = "https://$_`:7890/icm-dp/rest/DiagnosticPortal/ListAppServers"
    Write-Host "Getting Component List From: $url"
    $resultXml = Get-XmlFromUrl -url $url
    return @($resultXml.ListAppServersReply.AppServerList.AppServer | where {$_.ProductComponentType -ne "Cisco ICM Diagnostic Framework"} | select -expand ProductComponentType)
}

Get-Content c:\Scripts\Servers.txt | ForEach-Object {
    $ResultsPath = "C:\Temp\AuditResults"
    $HTMLFile = "$_.htm"
    $CsvFile = "$_.csv"

    #TempVars
    $TwoNICs = $true

    $HTMLOuputStart = "<html><body><br><b>UCCE/PCCE Server Audit Report.</b></body><html>
    <html><body>"
    $HTMLOuputEnd = "</body></html>"
    Set-Content -Path "$ResultsPath\$HTMLFile" $HTMLOuputStart
    Set-Content -Path "$ResultsPath\$CsvFile" ""

    function GetComponents(){
        $url = "https://$($server):7890/icm-dp/rest/DiagnosticPortal/ListAppServers"
        Write-Host "Getting Component List From: $($url)"
        $resultXml = Get-XmlFromUrl -url $url
        return @($resultXml.ListAppServersReply.AppServerList.AppServer | where {$_.ProductComponentType -ne "Cisco ICM Diagnostic Framework"} | select -expand ProductComponentType)
    }

    #Write results to CSV, html file and PowerShell window
    #To use function, send it the Color of the message and up to 3 strings to write to audit results
    Function WriteResults ($Color,$String1,$String2,$String3){
        if ($Color -eq "Green") {$HtmlColor = "008000"; $ConsColor = "Green"}
        elseif ($Color -eq "Red") {$HtmlColor = "F00000"; $ConsColor = "Red"}
        elseif ($Color -eq "Yellow") {$HtmlColor = "FFC000"; $ConsColor = "Yellow"}
        else {$HtmlColor = "000000"; $ConsColor = "White"}
        Add-Content "$ResultsPath\$HTMLFile" "<br><font color =`"#$HtmlColor`">$String1 $String2 $String3</font>"
        Add-Content -Path "$ResultsPath\$CsvFile" "$String1,$String2,$String3"
        Write-Host -ForegroundColor $ConsColor $String1 $String2 $String3
    }

    #Write Page file notice for malconfigured page files
    Function WritePFNotice($Color){
        WriteResults $Color "It is recommended to configure the Swap File with an Inital and Max size of 1.5 x Memory" "" ""
        WriteResults $Color " - Use the below sizes to set the Swap File accordingly " "" ""
        WriteResults $Color " -  - 16GB RAM = 24576MB Page File | 12GB RAM = 18432MB Page File | 8GB RAM =  12288MB Page File" "" ""
        WriteResults $Color " -  -  6GB RAM =  9216MB Page File |  4GB RAM =  6144MB Page File | 2GB RAM =  3072MB Page File" "" ""
        WriteResults $Color " -  -  Note that Page File changes typically require a reboot" "" ""
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

    #Write Server name to results
    WriteResults "Default" "Server -" $_ ""

    #Check that the server is reachable
    if (Test-Connection -Count 1 -Quiet $_){
        
        #Get OS version
        $OS = Get-WmiObject -Class win32_operatingsystem -ComputerName $_ | select @{Name="OS"; Expression={"$($_.Caption)$($_.CSDVersion) $($_.OSArchitecture)"}} | select -expand OS
        WriteResults "Default" "OS -" $OS ""
        
        #Get Installed ICM Components
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
            $Services = @($ResultXml.ListAppServersReply.AppServerList.AppServer | where {$_.ProductComponentType -ne "Cisco ICM Diagnostic Framework"} | select -expand ProductComponentType)
            foreach ($Service in $Services){
                WriteResults "Green" $Service " Found" ""

            }
            <#
            if ($services -like "*CTI Server*"){
                Write-Host "Found CTI Server"
            }#>
            $reader.Close()
            $resp.Close()
        }

        #Check for ICM Components
        <#$components = @{}
        $components.Add($_, (-server $_ -creds $CredsWin))
        WriteResults "Green" $components "" "" #>

        #Get Advanced NIC Properties
        Invoke-Command -ComputerName $_ {Get-NetAdapterAdvancedProperty} | ForEach-Object {
            if ((($_.DisplayName -like "*Off*") -and ($_.DisplayValue -like "*Disabled*")) -or (
                    ($_.DisplayName -like "Speed*") -and ($_.DisplayValue -like "*1.0 Gbps Full*"))){
                WriteResults "Green" $_.Name $_.DisplayName $_.DisplayValue
            }
            elseif ((($_.DisplayName -like "*Off*") -and ($_.DisplayValue -notlike "*Disabled*"))-or(
                        ($_.DisplayName -like "Speed*") -and ($_.DisplayValue -notlike "*1.0 Gbps Full*"))){
                WriteResults "Red" $_.Name $_.DisplayName $_.DisplayValue
            }
        }
    
        #Get Cisco ICM Services and Startup Type
        Get-Service -ComputerName $_ | select -property DisplayName,StartType | ForEach-Object {
            if (($_.DisplayName -like "Cisco*")-and($_.StartType -eq "Automatic")){
                WriteResults "Green" $_.DisplayName " - " $_.StartType
            }
            elseif (($_.DisplayName -like "Cisco*")-and($_.StartType -ne "Automatic")) {
                WriteResults "Red" $_.DisplayName " - " $_.StartType
            }
        }
    
        #Check if RDP is enabled
        if ((Get-WmiObject -name "root\cimv2\TerminalServices" Win32_TerminalServiceSetting -Authentication 6 -ComputerName $_ | select -expand AllowTSConnections) -eq 1){
            WriteResults "Green" "Remote Desktop Enabled" "" ""
        }
        else {WriteResults "Red" "Remote Desktop DISABLED" "" ""}

        #Check for AntiVirus
        <#Get-WmiObject win32_product -ComputerName $_ | where {$_.Name -eq 'Microsoft Security Client'} | select -expand Name | ForEach-Object {
            if ($_ -ne ""){
                WriteResults "Green" "AntiVirus Installed" "" ""
            }
            else {WriteResults "Red" "NO AntiVirus Installed" "" ""}
        }#>
    
        #Check if CD Rom drive is assigned to Z:
        if ((Get-WmiObject win32_logicaldisk -ComputerName $_ | where {$_.DriveType -eq 5} |select -expand DeviceID) -eq "z:"){
            WriteResults "Green" "CD Drive Assigned to Z:" "" ""
        }
        else {WriteResults "Red" "CD Drive Assigned to $_" "- Should be reassigned to Z:" ""}

        #Check if WMI SNMP Provider is installed
        if ((Get-WmiObject win32_optionalfeature -ComputerName $_ | where {$_.Name -eq 'WMISnmpProvider'} | select -expand InstallState) -eq "1"){
            WriteResults "Green" "WMI SNMP Provider Installed" "" ""
        }
        else {WriteResults "Red" "WMI SNMP Provider NOT Installed" "- Should be installed" ""}

        #Check Page file is hard set to 1.5x RAM size
        $MemSzMB = [Math]::Ceiling((gwmi win32_computersystem -ComputerName $_  | select -ExpandProperty TotalPhysicalMemory) / 1048576 )
        if ((Get-WmiObject win32_computersystem -ComputerName $_ | select -expand AutomaticManagedPagefile) -eq "True"){
            WriteResults "Red" "Page File Configred to be managed by system" "" ""
            WritePFNotice "Red"
        }
        else{
            $PfSettings = Get-CimInstance -Class Win32_PageFileSetting -ComputerName $_
            $PfRangeLow = $MemSzMB*1.4 ; $PfRangeHigh = $MemSzMB*1.6
            #Write-Host $PfSettings.InitialSize $PfSettings.MaximumSize
            if ($PfSettings.InitialSize -eq $PfSettings.MaximumSize){
                if (($PfSettings.MaximumSize -gt $PfRangeLow) -and ($PfSettings.MaximumSize -lt $PfRangeHigh)){
                    WriteResults "Green" "Page File Configred to best practices" "" ""
                }
                elseif($PfSettings.MaximumSize -gt $PfRangeHigh){
                    WriteResults "Yellow" "Page File Configred larger than typical installs" "" ""
                    WritePFNotice "Yellow"
                }
                else{
                    WriteResults "Red" "Page File Size Should be increased" "" ""
                    WritePFNotice "Red"
                }
            }
            elseif($PfSettings.InitialSize -lt $PfRangeLow){
                WriteResults "Red" "Page File Size Should be increased and both Initial and Max Values shoufl be the same" "" ""
                WritePFNotice "Red"
            }
            else{
                WriteResults "Yellow" "Page File Size is large enough but both Initial and Max Values shoufl be the same" "" ""
                WritePFNotice "Yellow"
            }
        }

        #Check to see if Updates are Set to Manual
        $reg=[Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $_)
        if ($OS -like "*2016*"){
	        $regKey=$reg.OpenSubKey("SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU")
            $UpdateStatus = $regKey.GetValue('NoAutoUpdate')
            if ($UpdateStatus -eq 1){
                WriteResults "Green" "Windows Updates Set to manual" "" ""
            }
            else{WriteResults "Yellow" "Windows Updates enabled" "" ""}
        }
        elseif($OS -like "*2012*"){
            $regKey=$reg.OpenSubKey("SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update")
            $UpdateStatus = $regKey.GetValue('AUOptions')
            if ($UpdateStatus -eq 1){
                WriteResults "Green" "Windows Updates Set to manual" "" ""
            }
            else{WriteResults "Yellow" "Windows Updates enabled" "" ""}
        }

        #Check for recently installed updates
        $Hotfixes = gwmi win32_quickfixengineering -ComputerName $_ ; $LastUpdate = $Hotfixes.item(($Hotfixes.length - 1)).InstalledOn
        $Today = Get-Date ; $DateDif = $Today - $LastUpdate
        if ($DateDif.Days -lt 60){
            WriteResults "Green" "Windows Updates have been installed in the last 60 days" "" ""
        }
        else{WriteResults "Red" "NO Windows Updates have been installed in the last 60 days" "" ""}

        #Check NIC Priority
        if($TwoNICs -eq $true){
            #2016 NIC Metric Check
            if ($OS -like "*2016*"){
                $pubMetric = Invoke-Command -ComputerName $_ {get-netipinterface -interfacealias public | select -expand interfacemetric}
                $priMetric = Invoke-Command -ComputerName $_ {get-netipinterface -interfacealias private | select -expand interfacemetric}
                if ($pubMetric -lt $priMetric){
                    WriteResults "Green" "NIC Metric Priority correctly configured Public - NIC = $pubMetric and Private NIC = $priMetric" "" ""
                }
                else{
                   WriteResults "Red" "NIC Metric Priority NOT correctly configured - Public NIC = $pubMetric and Private NIC = $priMetric" "" ""
                    WriteResults "Red" " - Public NIC should have a lower Metric value than the Priate NIC" "" ""
                }
            }

            #2012 R2 Binding Order Check
            else{
                $Binding = Invoke-Command -ComputerName $_ {(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Linkage").Bind}
                $Return = New-Object PSobject
                $BindingOrder = @()
                ForEach ($Bind in $Binding)
                {
                    $DeviceId = $Bind.Split("\")[2]
                    $Adapter = (Get-WmiObject Win32_Networkadapter -ComputerName $_ | Where {$_.GUID -eq $DeviceId }).NetConnectionId
                    if (($Adapter -like '*public*')-or($Adapter -like '*private*')){
                        $BindingOrder += $Adapter
                    }
                }
                if (($BindingOrder[0] -like '*public*')-and($BindingOrder[1] -like '*private*')){
                    $ResultString =  "Binding Order correctly configured - " + $BindingOrder[0] + " above " + $BindingOrder[1]
                    WriteResults "Green" $ResultString "" ""
                }
                else {
                    $ResultString =  "Binding Order NOT correctly configured - " + $BindingOrder[1] + " above " + $BindingOrder[0]
                    WriteResults "Red" $ResultString "" ""
                    WriteResults "Red" " - the Public NIC should be listed above the Private NIC in the Binding Order" "" ""
                }
            }
        }

        Add-Content "$ResultsPath\$HTMLFile" $HTMLOuputEnd
    }

    #If Server not Reachable NOT continuing with Audit Checks
    Else{
        WriteResults "Red" "Server $_ is not reachable - Ensure server is online and attempt to audit again." "" ""
    }
}
