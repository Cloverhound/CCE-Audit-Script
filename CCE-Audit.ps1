
Get-Content c:\Scripts\Servers.txt | ForEach-Object {
    $ResultsPath = "C:\Temp\AuditResults"
    $HTMLFile = "$_.htm"
    $CsvFile = "$_.csv"

    $HTMLOuputStart = "<html><body><br><b>UCCE/PCCE Server Audit Report.</b></body><html>
    <html><body>"
    $HTMLOuputEnd = "</body></html>"
    Set-Content -Path "$ResultsPath\$HTMLFile" $HTMLOuputStart
    Set-Content -Path "$ResultsPath\$CsvFile" ""


    Function WriteResults ($Color,$String1,$String2,$String3){
        if ($Color -eq "Green") {$HtmlColor = "008000"; $ConsColor = "Green"}
        elseif ($Color -eq "Red") {$HtmlColor = "F00000"; $ConsColor = "Red"}
        else {$HtmlColor = "000000"; $ConsColor = "White"}
        Add-Content "$ResultsPath\$HTMLFile" "<br><font color =`"#$HtmlColor`">$String1 $String2 $String3</font>"
        Add-Content -Path "$ResultsPath\$CsvFile" "$String1,$String2,$String3"
        Write-Host -ForegroundColor $ConsColor $String1 $String2 $String3
    }
    #Write Server name to results
    WriteResults "Default" "Server -" $_ ""

    #Get OS version
    $OS = Get-WmiObject -Class win32_operatingsystem -ComputerName $_ | select @{Name="OS"; Expression={"$($_.Caption)$($_.CSDVersion) $($_.OSArchitecture)"}} | select -expand OS
    WriteResults "Default" "OS -" $OS ""

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
    if ((Get-WmiObject win32_computersystem -ComputerName $_ | select -expand AutomaticManagedPagefile) -eq "True"){
        WriteResults "Red" "It is recommended to configure the Swap File with an Inital and Max size of 1.5 x Memory" "" ""
        WriteResults "Red" " - Use the below sizes to set the Swap File accordingly " "" ""
        WriteResults "Red" " -  - 16GB RAM = 24576MB Page File | 8GB RAM =  12288MB Page File" "" ""
        WriteResults "Red" " -  - 6GB RAM =  9216MB Page File | 2GB RAM =  3072MB Page File" "" ""
    }
    else {WriteResults "Green" "Check Min-Max Size" "" ""}

    Add-Content "$ResultsPath\$HTMLFile" $HTMLOuputEnd
}
