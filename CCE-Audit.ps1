
Get-Content c:\Scripts\Servers.txt | ForEach-Object {
    $ResultsPath = "C:\Temp\AuditResults"
    $HTMLFile = "$_.htm"
    $CsvFile = "$_.csv"

    $HTMLOuputStart = "<html><body><br><b>UCCE/PCCE Server Audit Report.</b></body><html>
    <html><body>"
    $HTMLOuputEnd = "</body></html>"
    Set-Content -Path "$ResultsPath\$HTMLFile" $HTMLOuputStart
    Set-Content -Path "$ResultsPath\$CsvFile" ""


    Function WriteResults ($HtmlColor,$ConsColor,$String1,$String2,$String3){
        Add-Content "$ResultsPath\$HTMLFile" "<br><font color =`"#$HtmlColor`">$String1 $String2 $String3</font>"
        Add-Content -Path "$ResultsPath\$CsvFile" "$String1,$String2,$String3"
        Write-Host -ForegroundColor $ConsColor $String1 $String2 $String3
    }
    #Write Server name to results
    WriteResults "000000" "White" "Server -" $_ ""

    #Get OS version
    $OS = Get-WmiObject -Class win32_operatingsystem -ComputerName $_ | select @{Name="OS"; Expression={"$($_.Caption)$($_.CSDVersion) $($_.OSArchitecture)"}} | select -expand OS
    WriteResults "000000" "White" "OS -" $OS ""

    #Get Advanced NIC Properties
    Invoke-Command -ComputerName $_ {Get-NetAdapterAdvancedProperty} | ForEach-Object {
        if ((($_.DisplayName -like "*Off*") -and ($_.DisplayValue -like "*Disabled*")) -or (
                ($_.DisplayName -like "Speed*") -and ($_.DisplayValue -like "*1.0 Gbps Full*"))){
            WriteResults "008000" "Green" $_.Name $_.DisplayName $_.DisplayValue
        }
        elseif ((($_.DisplayName -like "*Off*") -and ($_.DisplayValue -notlike "*Disabled*"))-or(
                    ($_.DisplayName -like "Speed*") -and ($_.DisplayValue -notlike "*1.0 Gbps Full*"))){
            WriteResults "F00000" "Red" $_.Name $_.DisplayName $_.DisplayValue
        }
    }
    
    #Get Cisco ICM Services and Startup Type
    Get-Service -ComputerName $_ | select -property DisplayName,StartType | ForEach-Object {
        if (($_.DisplayName -like "Cisco*")-and($_.StartType -eq "Automatic")){
            WriteResults "008000" "Green" $_.DisplayName " - " $_.StartType
        }
        elseif (($_.DisplayName -like "Cisco*")-and($_.StartType -ne "Automatic")) {
            WriteResults "F00000" "Red" $_.DisplayName " - " $_.StartType
        }
    }
    
    #Check if RDP is enabled
    Get-WmiObject -name "root\cimv2\TerminalServices" Win32_TerminalServiceSetting -Authentication 6 -ComputerName $_ | select -expand AllowTSConnections | ForEach-Object {
        if ($_ -eq 1){
            WriteResults "008000" "Green" "Remote Desktop Enabled" "" ""
        }
        else {WriteResults "F00000" "Red" "Remote Desktop DISABLED" "" ""}
    }

    #Check for AntiVirus
    <#Get-WmiObject win32_product -ComputerName $_ | where {$_.Name -eq 'Microsoft Security Client'} | select -expand Name | ForEach-Object {
        if ($_ -ne ""){
            WriteResults "008000" "Green" "AntiVirus Installed" "" ""
        }
        else {WriteResults "F00000" "Red" "NO AntiVirus Installed" "" ""}
    }#>

    Get-WmiObject win32_logicaldisk -ComputerName $_ | where {$_.DriveType -eq 5} |select -expand DeviceID | ForEach-Object {
        if ($_ -eq "z:"){
            WriteResults "008000" "Green" "CD Drive Assigned to Z:" "" ""
        }
        else {WriteResults "F00000" "Red" "CD Drive Assigned to $_" "- Should be reassigned to Z:" ""}
    }

    gwmi win32_optionalfeature -ComputerName $_ | where {$_.Name -eq 'WMISnmpProvider'} | select -expand InstallState | ForEach-Object {
        if ($_ -eq "1"){
            WriteResults "008000" "Green" "WMI SNMP Provider Installed" "" ""
        }
        else {WriteResults "F00000" "Red" "WMI SNMP Provider NOT Installed" "- Should be installed" ""}
    }

    Add-Content "$ResultsPath\$HTMLFile" $HTMLOuputEnd
}
