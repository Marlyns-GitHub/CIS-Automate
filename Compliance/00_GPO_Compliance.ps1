Write-Host ""
Write-Host "[Task 0 :] Gathering Domain Informations, CIS Compliance, variables creating... " -ForegroundColor Green -NoNewline; Write-Host "[OK]" -ForegroundColor Green 

$DC = (Get-ADDomainController)
$DomainDistinguishedName = (Get-ADDomain).DistinguishedName
$Hostname = $DC.Name
$Domain = $DC.Domain

$Checks = "C:\GPOList.txt"
$CheckGPO = (Get-GPO -all | Select-Object -ExpandProperty DisplayName) | Out-File $Checks

$HardenAD = "CIS_000_Account", 
            "CIS_001_Audit",
            "CIS_002_Devices",
            "CIS_003_DomainController",
            "CIS_004_DomainMember",
            "CIS_005_InteractiveLogon",
            "CIS_006_MicrosoftNetworkClient",
            "CIS_007_MicrosoftNetworkServer",
            "CIS_008_NetworkAccess",
            "CIS_009_NetworkSecurity",
            "CIS_010_ShutdownSystemObjects",
            "CIS_011_UserAccountControl",
            "CIS_012_DisabledSpooler",
            "CIS_013_UserLogonCacheLaptop",
            "CIS_014_UserLogonCacheWorkStation",
            "CIS_015_DisabledUSBPorts",
            "CIS_016_WinRemoteShell",
            "CIS_017_WinRM",
            "CIS_018_RemoteProcedureCall",
            "CIS_019_RemoteAssistance",
            "CIS_020_RemoteDesktopService",
            "CIS_021_TimeProvider",
            "CIS_022_DisabledAutoRun",
            "CIS_023_PowerSleepSettings",
            "CIS_024_DeviceGuard",
            "CIS_025_CredentialsDelegation",
            "CIS_026_DisabledWinStore"

if ((Get-Content $Checks | Select-String -Pattern "CIS_000") -and
    (Get-Content $Checks | Select-String -Pattern "CIS_001") -and
    (Get-Content $Checks | Select-String -Pattern "CIS_002") -and
    (Get-Content $Checks | Select-String -Pattern "CIS_003") -and
    (Get-Content $Checks | Select-String -Pattern "CIS_004") -and
    (Get-Content $Checks | Select-String -Pattern "CIS_005") -and
    (Get-Content $Checks | Select-String -Pattern "CIS_006") -and
    (Get-Content $Checks | Select-String -Pattern "CIS_007") -and
    (Get-Content $Checks | Select-String -Pattern "CIS_008") -and
    (Get-Content $Checks | Select-String -Pattern "CIS_009") -and
    (Get-Content $Checks | Select-String -Pattern "CIS_010") -and
    (Get-Content $Checks | Select-String -Pattern "CIS_011") -and
    (Get-Content $Checks | Select-String -Pattern "CIS_012") -and
    (Get-Content $Checks | Select-String -Pattern "CIS_013") -and
    (Get-Content $Checks | Select-String -Pattern "CIS_014") -and
    (Get-Content $Checks | Select-String -Pattern "CIS_015") -and
    (Get-Content $Checks | Select-String -Pattern "CIS_016") -and
    (Get-Content $Checks | Select-String -Pattern "CIS_017") -and
    (Get-Content $Checks | Select-String -Pattern "CIS_018") -and
    (Get-Content $Checks | Select-String -Pattern "CIS_019") -and
    (Get-Content $Checks | Select-String -Pattern "CIS_020") -and
    (Get-Content $Checks | Select-String -Pattern "CIS_021") -and
    (Get-Content $Checks | Select-String -Pattern "CIS_022") -and
    (Get-Content $Checks | Select-String -Pattern "CIS_023") -and
    (Get-Content $Checks | Select-String -Pattern "CIS_024") -and
    (Get-Content $Checks | Select-String -Pattern "CIS_025") -and
    (Get-Content $Checks | Select-String -Pattern "CIS_026"))
{

     Write-Host "[Task 1 :] Checking if The Compliance CIS GPOs already exists...                " -ForegroundColor DarkGray -NoNewline; Write-Host "[Ok]" -ForegroundColor Green
     Write-Host "[Task 2 :] Here is the list of Compliance CIS GPOs...                           " -ForegroundColor DarkGray -NoNewline; Write-Host "[Ok]" -ForegroundColor Green
     Write-Host ""
     Write-Host $HardenAD[0] -ForegroundColor DarkGray
     Write-Host $HardenAD[1] -ForegroundColor DarkGray
     Write-Host $HardenAD[2] -ForegroundColor DarkGray
     Write-Host $HardenAD[3] -ForegroundColor DarkGray
     Write-Host $HardenAD[4] -ForegroundColor DarkGray
     Write-Host $HardenAD[5] -ForegroundColor DarkGray
     Write-Host $HardenAD[6] -ForegroundColor DarkGray
     Write-Host $HardenAD[7] -ForegroundColor DarkGray
     Write-Host $HardenAD[8] -ForegroundColor DarkGray
     Write-Host $HardenAD[9] -ForegroundColor DarkGray
     Write-Host $HardenAD[10] -ForegroundColor DarkGray
     Write-Host $HardenAD[11] -ForegroundColor DarkGray
     Write-Host $HardenAD[13] -ForegroundColor DarkGray
     Write-Host $HardenAD[13] -ForegroundColor DarkGray
     Write-Host $HardenAD[14] -ForegroundColor DarkGray
     Write-Host $HardenAD[15] -ForegroundColor DarkGray
     Write-Host $HardenAD[16] -ForegroundColor DarkGray
     Write-Host $HardenAD[17] -ForegroundColor DarkGray
     Write-Host $HardenAD[18] -ForegroundColor DarkGray
     Write-Host $HardenAD[19] -ForegroundColor DarkGray
     Write-Host $HardenAD[20] -ForegroundColor DarkGray
     Write-Host $HardenAD[21] -ForegroundColor DarkGray
     Write-Host $HardenAD[22] -ForegroundColor DarkGray
     Write-Host $HardenAD[23] -ForegroundColor DarkGray
     Write-Host $HardenAD[24] -ForegroundColor DarkGray
     Write-Host $HardenAD[25] -ForegroundColor DarkGray
     Write-Host $HardenAD[26] -ForegroundColor DarkGray
     Write-Host ""
     Get-Content .\Compliance\info.md
     Write-Host ""
}
else {
     Write-Host "[Task 1 :] Creating CIS Compliance GPO and Link it to Domain...                 " -ForegroundColor Green -NoNewline; Write-Host "[OK]" -ForegroundColor Green
     foreach ($gpo in $HardenAD)
        {
             $CreateGPO = New-GPO -Name $gpo; $Linkgpo = New-GPLink -Name $gpo -Target $DomainDistinguishedName
        }
     
    # Copy SecGuide to Localhost
    $Admx = "\PolicyDefinitions"
    $Adml = "\PolicyDefinitions\en-US"
    $Path = $env:windir
    $PathAdmx = "$Path\$Admx"
    $PathAdml = "$Path\$Adml"

    if((-not(Test-Path -Path $PathAdmx\SecGuide.amdx)) -and
       (-not(Test-Path -Path $PathAdml\SecGuide.amdl)))
       {        
           Copy-Item -Path .\Compliance\SecGuide\SecGuide.admx -Destination $PathAdmx
           Copy-Item -Path .\Compliance\SecGuide\SecGuide.adml -Destination $PathAdml
       }
     Write-Host "[Task 2 :] Successful.                                                          " -ForegroundColor Green -NoNewline; Write-Host "[Ok]" -ForegroundColor Green
     Write-Host ""
     Get-Content .\Compliance\info.md
     Write-Host ""
}

