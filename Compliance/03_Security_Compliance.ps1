Write-Host ""
Write-Host "[Task : 0] Gathering Domain Informations, Export All GPOs, and GPOs Id...          " -ForegroundColor Green -NoNewline; Write-Host "[OK]" -ForegroundColor Green 

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
            "CIS_014_UserLogonCacheWorkStation"

# Check if the compliance CIS hardening has been configured...

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
    (Get-Content $Checks | Select-String -Pattern "CIS_014"))  
    {
        
        $000Id = (Get-GPO -Name $hardenAD[0]).Id.ToString()
        $001Id = (Get-GPO -Name $hardenAD[1]).Id.ToString()
        $002Id = (Get-GPO -Name $hardenAD[2]).Id.ToString()
        $003Id = (Get-GPO -Name $hardenAD[3]).Id.ToString()
        $004Id = (Get-GPO -Name $hardenAD[4]).Id.ToString()
        $005Id = (Get-GPO -Name $hardenAD[5]).Id.ToString()
        $006Id = (Get-GPO -Name $hardenAD[6]).Id.ToString()
        $007Id = (Get-GPO -Name $hardenAD[7]).Id.ToString()
        $008Id = (Get-GPO -Name $hardenAD[8]).Id.ToString()
        $009Id = (Get-GPO -Name $hardenAD[9]).Id.ToString()
        $010Id = (Get-GPO -Name $hardenAD[10]).Id.ToString()
        $011Id = (Get-GPO -Name $hardenAD[11]).Id.ToString()
        $012Id = (Get-GPO -Name $hardenAD[12]).Id.ToString()
        $013Id = (Get-GPO -Name $hardenAD[13]).Id.ToString()
        $014Id = (Get-GPO -Name $hardenAD[14]).Id.ToString()

        # 
        $Template="[Unicode]
        Unicode=yes
        [Version]
        signature=`"`$CHICAGO$`"
        Revision=1"
        
        # Create SecEdit directory and GptTmpl.inf file

        if (!(Get-Content -Path "\\$Hostname\Sysvol\$Domain\Policies\{$($000Id)}\GPT.INI" | Select-String -Pattern Version=0 ) -and
            !(Get-Content -Path "\\$Hostname\Sysvol\$Domain\Policies\{$($001Id)}\GPT.INI" | Select-string -Pattern Version=0 ) -and
            !(Get-Content -Path "\\$Hostname\Sysvol\$Domain\Policies\{$($002Id)}\GPT.INI" | Select-string -Pattern Version=0 ) -and
            !(Get-Content -Path "\\$Hostname\Sysvol\$Domain\Policies\{$($003Id)}\GPT.INI" | Select-string -Pattern Version=0 ) -and
            !(Get-Content -Path "\\$Hostname\Sysvol\$Domain\Policies\{$($004Id)}\GPT.INI" | Select-string -Pattern Version=0 ) -and
            !(Get-Content -Path "\\$Hostname\Sysvol\$Domain\Policies\{$($005Id)}\GPT.INI" | Select-string -Pattern Version=0 ) -and
            !(Get-Content -Path "\\$Hostname\Sysvol\$Domain\Policies\{$($006Id)}\GPT.INI" | Select-string -Pattern Version=0 ) -and
            !(Get-Content -Path "\\$Hostname\Sysvol\$Domain\Policies\{$($007Id)}\GPT.INI" | Select-string -Pattern Version=0 ) -and
            !(Get-Content -Path "\\$Hostname\Sysvol\$Domain\Policies\{$($008Id)}\GPT.INI" | Select-string -Pattern Version=0 ) -and
            !(Get-Content -Path "\\$Hostname\Sysvol\$Domain\Policies\{$($009Id)}\GPT.INI" | Select-string -Pattern Version=0 ) -and
            !(Get-Content -Path "\\$Hostname\Sysvol\$Domain\Policies\{$($010Id)}\GPT.INI" | Select-string -Pattern Version=0 ) -and
            !(Get-Content -Path "\\$Hostname\Sysvol\$Domain\Policies\{$($011Id)}\GPT.INI" | Select-string -Pattern Version=0 ) -and
            !(Get-Content -Path "\\$Hostname\Sysvol\$Domain\Policies\{$($012Id)}\GPT.INI" | Select-string -Pattern Version=0 ) -and
            !(Get-Content -Path "\\$Hostname\Sysvol\$Domain\Policies\{$($013Id)}\GPT.INI" | Select-string -Pattern Version=0 ) -and
            !(Get-Content -Path "\\$Hostname\Sysvol\$Domain\Policies\{$($014Id)}\GPT.INI" | Select-string -Pattern Version=0 ))
            {
                Write-Host "[Task : 1] The compliance CIS security already configured.                         " -ForegroundColor DarkGray -NoNewline; Write-Host "[Ok]" -ForegroundColor Green
            }
        else
            {
                Write-Host "[Task : 1] Configuring GPOs, creating SecEdit directory and GptTmpl.inf files...   " -ForegroundColor Green -NoNewline; Write-Host "[Ok]" -ForegroundColor Green
                
                $SecEdit0 = New-Item "\\$Hostname\Sysvol\$Domain\Policies\{$($000Id)}\Machine\Microsoft\Windows NT\SecEdit" -ItemType Directory
                $SecEdit1 = New-Item "\\$Hostname\Sysvol\$Domain\Policies\{$($001Id)}\Machine\Microsoft\Windows NT\SecEdit" -ItemType Directory
                $SecEdit2 = New-Item "\\$Hostname\Sysvol\$Domain\Policies\{$($002Id)}\Machine\Microsoft\Windows NT\SecEdit" -ItemType Directory
                $SecEdit3 = New-Item "\\$Hostname\Sysvol\$Domain\Policies\{$($003Id)}\Machine\Microsoft\Windows NT\SecEdit" -ItemType Directory
                $SecEdit4 = New-Item "\\$Hostname\Sysvol\$Domain\Policies\{$($004Id)}\Machine\Microsoft\Windows NT\SecEdit" -ItemType Directory
                $SecEdit5 = New-Item "\\$Hostname\Sysvol\$Domain\Policies\{$($005Id)}\Machine\Microsoft\Windows NT\SecEdit" -ItemType Directory
                $SecEdit6 = New-Item "\\$Hostname\Sysvol\$Domain\Policies\{$($006Id)}\Machine\Microsoft\Windows NT\SecEdit" -ItemType Directory
                $SecEdit7 = New-Item "\\$Hostname\Sysvol\$Domain\Policies\{$($007Id)}\Machine\Microsoft\Windows NT\SecEdit" -ItemType Directory
                $SecEdit8 = New-Item "\\$Hostname\Sysvol\$Domain\Policies\{$($008Id)}\Machine\Microsoft\Windows NT\SecEdit" -ItemType Directory
                $SecEdit9 = New-Item "\\$Hostname\Sysvol\$Domain\Policies\{$($009Id)}\Machine\Microsoft\Windows NT\SecEdit" -ItemType Directory
                $SecEdit10 = New-Item "\\$Hostname\Sysvol\$Domain\Policies\{$($010Id)}\Machine\Microsoft\Windows NT\SecEdit" -ItemType Directory
                $SecEdit11 = New-Item "\\$Hostname\Sysvol\$Domain\Policies\{$($011Id)}\Machine\Microsoft\Windows NT\SecEdit" -ItemType Directory
                $SecEdit12 = New-Item "\\$Hostname\Sysvol\$Domain\Policies\{$($012Id)}\Machine\Microsoft\Windows NT\SecEdit" -ItemType Directory
                $SecEdit13 = New-Item "\\$Hostname\Sysvol\$Domain\Policies\{$($013Id)}\Machine\Microsoft\Windows NT\SecEdit" -ItemType Directory
                $SecEdit14 = New-Item "\\$Hostname\Sysvol\$Domain\Policies\{$($014Id)}\Machine\Microsoft\Windows NT\SecEdit" -ItemType Directory
        
                $Template | Out-File "$SecEdit0\GptTmpl.inf"; $gptFile0 = "$SecEdit0\GptTmpl.inf"
                $Template | Out-File "$SecEdit1\GptTmpl.inf"; $gptFile1 = "$SecEdit1\GptTmpl.inf"
                $Template | Out-File "$SecEdit2\GptTmpl.inf"; $gptFile2 = "$SecEdit2\GptTmpl.inf"
                $Template | Out-File "$SecEdit3\GptTmpl.inf"; $gptFile3 = "$SecEdit3\GptTmpl.inf"
                $Template | Out-File "$SecEdit4\GptTmpl.inf"; $gptFile4 = "$SecEdit4\GptTmpl.inf"
                $Template | Out-File "$SecEdit5\GptTmpl.inf"; $gptFile5 = "$SecEdit5\GptTmpl.inf"
                $Template | Out-File "$SecEdit6\GptTmpl.inf"; $gptFile6 = "$SecEdit6\GptTmpl.inf"
                $Template | Out-File "$SecEdit7\GptTmpl.inf"; $gptFile7 = "$SecEdit7\GptTmpl.inf"
                $Template | Out-File "$SecEdit8\GptTmpl.inf"; $gptFile8 = "$SecEdit8\GptTmpl.inf"
                $Template | Out-File "$SecEdit9\GptTmpl.inf"; $gptFile9 = "$SecEdit9\GptTmpl.inf"
                $Template | Out-File "$SecEdit10\GptTmpl.inf"; $gptFile10 = "$SecEdit10\GptTmpl.inf"
                $Template | Out-File "$SecEdit11\GptTmpl.inf"; $gptFile11 = "$SecEdit11\GptTmpl.inf"
                $Template | Out-File "$SecEdit12\GptTmpl.inf"; $gptFile12 = "$SecEdit12\GptTmpl.inf"
                $Template | Out-File "$SecEdit13\GptTmpl.inf"; $gptFile13 = "$SecEdit13\GptTmpl.inf"
                $Template | Out-File "$SecEdit14\GptTmpl.inf"; $gptFile14 = "$SecEdit14\GptTmpl.inf"

                # Sysvol versionNumber Gpt.INI file path

                $GptIni0 = "\\$Hostname\Sysvol\$Domain\Policies\{$($000Id)}\GPT.INI"
                $GptIni1 = "\\$Hostname\Sysvol\$Domain\Policies\{$($001Id)}\GPT.INI"
                $GptIni2 = "\\$Hostname\Sysvol\$Domain\Policies\{$($002Id)}\GPT.INI"
                $GptIni3 = "\\$Hostname\Sysvol\$Domain\Policies\{$($003Id)}\GPT.INI"
                $GptIni4 = "\\$Hostname\Sysvol\$Domain\Policies\{$($004Id)}\GPT.INI"
                $GptIni5 = "\\$Hostname\Sysvol\$Domain\Policies\{$($005Id)}\GPT.INI"
                $GptIni6 = "\\$Hostname\Sysvol\$Domain\Policies\{$($006Id)}\GPT.INI"
                $GptIni7 = "\\$Hostname\Sysvol\$Domain\Policies\{$($007Id)}\GPT.INI"
                $GptIni8 = "\\$Hostname\Sysvol\$Domain\Policies\{$($008Id)}\GPT.INI"
                $GptIni9 = "\\$Hostname\Sysvol\$Domain\Policies\{$($009Id)}\GPT.INI"
                $GptIni10 = "\\$Hostname\Sysvol\$Domain\Policies\{$($010Id)}\GPT.INI"
                $GptIni11 = "\\$Hostname\Sysvol\$Domain\Policies\{$($011Id)}\GPT.INI"
                $GptIni12 = "\\$Hostname\Sysvol\$Domain\Policies\{$($012Id)}\GPT.INI"
                $GptIni13 = "\\$Hostname\Sysvol\$Domain\Policies\{$($013Id)}\GPT.INI"
                $GptIni14 = "\\$Hostname\Sysvol\$Domain\Policies\{$($014Id)}\GPT.INI"
        }
    }
else 
    {
       Write-Warning "Run Compliance 1) Create CIS Compliance Group Policies first."
       Write-Host ""            
       Get-Content .\Compliance\info.md
       Write-Host"" 
       exit
    }

# GPO Default directory path and pPCMachineExtensionNames attribute

$PathPolicy = (Get-ADObject -Filter 'Name -eq "Policies"' -Properties * | Where-Object ObjectClass -eq container | Select-Object Name, distinguishedName).DistinguishedName    
$pPCMachineExtensionNames = "{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}"


function CIS_000_Account (){

    $VersionNumber = (Get-ADObject "CN={$($000Id)},$PathPolicy" -Properties *)
    $VersionNumber.versionNumber | ForEach {

        if ( $VersionNumber.versionNumber -eq "7" )
            {
                Write-Host "[Task : 3] Checking if Account CIS Compliance is configured...                     " -ForegroundColor DarkGray -NoNewline; Write-Host "[OK]" -ForegroundColor Green
                Write-Host ""
                Write-Host "Account : "
                Write-Host "Limit local account use black passwords to console logon only                    : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
                Write-Host "Rename administrator account                                                     : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
                Write-Host "Rename guest account                                                             : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
                Write-Host "Block Microsoft accounts                                                         : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
                Write-Host ""
            }
        else
            {
                Write-Host "[Task : 3] Configuring Account CIS Compliance...                                   " -ForegroundColor Green -NoNewline; Write-Host "[OK]" -ForegroundColor Green
                $account0 = 'NewAdministratorName = "Administrator"'
                $account1 = 'NewGuestName = "Guest"'
                $account2 = "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\NoConnectedUser=4,3"
                $account3 = "MACHINE\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse=4,1"

                Add-Content -Path $gptFile0 -Value '[System Access]'
                Add-Content -Path $gptFile0 -Value $account0
                Add-Content -Path $gptFile0 -Value $account1

                Add-Content -Path $gptFile0 -Value '[Registry Values]'
                Add-Content -Path $gptFile0 -Value $account2
                Add-Content -Path $gptFile0 -Value $account3

                $getGPO = (Get-ADObject "CN={$($000Id)},$PathPolicy").DistinguishedName
                Set-ADObject -Identity $getGPO -Replace @{gPCMachineExtensionNames="[$pPCMachineExtensionNames]"}

                # Edit GPT.INI and update Sysvol versionNumber

                $GptContent = Get-Content $GptIni0
                $GptContent = $GptContent -replace "Version=0", "Version=7"
                Set-Content $GptIni0 $GptContent

                # Update AD versionNumber

                $VersionNumber = (Get-ADObject "CN={$($000Id)},$PathPolicy" -Properties *)
                Set-ADObject -Identity $VersionNumber -Replace @{versionNumber="7"}  
            }
    }   
}

function CIS_001_Audit (){

    $VersionNumber = (Get-ADObject "CN={$($001Id)},$PathPolicy" -Properties *)
    $VersionNumber.versionNumber | ForEach {

        if ( $VersionNumber.versionNumber -eq "4" )
            {
                Write-Host "[Task : 4] Checking if Audit CIS Compliance is configured...                          " -ForegroundColor DarkGray -NoNewline; Write-Host "[OK]" -ForegroundColor Green
                Write-Host ""
                Write-Host "Audit : "
                Write-Host "Shutdown system immediately if unable to log security audits                     : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Disabled]" -ForegroundColor Green
                Write-Host "Force audit policy subcategory settings (Windows Vista or later) to override audit policy category seeting : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
                Write-Host ""
            }
        else
            {
                Write-Host "[Task : 4] Configuring Audit CIS Compliance...                                     " -ForegroundColor Green -NoNewline; Write-Host "[OK]" -ForegroundColor Green
                $audit0 = "MACHINE\System\CurrentControlSet\Control\Lsa\CrashOnAuditFail=4,0"
                $audit1 = "MACHINE\System\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy=4,1"

                Add-Content -Path $gptFile1 -Value '[Registry Values]'
                Add-Content -Path $gptFile1 -Value $audit0
                Add-Content -Path $gptFile1 -Value $audit1
            
                $getGPO = (Get-ADObject "CN={$($001Id)},$PathPolicy").DistinguishedName
                Set-ADObject -Identity $getGPO -Replace @{gPCMachineExtensionNames="[$pPCMachineExtensionNames]"}

                # Edit GPT.INI and update Sysvol versionNumber

                $GptContent = Get-Content $GptIni1
                $GptContent = $GptContent -replace "Version=0", "Version=4"
                Set-Content $GptIni1 $GptContent

                # Update AD versionNumber

                $VersionNumber = (Get-ADObject "CN={$($001Id)},$PathPolicy" -Properties *)
                Set-ADObject -Identity $VersionNumber -Replace @{versionNumber="4"}  
            }
    } 
}

function CIS_002_Devices (){

    $VersionNumber = (Get-ADObject "CN={$($002Id)},$PathPolicy" -Properties *)
    $VersionNumber.versionNumber | ForEach {

        if ( $VersionNumber.versionNumber -eq "3" )
            {
                Write-Host "[Task : 5] Checking if Devices CIS Compliance is configured...                        " -ForegroundColor DarkGray -NoNewline; Write-Host "[OK]" -ForegroundColor Green
                Write-Host ""
                Write-Host "Devices : "
                Write-Host "Allowed to format and eject removable media                                      : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
                Write-Host "Prevent users from installing printer drivers                                    : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
                Write-Host ""
            }
        else
            {
                Write-Host "[Task : 5] Configuring Devices CIS Compliance...                                   " -ForegroundColor Green -NoNewline; Write-Host "[OK]" -ForegroundColor Green
                $device0 = 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AllocateDASD=1,"0"'
                $device1 = "MACHINE\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers\AddPrinterDrivers=4,1"

                Add-Content -Path $gptFile2 -Value '[Registry Values]'
                Add-Content -Path $gptFile2 -Value $device0
                Add-Content -Path $gptFile2 -Value $device1

                $getGPO = (Get-ADObject "CN={$($002Id)},$PathPolicy").DistinguishedName
                Set-ADObject -Identity $getGPO -Replace @{gPCMachineExtensionNames="[$pPCMachineExtensionNames]"}

                # Edit GPT.INI and update Sysvol versionNumber
                $GptContent = Get-Content $GptIni2
                $GptContent = $GptContent -replace "Version=0", "Version=3"
                Set-Content $GptIni2 $GptContent

                # Update AD versionNumber
                $VersionNumber = (Get-ADObject "CN={$($002Id)},$PathPolicy" -Properties *)
                Set-ADObject -Identity $VersionNumber -Replace @{versionNumber="3"} 
            }
    } 
}

function CIS_003_DomainController (){

    $VersionNumber = (Get-ADObject "CN={$($003Id)},$PathPolicy" -Properties *)
    $VersionNumber.versionNumber | ForEach {

        if ( $VersionNumber.versionNumber -eq "6" )
            {
                Write-Host "[Task : 6] Checking if Domain Controller CIS Compliance is configured...              " -ForegroundColor DarkGray -NoNewline; Write-Host "[OK]" -ForegroundColor Green
                Write-Host ""
                Write-Host "Domain Controller :"
                Write-Host "Allow Server operators to schedule tasks                                         : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Disabled]" -ForegroundColor Green
                Write-Host "LDAP Server singing requirements                                                 : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
                Write-Host "Refuse machine account password changes                                          : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Disabled]" -ForegroundColor Green
                Write-Host "LDAP server channel binding token requirements                                   : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
                Write-Host ""
            }
        else
            {
                Write-Host "[Task : 6] Configuring Domain Controller CIS Compliance...                         " -ForegroundColor Green -NoNewline; Write-Host "[OK]" -ForegroundColor Green
                $domain0 = "MACHINE\System\CurrentControlSet\Control\Lsa\SubmitControl=4,0"
                $domain1 = "MACHINE\System\CurrentControlSet\Services\NTDS\Parameters\LdapEnforceChannelBinding=4,2"
                $domain2 = "MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RefusePasswordChange=4,0"
                $domain3 = "MACHINE\System\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity=4,2"
           
                Add-Content -Path $gptFile3 -Value '[Registry Values]'
                Add-Content -Path $gptFile3 -Value $domain0
                Add-Content -Path $gptFile3 -Value $domain1
                Add-Content -Path $gptFile3 -Value $domain2
                Add-Content -Path $gptFile3 -Value $domain3

                $getGPO = (Get-ADObject "CN={$($003Id)},$PathPolicy").DistinguishedName
                Set-ADObject -Identity $getGPO -Replace @{gPCMachineExtensionNames="[$pPCMachineExtensionNames]"}

                # Edit GPT.INI and update Sysvol versionNumber

                $GptContent = Get-Content $GptIni3
                $GptContent = $GptContent -replace "Version=0", "Version=6"
                Set-Content $GptIni3 $GptContent

                # Update AD versionNumber

                $VersionNumberDController = (Get-ADObject "CN={$($003Id)},$PathPolicy" -Properties *)
                Set-ADObject -Identity $VersionNumberDController -Replace @{versionNumber="6"}  
            }
    } 
}

function CIS_004_DomainMember (){

    $VersionNumber = (Get-ADObject "CN={$($004Id)},$PathPolicy" -Properties *)
    $VersionNumber.versionNumber | ForEach {

        if ( $VersionNumber.versionNumber -eq "11" )
            {
                Write-Host "[Task : 7] Checking if Domain Member CIS Compliance is configured...                  " -ForegroundColor DarkGray -NoNewline; Write-Host "[OK]" -ForegroundColor Green 
                Write-Host ""
                Write-Host "Domain Member : "
                Write-Host "Digitally encrypt or sign secure channel data (alwqys)                           : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
                Write-Host "Digitally encrypt secure channel data (when possible)                            : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
                Write-Host "Digitally sign secure channel data (when possible)                               : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
                Write-Host "Disable machine account password changes                                         : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Disabled]" -ForegroundColor Green
                Write-Host "Maximum machine account password age                                             : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
                Write-Host "Require strong (Windows 2000 or later) session key                               : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
                Write-Host ""
            }
        else
            {
                Write-Host "[Task : 7] Configuring Domain Member CIS Compliance...                             " -ForegroundColor Green -NoNewline; Write-Host "[OK]" -ForegroundColor Green
                $member0 = "MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange=4,0"
                $member1 = "MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\MaximumPasswordAge=4,30"
                $member2 = "MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireSignOrSeal=4,1"
                $member3 = "MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireStrongKey=4,1"
                $member4 = "MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SealSecureChannel=4,1"
                $member5 = "MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SignSecureChannel=4,1"
           
                Add-Content -Path $gptFile4 -Value '[Registry Values]'
                Add-Content -Path $gptFile4 -Value $member0
                Add-Content -Path $gptFile4 -Value $member1
                Add-Content -Path $gptFile4 -Value $member2
                Add-Content -Path $gptFile4 -Value $member3
                Add-Content -Path $gptFile4 -Value $member4
                Add-Content -Path $gptFile4 -Value $member5

                $getGPO = (Get-ADObject "CN={$($004Id)},$PathPolicy").DistinguishedName
                Set-ADObject -Identity $getGPO -Replace @{gPCMachineExtensionNames="[$pPCMachineExtensionNames]"}

                # Edit GPT.INI and update Sysvol versionNumber

                $GptContent = Get-Content $GptIni4
                $GptContent = $GptContent -replace "Version=0", "Version=11"
                Set-Content $GptIni4 $GptContent

                # Update AD versionNumber

                $VersionNumberMember = (Get-ADObject "CN={$($004Id)},$PathPolicy" -Properties *)
                Set-ADObject -Identity $VersionNumberMember -Replace @{versionNumber="11"}   
            }
    } 
}

function CIS_005_InteractiveLogon (){

    $VersionNumber = (Get-ADObject "CN={$($005Id)},$PathPolicy" -Properties *)
    $VersionNumber.versionNumber | ForEach {

        if ( $VersionNumber.versionNumber -eq "7" )
            {
                Write-Host "[Task : 8] Checking if Interactive Logon CIS Compliance is configured...             " -ForegroundColor DarkGray -NoNewline; Write-Host "[OK]" -ForegroundColor Green
                Write-Host ""
                Write-Host "Interactive Logon : "
                Write-Host "Do not require CTRL+ALT+DEL                                                      : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Disabled]" -ForegroundColor Green
                Write-Host "Don't display last signed-in                                                     : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
                Write-Host "Prompt user to change password before expiration                                 : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
                Write-Host "Smart card removal behavior                                                      : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
                Write-Host "Machine inactivity limit                                                         : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
                Write-Host ""
            }
        else
            {
                Write-Host "[Task : 8] Configuring Interactive Logon CIS Compliance...                         " -ForegroundColor Green -NoNewline; Write-Host "[OK]" -ForegroundColor Green
                $logon0 = "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\InactivityTimeoutSecs=4,900"
                $logon1 = 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ScRemoveOption=1,"1"'
                $logon2 = "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableCAD=4,0"
                $logon3 = "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUserName=4,1"
                $logon4 = "MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\PasswordExpiryWarning=4,5"
           
                Add-Content -Path $gptFile5 -Value '[Registry Values]'
                Add-Content -Path $gptFile5 -Value $logon0
                Add-Content -Path $gptFile5 -Value $logon1
                Add-Content -Path $gptFile5 -Value $logon2
                Add-Content -Path $gptFile5 -Value $logon3
                Add-Content -Path $gptFile5 -Value $logon4

                $getGPO = (Get-ADObject "CN={$($005Id)},$PathPolicy").DistinguishedName
                Set-ADObject -Identity $getGPO -Replace @{gPCMachineExtensionNames="[$pPCMachineExtensionNames]"}

                # Edit GPT.INI and update Sysvol versionNumber

                $GptContent = Get-Content $GptIni5
                $GptContent = $GptContent -replace "Version=0", "Version=7"
                Set-Content $GptIni5 $GptContent

                # Update AD versionNumber

                $VersionNumber = (Get-ADObject "CN={$($005Id)},$PathPolicy" -Properties *)
                Set-ADObject -Identity $VersionNumber -Replace @{versionNumber="7"}
            }
    } 
}

function CIS_006_MicrosoftNetworkClient (){

    $VersionNumber = (Get-ADObject "CN={$($006Id)},$PathPolicy" -Properties *)
    $VersionNumber.versionNumber | ForEach {

        if ( $VersionNumber.versionNumber -eq "6" )
            {
                Write-Host "[Task : 9] Checking if Microsoft Network Client CIS Compliance is configured...       " -ForegroundColor DarkGray -NoNewline; Write-Host "[OK]" -ForegroundColor Green
                Write-Host ""
                Write-Host "Microsoft Network Client : "
                Write-Host "Digitally sign communications (always)                                           : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
                Write-Host "Digitally sign communications (if server agreens)                                : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
                Write-Host "Send unencrypted password to third-party SMB servers                             : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Disabled]" -ForegroundColor Green
                Write-Host ""
            }
        else
            {
                Write-Host "[Task : 9] Configuring Microsoft Network Client CIS Compliance...                  " -ForegroundColor Green -NoNewline; Write-Host "[OK]" -ForegroundColor Green
                $client0 = "MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnablePlainTextPassword=4,0"
                $client1 = "MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnableSecuritySignature=4,1"
                $client2 = "MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature=4,1"

                Add-Content -Path $gptFile6 -Value '[Registry Values]'
                Add-Content -Path $gptFile6 -Value $client0
                Add-Content -Path $gptFile6 -Value $client1
                Add-Content -Path $gptFile6 -Value $client2

                $getGPO = (Get-ADObject "CN={$($006Id)},$PathPolicy").DistinguishedName
                Set-ADObject -Identity $getGPO -Replace @{gPCMachineExtensionNames="[$pPCMachineExtensionNames]"}

                # Edit GPT.INI and update Sysvol versionNumber

                $GptContent = Get-Content $GptIni6
                $GptContent = $GptContent -replace "Version=0", "Version=6"
                Set-Content $GptIni6 $GptContent

                # Update AD versionNumber

                $VersionNumber = (Get-ADObject "CN={$($006Id)},$PathPolicy" -Properties *)
                Set-ADObject -Identity $VersionNumber -Replace @{versionNumber="6"}  
            }
    } 
}

function CIS_007_MicrosoftNetworkServer (){

    $VersionNumber = (Get-ADObject "CN={$($007Id)},$PathPolicy" -Properties *)
    $VersionNumber.versionNumber | ForEach {

        if ( $VersionNumber.versionNumber -eq "6" )
            {
                Write-Host "[Task : 10] Checking if Microsoft Network server CIS Compliance is configured...       " -ForegroundColor DarkGray -NoNewline; Write-Host "[OK]" -ForegroundColor Green
                Write-Host ""
                Write-Host "Microsoft Network Server : "
                Write-Host "Amount of idle time required before suspending session                            : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
                Write-Host "Digitally sign communications (always)                                            : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
                Write-Host "Digitally sign communications (if client agreens)                                 : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
                Write-Host "Server SPN target name validation level                                           : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
                Write-Host ""
            }
        else
            {
                Write-Host "[Task : 10] Configuring Microsoft Network server CIS Compliance...                 " -ForegroundColor Green -NoNewline; Write-Host "[OK]" -ForegroundColor Green
                $server0 = "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\AutoDisconnect=4,15"
                $server1 = "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableSecuritySignature=4,1"
                $server2 = "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature=4,1"
                $server3 = "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\SmbServerNameHardeningLevel=4,1"

                Add-Content -Path $gptFile7 -Value '[Registry Values]'
                Add-Content -Path $gptFile7 -Value $server0
                Add-Content -Path $gptFile7 -Value $server1
                Add-Content -Path $gptFile7 -Value $server2
                Add-Content -Path $gptFile7 -Value $server3

                $getGPO = (Get-ADObject "CN={$($007Id)},$PathPolicy").DistinguishedName
                Set-ADObject -Identity $getGPO -Replace @{gPCMachineExtensionNames="[$pPCMachineExtensionNames]"}

                # Edit GPT.INI and update Sysvol versionNumber

                $GptContent = Get-Content $GptIni7
                $GptContent = $GptContent -replace "Version=0", "Version=6"
                Set-Content $GptIni7 $GptContent

                # Update AD versionNumber

                $VersionNumber = (Get-ADObject "CN={$($007Id)},$PathPolicy" -Properties *)
                Set-ADObject -Identity $VersionNumber -Replace @{versionNumber="6"}  
            }
    } 
}

function CIS_008_NetworkAccess (){

    $VersionNumber = (Get-ADObject "CN={$($008Id)},$PathPolicy" -Properties *)
    $VersionNumber.versionNumber | ForEach {

        if ( $VersionNumber.versionNumber -eq "23" )
            {
                Write-Host "[Task : 11] Checking if Network Access CIS Compliance is configured...                 " -ForegroundColor DarkGray -NoNewline; Write-Host "[OK]" -ForegroundColor Green
                Write-Host ""
                Write-Host "Network Access : "
                Write-Host "Allow anonymous SID/Name translation                                              : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Disabled]" -ForegroundColor Green
                Write-Host "Do not allow anonymous enumeration of SAM accounts                                : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
                Write-Host "Do not allow anonymous enumeration of SAM accounts and shares                     : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
                Write-Host "Do not allow storage of passwords and credentials for network authentication      : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
                Write-Host "Let everyone permissions apply to anonymous users                                 : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Disabled]" -ForegroundColor Green
                Write-Host "Named pipes that can be accessed anonymously                                      : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
                Write-Host "Remotely accessible registry paths                                                : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
                Write-Host "Remotely accessible registry paths and sub-paths                                  : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
                Write-Host "Restrict anonymous access to Named Pipes and Shares                               : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
                Write-Host "Shares that can be accessed anonymously                                           : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
                Write-Host "Sharing and security model for local accounts                                     : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
                Write-Host "Restricte clients allowed to make remote calls to SAM                             : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
                Write-Host ""
            }
        else
            {
                Write-Host "[Task : 11] Configuring Network Access CIS Compliance...                           " -ForegroundColor Green -NoNewline; Write-Host "[OK]" -ForegroundColor Green
                $access0 = "LSAAnonymousNameLookup = 0"
                $access1 = 'MACHINE\System\CurrentControlSet\Control\Lsa\RestrictRemoteSAM=1,"O:BAG:BAD:(A;;RC;;;BA)"'
                $access2 = "MACHINE\System\CurrentControlSet\Control\Lsa\DisableDomainCreds=4,1"
                $access3 = "MACHINE\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous=4,0"
                $access4 = "MACHINE\System\CurrentControlSet\Control\Lsa\ForceGuest=4,0"
                $access5 = "MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymous=4,1"
                $access6 = "MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM=4,1"
                $access7 = "MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths\Machine=7,System\CurrentControlSet\Control\ProductOptions,System\CurrentControlSet\Control\Server Applications,Software\Microsoft\Windows NT\CurrentVersion"
                $access8 = "MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths\Machine=7,Software\Microsoft\Windows NT\CurrentVersion\Print,Software\Microsoft\Windows NT\CurrentVersion\Windows,System\CurrentControlSet\Control\Print\Printers,System\CurrentControlSet\Services\Eventlog,Software\Microsoft\OLAP Server,System\CurrentControlSet\Control\ContentIndex,System\CurrentControlSet\Control\Terminal Server,System\CurrentControlSet\Control\Terminal Server\UserConfig,System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration,Software\Microsoft\Windows NT\CurrentVersion\Perflib,System\CurrentControlSet\Services\SysmonLog"
                $access9 = "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionPipes=7,LLSRPC,BROWSER,netlogon,samr"
                $access10 = "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionShares=7,"
                $access11 = "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RestrictNullSessAccess=4,1"

                Add-Content -Path $gptFile8 -Value '[System Access]'
                Add-Content -Path $gptFile8 -Value $access0

                Add-Content -Path $gptFile8 -Value '[Registry Values]'
                Add-Content -Path $gptFile8 -Value $access1
                Add-Content -Path $gptFile8 -Value $access2
                Add-Content -Path $gptFile8 -Value $access3
                Add-Content -Path $gptFile8 -Value $access4
                Add-Content -Path $gptFile8 -Value $access5
                Add-Content -Path $gptFile8 -Value $access6
                Add-Content -Path $gptFile8 -Value $access7
                Add-Content -Path $gptFile8 -Value $access8
                Add-Content -Path $gptFile8 -Value $access9
                Add-Content -Path $gptFile8 -Value $access10
                Add-Content -Path $gptFile8 -Value $access11

                $getGPO = (Get-ADObject "CN={$($008Id)},$PathPolicy").DistinguishedName
                Set-ADObject -Identity $getGPO -Replace @{gPCMachineExtensionNames="[$pPCMachineExtensionNames]"}

                # Edit GPT.INI and update Sysvol versionNumber

                $GptContent = Get-Content $GptIni8
                $GptContent = $GptContent -replace "Version=0", "Version=23"
                Set-Content $GptIni8 $GptContent

                # Update AD versionNumber

                $VersionNumber = (Get-ADObject "CN={$($008Id)},$PathPolicy" -Properties *)
                Set-ADObject -Identity $VersionNumber -Replace @{versionNumber="23"}        
            }
    }    
}

function CIS_009_NetworkSecurity (){

    $VersionNumber = (Get-ADObject "CN={$($009Id)},$PathPolicy" -Properties *)
    $VersionNumber.versionNumber | ForEach {

        if ( $VersionNumber.versionNumber -eq "13" )
            {
                Write-Host "[Task : 12] Checking if Network Security CIS Compliance is configured...               " -ForegroundColor DarkGray -NoNewline; Write-Host "[OK]" -ForegroundColor Green
                Write-Host ""
                Write-Host "Network Security : "
                Write-Host "Do not store LAN Manager hash value on next password change                       : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
                Write-Host "LAN Manager authentication level                                                  : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
                Write-Host "LDAP client signing requirements                                                  : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
                Write-Host "Minimum session security for NTLM SSP based (including secure PRC) clients        : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
                Write-Host "Minimum session security for NTLM SSP based (including secure PRC) servers        : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
                Write-Host "Allow Local System to use computer identity for NTLM                              : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
                Write-Host "Allow LocalSystem Null session fallback                                           : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Disabled]" -ForegroundColor Green
                Write-Host "Allow PKU2U authentication requests to this computer to use online identities     : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Disabled]" -ForegroundColor Green
                Write-Host "Configure encryption types allowed for Kerberos                                   : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
                Write-Host ""
            }
        else
            {
                Write-Host "[Task : 12] Configuring Network Security CIS Compliance...                         " -ForegroundColor Green -NoNewline; Write-Host "[OK]" -ForegroundColor Green
                $disabledNtlm0 = "MACHINE\System\CurrentControlSet\Services\LDAP\LDAPClientIntegrity=4,1"
                $disabledNtlm1 = "MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash=4,1"
                $disabledNtlm2 = "MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinServerSec=4,537395200"
                $disabledNtlm3 = "MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinClientSec=4,537395200"
                $disabledNtlm4 = "MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel=4,5"
                $disabledNtlm5 = "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\SupportedEncryptionTypes=4,2147483640"
                $disabledNtlm6 = "MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\allownullsessionfallback=4,0"
                $disabledNtlm7 = "MACHINE\System\CurrentControlSet\Control\Lsa\pku2u\AllowOnlineID=4,0"
                $disabledNtlm8 = "MACHINE\System\CurrentControlSet\Control\Lsa\UseMachineId=4,1"

                Add-Content -Path $gptFile9 -Value '[Registry Values]'
                Add-Content -Path $gptFile9 -Value $disabledNtlm0
                Add-Content -Path $gptFile9 -Value $disabledNtlm1
                Add-Content -Path $gptFile9 -Value $disabledNtlm2
                Add-Content -Path $gptFile9 -Value $disabledNtlm3
                Add-Content -Path $gptFile9 -Value $disabledNtlm4
                Add-Content -Path $gptFile9 -Value $disabledNtlm5
                Add-Content -Path $gptFile9 -Value $disabledNtlm6
                Add-Content -Path $gptFile9 -Value $disabledNtlm7
                Add-Content -Path $gptFile9 -Value $disabledNtlm8

                $getGPO = (Get-ADObject "CN={$($009Id)},$PathPolicy").DistinguishedName
                Set-ADObject -Identity $getGPO -Replace @{gPCMachineExtensionNames="[$pPCMachineExtensionNames]"}

                # Edit GPT.INI and update Sysvol versionNumber

                $GptContent = Get-Content $GptIni9
                $GptContent = $GptContent -replace "Version=0", "Version=13"
                Set-Content $GptIni9 $GptContent

                # Update AD versionNumber

                $VersionNumberNtlm = (Get-ADObject "CN={$($009Id)},$PathPolicy" -Properties *)
                Set-ADObject -Identity $VersionNumberNtlm -Replace @{versionNumber="13"}
            }
    }      
}

function CIS_010_ShutdownSystemObjects (){

    $VersionNumber = (Get-ADObject "CN={$($010Id)},$PathPolicy" -Properties *)
    $VersionNumber.versionNumber | ForEach {

        if ( $VersionNumber.versionNumber -eq "6" )
            { 

                Write-Host "[Task : 13] Checking if Shutdown, System, and Objects CIS Compliance are configured... " -ForegroundColor DarkGray -NoNewline; Write-Host "[OK]" -ForegroundColor Green
                Write-Host ""
                Write-Host "Shutdown and System Objects : "
                Write-Host "Allow system to be shut down without having to log on                             : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Disabled]" -ForegroundColor Green
                Write-Host "Requre case insensitivity for non-Windows subsystems                              : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
                Write-Host "Strengthen default permissions of internal system objects (e.g Symbolic Links)    : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
                Write-Host ""
            }
        else
            {
                Write-Host "[Task : 13] Configuring Shutdown, System, and Objects CIS Compliance...            " -ForegroundColor Green -NoNewline; Write-Host "[OK]" -ForegroundColor Green
                $device0 = 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AllocateDASD=1,"0"'
                $device1 = "MACHINE\System\CurrentControlSet\Control\Session Manager\Kernel\ObCaseInsensitive=4,1"
                $device2 = "MACHINE\System\CurrentControlSet\Control\Session Manager\ProtectionMode=4,1"

                Add-Content -Path $gptFile10 -Value '[Registry Values]'
                Add-Content -Path $gptFile10 -Value $device0
                Add-Content -Path $gptFile10 -Value $device1
                Add-Content -Path $gptFile10 -Value $device2

                $getGPO = (Get-ADObject "CN={$($010Id)},$PathPolicy").DistinguishedName
                Set-ADObject -Identity $getGPO -Replace @{gPCMachineExtensionNames="[$pPCMachineExtensionNames]"}

                # Edit GPT.INI and update Sysvol versionNumber

                $GptContent = Get-Content $GptIni10
                $GptContent = $GptContent -replace "Version=0", "Version=6"
                Set-Content $GptIni10 $GptContent

                # Update AD versionNumber

                $VersionNumber = (Get-ADObject "CN={$($010Id)},$PathPolicy" -Properties *)
                Set-ADObject -Identity $VersionNumber -Replace @{versionNumber="6"}  
            }
    }
}

function CIS_011_UserAccountControl (){

    $VersionNumber = (Get-ADObject "CN={$($011Id)},$PathPolicy" -Properties *)
    $VersionNumber.versionNumber | ForEach {

        if ( $VersionNumber.versionNumber -eq "15" )
            {
                Write-Host "[Task : 14] Checking if User Account Control CIS Compliance is configured...           " -ForegroundColor DarkGray -NoNewline; Write-Host "[OK]" -ForegroundColor Green
                Write-Host ""
                Write-Host "User Account Control :"
                Write-Host "Admin Approval Mode for the Built-in Administrator account                        : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
                Write-Host "Behavior of the elevation prompt for administrators in Admin Approval Mode        : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
                Write-Host "Behavior of the elevation prompt for standard users                               : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
                Write-Host "Detect application installation and prompt for elevation                          : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
                Write-Host "Only elevate UIAccess applications that are installed in secure locations         : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
                Write-Host "Run all administrators in Admin Approval Mode                                     : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
                Write-Host "Switch to the secure desktop when prompting for elevation                         : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
                Write-Host "Virtualize file and registry write failure to per-user locations                  : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
                Write-Host ""
            }
        else
            {
                Write-Host "[Task : 14] Configuring User Account Control CIS Compliance...                     " -ForegroundColor Green -NoNewline; Write-Host "[OK]" -ForegroundColor Green
                $uac0 = "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin=4,2"
                $uac1 = "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser=4,3"
                $uac2 = "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection=4,1"
                $uac3 = "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA=4,1"
                $uac4 = "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths=4,1"
                $uac5 = "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization=4,1"
                $uac6 = "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken=4,1"
                $uac7 = "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop=4,1"

                Add-Content -Path $gptFile11 -Value '[Registry Values]'
                Add-Content -Path $gptFile11 -Value $uac0
                Add-Content -Path $gptFile11 -Value $uac1
                Add-Content -Path $gptFile11 -Value $uac2
                Add-Content -Path $gptFile11 -Value $uac3
                Add-Content -Path $gptFile11 -Value $uac4
                Add-Content -Path $gptFile11 -Value $uac5
                Add-Content -Path $gptFile11 -Value $uac6
                Add-Content -Path $gptFile11 -Value $uac7

                $getGPO = (Get-ADObject "CN={$($011Id)},$PathPolicy").DistinguishedName
                Set-ADObject -Identity $getGPO -Replace @{gPCMachineExtensionNames="[$pPCMachineExtensionNames]"}

                # Edit GPT.INI and update Sysvol versionNumber

                $GptContent = Get-Content $GptIni11
                $GptContent = $GptContent -replace "Version=0", "Version=15"
                Set-Content $GptIni11 $GptContent

                # Update AD versionNumber

                $VersionNumber = (Get-ADObject "CN={$($011Id)},$PathPolicy" -Properties *)
                Set-ADObject -Identity $VersionNumber -Replace @{versionNumber="15"} 
            }
    }
}

function CIS_012_DisabledSpooler (){

    $VersionNumber = (Get-ADObject "CN={$($012Id)},$PathPolicy" -Properties *)
    $VersionNumber.versionNumber | ForEach {
         
        if ( $VersionNumber.versionNumber -eq "2" )
            {
                Write-Host "[Task : 15] Checking if Spooler Service CIS Compliance is configured...                " -ForegroundColor DarkGray -NoNewline; Write-Host "[OK]" -ForegroundColor Green
                Write-Host ""
                Write-Host "Spooler Service :"
                Write-Host "Spooler Service                                                                   : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Disabled]" -ForegroundColor Green
                Write-Host ""
            }
        else
            {
                Write-Host "[Task : 15] Configuring disable spooler CIS Compliance...                          " -ForegroundColor Green -NoNewline; Write-Host "[OK]" -ForegroundColor Green
                $Spooler = '"Spooler",4,""'
        
                # Update GptTmpl.inf file
                Add-Content -Path $gptFile12 -Value '[Service General Setting]'
                Add-Content -Path $gptFile12 -Value $Spooler

                # set the gPCMachineExtension to Apply the GPO
                $getGPO = (Get-ADObject "CN={$($012Id)},$PathPolicy").DistinguishedName
                Set-ADObject -Identity $getGPO -Replace @{gPCMachineExtensionNames="[$pPCMachineExtensionNames]"} 

                # Edit GPT.INI and update Sysvol versionNumber

                $GptContent = Get-Content $GptIni12
                $GptContent = $GptContent -replace "Version=0", "Version=2"
                Set-Content $GptIni12 $GptContent

                # Update AD versionNumber

                $VersionNumberAudit = (Get-ADObject "CN={$($012Id)},$PathPolicy" -Properties *)
                Set-ADObject -Identity $VersionNumberAudit -Replace @{versionNumber="2"}
            }
    }
}        

function CIS_013_UserLogonCacheLaptop (){

    $VersionNumber = (Get-ADObject "CN={$($013Id)},$PathPolicy" -Properties *)
    $VersionNumber.versionNumber | ForEach {
         
        if ( $VersionNumber.versionNumber -eq "2" )
            {
                Write-Host "[Task : 16] Checking if User Logon Cache for Laptop CIS Compliance is configured...    " -ForegroundColor DarkGray -NoNewline; Write-Host "[OK]" -ForegroundColor Green
                Write-Host ""
                Write-Host "User Logon Cache for Laptop :"
                Write-Host "Number of previous logons to cache set to 1                                       : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
                Write-Host ""
            }
        else
            {
                Write-Host "[Task : 16] Configuring User Logon Cache for Laptops CIS Compliance...             " -ForegroundColor Green -NoNewline; Write-Host "[OK]" -ForegroundColor Green

                # Variables UserLogonCached
                $UserLogonCached1 = 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\CachedLogonsCount=1,"1"'

                # Update GptTmpl.inf file
                Add-Content -Path $gptFile13 -Value '[Registry Values]'
                Add-Content -Path $gptFile13 -Value $UserLogonCached1

                $getGPOPath = (Get-ADObject "CN={$($013Id)},$PathPolicy").DistinguishedName #-Replace @{gPCMachineExtensionNames="[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]"}  
                Set-ADObject -Identity $getGPOPath -Replace @{gPCMachineExtensionNames="[$pPCMachineExtensionNames]"}
 
                # Edit GPT.INI and update Sysvol versionNumber

                $GptContent = Get-Content $GptIni13
                $GptContent = $GptContent -replace "Version=0", "Version=2"
                Set-Content $GptIni13 $GptContent

                # Update AD versionNumber

                $VersionNumber = (Get-ADObject "CN={$($013Id)},$PathPolicy" -Properties *)
                Set-ADObject -Identity $VersionNumber -Replace @{versionNumber="2"}
            }
    }
}

function CIS_014_UserLogonCacheWorkStation (){

    $VersionNumber = (Get-ADObject "CN={$($014Id)},$PathPolicy" -Properties *)
    $VersionNumber.versionNumber | ForEach {
         
        if ( $VersionNumber.versionNumber -eq "2" )
            {
                Write-Host "[Task : 17] Checking if User Logon Cache for WorkStation CIS Compliance is configured... " -ForegroundColor DarkGray -NoNewline; Write-Host "[OK]" -ForegroundColor Green
                Write-Host ""
                Write-Host "User Logon Cache for WorkStation :"
                Write-Host "Number of previous logons to cache set to 0                                      : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
                Write-Host ""
            }
        else
            {
                Write-Host "[Task : 17] Configuring User Logon Cache for WorkStations CIS Compliance...        " -ForegroundColor Green -NoNewline; Write-Host "[OK]" -ForegroundColor Green

                # Variables UserLogonCached
                $UserLogonCached0 = 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\CachedLogonsCount=1,"0"'

                # Update GptTmpl.inf file

                Add-Content -Path $gptFile14 -Value '[Registry Values]'
                Add-Content -Path $gptFile14 -Value $UserLogonCached0

                $getGPOPath = (Get-ADObject "CN={$($014Id)},$PathPolicy").DistinguishedName
                Set-ADObject -Identity $getGPOPath -Replace @{gPCMachineExtensionNames="[$pPCMachineExtensionNames]"}

                # Edit GPT.INI and update Sysvol versionNumber

                $GptContent = Get-Content $GptIni14
                $GptContent = $GptContent -replace "Version=0", "Version=2"
                Set-Content $GptIni14 $GptContent

                # Update AD versionNumber

                $VersionNumber = (Get-ADObject "CN={$($014Id)},$PathPolicy" -Properties *)
                Set-ADObject -Identity $VersionNumber -Replace @{versionNumber="2"}

            }
    }
}

# Running functions
Write-Host "[Task : 2] Applying Security Options CIS Benchmark Compliance...                   " -ForegroundColor Green -NoNewline; Write-Host "[OK]" -ForegroundColor Green
CIS_000_Account
CIS_001_Audit
CIS_002_Devices
CIS_003_DomainController
CIS_004_DomainMember
CIS_005_InteractiveLogon
CIS_006_MicrosoftNetworkClient
CIS_007_MicrosoftNetworkServer
CIS_008_NetworkAccess
CIS_009_NetworkSecurity
CIS_010_ShutdownSystemObjects
CIS_011_UserAccountControl
CIS_012_DisabledSpooler
CIS_013_UserLogonCacheLaptop
CIS_014_UserLogonCacheWorkStation

Write-Host "[Task : 18] Successful.                                                            " -ForegroundColor Green -NoNewline; Write-Host "[OK]" -ForegroundColor Green
Write-Host ""
Get-Content .\Compliance\info.md
Write-Host"" 