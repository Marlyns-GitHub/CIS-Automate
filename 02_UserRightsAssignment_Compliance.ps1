Write-Host ""
Write-Host "[Task : 0] Gathering Domain Informations, Security Group Ids, Default Domain Controllers policy Id...          " -ForegroundColor Green -NoNewline; Write-Host "[OK]" -ForegroundColor Green 

$DC = (Get-ADDomainController)
$Hostname = $DC.Name
$Domain = $DC.Domain
$DomainName = (Get-ADDomain).NetBIOSName
$FQDNDomainName = (Get-ADDomain).DnsRoot
$DomainSid = (Get-ADDomain).DomainSid.Value

$EveryoneSid = (Get-WMIObject -Class 'Win32_Account' -Filter 'name="Everyone"').Sid
$ServiceSid = (Get-WMIObject -Class 'Win32_Account' -Filter 'name="SERVICE"').Sid
$EnterpriseDCSid = (Get-WMIObject -Class 'Win32_Account' -Filter 'name="ENTERPRISE DOMAIN CONTROLLERS"').Sid
$AuthUserSid = (Get-WMIObject -Class 'Win32_Account' -Filter 'name="Authenticated Users"').Sid
$LocalSrvSid = (Get-WMIObject -Class 'Win32_Account' -Filter 'name="LOCAL SERVICE"').Sid
$NetworkSrvSid = (Get-WMIObject -Class 'Win32_Account' -Filter 'name="NETWORK SERVICE"').Sid
$WindowsMgrGroupSid = "S-1-5-90-0" # Windows Manager\Windows Manager Group
$DefaultAppPoolSid = "S-1-5-82-3006700770-424185619-1745488364-794895919-4004696415"  # IIS APPPOOL\DefaultAppPool
$WdiServiceHostSid = "S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420" # NT SERVICE\WdiServiceHost

$DASid = (Get-ADGroup -Filter "SID -eq ""$DomainSid-512""").SID.Value    # Domain Admins
$AdminsSid = (Get-ADGroup -Filter "SID -eq ""S-1-5-32-544""").SID.Value  # Administrators
$GuestsSid = (Get-ADGroup -Filter "SID -eq ""S-1-5-32-546""").SID.Value  # Guests
$AccountSid = (Get-ADGroup -Filter "SID -eq ""S-1-5-32-548""").SID.Value # Account Operators
$ServerSid = (Get-ADGroup -Filter "SID -eq ""S-1-5-32-549""").SID.Value  # Server Operators
$PrintSid = (Get-ADGroup -Filter "SID -eq ""S-1-5-32-550""").SID.Value   # Print Operators
$BackupSid = (Get-ADGroup -Filter "SID -eq ""S-1-5-32-551""").SID.Value  # Backoup Operators
$PreWinSid = (Get-ADGroup -Filter "SID -eq ""S-1-5-32-554""").SID.Value  # Pre-Windows 2000
$PerfLogSid = (Get-ADGroup -Filter "SID -eq ""S-1-5-32-559""").SID.Value # Performance Log Users

$DefaultGPO = "Default Domain Policy",
              "Default Domain Controllers Policy"


foreach ( $GPO in $DefaultGPO ){
    
    if ($GPO -eq $DefaultGPO[1]){
        
       $001Id = (Get-GPO -Name $DefaultGPO[1]).Id.ToString()
       $PathDomainCtrlPolicy = Get-Item "\\$Hostname\Sysvol\$Domain\Policies\{$($001Id)}\Machine\Microsoft\Windows NT\SecEdit"
       $GptTmplPath = "$PathDomainCtrlPolicy\GptTmpl.inf"
       $GptIniPath = "\\$Hostname\Sysvol\$Domain\Policies\{$($001Id)}\GPT.INI"
    }
}

$PathPolicy = (Get-ADObject -Filter 'Name -eq "Policies"' -Properties * | Where-Object ObjectClass -eq container | Select-Object Name, distinguishedName).DistinguishedName    
$VersionNumber = (Get-ADObject "CN={$($001Id)},$PathPolicy" -Properties *)
$VersionNumber.versionNumber | ForEach {

       $InitialVNumber = $VersionNumber.versionNumber
       $NewVersionNumber = 34
       $ResultVNumber = [int]"$InitialVNumber" + [int]"$NewVersionNumber"

    if ( $VersionNumber.versionNumber -eq "1" )
        {
            
            Write-Host "[Task : 1] Checking if Version Number doesn't modified, if not deploy CIS User Rights Assignment compliance... " -ForegroundColor Green -NoNewline; Write-Host "[OK]" -ForegroundColor Green 
            #Write-Host "Your DC Policy doesn't been modified, you need to deploy Compliance" -ForegroundColor Green
            function Default_Domain_controllers_policy 
                {
     
                    $Backup = "^SeBackupPrivilege.*"
                    $BatchLogonRight = "^SeBatchLogonRight.*"
                    $InteractiveLogonRight = "^SeInteractiveLogonRight.*"
                    $LoadDriver = "^SeLoadDriverPrivilege.*"
                    $MachineAccount = "^SeMachineAccountPrivilege.*"
                    $NetworkLogonRight = "^SeNetworkLogonRight.*"
                    $RemoteShutdown = "^SeRemoteShutdownPrivilege.*"
                    $Restore = "^SeRestorePrivilege.*"
                    $Shutdown = "^SeShutdownPrivilege.*"
                    $SystemTime = "^SeSystemTimePrivilege.*"

                    # Change Compliance CIS Benchmark

                    $URABackup = "SeBackupPrivilege = *$AdminsSid"
                    $URABatchlogonRight = "SeBatchLogonRight = *$BackupSid,*$AdminsSid"
                    $URAInteractiveLogonRight = "SeInteractiveLogonRight = *$BackupSid,*$AdminsSid"
                    $URALoadDriver = "SeLoadDriverPrivilege = *$AdminsSid"
                    $URAMachineAccount = "SeMachineAccountPrivilege = *$DASid"
                    $URANetworkLogonRight = "SeNetworkLogonRight = *$EnterpriseDCSid,*$AuthUserSid,*$AdminsSid"
                    $URARemoteShutdown = "SeRemoteShutdownPrivilege = *$AdminsSid"
                    $URARestore = "SeRestorePrivilege = *$AdminsSid"
                    $URAShutdown = "SeShutdownPrivilege = *$AdminsSid"
                    $URASystemTime = "SeSystemTimePrivilege = *$AdminsSid,*$LocalSrvSid"
          
                    # Add those lines after this pattern SeEnableDelegationPrivilege
                    $URARemoteInteractiveLogonRight = "SeRemoteInteractiveLogonRight = *$AdminsSid"
                    $URATimeZone = "SeTimeZonePrivilege = *$LocalSrvSid,*$AdminsSid"
                    $URACreateGlobal = "SeCreateGlobalPrivilege = *$ServiceSid,*$NetworkSrvSid,*$LocalSrvSid,*$AdminsSid"
                    $URACreateSymbolic = "SeCreateSymbolicLinkPrivilege = *$AdminsSid"
                    $URADenyNetLogonRight = "SeDenyNetworkLogonRight = *$GuestsSid"
                    $URADenyBatchLogonRight = "SeDenyBatchLogonRight = *$GuestsSid"
                    $URADenyServiceLogonRight = "SeDenyServiceLogonRight = *$GuestsSid"
                    $URADenyInteractiveLogonRight = "SeDenyInteractiveLogonRight = *$GuestsSid"
                    $URADenyRemoteInteractiveLogonRight = "SeDenyRemoteInteractiveLogonRight = *$GuestsSid"
                    $URAImpersonate = "SeImpersonatePrivilege = *$ServiceSid,*$NetworkSrvSid,*$LocalSrvSid,*$AdminsSid"
                    $URAIncreaseWorking = "SeIncreaseWorkingSetPrivilege = *$AdminsSid"
                    $URAMangeVolume = "SeManageVolumePrivilege = *$AdminsSid"
          
                    function Backup (){
                        $DCContent = Get-Content $GptTmplPath
                        $URA1 = $DCContent -replace $Backup, $URABackup
                        Set-Content $GptTmplPath $URA1
                    }
                    Backup

                    function BatchLogon (){
                        $DCContent = Get-Content $GptTmplPath
                        $URA2 = $DCContent -replace $BatchLogonRight, $URABatchLogonRight
                        Set-Content $GptTmplPath $URA2
                    }
                    BatchLogon         

                    function InteractiveLogon (){
                        $DCContent = Get-Content $GptTmplPath
                        $URA3 = $DCContent -replace $InteractiveLogonRight, $URAInteractiveLogonRight
                        Set-Content $GptTmplPath $URA3
                    }
                    InteractiveLogon

                    function LoadDriver (){
                        $DCContent = Get-Content $GptTmplPath
                        $URA4 = $DCContent -replace $LoadDriver, $URALoadDriver
                        Set-Content $GptTmplPath $URA4
                    }
                    LoadDriver

                    function MachineAccount (){
                        $DCContent = Get-Content $GptTmplPath
                        $URA5 = $DCContent -replace $MachineAccount, $URAMachineAccount
                        Set-Content $GptTmplPath $URA5
                    }
                    MachineAccount

                    function NetworkLogon (){
                        $DCContent = Get-Content $GptTmplPath
                        $URA6 = $DCContent -replace $NetworkLogonRight, $URANetworkLogonRight
                        Set-Content $GptTmplPath $URA6
                    }
                    NetworkLogon

                    function RemoteShutdown (){
                        $DCContent = Get-Content $GptTmplPath
                        $URA7 = $DCContent -replace $RemoteShutdown, $URARemoteShutdown
                        Set-Content $GptTmplPath $URA7
                    }
                    RemoteShutdown

                    function Restore (){
                        $DCContent = Get-Content $GptTmplPath
                        $URA8 = $DCContent -replace $Restore, $URARestore
                        Set-Content $GptTmplPath $URA8
                    }
                    Restore

                    function Shutdown (){
                        $DCContent = Get-Content $GptTmplPath
                        $URA9 = $DCContent -replace $Shutdown, $URAShutdown
                        Set-Content $GptTmplPath $URA9
                    }
                    Shutdown

                    function SystemTime (){
                        $DCContent = Get-Content $GptTmplPath
                        $URA10 = $DCContent -replace $SystemTime, $URASystemTime
                        Set-Content $GptTmplPath $URA10
                    }
                    SystemTime

                    #Add New line after a Pattern LockoutBadCount and Registy Values
                    $GptTmplPathVars = Get-Content $GptTmplPath | ForEach-Object {
     
                        $_
                        if ($_ -match "SeEnableDelegationPrivilege")
                            {
                                $URARemoteInteractiveLogonRight
                                $URATimeZone
                                $URACreateGlobal
                                $URACreateSymbolic
                                $URADenyNetLogonRight
                                $URADenyBatchLogonRight
                                $URADenyServiceLogonRight
                                $URADenyInteractiveLogonRight
                                $URADenyRemoteInteractiveLogonRight
                                $URAImpersonate
                                $URAIncreaseWorking
                                $URAMangeVolume
                            }
                    } 

                    $GptTmplPathVars > $GptTmplPath

                    # Edit GPT.INI and update Sysvol versionNumber
                    Write-Host "[Task : 3] Updating VersionNumber of the Default Domain Controllers policy...                                  " -ForegroundColor Green -NoNewline; Write-Host "[OK]" -ForegroundColor Green 
                
                    $DCGptContent = Get-Content $GptIniPath
                    $DCGptContent = $DCGptContent -replace "Version=1", "Version=35"
                    Set-Content $GptIniPath $DCGptContent

                    # Update AD versionNumber

                    $VersionNumber = (Get-ADObject "CN={$($001Id)},$PathPolicy" -Properties *)
                    Set-ADObject -Identity $VersionNumber -Replace @{versionNumber="35"}

                    # Change the attribute ms-DS-MachineAccountQuota
                    Write-Host "[Task : 4] Changing the value of the attribute ms-DS-MachineAccountQuota set to 0...                           " -ForegroundColor Green -NoNewline; Write-Host "[OK]" -ForegroundColor Green 
                
                    Set-ADDomain -Identity $FQDNDomainName -Replace @{"ms-DS-MachineAccountQuota"="0"}
                }

                # Launch the functions
                Write-Host "[Task : 2] Applying User Rights Assignemnt CIS Benchmark Compliance...                                        " -ForegroundColor Green -NoNewline; Write-Host "[OK]" -ForegroundColor Green
                Default_Domain_controllers_policy
                $command = gpupdate /force

                Write-Host "[Task : 5] Successful.                                                                                        " -ForegroundColor Green -NoNewline; Write-Host "[OK]" -ForegroundColor Green           
                Write-Host ""
                Get-Content .\Compliance\info.md
                Write-Host ""
        }

    elseif ( $VersionNumber.versionNumber -eq "35" )
        
        {
              $Pattern = "SeNetworkLogonRight",
                         "SeInteractiveLogonRight",
                         "SeRemoteInteractiveLogonRight",
                         "SeBatchLogonRight",
                         "SeMachineAccountPrivilege",
                         "SeDenyNetworkLogonRight",
                         "SeDenyBatchLogonRight",
                         "SeDenyServiceLogonRight",
                         "SeDenyInteractiveLogonRight",
                         "SeDenyRemoteInteractiveLogonRight"
                         
              Write-Host "[Task : 1] User Rights Assignment CIS Compliance already configured.                                           " -ForegroundColor DarkGray -NoNewline; Write-Host "[Ok]" -ForegroundColor Green
              $CheckContent = Get-Content $GptTmplPath
              $Content = $CheckContent | Select-String $Pattern
              
              Write-Host "" 
              $AdminsSid = (Get-ADGroup -Filter "SID -eq ""S-1-5-32-544""").Name  # Administrators
              $GuestsSid = (Get-ADGroup -Filter "SID -eq ""S-1-5-32-546""").Name  # Guests
              $BackupSid = (Get-ADGroup -Filter "SID -eq ""S-1-5-32-551""").Name  # Backoup Operators
              $DASid = (Get-ADGroup -Filter "SID -eq ""$DomainSid-512""").Name    # Domain Admins
              $EnterpriseDCSid = (Get-WMIObject -Class 'Win32_Account' -Filter 'name="ENTERPRISE DOMAIN CONTROLLERS"').Name
              $AuthUserSid = (Get-WMIObject -Class 'Win32_Account' -Filter 'name="Authenticated Users"').Name

              Write-Host "Allow og on as a batch job                    : " -ForegroundColor DarkGray -NoNewline; Write-Host $BackupSid,$AdminsSid -ForegroundColor DarkGray
              Write-Host "Allow log on locally                          : " -ForegroundColor DarkGray -NoNewline; Write-Host $BackupSid,$AdminsSid -ForegroundColor DarkGray 
              Write-Host "Add workstations to domain                    : " -ForegroundColor DarkGray -NoNewline; Write-Host $DASid -ForegroundColor DarkGray
              Write-Host "Access this computer from the network         : " -ForegroundColor DarkGray -NoNewline; Write-Host $EnterpriseDCSid,$AuthUserSid,$AdminsSid -ForegroundColor DarkGray
              Write-Host "Allow log on through Remote Desktop Services  : " -ForegroundColor DarkGray -NoNewline; Write-Host $AdminsSid -ForegroundColor DarkGray
              Write-Host "Deny log on locally                           : " -ForegroundColor DarkGray -NoNewline; Write-Host $GuestsSid -ForegroundColor DarkGray
              Write-Host "Deny log on as a service                      : " -ForegroundColor DarkGray -NoNewline; Write-Host $GuestsSid -ForegroundColor DarkGray
              Write-Host "Deny log on as a batch job                    : " -ForegroundColor DarkGray -NoNewline; Write-Host $GuestsSid -ForegroundColor DarkGray
              Write-Host "Deny log on through Remote Desktop Services   : " -ForegroundColor DarkGray -NoNewline; Write-Host $GuestsSid -ForegroundColor DarkGray
              Write-Host "Deny access to this computer from the network : " -ForegroundColor DarkGray -NoNewline; Write-Host $GuestsSid -ForegroundColor DarkGray
              Write-Host "Attribute ms-DS-MachineAccountQuota is set to : " -ForegroundColor DarkGray -NoNewline; Write-Host "0" -ForegroundColor DarkGray  
              Write-Host ""
              Get-Content .\Compliance\info.md
              Write-Host ""
              
        }
        

    elseif ( $VersionNumber.versionNumber -eq $ResultVNumber )            
        {
              Write-Host "[Task : 1] User Rights Assignment CIS Compliance already configured.                                           " -ForegroundColor DarkGray -NoNewline; Write-Host "[Ok]" -ForegroundColor Green

              $Pattern = "SeNetworkLogonRight",
                         "SeInteractiveLogonRight",
                         "SeRemoteInteractiveLogonRight",
                         "SeBatchLogonRight",
                         "SeMachineAccountPrivilege",
                         "SeDenyNetworkLogonRight",
                         "SeDenyBatchLogonRight",
                         "SeDenyServiceLogonRight",
                         "SeDenyInteractiveLogonRight",
                         "SeDenyRemoteInteractiveLogonRight"
                         
              #Write-Host "User Right Assignment Compliance has deployied" -ForegroundColor Green
              $CheckContent = Get-Content $GptTmplPath
              $Content = $CheckContent | Select-String $Pattern

              Write-Host "" 
              $AdminsSid = (Get-ADGroup -Filter "SID -eq ""S-1-5-32-544""").Name  # Administrators
              $GuestsSid = (Get-ADGroup -Filter "SID -eq ""S-1-5-32-546""").Name  # Guests
              $BackupSid = (Get-ADGroup -Filter "SID -eq ""S-1-5-32-551""").Name  # Backoup Operators
              $DASid = (Get-ADGroup -Filter "SID -eq ""$DomainSid-512""").Name    # Domain Admins
              $EnterpriseDCSid = (Get-WMIObject -Class 'Win32_Account' -Filter 'name="ENTERPRISE DOMAIN CONTROLLERS"').Name
              $AuthUserSid = (Get-WMIObject -Class 'Win32_Account' -Filter 'name="Authenticated Users"').Name

              Write-Host "Allow og on as a batch job                    : " -ForegroundColor DarkGray -NoNewline; Write-Host $BackupSid,$AdminsSid -ForegroundColor DarkGray
              Write-Host "Allow log on locally                          : " -ForegroundColor DarkGray -NoNewline; Write-Host $BackupSid,$AdminsSid -ForegroundColor DarkGray 
              Write-Host "Add workstations to domain                    : " -ForegroundColor DarkGray -NoNewline; Write-Host $DASid -ForegroundColor DarkGray
              Write-Host "Access this computer from the network         : " -ForegroundColor DarkGray -NoNewline; Write-Host $EnterpriseDCSid,$AuthUserSid,$AdminsSid -ForegroundColor DarkGray
              Write-Host "Allow log on through Remote Desktop Services  : " -ForegroundColor DarkGray -NoNewline; Write-Host $AdminsSid -ForegroundColor DarkGray
              Write-Host "Deny log on locally                           : " -ForegroundColor DarkGray -NoNewline; Write-Host $GuestsSid -ForegroundColor DarkGray
              Write-Host "Deny log on as a service                      : " -ForegroundColor DarkGray -NoNewline; Write-Host $GuestsSid -ForegroundColor DarkGray
              Write-Host "Deny log on as a batch job                    : " -ForegroundColor DarkGray -NoNewline; Write-Host $GuestsSid -ForegroundColor DarkGray
              Write-Host "Deny log on through Remote Desktop Services   : " -ForegroundColor DarkGray -NoNewline; Write-Host $GuestsSid -ForegroundColor DarkGray
              Write-Host "Deny access to this computer from the network : " -ForegroundColor DarkGray -NoNewline; Write-Host $GuestsSid -ForegroundColor DarkGray
              Write-Host "Attribute ms-DS-MachineAccountQuota is set to : " -ForegroundColor DarkGray -NoNewline; Write-Host "0" -ForegroundColor DarkGray                          
              Write-Host ""
              Get-Content .\Compliance\info.md
              Write-Host ""
              
        }
        
    else
        {
            Write-Host "[Task : 1] Checking if Version Number doesn't modified, if not deploy CIS User Rights Assignment compliance... " -ForegroundColor Green -NoNewline; Write-Host "[OK]" -ForegroundColor Green 
            #Write-Host "Your DC Policy doesn't been modified, you need to deploy Compliance" -ForegroundColor Green
            function Default_Domain_controllers_policy 
                {
     
                    $Backup = "^SeBackupPrivilege.*"
                    $BatchLogonRight = "^SeBatchLogonRight.*"
                    $InteractiveLogonRight = "^SeInteractiveLogonRight.*"
                    $LoadDriver = "^SeLoadDriverPrivilege.*"
                    $MachineAccount = "^SeMachineAccountPrivilege.*"
                    $NetworkLogonRight = "^SeNetworkLogonRight.*"
                    $RemoteShutdown = "^SeRemoteShutdownPrivilege.*"
                    $Restore = "^SeRestorePrivilege.*"
                    $Shutdown = "^SeShutdownPrivilege.*"
                    $SystemTime = "^SeSystemTimePrivilege.*"

                    # Change Compliance CIS Benchmark

                    $URABackup = "SeBackupPrivilege = *$AdminsSid"
                    $URABatchlogonRight = "SeBatchLogonRight = *$BackupSid,*$AdminsSid"
                    $URAInteractiveLogonRight = "SeInteractiveLogonRight = *$BackupSid,*$AdminsSid"
                    $URALoadDriver = "SeLoadDriverPrivilege = *$AdminsSid"
                    $URAMachineAccount = "SeMachineAccountPrivilege = *$DASid"
                    $URANetworkLogonRight = "SeNetworkLogonRight = *$EnterpriseDCSid,*$AuthUserSid,*$AdminsSid"
                    $URARemoteShutdown = "SeRemoteShutdownPrivilege = *$AdminsSid"
                    $URARestore = "SeRestorePrivilege = *$AdminsSid"
                    $URAShutdown = "SeShutdownPrivilege = *$AdminsSid"
                    $URASystemTime = "SeSystemTimePrivilege = *$AdminsSid,*$LocalSrvSid"
          
                    # Add those lines after this pattern SeEnableDelegationPrivilege
                    $URARemoteInteractiveLogonRight = "SeRemoteInteractiveLogonRight = *$AdminsSid"
                    $URATimeZone = "SeTimeZonePrivilege = *$LocalSrvSid,*$AdminsSid"
                    $URACreateGlobal = "SeCreateGlobalPrivilege = *$ServiceSid,*$NetworkSrvSid,*$LocalSrvSid,*$AdminsSid"
                    $URACreateSymbolic = "SeCreateSymbolicLinkPrivilege = *$AdminsSid"
                    $URADenyNetLogonRight = "SeDenyNetworkLogonRight = *$GuestsSid"
                    $URADenyBatchLogonRight = "SeDenyBatchLogonRight = *$GuestsSid"
                    $URADenyServiceLogonRight = "SeDenyServiceLogonRight = *$GuestsSid"
                    $URADenyInteractiveLogonRight = "SeDenyInteractiveLogonRight = *$GuestsSid"
                    $URADenyRemoteInteractiveLogonRight = "SeDenyRemoteInteractiveLogonRight = *$GuestsSid"
                    $URAImpersonate = "SeImpersonatePrivilege = *$ServiceSid,*$NetworkSrvSid,*$LocalSrvSid,*$AdminsSid"
                    $URAIncreaseWorking = "SeIncreaseWorkingSetPrivilege = *$AdminsSid"
                    $URAMangeVolume = "SeManageVolumePrivilege = *$AdminsSid"
          
                    function Backup (){
                        $DCContent = Get-Content $GptTmplPath
                        $URA1 = $DCContent -replace $Backup, $URABackup
                        Set-Content $GptTmplPath $URA1
                    }
                    Backup

                    function BatchLogon (){
                        $DCContent = Get-Content $GptTmplPath
                        $URA2 = $DCContent -replace $BatchLogonRight, $URABatchLogonRight
                        Set-Content $GptTmplPath $URA2
                    }
                    BatchLogon         

                    function InteractiveLogon (){
                        $DCContent = Get-Content $GptTmplPath
                        $URA3 = $DCContent -replace $InteractiveLogonRight, $URAInteractiveLogonRight
                        Set-Content $GptTmplPath $URA3
                    }
                    InteractiveLogon

                    function LoadDriver (){
                        $DCContent = Get-Content $GptTmplPath
                        $URA4 = $DCContent -replace $LoadDriver, $URALoadDriver
                        Set-Content $GptTmplPath $URA4
                    }
                    LoadDriver

                    function MachineAccount (){
                        $DCContent = Get-Content $GptTmplPath
                        $URA5 = $DCContent -replace $MachineAccount, $URAMachineAccount
                        Set-Content $GptTmplPath $URA5
                    }
                    MachineAccount

                    function NetworkLogon (){
                        $DCContent = Get-Content $GptTmplPath
                        $URA6 = $DCContent -replace $NetworkLogonRight, $URANetworkLogonRight
                        Set-Content $GptTmplPath $URA6
                    }
                    NetworkLogon

                    function RemoteShutdown (){
                        $DCContent = Get-Content $GptTmplPath
                        $URA7 = $DCContent -replace $RemoteShutdown, $URARemoteShutdown
                        Set-Content $GptTmplPath $URA7
                    }
                    RemoteShutdown

                    function Restore (){
                        $DCContent = Get-Content $GptTmplPath
                        $URA8 = $DCContent -replace $Restore, $URARestore
                        Set-Content $GptTmplPath $URA8
                    }
                    Restore

                    function Shutdown (){
                        $DCContent = Get-Content $GptTmplPath
                        $URA9 = $DCContent -replace $Shutdown, $URAShutdown
                        Set-Content $GptTmplPath $URA9
                    }
                    Shutdown

                    function SystemTime (){
                        $DCContent = Get-Content $GptTmplPath
                        $URA10 = $DCContent -replace $SystemTime, $URASystemTime
                        Set-Content $GptTmplPath $URA10
                    }
                    SystemTime

                    #Add New line after a Pattern LockoutBadCount and Registy Values
                    $GptTmplPathVars = Get-Content $GptTmplPath | ForEach-Object {
     
                        $_
                        if ($_ -match "SeEnableDelegationPrivilege")
                            {
                                $URARemoteInteractiveLogonRight
                                $URATimeZone
                                $URACreateGlobal
                                $URACreateSymbolic
                                $URADenyNetLogonRight
                                $URADenyBatchLogonRight
                                $URADenyServiceLogonRight
                                $URADenyInteractiveLogonRight
                                $URADenyRemoteInteractiveLogonRight
                                $URAImpersonate
                                $URAIncreaseWorking
                                $URAMangeVolume
                            }
                    } 

                    $GptTmplPathVars > $GptTmplPath

                    # Edit GPT.INI and update Sysvol versionNumber
                    Write-Host "[Task : 3] Updating VersionNumber of the Default Domain Controllers policy...                                  " -ForegroundColor Green -NoNewline; Write-Host "[OK]" -ForegroundColor Green 
                
                    $DCGptContent = Get-Content $GptIniPath
                    $DCGptContent = $DCGptContent -replace "Version=$InitialVNumber", "Version=$ResultVNumber"
                    Set-Content $GptIniPath $DCGptContent

                    # Update AD versionNumber

                    $VersionNumber = (Get-ADObject "CN={$($001Id)},$PathPolicy" -Properties *)
                    Set-ADObject -Identity $VersionNumber -Replace @{versionNumber="$ResultVNumber"}

                    # Change the attribute ms-DS-MachineAccountQuota
                    Write-Host "[Task : 4] Changing the value of the attribute ms-DS-MachineAccountQuota set to 0...                           " -ForegroundColor Green -NoNewline; Write-Host "[OK]" -ForegroundColor Green 
                
                    Set-ADDomain -Identity $FQDNDomainName -Replace @{"ms-DS-MachineAccountQuota"="0"}
                }

                # Launch the functions
                Write-Host "[Task : 2] Applying User Rights Assignemnt CIS Benchmark Compliance...                                      " -ForegroundColor Green -NoNewline; Write-Host "[OK]" -ForegroundColor Green
                Default_Domain_controllers_policy
                $command = gpupdate /force

                Write-Host "[Task : 5] Successful.                                                                                      " -ForegroundColor Green -NoNewline; Write-Host "[OK]" -ForegroundColor Green
                Write-Host ""
                Get-Content .\Compliance\info.md
                Write-Host "" 
        }
}