Write-Host ""
Write-Host "[Task : 0] Gathering Domain Informations, Export All GPOs, and GPOs Id...                 " -ForegroundColor Green -NoNewline; Write-Host "[OK]" -ForegroundColor Green 

$DC = (Get-ADDomainController)
$Hostname = $DC.Name
$Domain = $DC.Domain

$Checks = "C:\GPOList.txt"
$CheckGPO = (Get-GPO -all | Select-Object -ExpandProperty DisplayName) | Out-File $Checks

$HardenAD = "CIS_015_DisabledUSBPorts",
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

# Template cmtx file
$Pattern = "CISTemplate"
$Template = @'
<?xml version='1.0' encoding='utf-8'?>
<policyComments xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" revision="1.0" schemaVersion="1.0" xmlns="http://www.microsoft.com/GroupPolicy/CommentDefinitions">
  <policyNamespaces>
    <using prefix="ns0" namespace="CISTemplate"></using>
  </policyNamespaces>
  <comments>
    <admTemplate></admTemplate>
  </comments>
  <resources minRequiredRevision="1.0">
    <stringTable></stringTable>
  </resources>
</policyComments>

'@

if ((Get-Content $Checks | Select-String -Pattern "CIS_015") -and
    (Get-Content $Checks | Select-String -Pattern "CIS_016") -and
    (Get-Content $Checks | Select-String -Pattern "CIS_017") -and
    (Get-Content $Checks | Select-String -Pattern "CIS_017") -and
    (Get-Content $Checks | Select-String -Pattern "CIS_019") -and
    (Get-Content $Checks | Select-String -Pattern "CIS_020") -and
    (Get-Content $Checks | Select-String -Pattern "CIS_021") -and
    (Get-Content $Checks | Select-String -Pattern "CIS_022") -and
    (Get-Content $Checks | Select-String -Pattern "CIS_023") -and
    (Get-Content $Checks | Select-String -Pattern "CIS_024") -and
    (Get-Content $Checks | Select-String -Pattern "CIS_025") -and
    (Get-Content $Checks | Select-String -Pattern "CIS_026"))  
    {

        $015Id = (Get-GPO -Name $hardenAD[0]).Id.ToString()
        $016Id = (Get-GPO -Name $hardenAD[1]).Id.ToString()
        $017Id = (Get-GPO -Name $hardenAD[2]).Id.ToString()
        $018Id = (Get-GPO -Name $hardenAD[3]).Id.ToString()
        $019Id = (Get-GPO -Name $hardenAD[4]).Id.ToString()
        $020Id = (Get-GPO -Name $hardenAD[5]).Id.ToString()
        $021Id = (Get-GPO -Name $hardenAD[6]).Id.ToString()
        $022Id = (Get-GPO -Name $hardenAD[7]).Id.ToString()
        $023Id = (Get-GPO -Name $hardenAD[8]).Id.ToString()
        $024Id = (Get-GPO -Name $hardenAD[9]).Id.ToString()
        $025Id = (Get-GPO -Name $hardenAD[10]).Id.ToString()
        $026Id = (Get-GPO -Name $hardenAD[11]).Id.ToString()
        
        # Create RegistryPolPath directory and comment.cmtx file

        if (!(Get-Content -Path "\\$Hostname\SYSVOL\$Domain\Policies\{$($015Id)}\GPT.INI" | Select-String -Pattern Version=0 ) -and
            !(Get-Content -Path "\\$Hostname\Sysvol\$Domain\Policies\{$($016Id)}\GPT.INI" | Select-String -Pattern Version=0 ) -and
            !(Get-Content -Path "\\$Hostname\Sysvol\$Domain\Policies\{$($017Id)}\GPT.INI" | Select-String -Pattern Version=0 ) -and
            !(Get-Content -Path "\\$Hostname\Sysvol\$Domain\Policies\{$($018Id)}\GPT.INI" | Select-String -Pattern Version=0 ) -and
            !(Get-Content -Path "\\$Hostname\Sysvol\$Domain\Policies\{$($019Id)}\GPT.INI" | Select-String -Pattern Version=0 ) -and
            !(Get-Content -Path "\\$Hostname\Sysvol\$Domain\Policies\{$($020Id)}\GPT.INI" | Select-String -Pattern Version=0 ) -and
            !(Get-Content -Path "\\$Hostname\Sysvol\$Domain\Policies\{$($021Id)}\GPT.INI" | Select-String -Pattern Version=0 ) -and
            !(Get-Content -Path "\\$Hostname\Sysvol\$Domain\Policies\{$($022Id)}\GPT.INI" | Select-String -Pattern Version=0 ) -and
            !(Get-Content -Path "\\$Hostname\Sysvol\$Domain\Policies\{$($023Id)}\GPT.INI" | Select-String -Pattern Version=0 ) -and
            !(Get-Content -Path "\\$Hostname\Sysvol\$Domain\Policies\{$($024Id)}\GPT.INI" | Select-String -Pattern Version=0 ) -and
            !(Get-Content -Path "\\$Hostname\Sysvol\$Domain\Policies\{$($025Id)}\GPT.INI" | Select-String -Pattern Version=0 ) -and
            !(Get-Content -Path "\\$Hostname\Sysvol\$Domain\Policies\{$($026Id)}\GPT.INI" | Select-String -Pattern Version=0 ))
            {
                Write-Host "[Task : 1] The compliance CIS Hardening already configured.                               " -ForegroundColor DarkGray -NoNewline; Write-Host "[Ok]" -ForegroundColor Green
            }
        else
            {
                Write-Host "[Task : 1] Configuring GPOs, creating RegistryPolPath directory and comment.cmtx files... " -ForegroundColor Green -NoNewline; Write-Host "[Ok]" -ForegroundColor Green
                $RegistryPolPath0 = "\\$Hostname\Sysvol\$Domain\Policies\{$($015Id)}\Machine"
                $RegistryPolPath1 = "\\$Hostname\Sysvol\$Domain\Policies\{$($016Id)}\Machine"
                $RegistryPolPath2 = "\\$Hostname\Sysvol\$Domain\Policies\{$($017Id)}\Machine"
                $RegistryPolPath3 = "\\$Hostname\Sysvol\$Domain\Policies\{$($018Id)}\Machine"
                $RegistryPolPath4 = "\\$Hostname\Sysvol\$Domain\Policies\{$($019Id)}\Machine"
                $RegistryPolPath5 = "\\$Hostname\Sysvol\$Domain\Policies\{$($020Id)}\Machine"
                $RegistryPolPath6 = "\\$Hostname\Sysvol\$Domain\Policies\{$($021Id)}\Machine"
                $RegistryPolPath7 = "\\$Hostname\Sysvol\$Domain\Policies\{$($022Id)}\Machine"
                $RegistryPolPath8 = "\\$Hostname\Sysvol\$Domain\Policies\{$($023Id)}\Machine"
                $RegistryPolPath9 = "\\$Hostname\Sysvol\$Domain\Policies\{$($024Id)}\Machine"
                $RegistryPolPath10 = "\\$Hostname\Sysvol\$Domain\Policies\{$($025Id)}\Machine"
                $RegistryPolPath11 = "\\$Hostname\Sysvol\$Domain\Policies\{$($026Id)}\Machine"
        
                $Template | Out-File "$RegistryPolPath0\comment.cmtx" -Encoding utf8; $Cmtxfile015 = "$RegistryPolPath0\comment.cmtx"
                $Template | Out-File "$RegistryPolPath1\comment.cmtx" -Encoding utf8; $Cmtxfile016 = "$RegistryPolPath1\comment.cmtx"
                $Template | Out-File "$RegistryPolPath2\comment.cmtx" -Encoding utf8; $Cmtxfile017 = "$RegistryPolPath2\comment.cmtx"
                $Template | Out-File "$RegistryPolPath3\comment.cmtx" -Encoding utf8; $Cmtxfile018 = "$RegistryPolPath3\comment.cmtx"
                $Template | Out-File "$RegistryPolPath4\comment.cmtx" -Encoding utf8; $Cmtxfile019 = "$RegistryPolPath4\comment.cmtx"
                $Template | Out-File "$RegistryPolPath5\comment.cmtx" -Encoding utf8; $Cmtxfile020 = "$RegistryPolPath5\comment.cmtx"
                $Template | Out-File "$RegistryPolPath6\comment.cmtx" -Encoding utf8; $Cmtxfile021 = "$RegistryPolPath6\comment.cmtx"
                $Template | Out-File "$RegistryPolPath7\comment.cmtx" -Encoding utf8; $Cmtxfile022 = "$RegistryPolPath7\comment.cmtx"
                $Template | Out-File "$RegistryPolPath8\comment.cmtx" -Encoding utf8; $Cmtxfile023 = "$RegistryPolPath8\comment.cmtx"
                $Template | Out-File "$RegistryPolPath9\comment.cmtx" -Encoding utf8; $Cmtxfile024 = "$RegistryPolPath9\comment.cmtx"
                $Template | Out-File "$RegistryPolPath10\comment.cmtx" -Encoding utf8; $Cmtxfile025 = "$RegistryPolPath10\comment.cmtx"
                $Template | Out-File "$RegistryPolPath11\comment.cmtx" -Encoding utf8; $Cmtxfile026 = "$RegistryPolPath11\comment.cmtx"
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


$PathPolicy = (Get-ADObject -Filter 'Name -eq "Policies"' -Properties * | Where-Object ObjectClass -eq container | Select-Object Name, distinguishedName).DistinguishedName    
#$pPCMachineExtensionNames = "{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}"

function CIS_015_DisabledUSBPorts (){
   
   $VersionNumber = (Get-ADObject "CN={$($015Id)},$PathPolicy" -Properties *)
   $VersionNumber.versionNumber | ForEach {

     if ( $VersionNumber.versionNumber -eq "1" )
        {
            Write-Host "[Task : 3] Removoble Staorage Access CIS Compliance already configured. " -ForegroundColor DarkGray -NoNewline; Write-Host "[OK]" -ForegroundColor Green
            Write-Host ""
            Write-Host "Removoble Staorage Access : "
            Write-Host "All Removable Storage classes Deny all access                         : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
            Write-Host ""                          
        }
     else 
        {        
            Write-Host "[Task : 3] Configuring CIS Compliance Removoble Storage Access...   " -ForegroundColor Green -NoNewline; Write-Host "[OK]" -ForegroundColor Green
            $015Name = (Get-GPO -Name $HardenAD[0] | Select-Object -ExpandProperty DisplayName)
        
            # Modify content to comment.cmtx file
            #$Pattern = "CISTemplate"
            $PatternReplace = "Microsoft.Policies.RemovableStorageAccess"

            $Content = Get-Content $Cmtxfile015
            $Content = $Content -replace $Pattern, $PatternReplace
            Set-Content $Cmtxfile015 $Content
        
            $Params = @{
               Key = "Software\Policies\Microsoft\Windows\RemovableStorageDevices"
               ValueName = "Deny_All"
               Type = "DWORD"
               Value = 00000001
            }

            $StdOut = Set-GPRegistryValue -Name $015Name -Key "HKLM\$($Params.Key)" -ValueName $Params.ValueName -Type $Params.Type -Value $Params.Value
        }
   }

}

function CIS_016_WinRemoteShell (){
   
   $VersionNumber = (Get-ADObject "CN={$($016Id)},$PathPolicy" -Properties *)
   $VersionNumber.versionNumber | ForEach {

     if ( $VersionNumber.versionNumber -eq "1" )
        {
            Write-Host "[Task : 4] Windows Remote Shell CIS Compliance already configured. " -ForegroundColor DarkGray -NoNewline; Write-Host "[OK]" -ForegroundColor Green
            Write-Host ""
            Write-Host "Windows Remote Shell :"
            Write-Host "Allow Remote Shell Access                                        : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Disabled]" -ForegroundColor Green
            Write-Host ""                          
        }
     else 
        {
            Write-Host "[Task : 4] Configuring CIS Compliance Windows Remote Shell...       " -ForegroundColor Green -NoNewline; Write-Host "[OK]" -ForegroundColor Green
            $016Name = (Get-GPO -Name $HardenAD[1] | Select-Object -ExpandProperty DisplayName)
            # Modify content to comment.cmtx file
            #$Pattern = "CISTemplate"
            $PatternReplace = "Microsoft.Policies.WindowsRemoteShell"

            $Content = Get-Content $Cmtxfile016
            $Content = $Content -replace $Pattern, $PatternReplace
            Set-Content $Cmtxfile016 $Content
        
            $Params = @{
               Key = "Software\Policies\Microsoft\Windows\WinRM\Service\WinRS"
               ValueName = "AllowRemoteShellAccess"
               Type = "DWORD"
               Value = 00000000
            }
            
            $StdOut = Set-GPRegistryValue -Name $016Name -Key "HKLM\$($Params.Key)" -ValueName $Params.ValueName -Type $Params.Type -Value $Params.Value
        }
   }

}

function CIS_017_WinRM (){
   
   $VersionNumber = (Get-ADObject "CN={$($017Id)},$PathPolicy" -Properties *)
   $VersionNumber.versionNumber | ForEach {

     if ( $VersionNumber.versionNumber -eq "7" )
        {
            Write-Host "[Task : 5] WinRM Client and Service CIS Compliance already configured. " -ForegroundColor DarkGray -NoNewline; Write-Host "[OK]" -ForegroundColor Green
            Write-Host ""
            Write-Host "WinRM Client and Server :"
            Write-Host "Allow Basic authentication                                       : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Disabled]" -ForegroundColor Green
            Write-Host "All unencrypted traffic                                          : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Disabled]" -ForegroundColor Green
            Write-Host "Disallow Digest authentication                                   : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
            Write-Host "Allow Basic authentication                                       : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Disabled]" -ForegroundColor Green
            Write-Host "Allow remote server management through WinRM                     : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Disabled]" -ForegroundColor Green
            Write-Host "All unencrypted traffic                                          : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Disabled]" -ForegroundColor Green
            Write-Host "Disallow WinRM from storing RunAs credentials                    : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green   
            Write-Host ""                          
        }
     else 
        {
        
            Write-Host "[Task : 5] Configuring CIS Compliance WinRM Client and Service...   " -ForegroundColor Green -NoNewline; Write-Host "[OK]" -ForegroundColor Green
            $017Name = (Get-GPO -Name $HardenAD[2] | Select-Object -ExpandProperty DisplayName)
            
            # Modify content to comment.cmtx file
            #$Pattern = "CISTemplate"
            $PatternReplace = "Microsoft.Policies.WindowsRemoteManagement"

            $Content = Get-Content $Cmtxfile017
            $Content = $Content -replace $Pattern, $PatternReplace
            Set-Content $Cmtxfile017 $Content

            $Params = @{
               Key = "Software\Policies\Microsoft\Windows\WinRM\Client"
               Key0 = "Software\Policies\Microsoft\Windows\WinRM\Service"
               ValueName = "AllowBasic"
               ValueName0 = "AllowUnencryptedTraffic"
               ValueName1 = "AllowDigest"
               ValueName2 = "AllowAutoConfig"
               ValueName4 = "DisableRunAs"
               Type = "DWORD"
               Value = 00000000
               Value0 = 00000001
            }
            
            $StdOut = Set-GPRegistryValue -Name $017Name -Key "HKLM\$($Params.Key)" -ValueName $Params.ValueName -Type $Params.Type -Value $Params.Value
            $StdOut = Set-GPRegistryValue -Name $017Name -Key "HKLM\$($Params.Key)" -ValueName $Params.ValueName0 -Type $Params.Type -Value $Params.Value
            $StdOut = Set-GPRegistryValue -Name $017Name -Key "HKLM\$($Params.Key)" -ValueName $Params.ValueName1 -Type $Params.Type -Value $Params.Value
            $StdOut = Set-GPRegistryValue -Name $017Name -Key "HKLM\$($Params.Key0)" -ValueName $Params.ValueName -Type $Params.Type -Value $Params.Value
            $StdOut = Set-GPRegistryValue -Name $017Name -Key "HKLM\$($Params.Key0)" -ValueName $Params.ValueName2 -Type $Params.Type -Value $Params.Value
            $StdOut = Set-GPRegistryValue -Name $017Name -Key "HKLM\$($Params.Key0)" -ValueName $Params.ValueName0 -Type $Params.Type -Value $Params.Value
            $StdOut = Set-GPRegistryValue -Name $017Name -Key "HKLM\$($Params.Key0)" -ValueName $Params.ValueName4 -Type $Params.Type -Value $Params.Value0
        }

   }

}

function CIS_018_RemoteProcedureCall (){
   
   $VersionNumber = (Get-ADObject "CN={$($018Id)},$PathPolicy" -Properties *)
   $VersionNumber.versionNumber | ForEach {

     if ( $VersionNumber.versionNumber -eq "2" )
        {
            Write-Host "[Task : 6] Remote Procedure Call CIS Compliance already configured. " -ForegroundColor DarkGray -NoNewline; Write-Host "[OK]" -ForegroundColor Green
            Write-Host ""
            Write-Host "Remote Procedure Call :"
            Write-Host "Enable RPC Endpoint Mapper Client Authentication                  : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
            Write-Host "Restrict unauthenticated RPC clients                              : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
            Write-Host ""                          
        }
     else 
        {
        
            Write-Host "[Task : 6] Configuring CIS Compliance Remote Procedure Call...      " -ForegroundColor Green -NoNewline; Write-Host "[OK]" -ForegroundColor Green
            $018Name = (Get-GPO -Name $HardenAD[3] | Select-Object -ExpandProperty DisplayName)
        
            # Modify content to comment.cmtx file
        
            #$Pattern = "CISTemplate"
            $PatternReplace = "Microsoft.Policies.RemoteProcedureCalls"

            $Content = Get-Content $Cmtxfile018
            $Content = $Content -replace $Pattern, $PatternReplace
            Set-Content $Cmtxfile018 $Content
        
            $Params = @{
               Key = "Software\Policies\Microsoft\Windows NT\Rpc"
               ValueName = "EnableAuthEpResolution"
               ValueName0 = "RestrictRemoteClients"
               Type = "DWORD"
               Value = 00000001
            }

            $StdOut = Set-GPRegistryValue -Name $018Name -Key "HKLM\$($Params.Key)" -ValueName $Params.ValueName -Type $Params.Type -Value $Params.Value
            $StdOut = Set-GPRegistryValue -Name $018Name -Key "HKLM\$($Params.Key)" -ValueName $Params.ValueName0 -Type $Params.Type -Value $Params.Value
    
        }
   }

}

function CIS_019_RemoteAssistance (){
   
   $VersionNumber = (Get-ADObject "CN={$($019Id)},$PathPolicy" -Properties *)
   $VersionNumber.versionNumber | ForEach {

     if ( $VersionNumber.versionNumber -eq "2" )
        {
            Write-Host "[Task : 7] Remote Assistance CIS Compliance already configured.    " -ForegroundColor DarkGray -NoNewline; Write-Host "[OK]" -ForegroundColor Green
            Write-Host ""
            Write-Host "Remote Assistance :"
            Write-Host "Configure Offer Remote Assistance                                : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Disabled]" -ForegroundColor Green
            Write-Host "Configure Solicited Remote Assistance                            : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Disabled]" -ForegroundColor Green
            Write-Host ""                          
        }
     else 
        {
        
            Write-Host "[Task : 7] Configuring CIS Compliance Remote Assistance...          " -ForegroundColor Green -NoNewline; Write-Host "[OK]" -ForegroundColor Green
            $019Name = (Get-GPO -Name $HardenAD[4] | Select-Object -ExpandProperty DisplayName)
        
            # Modify content to comment.cmtx file
            #$Pattern = "CISTemplate"
            $PatternReplace = "Microsoft.Policies.RemoteAssistance"

            $Content = Get-Content $Cmtxfile019
            $Content = $Content -replace $Pattern, $PatternReplace
            Set-Content $Cmtxfile019 $Content

            $Params = @{
               Key = "Software\policies\Microsoft\Windows NT\Terminal Services"
               ValueName = "fAllowUnsolicited"
               ValueName1 = "fAllowToGetHelp"
               Type = "DWORD"
               Value = 00000000
            }
        
            $StdOut = Set-GPRegistryValue -Name $019Name -Key "HKLM\$($Params.Key)" -ValueName $Params.ValueName -Type $Params.Type -Value $Params.Value
            $StdOut = Set-GPRegistryValue -Name $019Name -Key "HKLM\$($Params.Key)" -ValueName $Params.ValueName1 -Type $Params.Type -Value $Params.Value     
        }
   }

}

function CIS_020_RemoteDesktopService (){
   
   $VersionNumber = (Get-ADObject "CN={$($020Id)},$PathPolicy" -Properties *)
   $VersionNumber.versionNumber | ForEach {

     if ( $VersionNumber.versionNumber -eq "15" )
        {
            Write-Host "[Task : 8] Remote Desktop Service CIS Compliance already configured.                         " -ForegroundColor DarkGray -NoNewline; Write-Host "[OK]" -ForegroundColor Green
            Write-Host ""
            Write-Host "Remote Desktop Service :"
            Write-Host "Do not allow passwords to be saved                                                         : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
            Write-Host "Restrict Remote Desktop Services users to a single Remote Desktop Services session         : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
            Write-Host "Do not allow COM port redirection                                                          : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
            Write-Host "Do not allow drive redirection                                                             : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
            Write-Host "Do not allow LPT redirection                                                               : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
            Write-Host "Do not allow supported Plug and Play device redirection                                    : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
            Write-Host "Always prompt for password upon connection                                                 : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
            Write-Host "Require secure PRC communication                                                           : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
            Write-Host "Require use of specific security layer for remote (RDP) connections                        : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
            Write-Host "Require user authentification for remote connections by using Network Level Authentication : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
            Write-Host "Set client connection encryption level                                                     : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
            Write-Host "Set time limit for active but idle Remote desktop services sessions                        : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
            Write-Host "Set time limit for disconnected sessions                                                   : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
            Write-Host "Do not delete temp folders upon exit                                                       : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Disabled]" -ForegroundColor Green
            Write-Host "Do not use temporary folders per session                                                   : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Disabled]" -ForegroundColor Green
            Write-Host ""                          
        }
     else 
        {
        
            Write-Host "[Task : 8] Configuring CIS Compliance Remote Desktop Service...     " -ForegroundColor Green -NoNewline; Write-Host "[OK]" -ForegroundColor Green
            $020Name = (Get-GPO -Name $HardenAD[5] | Select-Object -ExpandProperty DisplayName)
        
            # Modify content to comment.cmtx file
            #$Pattern = "CISTemplate"
            $PatternReplace = "Microsoft.Policies.TerminalServer"

            $Content = Get-Content $Cmtxfile020
            $Content = $Content -replace $Pattern, $PatternReplace
            Set-Content $Cmtxfile020 $Content

        
            $Params = @{
               Key = "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
               ValueName = "DisablePasswordSaving"
               ValueName1 = "fSingleSessionPerUser"
               ValueName2 = "fDisableCcm"
               ValueName3 = "fDisableCdm"
               ValueName4 = "fDisableLPT"
               ValueName5 = "fDisablePNPRedir"
               ValueName6 = "fPromptForPassword"
               ValueName7 = "fEncryptRPCTraffic"
               ValueName8 = "SecurityLayer"
               ValueName9 = "UserAuthentication"
               ValueName10 = "MinEncryptionLevel"
               ValueName11 = "MaxIdleTime"
               ValueName12 = "MaxDisconnectionTime"
               ValueName13 = "DeleteTempDirsOnExit"
               ValueName14 = "PerSessionTempDir"
               Type = "DWORD"
               Value = 00000001
               Value8 = 00000002
               Value10 = 00000003
               Value11 = 900000
               Value12 = 60000
            }
        
            $StdOut = Set-GPRegistryValue -Name $020Name -Key "HKLM\$($Params.Key)" -ValueName $Params.ValueName -Type $Params.Type -Value $Params.Value
            $StdOut = Set-GPRegistryValue -Name $020Name -Key "HKLM\$($Params.Key)" -ValueName $Params.ValueName1 -Type $Params.Type -Value $Params.Value
            $StdOut = Set-GPRegistryValue -Name $020Name -Key "HKLM\$($Params.Key)" -ValueName $Params.ValueName2 -Type $Params.Type -Value $Params.Value
            $StdOut = Set-GPRegistryValue -Name $020Name -Key "HKLM\$($Params.Key)" -ValueName $Params.ValueName3 -Type $Params.Type -Value $Params.Value
            $StdOut = Set-GPRegistryValue -Name $020Name -Key "HKLM\$($Params.Key)" -ValueName $Params.ValueName4 -Type $Params.Type -Value $Params.Value
            $StdOut = Set-GPRegistryValue -Name $020Name -Key "HKLM\$($Params.Key)" -ValueName $Params.ValueName5 -Type $Params.Type -Value $Params.Value
            $StdOut = Set-GPRegistryValue -Name $020Name -Key "HKLM\$($Params.Key)" -ValueName $Params.ValueName6 -Type $Params.Type -Value $Params.Value
            $StdOut = Set-GPRegistryValue -Name $020Name -Key "HKLM\$($Params.Key)" -ValueName $Params.ValueName7 -Type $Params.Type -Value $Params.Value
            $StdOut = Set-GPRegistryValue -Name $020Name -Key "HKLM\$($Params.Key)" -ValueName $Params.ValueName8 -Type $Params.Type -Value $Params.Value8
            $StdOut = Set-GPRegistryValue -Name $020Name -Key "HKLM\$($Params.Key)" -ValueName $Params.ValueName9 -Type $Params.Type -Value $Params.Value
            $StdOut = Set-GPRegistryValue -Name $020Name -Key "HKLM\$($Params.Key)" -ValueName $Params.ValueName10 -Type $Params.Type -Value $Params.Value10
            $StdOut = Set-GPRegistryValue -Name $020Name -Key "HKLM\$($Params.Key)" -ValueName $Params.ValueName11 -Type $Params.Type -Value $Params.Value11
            $StdOut = Set-GPRegistryValue -Name $020Name -Key "HKLM\$($Params.Key)" -ValueName $Params.ValueName12 -Type $Params.Type -Value $Params.Value12
            $StdOut = Set-GPRegistryValue -Name $020Name -Key "HKLM\$($Params.Key)" -ValueName $Params.ValueName13 -Type $Params.Type -Value $Params.Value
            $StdOut = Set-GPRegistryValue -Name $020Name -Key "HKLM\$($Params.Key)" -ValueName $Params.ValueName14 -Type $Params.Type -Value $Params.Value
        }
   }

}

function CIS_021_TimeProvider (){
   
   $VersionNumber = (Get-ADObject "CN={$($021Id)},$PathPolicy" -Properties *)
   $VersionNumber.versionNumber | ForEach {

     if ( $VersionNumber.versionNumber -eq "2" )
        {
            Write-Host "[Task : 9] Time Provider CIS Compliance already configured.        " -ForegroundColor DarkGray -NoNewline; Write-Host "[OK]" -ForegroundColor Green
            Write-Host ""
            Write-Host "Time Provider :"
            Write-Host "Enable Windows NTP Client                                        : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
            Write-Host "Enable Windows NTP Server                                        : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Disabled]" -ForegroundColor Green
            Write-Host ""         

                 
        }
     else 
        {
        
            Write-Host "[Task : 9] Configuring CIS Compliance Time Provider...              " -ForegroundColor Green -NoNewline; Write-Host "[OK]" -ForegroundColor Green
            $021Name = (Get-GPO -Name $HardenAD[6] | Select-Object -ExpandProperty DisplayName)
        
            # Modify content to comment.cmtx file
            #$Pattern = "CISTemplate"        
            $PatternReplace = "Microsoft.Policies.WindowsTimeService"

            $Content = Get-Content $Cmtxfile021
            $Content = $Content -replace $Pattern, $PatternReplace
            Set-Content $Cmtxfile021 $Content
        

            $Params = @{
               Key = "Software\Policies\Microsoft\W32time\TimeProviders\NtpClient"
               Key1 = "Software\Policies\Microsoft\W32time\TimeProviders\NtpServer"
               ValueName = "Enabled"
               Type = "DWORD"
               Value = 00000001
               Value1 = 00000000
            }
        
            $StdOut = Set-GPRegistryValue -Name $021Name -Key "HKLM\$($Params.Key)" -ValueName $Params.ValueName -Type $Params.Type -Value $Params.Value
            $StdOut = Set-GPRegistryValue -Name $021Name -Key "HKLM\$($Params.Key1)" -ValueName $Params.ValueName -Type $Params.Type -Value $Params.Value1
        }
   }

}

function CIS_022_DisabledAutoRun (){
   
   $VersionNumber = (Get-ADObject "CN={$($022Id)},$PathPolicy" -Properties *)
   $VersionNumber.versionNumber | ForEach {

     if ( $VersionNumber.versionNumber -eq "3" )
        {
            Write-Host "[Task : 10] AutoPaly policy CIS Compliance already configured.      " -ForegroundColor DarkGray -NoNewline; Write-Host "[OK]" -ForegroundColor Green
            Write-Host ""
            Write-Host "AutoPaly policy :"
            Write-Host "Disallow Autoplay for non-volume devices                          : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
            Write-Host "set the default behavior for AutoRun                              : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
            Write-Host "Turn off Autoplay                                                 : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
            Write-Host ""                          
        }
     else 
        {
        
            Write-Host "[Task : 10] Configuring CIS Compliance AutoPaly policy...           " -ForegroundColor Green -NoNewline; Write-Host "[OK]" -ForegroundColor Green
            $022Name = (Get-GPO -Name $HardenAD[7] | Select-Object -ExpandProperty DisplayName)
        
            # Modify content to comment.cmtx file
            #$Pattern = "CISTemplate"        
            $PatternReplace = "Microsoft.Policies.AutoPlay"

            $Content = Get-Content $Cmtxfile022
            $Content = $Content -replace $Pattern, $PatternReplace
            Set-Content $Cmtxfile022 $Content
        
            $Params = @{
               Key = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
               ValueName = "NoAutorun"
               Type = "DWORD"
               Value = 00000001

               ValueName2 = "NoDriveTypeAutoRun"
               Value2 = 255
               Key1 = "Software\Policies\Microsoft\Windows\Explorer"
               ValueName1 = "NoAutoplayfornonVolume"
            }
        
            $StdOut = Set-GPRegistryValue -Name $022Name -Key "HKLM\$($Params.Key)" -ValueName $Params.ValueName -Type $Params.Type -Value $Params.Value
            $StdOut = Set-GPRegistryValue -Name $022Name -Key "HKLM\$($Params.Key)" -ValueName $Params.ValueName2 -Type $Params.Type -Value $Params.Value2 # Modify
            $StdOut = Set-GPRegistryValue -Name $022Name -Key "HKLM\$($Params.Key1)" -ValueName $Params.ValueName1 -Type $Params.Type -Value $Params.Value
        }
   }

}

function CIS_023_PowerSleepSettings (){
   
   $VersionNumber = (Get-ADObject "CN={$($023Id)},$PathPolicy" -Properties *)
   $VersionNumber.versionNumber | ForEach {

     if ( $VersionNumber.versionNumber -eq "4" )
        {
            Write-Host "[Task : 11] Sleep Settings CIS Compliance already configured.       " -ForegroundColor DarkGray -NoNewline; Write-Host "[OK]" -ForegroundColor Green
            Write-Host ""
            Write-Host "Sleep Settings :"
            Write-Host "Allow network connectivity during connected-standby (on battery)  : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Disabled]" -ForegroundColor Green
            Write-Host "Allow network connectivity during connected-standby (plugged in)  : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Disabled]" -ForegroundColor Green
            Write-Host "Require a password when a computer wakes (on battery)             : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
            Write-Host "Require a password when a computer wakes (plugged in)             : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
            Write-Host ""                          
        }
     else 
        {
        
            Write-Host "[Task : 11] Configuring CIS Compliance Sleep Settings...            " -ForegroundColor Green -NoNewline; Write-Host "[OK]" -ForegroundColor Green
            $023Name = (Get-GPO -Name $HardenAD[8] | Select-Object -ExpandProperty DisplayName)
        
            # Modify content to comment.cmtx file
            #$Pattern = "CISTemplate"        
            $PatternReplace = "Microsoft.Policies.PowerManagement"

            $Content = Get-Content $Cmtxfile023
            $Content = $Content -replace $Pattern, $PatternReplace
            Set-Content $Cmtxfile023 $Content
        

            $Params = @{
               Key = "Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51"
               ValueName = "ACSettingIndex"
               Type = "DWORD"
               Value = 00000001
            
               Key1 = "Software\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9"
               ValueName1 = "DCSettingIndex"
               Value1 = 00000000
            }
        
            $StdOut = Set-GPRegistryValue -Name $023Name -Key "HKLM\$($Params.Key)" -ValueName $Params.ValueName -Type $Params.Type -Value $Params.Value
            $StdOut = Set-GPRegistryValue -Name $023Name -Key "HKLM\$($Params.Key)" -ValueName $Params.ValueName1 -Type $Params.Type -Value $Params.Value
            $StdOut = Set-GPRegistryValue -Name $023Name -Key "HKLM\$($Params.Key1)" -ValueName $Params.ValueName1 -Type $Params.Type -Value $Params.Value1        
            $StdOut = Set-GPRegistryValue -Name $023Name -Key "HKLM\$($Params.Key1)" -ValueName $Params.ValueName -Type $Params.Type -Value $Params.Value1
        }
   }

}

function CIS_024_DeviceGuard (){
   
   $VersionNumber = (Get-ADObject "CN={$($024Id)},$PathPolicy" -Properties *)
   $VersionNumber.versionNumber | ForEach {

     if ( $VersionNumber.versionNumber -eq "6" )
        {
            Write-Host "[Task : 12] Device Guard CIS Compliance already configured.         " -ForegroundColor DarkGray -NoNewline; Write-Host "[OK]" -ForegroundColor Green
            Write-Host ""
            Write-Host "Device Guard :"
            Write-Host "Turn On Virtualization Based Security                             : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
            Write-Host "Select Platform Securty Level                                     : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
            Write-Host "Virtualization Based Protection of Code Integrity                 : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
            Write-Host "Require UEFI Memory Attributes Table                              : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
            Write-Host "Credential Guard Configuration                                    : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Disabled]" -ForegroundColor Green
            Write-Host "Secure Launch Configuration                                       : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
            Write-Host ""                          
        }
     else 
        {
        
            Write-Host "[Task : 12] Configuring CIS Compliance Device Guard...              " -ForegroundColor Green -NoNewline; Write-Host "[OK]" -ForegroundColor Green
            $024Name = (Get-GPO -Name $HardenAD[9] | Select-Object -ExpandProperty DisplayName)
        
            # Modify content to comment.cmtx file
            #$Pattern = "CISTemplate"        
            $PatternReplace = "Microsoft.Windows.DeviceGuard"

            $Content = Get-Content $Cmtxfile024
            $Content = $Content -replace $Pattern, $PatternReplace
            Set-Content $Cmtxfile024 $Content

            $Params = @{
               Key = "SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
               ValueName = "EnableVirtualizationBasedSecurity"
               ValueName1 = "RequirePlatformSecurityFeatures"
               ValueName2 = "HypervisorEnforcedCodeIntegrity"
               ValueName3 = "HVCIMATRequired"
               ValueName4 = "LsaCfgFlags"
               ValueName5 = "ConfigureSystemGuardLaunch"
               Type = "DWORD"
               Value = 00000001
               Value4 = 00000000
               Value2 = 00000003
            }

        
            $StdOut = Set-GPRegistryValue -Name $024Name -Key "HKLM\$($Params.Key)" -ValueName $Params.ValueName -Type $Params.Type -Value $Params.Value
            $StdOut = Set-GPRegistryValue -Name $024Name -Key "HKLM\$($Params.Key)" -ValueName $Params.ValueName1 -Type $Params.Type -Value $Params.Value2
            $StdOut = Set-GPRegistryValue -Name $024Name -Key "HKLM\$($Params.Key)" -ValueName $Params.ValueName2 -Type $Params.Type -Value $Params.Value
            $StdOut = Set-GPRegistryValue -Name $024Name -Key "HKLM\$($Params.Key)" -ValueName $Params.ValueName3 -Type $Params.Type -Value $Params.Value
            $StdOut = Set-GPRegistryValue -Name $024Name -Key "HKLM\$($Params.Key)" -ValueName $Params.ValueName4 -Type $Params.Type -Value $Params.Value4
            $StdOut = Set-GPRegistryValue -Name $024Name -Key "HKLM\$($Params.Key)" -ValueName $Params.ValueName5 -Type $Params.Type -Value $Params.Value
        }
   }

}

function CIS_025_CredentialsDelegation (){
   
   $VersionNumber = (Get-ADObject "CN={$($025Id)},$PathPolicy" -Properties *)
   $VersionNumber.versionNumber | ForEach {

     if ( $VersionNumber.versionNumber -eq "2" )
        {
            Write-Host "[Task : 13] Credentials Delegation CIS Compliance already configured. " -ForegroundColor DarkGray -NoNewline; Write-Host "[OK]" -ForegroundColor Green
            Write-Host ""
            Write-Host "Credentials Delegation :"
            Write-Host "Encryption Oracle Remediation                                     : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
            Write-Host "Remote host allows delegation of non-exportable credentials       : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
            Write-Host ""                          
        }
     else 
        {
        
            Write-Host "[Task : 13] Configuring CIS Compliance Credentials Delegation...    " -ForegroundColor Green -NoNewline; Write-Host "[OK]" -ForegroundColor Green
            $025Name = (Get-GPO -Name $HardenAD[10] | Select-Object -ExpandProperty DisplayName)
        
            # Modify content to comment.cmtx file
            #$Pattern = "CISTemplate"        
            $PatternReplace = "Microsoft.Policies.CredentialsSSP"

            $Content = Get-Content $Cmtxfile025
            $Content = $Content -replace $Pattern, $PatternReplace
            Set-Content $Cmtxfile025 $Content
        
            $Params = @{
               Key = "Software\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters"
               ValueName = "AllowEncryptionOracle"
               Type = "DWORD"
               Value = 00000000

               Key1 = "Software\Policies\Microsoft\Windows\CredentialsDelegation"
               ValueName1 = "AllowProtectedCreds"
               Type1 = "DWORD"
               Value1 = 00000001
            }
        
            $StdOut = Set-GPRegistryValue -Name $025Name -Key "HKLM\$($Params.Key)" -ValueName $Params.ValueName -Type $Params.Type -Value $Params.Value
            $StdOut = Set-GPRegistryValue -Name $025Name -Key "HKLM\$($Params.Key1)" -ValueName $Params.ValueName1 -Type $Params.Type1 -Value $Params.Value1
        }
   }

}

function CIS_026_DisabledWinStore (){
   
   $VersionNumber = (Get-ADObject "CN={$($026Id)},$PathPolicy" -Properties *)
   $VersionNumber.versionNumber | ForEach {

     if ( $VersionNumber.versionNumber -eq "4" )
        {
            Write-Host "[Task : 14] Windows Store CIS Compliance already configured.        " -ForegroundColor DarkGray -NoNewline; Write-Host "[OK]" -ForegroundColor Green
            Write-Host ""
            Write-Host "Windows Store :"
            Write-Host "Disable all apps from Microsoft Store                             : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
            Write-Host "Only display the private store within the Microsoft Store         : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
            Write-Host "Turn off Automatic Download and Install of updates                : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Disabled]" -ForegroundColor Green
            Write-Host "Turn off the offer to update to the latest version of Windows     : " -ForegroundColor DarkGray -NoNewline; Write-Host "[Enabled]" -ForegroundColor Green
            Write-Host ""                          
        }
     else 
        {
        
            Write-Host "[Task : 14] Configuring CIS Compliance Windows Store...             " -ForegroundColor Green -NoNewline; Write-Host "[OK]" -ForegroundColor Green
            $026Name = (Get-GPO -Name $HardenAD[11] | Select-Object -ExpandProperty DisplayName)
            
            # Copy SecGuide to Localhost
            $Admx = "\PolicyDefinitions"
            $Adml = "\PolicyDefinitions\en-US"
            $Path = $env:windir
            $PathAdmx = "$Path\$Admx"
            $PathAdml = "$Path\$Adml"

            if(-not(Test-Path -Path $PathAdmx\SecGuide.amdx.)){
               
               Copy-Item -Path .\Compliance\SecGuide\SecGuide.admx -Destination $PathAdmx
               Copy-Item -Path .\Compliance\SecGuide\SecGuide.adml -Destination $PathAdml
            }

            # Modify content to comment.cmtx file
            #$Pattern = "CISTemplate"
            $PatternReplace = "Microsoft.Policies.WindowsStore"

            $Content = Get-Content $Cmtxfile026
            $Content = $Content -replace $Pattern, $PatternReplace
            Set-Content $Cmtxfile026 $Content

            $Params = @{
               Key = "Software\Policies\Microsoft\WindowsStore"
               ValueName = "DisableStoreApps"
               ValueName1 = "DisableOSUpgrade"
               ValueName2 = "AutoDownload"
               ValueName3 =  "RequirePrivateStoreOnly"
               Type = "DWORD"
               Value = 00000000
               Value1 = 00000001
               Value2 = 00000004
            }

            $StdOut = Set-GPRegistryValue -Name $026Name -Key "HKLM\$($Params.Key)" -ValueName $Params.ValueName -Type $Params.Type -Value $Params.Value
            $StdOut = Set-GPRegistryValue -Name $026Name -Key "HKLM\$($Params.Key)" -ValueName $Params.ValueName1 -Type $Params.Type -Value $Params.Value1
            $StdOut = Set-GPRegistryValue -Name $026Name -Key "HKLM\$($Params.Key)" -ValueName $Params.ValueName2 -Type $Params.Type -Value $Params.Value2
            $StdOut = Set-GPRegistryValue -Name $026Name -Key "HKLM\$($Params.Key)" -ValueName $Params.ValueName3 -Type $Params.Type -Value $Params.Value1
        }
   }

}
# Running functions
Write-Host "[Task : 2] Applying Hardening CIS Benchmark Compliance...                                 " -ForegroundColor Green -NoNewline; Write-Host "[OK]" -ForegroundColor Green

CIS_015_DisabledUSBPorts
CIS_016_WinRemoteShell
CIS_017_WinRM
CIS_018_RemoteProcedureCall
CIS_019_RemoteAssistance
CIS_020_RemoteDesktopService
CIS_021_TimeProvider
CIS_022_DisabledAutoRun
CIS_023_PowerSleepSettings
CIS_024_DeviceGuard
CIS_025_CredentialsDelegation
CIS_026_DisabledWinStore

Write-Host "[Task 15 :] Successful.                                                                   " -ForegroundColor Green -NoNewline; Write-Host "[Ok]" -ForegroundColor Green
Write-Host ""
Get-Content .\Compliance\info.md
Write-Host"" 