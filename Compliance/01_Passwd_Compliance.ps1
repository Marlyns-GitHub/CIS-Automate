Write-Host ""
Write-Host "[Task : 0] Gathering Domain Informations, Default Domain policies GPOs, and GPOs Id...           " -ForegroundColor Green -NoNewline; Write-Host "[OK]" -ForegroundColor Green 

$DC = (Get-ADDomainController)
$Hostname = $DC.Name
$Domain = $DC.Domain


$DefaultGPO = "Default Domain Policy",
              "Default Domain Controllers Policy"


foreach ( $GPO in $DefaultGPO ){
    
    if ($GPO -eq $DefaultGPO[0]){
        
       $000Id = (Get-GPO -Name $DefaultGPO[0]).Id.ToString()
       $PathDomainPolicy = Get-Item "\\$Hostname\Sysvol\$Domain\Policies\{$($000Id)}\Machine\Microsoft\Windows NT\SecEdit"
       $GptTmplPath = "$PathDomainPolicy\GptTmpl.inf"
       $GptIniPath = "\\$Hostname\Sysvol\$Domain\Policies\{$($000Id)}\GPT.INI"
    }
}

$PathPolicy = (Get-ADObject -Filter 'Name -eq "Policies"' -Properties * | Where-Object ObjectClass -eq container | Select-Object Name, distinguishedName).DistinguishedName    
$VersionNumber = (Get-ADObject "CN={$($000Id)},$PathPolicy" -Properties *)
$VersionNumber.versionNumber | ForEach {

       $InitialVNumber = $VersionNumber.versionNumber
       $NewVersionNumber = 11
       $ResultVNumber = [int]"$InitialVNumber" + [int]"$NewVersionNumber"

    if ( $VersionNumber.versionNumber -eq "3" )
        {
            Write-Host "[Task : 1] Checking if Version Number doesn't modified, if not deploy CIS Password compliance... " -ForegroundColor Green -NoNewline; Write-Host "[OK]" -ForegroundColor Green 
            
         function Default_Domain_policy 
            {
                function LockOut ()
                    {
                        $DContent = Get-Content $GptTmplPath
                        $LockOutBad = $DContent -replace "LockoutBadCount = 0", "LockoutBadCount = 5"
                        Set-Content $GptTmplPath $LockOutBad
                    }
                LockOut

                function MinPwd ()
                    {                  
                        $DContent = Get-Content $GptTmplPath
                        $MinPwdLength = $DContent -replace "MinimumPasswordLength = 7", "MinimumPasswordLength = 14"
                        Set-Content $GptTmplPath $MinPwdLength
                    }
                MinPwd

                function MaxPwd ()
                    {
                        $DContent = Get-Content $GptTmplPath
                        $MaxPwdAge = $DContent -replace "MaximumPasswordAge = 42", "MaximumPasswordAge = 60"
                        Set-Content $GptTmplPath $MaxPwdAge
                    }
                MaxPwd

                $MinPwdLengthAudit = "MACHINE\System\CurrentControlSet\Control\SAM\MinimumPasswordLengthAudit=4,14"
                $ResetLockOut = "ResetLockoutCount = 30"
                $LockOutDuration = "LockoutDuration = 30"

                #Add New line after a Pattern LockoutBadCount and Registy Values
                $GptTmplPathVars = Get-Content $GptTmplPath | ForEach-Object {
                    
                    $_
                    if ($_ -match "LockoutBadCount")
                        {
                            $ResetLockOut
                            $LockOutDuration
                        }
                    if ($_ -match "Registry Values")
                        {        
                            $MinPwdLengthAudit
                        }
                }  

                $GptTmplPathVars > $GptTmplPath

                # Edit GPT.INI and update Sysvol versionNumber
                Write-Host "[Task : 3] Update VersionNumber of the Default Domain policy...                                  " -ForegroundColor Green -NoNewline; Write-Host "[OK]" -ForegroundColor Green 
                            
                $GptDContent = Get-Content $GptIniPath
                $GptDContent = $GptDContent -replace "Version=3", "Version=14"
                Set-Content $GptIniPath $GptDContent

                # Update AD versionNumber

                $VersionNumber = (Get-ADObject "CN={$($000Id)},$PathPolicy" -Properties *)
                Set-ADObject -Identity $VersionNumber -Replace @{versionNumber="14"}
            }  
            # Launch the functions
            Write-Host "[Task : 2] Applying the Password Policy CIS Compliance...                                        " -ForegroundColor Green -NoNewline; Write-Host "[OK]" -ForegroundColor Green 
                 
            Default_Domain_policy
            $command = gpupdate /force
            Write-Host "[Task : 4] Successful...                                                                         " -ForegroundColor Green -NoNewline; Write-Host "[OK]" -ForegroundColor Green
            Write-Host""
            Get-Content .\Compliance\info.md
            Write-Host"" 
                             
        }

    elseif ( $VersionNumber.versionNumber -eq "14" )

        {
              Write-Host "[Task : 1] The Password Policy CIS compliance already configured...                              " -ForegroundColor DarkGray -NoNewline; Write-Host "[OK]" -ForegroundColor Green 
              Write-Host "" 
              # Check Password Policy
              $SRV = Get-ADDomainController
              $Server = $SRV.HostName

              $PWD = Get-ADDefaultDomainPasswordPolicy -Server $Server | Select-Object ComplexityEnabled, LockoutDuration, LockOutObservationWindow, LockoutThreshold, MaxPasswordAge, MinPasswordAge, MinPasswordLength, PasswordHistoryCount, ReversibleEncryptionEnabled
              #$PWD = Get-ADDefaultDomainPasswordPolicy -Server $Server
              $Enabled = $PWD.ComplexityEnabled
              $LockDuration = $PWD.lockoutDuration
              $LockObservation = $PWD.lockOutobservationWindow
              $LockThreshold = $PWD.LockoutThreshold
              $MaxPass = $PWD.MaxPasswordAge
              $MinPassAge = $PWD.MinPasswordAge
              $MinPass = $PWD.MinPasswordLength
              $PassHistory = $PWD.PasswordHistoryCount
              $Reversible = $PWD.ReversibleEncryptionEnabled

              Write-Host "ComplexityEnabled...........: " -ForegroundColor DarkGray -NoNewline; Write-Host $Enabled -ForegroundColor DarkGray
              Write-Host "LockoutDuration.............: " -ForegroundColor DarkGray -NoNewline; Write-Host $LockDuration -ForegroundColor DarkGray 
              Write-Host "LockOutObservationWindow....: " -ForegroundColor DarkGray -NoNewline; Write-Host $LockObservation -ForegroundColor DarkGray
              Write-Host "LockoutThreshold............: " -ForegroundColor DarkGray -NoNewline; Write-Host $LockThreshold -ForegroundColor DarkGray
              Write-Host "MaxPasswordAge..............: " -ForegroundColor DarkGray -NoNewline; Write-Host $MaxPass -ForegroundColor DarkGray
              Write-Host "MinPasswordAge..............: " -ForegroundColor DarkGray -NoNewline; Write-Host $MinPassAge -ForegroundColor DarkGray
              Write-Host "MinPasswordLength...........: " -ForegroundColor DarkGray -NoNewline; Write-Host $MinPass -ForegroundColor DarkGray
              Write-Host "PasswordHistoryCount........: " -ForegroundColor DarkGray -NoNewline; Write-Host $PassHistory -ForegroundColor DarkGray
              Write-Host "ReversibleEncryptionEnabled.: " -ForegroundColor DarkGray -NoNewline; Write-Host $Reversible -ForegroundColor DarkGray
              Write-Host ""            
              Get-Content .\Compliance\info.md
              Write-Host ""   
        }

    elseif ( $VersionNumber.versionNumber -eq $InitialVNumber )       
        {
              Write-Host "[Task : 1] The Password Policy CIS compliance already configured...                              " -ForegroundColor DarkGray -NoNewline; Write-Host "[OK]" -ForegroundColor Green 
        
              Write-Host "" 
              # Check Password Policy
              $SRV = Get-ADDomainController
              $Server = $SRV.HostName

              $PWD = Get-ADDefaultDomainPasswordPolicy -Server $Server | Select-Object ComplexityEnabled, LockoutDuration, LockOutObservationWindow, LockoutThreshold, MaxPasswordAge, MinPasswordAge, MinPasswordLength, PasswordHistoryCount, ReversibleEncryptionEnabled
              #$PWD = Get-ADDefaultDomainPasswordPolicy -Server $Server
              $Enabled = $PWD.ComplexityEnabled
              $LockDuration = $PWD.lockoutDuration
              $LockObservation = $PWD.lockOutobservationWindow
              $LockThreshold = $PWD.LockoutThreshold
              $MaxPass = $PWD.MaxPasswordAge
              $MinPassAge = $PWD.MinPasswordAge
              $MinPass = $PWD.MinPasswordLength
              $PassHistory = $PWD.PasswordHistoryCount
              $Reversible = $PWD.ReversibleEncryptionEnabled

              Write-Host "ComplexityEnabled...........: " -ForegroundColor DarkGray -NoNewline; Write-Host $Enabled -ForegroundColor DarkGray
              Write-Host "LockoutDuration.............: " -ForegroundColor DarkGray -NoNewline; Write-Host $LockDuration -ForegroundColor DarkGray 
              Write-Host "LockOutObservationWindow....: " -ForegroundColor DarkGray -NoNewline; Write-Host $LockObservation -ForegroundColor DarkGray
              Write-Host "LockoutThreshold............: " -ForegroundColor DarkGray -NoNewline; Write-Host $LockThreshold -ForegroundColor DarkGray
              Write-Host "MaxPasswordAge..............: " -ForegroundColor DarkGray -NoNewline; Write-Host $MaxPass -ForegroundColor DarkGray
              Write-Host "MinPasswordAge..............: " -ForegroundColor DarkGray -NoNewline; Write-Host $MinPassAge -ForegroundColor DarkGray
              Write-Host "MinPasswordLength...........: " -ForegroundColor DarkGray -NoNewline; Write-Host $MinPass -ForegroundColor DarkGray
              Write-Host "PasswordHistoryCount........: " -ForegroundColor DarkGray -NoNewline; Write-Host $PassHistory -ForegroundColor DarkGray
              Write-Host "ReversibleEncryptionEnabled.: " -ForegroundColor DarkGray -NoNewline; Write-Host $Reversible -ForegroundColor DarkGray
              Write-Host ""            
              Get-Content .\Compliance\info.md
              Write-Host ""
        }
    else
        {
            Write-Host "[Task : 1] Checking if Version Number doesn't modified, if not deploy CIS Password compliance... " -ForegroundColor Green -NoNewline; Write-Host "[OK]" -ForegroundColor Green 
            
       function Default_Domain_policy 
            {
                function LockOut ()
                    {
                        $DContent = Get-Content $GptTmplPath
                        $LockOutBad = $DContent -replace "LockoutBadCount = 0", "LockoutBadCount = 5"
                        Set-Content $GptTmplPath $LockOutBad
                    }
                LockOut

                function MinPwd ()
                    {                  
                        $DContent = Get-Content $GptTmplPath
                        $MinPwdLength = $DContent -replace "MinimumPasswordLength = 7", "MinimumPasswordLength = 14"
                        Set-Content $GptTmplPath $MinPwdLength
                    }
                MinPwd

                function MaxPwd ()
                    {
                        $DContent = Get-Content $GptTmplPath
                        $MaxPwdAge = $DContent -replace "MaximumPasswordAge = 42", "MaximumPasswordAge = 60"
                        Set-Content $GptTmplPath $MaxPwdAge
                    }
                MaxPwd

                $MinPwdLengthAudit = "MACHINE\System\CurrentControlSet\Control\SAM\MinimumPasswordLengthAudit=4,14"
                $ResetLockOut = "ResetLockoutCount = 30"
                $LockOutDuration = "LockoutDuration = 30"

                #Add New line after a Pattern LockoutBadCount and Registy Values
                $GptTmplPathVars = Get-Content $GptTmplPath | ForEach-Object {
                    
                    $_
                    if ($_ -match "LockoutBadCount")
                        {
                            $ResetLockOut
                            $LockOutDuration
                        }
                    if ($_ -match "Registry Values")
                        {        
                            $MinPwdLengthAudit
                        }
                }  

                $GptTmplPathVars > $GptTmplPath
                # Edit GPT.INI and update Sysvol versionNumber
                Write-Host "[Task : 3] Update VersionNumber of the Default Domain policy...                                  " -ForegroundColor Green -NoNewline; Write-Host "[OK]" -ForegroundColor Green 
             
                $GptDContent = Get-Content $GptIniPath
                $GptDContent = $GptDContent -replace "Version=$InitialVNumber", "Version=$ResultVNumber"
                Set-Content $GptIniPath $GptDContent

                # Update AD versionNumber

                $VersionNumber = (Get-ADObject "CN={$($000Id)},$PathPolicy" -Properties *)
                Set-ADObject -Identity $VersionNumber -Replace @{versionNumber="$ResultVNumber"}
            }  
            # Launch the functions
            Write-Host "[Task : 2] Applying the Password Policy CIS Compliance...                                        " -ForegroundColor Green -NoNewline; Write-Host "[OK]" -ForegroundColor Green 
            
            Default_Domain_policy
            $command = gpupdate /force
            Write-Host "[Task : 4] Successful...                                                                         " -ForegroundColor Green -NoNewline; Write-Host "[OK]" -ForegroundColor Green 
            Write-Host""
            Get-Content .\Compliance\info.md
            Write-Host"" 
        }
}