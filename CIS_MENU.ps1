# CIS Benchmark Compliance Automate
@'
  Purpose is to Automate CIS Benchmark Compliance
  Written by Marlyns Nkunga, August 2025

'@
Clear-Host

function Print_Menu
{
   Write-Host ""
   Get-Content .\Compliance\banner.md
   Write-Host ""

   Write-Host "1) Create CIS Compliance Group Policies"
   Write-Host "2) Configure CIS Compliance Password Policy"
   Write-Host "3) Configure CIS Compliance User Rights Assignment"
   Write-Host "4) Configure CIS Compliance Security Options"
   Write-Host "5) Configure CIS Compliance Hardening"
   Write-Host "0) Exit"
}

do {

      Print_Menu

      Write-Host ""
      Write-Host "Make choise : " -NoNewline

      switch ($choise = Read-Host)
      {  
	
       "1" { 
           
               .\Compliance\00_GPO_Compliance.ps1
        }
        
        "2"{

               .\Compliance\01_Passwd_Compliance.ps1
        }

        "3"{

               .\Compliance\02_UserRightsAssignment_Compliance.ps1
        }

        "4"{

               .\Compliance\03_Security_Compliance.ps1
        }

        "5"{

               .\Compliance\04_Hardening_Compliance.ps1
        }

        "0"{
               Exit
        }

       default {

            Write-Warning " This choise is not valid"
       }
    }
      pause
      Clear-Host
}while($true)