# CIS-Automate
Automating Active Directory Hardening using CIS Benchmarks Standard
1. Overview

The purpose of this script is to autonate the hardening of Active Directory, I know that Active Directory hardening is complex, it's done manually.
That's why, I thought to simplify this process and created this PowerShell script called CIS_Automate.

2. CIS_Automate
   
CIS_Automate is a native PowerShell script focused on automating the hardening of the Active Directory, it is a standard and tested in different environments Windows Servers 2k16-2k22, I referred to CIS benchmarks and STIG frameworks. CIS_Automate is a set of PowerShell scripts on a single interface, the hardering include :

- Password Policy
- User Rights Assignment
- Security Options
- Others

3. Usage

After downloading CIS_Automate, you need to create a folder called Compliance anywhere and extract CIS_Automate on it, your Compliance folder must contain: 

- CIS_MENU.ps1
- 00_Compliance_CreatedGPO.ps1
- 01_Compliace_Passwd.ps1
- 02_Compliance_UserRightsAssignmtnt.ps1
- 03_Compliance_Security.ps1
- 04_Compliance_HArdening.ps1
- banner.md
- info.md

Next, move the PowerShell script CIS_MENU to the desktop. CIS_MENU is a central interface for managing CIS_Automate.

Notice :

- Scripts 01 and 02 use the Default Domain Policies.
- Scripts 03 and 04 depend of the 00 script. 



