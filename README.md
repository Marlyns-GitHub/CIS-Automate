# CIS-Automate : Automating Active Directory Hardening using CIS Benchmarks Standard

1. Overview

The purpose of this script is to autonate the hardening of Active Directory, I know that Active Directory hardening is complex, it's done manually.
That's why, I thought to simplify this process and created this PowerShell script called CIS_Automate.

2. CIS_Automate
   
CIS_Automate is a native PowerShell script focused on automating the hardening of Active Directory, it is a standard and tested in different environments Windows Servers 2k16-2k22, I referred to CIS benchmarks and STIG frameworks. CIS_Automate is a set of PowerShell scripts on a single interface, the hardering include :

- Password Policy
- User Rights Assignment
- Security Options
- Others

3. Use

After downloading CIS_Automate, the Compliance folder can be anywhere and must contain: 

- CIS_MENU.ps1
- 00_GPO_Compliance.ps1
- 01_Passwd_Compliance.ps1
- 02_UserRightsAssignmtnt_Compliance.ps1
- 03_Security_Compliance.ps1
- 04_HArdening_Compliance.ps1
- banner.md
- info.md
- README.md

Next, move CIS_MENU script on the desktop. CIS_MENU is a central interface for managing CIS_Automate, it must not be inside the Compliance folder.

Notice :

- Scripts 01 and 02 use the Default Domain Policies.
- Scripts 03 and 04 depend of the 00 script. 



