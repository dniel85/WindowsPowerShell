# WindowsPowerShell 

Collection of PowerShell Modules and scripts

Example:  
PowerShell script that collects Active Directory information and displays it in an interactive menu.

---

# Overview

Explain what the script/program does and why it exists.

Example:

This script automates the collection of Active Directory data in the background using runspaces and provides a menu interface for administrators to quickly access domain information.

---

# Features

- Feature 1
- Feature 2
- Feature 3
- Background processing
- Logging support
- Error handling

---

# Requirements

List dependencies.

Example:

- PowerShell 5.1+
- Windows Server 2016+
- ActiveDirectory module
- .NET Framework 4.7+
- PowerShell 7.4

---

# Installation

Steps required for setup, install or deployment.

```powershell
cd ~\documents
git clone https://github.com/dniel85/WindowsPowerShell.git

if(-not(test-path ~\documents\PowerShell)){mkdir ~\Documents\PowerShell}
"$env:USERPROFILE\Documents\windowspowershell\Microsoft.PowerShell_profile.ps1","$env:USERPROFILE\Documents\Powershell\Microsoft.PowerShell_profile.ps1","$env:USERPROFILE\Documents\PowerShell\Microsoft.VSCode_profile.ps1" | foreach-Object {"import-module Mycustomshell -warningaction ignore" | Out-File $_}
