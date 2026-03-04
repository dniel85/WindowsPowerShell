function sudo {
<#
.SYNOPSIS
Opens a new shell asAdmin. 

.DESCRIPTION
Auto opens a new shell, prompts for credentials and allows commands to be ran as admin. 

.EXAMPLE
sudo 
#>
start-process powershell -verb runAs}