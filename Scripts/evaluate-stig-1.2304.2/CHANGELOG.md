# Evaluate-STIG ChangeLog

## **1.2304.2**

### What's New

* Update for Cisco IOS XE Router NDM V2R7.
* Update for Cisco IOS XE Router NDM V2R6.
* Update for Microsoft Windows 10 V2R7.
* Update for Microsoft Windows 11 V1R4.
* Update for Microsoft Windows Server 2019 V2R7.
* Update for Microsoft Windows Server 2022 V1R3.

### Other Changes

* Modified bash script to ensure a valid owner on the extracted PowerShell directory (issue 1024)
* Bug fixes:
  * Issue 1025 : RHEL 7 Group matching
  * Issue 1028 : RHEL 7 V-204477 & RHEL 8 V-230317 (Identical code in both), fail with Exception calling "ToInt16"
  * Issue 1047 : RHEL 7 V-204463
  * Issue 1048 : RHEL/CentOS 7 V-204403 - Results in false positive in CentOS 7 with no GUI installed

## **1.2304.1**

### What's New

* Update for Microsoft Active Directory Domain V3R3.
* Update for Microsoft Windows 10 V2R6.
* Update for Microsoft Windows 11 V1R3.
* Update for Microsoft Windows 2012/2012 R2 DC V3R6.
* Update for Microsoft Windows 2012/2012 R2 MS V3R6.
* Update for Microsoft Windows Server 2016 V2R6.
* Update for Microsoft Windows Server 2019 V2R6.
* Update for Microsoft Windows Server 2022 V1R2

### Other Changes

* Add logic to confirm that `-ListApplicableProducts`, `-ListSupportedProducts`, and `-Version` do not have additional parameters specified.
* Bug fixes:
  * Issue 1010 : Support RedHawk RealTime OS
  * Issue 1011 : Ubuntu 20.04 - V-238335, V-238365, and V-238366
  * Issue 1012 : Firefox (V-251550) Failed
  * Issue 1013 : -ListApplicableProducts and -ListSupportedProducts Result in an Error
  * Issue 1014 : RHEL8 false positives for all blacklist.conf STIG's (V-230494, V-230495, V-230496, V-230497, V-230498, V-230499, V-230503)
  * Issue 1015 : RHEL8 false positive for V-256973 with wrong finding wording
  * Issue 1025 : RHEL 7 Group matching
  * Issue 1026 : Hardened UNC Path Check False Positive
  * Issue 1027 : RHEL 7 & 8 issues with checks using find on systems with an ext4 root filesystem
  * Issue 1028 : RHEL 7 V-204477 & RHEL 8 V-230317 (Identical code in both), fail with Exception calling "ToInt16"
  * Issue 1029 : Evaluate-STIG.log missing closing of tags on entries.
  * Issue 1031 : V-204470 Check does not appear to compare the Primary GID found in /etc/passwd of the user with the group owner of the home directory as spelled out by the STIG.
  * Issue 1032 : Remote Scan Progress Bar Can Show Computers Not Part of Scan
  * Issue 1034 : Evaluate-STIG_Bash.sh --ExcludeVuln not taking multiple arguments
  * Issue 1037 : RHEL 7 V-204469 False Positive
  * Issue 1038 : RHEL 8 false positive when evaluating modprobe.d
  * Issue 1039 : Mozilla Firefox V-252908 and V-252909 Checking Wrong Value
  * Issue 1040 : RHEL 8 - V-230256 DOD-approved TLS encryption GnuTLS config - False Positive
  * Issue 1041 : RHEL8 (V-230396) : Failed
  * Issue 1044 : Evaluate-Stig_1.2304.0 ENS scan failure
  * Issue 1045 : Windows Server DC "Certifications" Should be "Certificates"
  * Issue 1046 : Invoke-Sqlcmd Check Occurring when IIS is Selected

## **1.2304.0**

### What's New

* Removed requirement for `SqlServer` module to complete SQL scans.  Will now use either `SQLPS` (installed by default) or `SqlServer`.
* Add detection logic to support for RedHawk RealTime OS (issue 1010).
* Update for Cisco IOS XE Router NDM V2R6.
* Update for Cisco IOS XE Switch NDM V2R5.
* Update for McAfee ENS 10.x Local Client V1R4.
* Update for Microsoft Internet Explorer 11 V2R4.
* Update for Microsoft IIS 8.5 Server V2R6.
* Update for Microsoft IIS 8.5 Site V2R8.
* Update for Microsoft IIS 10.0 Server V2R9.
* Update for Microsoft IIS 10.0 Site V2R8.
* Update for Microsoft Office 365 ProPlus V2R9.
* Update for Microsoft SQL Server 2016 Database V2R6.
* Update for Microsoft SQL Server 2016 Instance V2R9.
* Update for Oracle Linux 7 V2R11.
* Update for Oracle Linux 8 V1R6.
* Update for RHEL 7 V3R11.
* Update for RHEL 8 V1R10.
* Update for Ubuntu 10.04 LTS V2R11.
* Update for Ubuntu 20.04 LTS V1R8.

### Other Changes

* Improve Cisco code to use Base Ethernet MAC Address in "Target Data" section of CKL (issue 945).
* Improve error trapping of ValidationCode from answer files (issue 959).
* Improve logging of Cisco config file support (issue 960).
* Improve user hive handling (issue 966).
* Improve cleanup code (issue 968).
* Improve answer file schema to validate `STIGComments Name` attribute (issue 975).
* Bug fixes:
  * Issue 909 : Not able to see stig checklist result
  * Issue 913 : RHEL 8 V-230256 script compares with check text example output instead of required values
  * Issue 915 : RHEL 8 V-230265 (RHEL-08-010371) false positive
  * Issue 923 : SQL Server 2016 Instance - V213968, V213969, and V13971 FindingDetails are not correct
  * Issue 924 : SQL Server Database - V213910, V213914, and V213924 reported data should be filtered for only the database being processed.
  * Issue 925 : SQL Server 2016 Database - V215040 Typo in WHERE clause line 1908
  * Issue 927 : Get-AllInstances in Master_Functions.psm1 Broken - Possible correction in post
  * Issue 930 : RHEL 7 v-250313 - Cannot call a method on a null-valued expression
  * Issue 931 : Apache 2.4 Server Unix (V-214235) | Apache 2.4 Site Unix (V-214287) - Cannot call a method on a null-valued expression
  * Issue 933 : SQL Server 2016 Instance - V-213931, V-213942, V-213961, V-213964, V-213966, V-213980 - mark as Not reviewed instead of OPEN
  * Issue 934 : SQL Server 2016 Database - V-213908, V-213921, V-25104 - mark as Not reviewed instead of OPEN
  * Issue 937 : RHEL8 V-230357 Grep path is incorrect
  * Issue 941 : SQL Server 2014 Instance -- V-213849 if finding, return NR instead of Open
  * Issue 942 : SQL Server 2016 Instance - V213957 check changes server config, plus should return NR instead of Open
  * Issue 943 : SQL Server 2016 Instance - V213958 check changes server config; need NR instead of Open
  * Issue 946 : RHEL 7 V-204482, V-204483, and V-204626 false positive
  * Issue 947 : RHEL 7 V-204411 false positive
  * Issue 948 : RHEL 7 V-204517 false positive
  * Issue 949 : RHEL 7 V-204610 false positive
  * Issue 950 : V-230323 and V-230320 pwck -r
  * Issue 951 : RHEL 7 V-204597 false positive
  * Issue 952 : RHEL 7 V-204469 and V-204470 false positives
  * Issue 954 : RHEL 8 V-244522 grep command missing the third line
  * Issue 956 : RHEL 7 V-228564 false positive
  * Issue 965 : RHEL 8 V-230360 False Negative
  * Issue 967 : RHEL 7 V-255928 false positive
  * Issue 977 : RHEL 7 V-204430 false positive and improvement request
  * Issue 1002 : GPResult OQE not Generated if No User Profile is Scanned
  * Issue 1004 : RHEL 7 V-204489 False Positive
  * Issue 1005 : Whitespace in Eval-STIG Path and GUI
  * Issue 1006 : RHEL 7 V-204472 & V-204475 - False Positive
  * Issue 1008 : RHEL 8 - V-230385 Comment handling

## **1.2301.1**

### What's New

* Added a GUI front end for Evaluate-STIG (`Manage-Evaluate-STIG.ps1`) under the Auxiliary Files.
* Added protection to prevent multiple/simultaneous scans of an asset.  This could lead to file lock issues and log file scrambling.

### Other Changes

* Removed additional code from Windows modules that referenced "McAfee" (issue 716).
* Update `Manage-AnswerFile.ps1` to display CAT level of checks (issue 757).
* Update PostgreSQL9.x to also scan 15.x.  Versions in between have not been tested so use at own risk.
* Update to output scan results to console when using `-SelectVuln` (issue 884).
* Update Windows scans to only import user registry hive if a scan requires it (issue 888).
* Update RHEL 8 V-230479 to allow for UDP syslog (issue 890).
* Update `-SelectVuln` and `-ExcludeVuln` to require proper vuln ID (*V-####*) formatting (issue 893).
* Update linux audit rules to not require a certain order (issue 897).
* Update Evaluate-STIG documentation to correct slight error (issue 898).
* Bug fixes:
  * Issue 548 : AD Forest V-8555 & V-72835
  * Issue 833 : Feature categories are listed in addition to actual installed features
  * Issue 847 : RHEL 7 V-204501 not splitting correctly
  * Issue 874 : SQL Server 2016 Instance - Typos/Formatting issues
  * Issue 875 : PostgreSQL Issues
  * Issue 883 : Windows Server 2016 V-224971, V-224974
  * Issue 902 : RHEL 7 V-225928
  * Issue 904 : SQL2016 DB Scan Marked V-213905, V-213922, and V-213923 as NR, but No Results should be NF
  * Issue 905 : Scan-WindowsServer20xx_Checks
  * Issue 907 : Windows 10 V-220847 error converting "e" to int32
  * Issue 908 : Windows Server 2016 V-224842 says NotAFinding but .p12 files exist
  * Issue 911 : RHEL7 false positives for RHEL-07-021020 and RHEL-07-021021, possible code misconfiguration
  * Issue 912 : CKL Templates Do Not Match STIG Viewer Saved CKL Format
  * Issue 913 : RHEL 8 V-230256 script compares with check text example output instead of required values

## **1.2301.0**

### What's New

* New option ***-CiscoConfig*** : To scan Cisco `show tech-support` output file(s).  Usage:
  * `Evaluate-STIG.ps1 -CiscoConfig C:\MyConfig\ShowTech.txt`
  * `Evaluate-STIG.ps1 -CiscoConfig C:\Configs\`
  * `Evaluate-STIG.ps1 -CiscoConfig C:\Configs\,C:\MyConfig\ShowTech.txt`
* New option ***-Marking*** :  To optionally set Marking in CKL and on header/footer of files generated by Evaluate-STIG.  Usage:
  * `Evaluate-STIG.ps1 -Marking "CUI"`
* Add support for Cisco IOS XE Router NDM V2R5.
* Add support for Cisco IOS XE Switch L2S V2R3.
* Add support for Cisco IOS XE Switch NDM V2R4.
* Add support for Oracle Java JRE 8 for Unix V1R3.  *Note: this is for "Oracle Java JRE 8" only and not OpenJDK 8.  It is unclear at this time if OpenJDK 8's version of JRE will actually utilize the deployment.config, deployment.properties, and exception.sites files.*
* Add schema validation for completed checklists.  If validation fails, CKL will be moved to `%WINDIR%\Temp\Evaluate-STIG\Bad_Ckl` for troubleshooting evidence.

### Other Changes

* STIG Viewer 2.17 or greater now required for Evaluate-STIG generated checklists.
* Change STIGList Name for `Oracle Java JRE 8` to `Oracle Java JRE 8 for Windows` and ShortName to `JavaJRE8Windows` to allow for the addition of Java JRE 8 for Unix.
* Update Java JRE 8 Windows module to allow for UNC paths and hidden shares in deployment.properties (issue 845). Note: due to double hop limitations, UNC paths will not work in remote scans.
* Update for Apache Server 2.4 UNIX Server V2R4.
* Update for Apache Server 2.4 UNIX Site V2R3.
* Update for Apache Server 2.4 Windows Server V2R3.
* Update for Google Chrome V2R8.
* Update for Microsoft IIS 8.5 Server V2R5.
* Update for Microsoft IIS 8.5 Site V2R7.
* Update for Microsoft IIS 10.0 Server V2R8.
* Update for Microsoft Office 365 ProPlus V2R8.
* Update for Oracle Linux 7 V2R10.
* Update for Oracle Linux 8 V1R5.
* Update for RHEL 7 V3R10.
* Update for RHEL 8 V1R9.
* Update for Ubuntu 18.04 LTS V2R9.
* Update for Ubuntu 20.04 LTS V1R6.
* Bug fixes:
  * Issue 804 : SQL Component Creating Unnecessary Opens
  * Issue 836 : V-213907 for SQL 2016 DB needs replmonitor and ##MS_SSISServerCleanupJobLogin##
  * Issue 850 : V-204563 RHEL 7 kmod audit no longer starts with -w
  * Issue 852 : Get-V67365, 67 and 69 give false NotAFinding in SQL 2014 Database
  * Issue 853 : MS Project/Visio 2016 EvalStig Scans are skipped
  * Issue 876 : V-225082 (Server 2016), V-205846 (Windows Server 2019): Open Instead of NF, Manual Review?
  * Issue 878 : V-252910 False positive when IE11 is installed on Windows 11
  * Issue 886 : Java JRE Windows V-234697

## **1.2210.2**

### What's New

* No new features or STIGs added to this release.

### Other Changes

* The Ansible playbook has be rewritten to replicate the process for Evaluate-STIG Remote scanning on Windows. No longer will the Ansible script remove password restrictions to allow for rsync. The playbook now archives Evaluate-STIG, copies to the target machine, extracts and runs the evaluation, then archives the results to copy back to the path defined and extracted.
* Update detection logic for Apache 2.5 on Linux to look for a service instead of an installed package.
* Update IIS 10.0 detection logic to include Windows 11 with IIS installed.
* Bug fixes:
  * Issue 823 : SQL 2016 Instance V-213944 and V-213977
  * Issue 824 : PowerShell 7.3 gets permissions denied
  * Issue 826 : Edge V1R6 V-251694 NA condition
  * Issue 832 : ThrottleLimit switch still only does 10 systems at a time
  * Issue 835 : V-213192 for Adobe Reader check does not pull version information
  * Issue 837 : Win11 V-253364 Simultaneous connections to the internet or a Windows domain must be limited.
  * Issue 841 : RHEL 7 Apache CKL names
  * Issue 842 : Adobe Pro DC (64-bit) not Detected
  * Issue 843 : RHEL 8 - V-230507 - Check comes back as Not Reviewed
  * Issue 844 : RHEL 8 V-230479 rsyslog relp not detected

## **1.2210.1**

### What's New

* Add support for Apache Server 2.4 UNIX Server V2R3.
* Add support for Apache Server 2.4 UNIX Site V2R2.

### Other Changes

* Update tattoo `LastRun` registry value to be ISO 8601 compliant (issue 811).  To convert the value into a DateTime object:
  * `$LastRun = [datetime]::ParseExact((Get-ItemProperty HKLM:\SOFTWARE\Evaluate-STIG).LastRun, 'yyyyMMddTHHmmssffff', $null)`
* Update for Microsoft Active Directory Domain V3R2.
* Update for Microsoft Internet Explorer 11 V2R3 (repost on cyber.mil).
* Update for Microsoft Windows 10 V2R5.
* Update for Microsoft Windows 11 V1R2.
* Update for Microsoft Windows Server 2012/2012 R2 DC V3R5.
* Update for Microsoft Windows Server 2012/2012 R2 MS V3R5.
* Update for Microsoft Windows Server 2016 V2R5.
* Update for Microsoft Windows Server 2019 V2R5.
* Bug fixes:
  * Issue 213 : Windows Server 2016 V-225013 should be NA for Domain Controllers
  * Issue 808 : Improve -Update switch
  * Issue 813 : Exception list path in deployments.properties isn't evaluating correctly for Java STIG checks

## **1.2210.0**

### What's New

* New option ***-Version*** :  To display the version of Evaluate-STIG and the running path.  Usage:
  * `Evaluate-STIG.ps1 -Version`
  * `Evaluate-STIG_Bash.sh --Version`
* Add support for Microsoft Exchange 2016 Edge Transport Server V2R4.
* Add support for Microsoft Exchange 2016 Mailbox Server V2R4.
* Add support for Microsoft Windows Server 2022 V1R1.

### Other Changes

* Add `--ListSupportedProducts` to **Evaluate-STIG_Bash.sh**
* Add `--ListApplicableProducts` to **Evaluate-STIG_Bash.sh**
* Add `ScanType` to summary reports.
* Add progress bar to `-ListApplicableProducts`
* Add support for SQL 2014 Database V-67373.  Issue 728.
* Add support for SQL 2014 Database V-67375.  Issue 727.
* Add support for SQL 2014 Database V-67383.  Issue 726.
* Add support for SQL 2014 Database V-67385.  Issue 725.
* Add `Offline_Hosts.txt` under `%temp%\Evaluate-STIG` to document offline computers during a remote scan. Issue 633.
* Remove support for V-224825 (Windows Server 2016) and V-205699 (Windows Server 2019).  Issue 765.
* Update detection logic for VMware Horizon Agent and Connection Server to create CKLs for 7.x instead of just 7.13 as the settings are the same for all 7.x versions.
* Update `Evaluate-STIG_Calculator_and_CKL_Metrics.xlsx` metrics and include additional charts.
* Update Office 365 module to mark as NA for checks targeting an Office product that is not installed.  This is per the STIG Overview.pdf.  Issue 779.
* Update to only compress Evaluate-STIG required files for remote scans.  Issue 608.
* Update for Google Chrome V2R7.
* Update for McAfee ENS 10.x Local Client V1R3.
* Update for Microsoft .NET Framework 4.0 V2R2.
* Update for Microsoft Edge V1R6.
* Update for Microsoft Internet Explorer V2R3.
* Update for Microsoft IIS 10.0 Server V2R7.
* Update for Microsoft IIS 10.0 Site V2R7.
* Update for Microsoft Office 365 ProPlus V2R7.
* Update for Microsoft SQL Server 2014 Instance V2R3.
* Update for Microsoft SQL Server 2016 Database V2R5.
* Update for Microsoft SQL Server 2016 Instance V2R8.
* Update for Mozilla Firefox V6R4.
* Update for Oracle Linux 7 V2R9.
* Update for Oracle Linux 8 V1R4.
* Update for RHEL 8 V1R8.
* Update for RHEL 7 V3R9.
* Update for Ubuntu 18.04 LTS V2R9.
* Update for Ubuntu 20.04 LTS V1R6.
* Bug fixes:
  * Issue 735 : Java JRE8 V-234693 False Positive
  * Issue 737 : [Server 2016] Check 224831 marked Open due to recovery partition
  * Issue 755 : Java JRE8 multiple checks fail to execute due to a path validation error.
  * Issue 756 : McAfee ENS 10 Local Client - V-252798, V-252803, V-252804
  * Issue 760 : AuditPol Check Improvements
  * Issue 768 : RHEL8 V-244531 (RHEL-08-010731) check does not examine files
  * Issue 770 : Get-WindowsOptionalFeature Commands in Try/Catch
  * Issue 778 : RHEL8 V-244533 results in open finding even if preauth is before unix line
  * Issue 799 : Windows 10 V-220715 on Workgroup Computers

## **1.2207.3**

### What's New

* New option ***-SelectVuln*** : To selectively specify which vulnerability IDs to include in scan.  For multiple vuln IDs, separate with commas.  Requires *-SelectSTIG* parameter.  Results will be saved to a "_Partial" folder under [OutputPath].  Usage:\
  * `Evaluate-STIG.ps1 -SelectSTIG Firefox -SelectVuln V-251553,V-251557`
* New option ***-ExcludeVuln*** : To selectively specify which vulnerability IDs to exclude from scan.  For multiple vuln IDs, separate with commas.  Requires *-SelectSTIG* parameter.  Usage:\
  * `Evaluate-STIG.ps1 -SelectSTIG Firefox -ExcludeVuln V-251553,V-251557`<br />
    *Note: If a vuln ID is both selected (-SelectVuln) and excluded (-ExcludeVuln), exclusion will take precedent for that vuln ID.  Example : `Evaluate-STIG.ps1 -SelectSTIG Firefox -SelectVuln V-251553,V-251557 -ExcludeVuln V-251557` would result in a partial CKL with only V-251553 completed because V-251557 is ultimately excluded per -ExcludeVuln.*

### Other Changes

* A restart of PowerShell no longer required after *-Update*.
* Improvements to *Evaluate-STIG_Bash.sh*
* Remote scanning of Linux assets now asks for an username for SSH prior to beginning the bulk scan process. This allows for authorized keys to be used to automatically connect to remote hosts where they have been set up. Evaluate-STIG will also attempt to elevate permissions prior to asking for a sudo password. This allows for NOPASSWD in visudo in environments where that is allowed. These changes will allow for an unattended bulk scan of Linux assets from a Windows host.
* Bug fixes:
  * Issue 715 : SQL2016 V-213907, V-213909 Falsely Marked Needs Reviewed
  * Issue 722 : Running Evaluate-STIG 1.2207.2 gives error of missing CKL: "(CUI)_McAfeeENS10xLocal.ckl"
  * Issue 730 : False 'Open' in Scan-CENTOS7_Checks.psm1
  * Issue 732 : Remote Scan Failure Due to $env:TEMP Not Found
  * Issue 733 : Windows Server 2012 V-226314
  * Issue 736 : Firefox V-251553 False Negative
  * Issue 743 : Firefox V-251573 RHEL7 missing /etc/firefox/policies/policies.json file check
  * Issue 748 : RHEL 7 - V-204422 missing int cast and typos
  * Issue 752 : RHEL 7 V-204486 /dev/shm missing from /etc/fstab does not mean not applicable
  * Issue 753 : RHEL 8 251714 checks wrong value

## **1.2207.2**

### What's New

* Add support for Adobe Acrobat Pro XI V1R2.
* Add support for Adobe Acrobat Reader DC Classic Track V2R1.
* Add support for Windows 11 V1R1.

### Other Changes

* Add Dark Mode to Answer File GUI.
* Bug fixes:
  * Issue #630 : Ubuntu 20.04 V-238225 check broken
  * Issue #697 : Java JRE 8 V-234697 crashing in some configurations.
  * Issue #699 : Wrong Adobe being recognized
  * Issue #700 : Windows 10 V-220706 not comparing to proper value.
  * Issue #701 : Manage-answerfile.ps1 closes on old version of ckl being selected.
  * Issue #703 : Java JRE 8 deployment.properties with trailing `=` on .locked properties result in failed check.
  * Issue #704 : McAfee ENS Local Client usage of `$IsWindows` variable will not work with PowerShell 5.1"
  * Issue #706 : V-238233 Ubuntu False Positive
  * Issue #707 : V-238249 Ubuntu False Positive
  * Issue #708 : V-238255 Ubuntu False Positive
  * Issue #709 : V-238337 Ubuntu Wrong Directory Searched
  * Issue #716 : Update McAfee Agent References to Include Trellix
  * Issue #717 : Adobe Acrobat Pro DC "Repair Installation on 32/64 bit" Checks not Looking at "Wow6432Node"
  * Issue #718 : V-238198 Ubuntu 20.04 Banner doesn't match

## **1.2207.1**

### What's New

* New switch ***-ListApplicableProducts*** to display which Evaluate-STIG supported STIGs are applicable to the asset.  Local asset only and requires elevation.  Usage:\
  * `Evaluate-STIG.ps1 -ListApplicableProducts`

### Other Changes

* Bug fixes

## **1.2207.0**

### What's New

* Added support for Adobe Acrobat Professional DC Classic Track V2R1.
* Added support for McAfee ENS 10.x Local Client V1R2.
  * *This is CUI and an optional add-on available for download from IntelShare:*
    * <https://intelshare.intelink.gov/sites/NAVSEA-RMF>
    * <https://intelshare.intelink.sgov.gov/sites/NAVSEA-RMF>
* Added support for Windows Server 2008 R2 MS V1R33.
* Added `Manage-AnswerFile.ps1` to the root of Evaluate-STIG to assist with creating and managing AnswerFiles.
  * *This is in beta and we welcome any feedback.*

### Other Changes

* Changed shortnames for `Apache 2.4 Server Windows` and `Apache 2.4 Site Windows` to `Apache24SvrWin` and `Apache24SiteWin`.
* PowerShell elevation no longer required for remote scans.  If "LOCALHOST" is specified in `-ComputerName`, then elevation or `-AltCredential` is required.
* Remote scan logging moved to `%temp%\Evaluate-STIG`
* Finding Details will be truncated after 32,767 characters.
* Removed Windows 11 from Windows 10 STIG detection.  A true Windows 11 STIG has been released and Evaluate-STIG will support in a future version.
* Updated for Microsoft Internet Explorer V2R2.
* Updated for Microsoft Edge V1R5.
* Updated for Microsoft IIS 8.5 Server V2R4.
* Updated for Microsoft IIS 8.5 Site V2R6.
* Updated for Microsoft IIS 10.0 Server V2R6.
* Updated for Microsoft IIS 10.0 Site V2R6.
* Updated for Microsoft Internet Explorer 11 V2R2.
* Updated for Microsoft Office 365 ProPlus V2R6.
* Updated for Mozilla Firefox V6R3.
* Updated for Oracle Linux 7 V2R8.
* Updated for Oracle Linux 8 V1R3.
* Updated for PostgreSQL 9.x V2R3.
* Updated for RHEL 7 V3R8.
* Updated for RHEL 8 V1R7.
* Updated for Ubuntu 18.04 LTS V2R8.
* Updated for Ubuntu 20.04 LTS V1R5.
* Updated some Windows Server DC and Active Directory Domain checks to hopefully complete faster in larger environments.
* Updated detection logic for Adobe Professional and Adobe Reader to better detect installed products and tracks.
* Updated detection logic for Java JRE 8 to only consider workstations as applicable.  Per the STIG overview, `This STIG is intended for desktop installations of the Oracle JRE and is not intended for Java Development Kit (JDK) installations, installs on server systems, or other JRE products.`  Issue #618.
* Changed licensing to match RMF-Automation End User Agreement verbiage.
* Bug fixes

## **1.2204.1**

### What's New

* New switch ***-NoPrevious*** to disable preservation of current CKLs into Previous subfolder.  Usage:\
  * `Evaluate-STIG.ps1 -NoPrevious`
* Added support for PostgreSQL 9.x V2R2.
* Added **Get-AnswerFileSummary.ps1** in Auxiliary/pub.  Creates a HTML report from Evaluate-STIG Answer Files.
* Updated for Microsoft Defender Antivirus V2R4.
* Updated for Microsoft Windows 10 V2R4.
* Updated for Microsoft Windows Server 2012/2012 R2 Domain Controller V3R4.
* Updated for Microsoft Windows Server 2012/2012 R2 Member Server V3R4.
* Updated for Microsoft Windows Server 2016 V2R4.
* Updated for Microsoft Windows Server 2019 V2R4.

### Other Changes

* Defender Antivirus entries in `-ListSupportedProducts` changed to reflect new STIG name:
  * Name : `Microsoft Defender Antivirus`
  * ShortName : `MSDefender`
* Updated to generate Windows 10 CKL for Windows 11 assets as directed on cyber.mil.
* Updated to generate Windows Server 2019 CKL for Windows Server 2022 assets as directed on cyber.mil.
* Removed support for IIS 8.5 Server V-214399 and V-214426 (issue #555).
* Removed support for IIS 10.0 Server V-218784 and V-218811 (issue #555).
* Removed sample .NET 4 answer file and replaced with a blank answer file template.
* Bug fixes

## **1.2204.0**

### What's New

* New switch ***-VulnTimeout*** to set the maximum time in minutes allowed for a singular Vuln ID check to run.  Default is 15 minutes.  Usage example:\
  * `Evaluate-STIG.ps1 -VulnTimeout 10`
* Added **Evaluate-STIG_Bash.sh** for Linux systems which allows local instances of Evaluate-STIG to be run without PowerShell 7 installed.  It must be run with sudo privileges.  `sudo bash Evaluate-STIG_Bash.sh -h` to show supported switches.  Usage examples:\
  * `sudo bash Evaluate-STIG_Bash.sh`
  * `sudo bash Evaluate-STIG_Bash.sh --ScanType Classified --SelectSTIG Ubuntu20,Firefox`
* Added **Evaluate-STIG.yml** in Auxiliary/pub.  This an Ansible playbook designed to assist with remote Evaluate-STIG scans in a Linux-only environment.
* Updated for Google Chrome Current Windows V2R6.
* Updated for Microsoft Office 365 ProPlus V2R5.
* Updated for Microsoft Outlook 2016 V2R3.
* Updated for Microsoft SQL Server 2016 Database V2R4.
* Updated for Microsoft SQL Server 2016 Instance V2R7.
* Updated for Mozilla Firefox V6R2.
* Updated for Oracle Linux 7 V2R7.
* Updated for Oracle Linux 8 V1R2.
* Updated for RHEL 7 V3R7.
* Updated for RHEL 8 V1R6.
* Updated for Ubuntu 18.04 V2R7.
* Updated for Ubuntu 20.04 V1R4.

### Other Changes

* Added support for Active Directory Forest V-15372.
* Updated to add the scan start date to both Finding Details and Answer File comments.
* Updated Answer File functionality to append **\<ValidationCode\>** results to Comment.  Will truncate after 32767 characters.
* Updated so that VMware Horizon 7.13 STIGs are only applicable to Horizon 7.13 installs.  Per DISA, these STIGs are not applicable to other versions (e.g. 8.x).
* Improved parsing of Java path formatting.
* Reorganized folder structure.  **XmlSchema** renamed to **XML** and *STIGList.xml* moved into it.  This is to further discourage modification of *STIGList.xml* (not supported).
* Added comments to CKL for checks where an answer was applied.  This is for STIG Manager usage.
* Bug fixes

## **1.2201.2**

### What's New

* New switch ***-Proxy*** to set a proxy for use with *-Update*.  Usage examples:\
  * `Evaluate-STIG.ps1 -Update -Proxy 10.0.0.5:8080`
  * `Evaluate-STIG.ps1 -Update -Proxy http://proxy.mil:1234`
* Added support for VMware Horizon 7.13 Agent V1R1.
* Added support for VMware Horizon 7.13 Client V1R1.
* Added support for VMware Horizon 7.13 Connection Server V1R1.

### Other Changes

* Added `::1` as a valid entry for -ComputerName
* Added Evaluate-STIG version used to SummaryReport files.
* Improved error logging.
* Bug fixes

## **1.2201.1**

### What's New

* Added support for Oracle Linux 7 V2R6.
* Added support for Oracle Linux 8 V1R1.

### Other Changes

* Remote scan connections will now be attempted to the FQDN of the remote asset.
* Evaluate-STIG will no longer place canned comments into the Comments field.  This is not a Navy SCA requirement.  Supporting text in Finding Details is the requirement and Evaluate-STIG meets this.
* IIS 10 checklists will now be generated on Windows 10 systems with the IIS-WebServer feature enabled.
* Bug fixes

## **1.2201.0**

### What's New

***IMPORTANT: Remote scanning has been reworked and switches involved changed.***

* *-ComputerName* now supports multiple computer names and lists through comma separation.  Can be a computer name, a file with a list of computers, or a combination.  Usage examples:
  * To scan a single computer named "MyComputer1":\
  `Evaluate-STIG.ps1 -ComputerName MyComputer1`<br />
  * To scan computers "mycomputer1" and "mycomputer2" and a list of computers:\
  `Evaluate-STIG.ps1 -ComputerName MyComputer1,MyComputer2,C:\Computers.txt`
* New switch ***-AltCredential*** added to prompt for an alternate credential to be used in conjunction with *-ComputerName*.  If connection to the remote machine fails with the alternate credential, Evaluate-STIG will fallback to the launching user and attempt the connection.  Essentially, this allows you to use two different credentials for your scans.  For instance, if the launching user has admin rights to workstations and the alternate credential is server admin, you could scan both servers and workstations in a single scan.  Usage example:\
  * `Evaluate-STIG.ps1 -ComputerName MyComputer1,MyComputer2,C:\Computers.txt -AltCredential`
* New switch ***-ThrottleLimit*** to set the maximum concurrent connections for *-ComputerName* (default is 10).  Usage example.\
  * `Evaluate-STIG.ps1 -ComputerName MyComputer1,MyComputer2,C:\Computers.txt -AltCredential -ThrottleLimit 7`
* Added support for Apache Server 2.4 Windows Server V2R2.
* Added support for Apache Server 2.4 Windows Site V2R1.
* Added support for Microsoft SharePoint Designer 2013 V1R3.
* Added support for Mozilla Firefox V6R1.
* Added manifests for all module files.
* Added HTML summary report.
* Added file integrity checking for all Evaluate-STIG content excluding AnswerFiles.
* Updated for Google Chrome Current Windows V2R5.
* Updated for McAfee VirusScan 8.8 Local Client V6R1.
* Updated for Microsoft Edge V1R4.
* Updated for Microsoft Office 365 ProPlus V2R4.
* Updated for Microsoft Office System 2016 V2R2.
* Updated for Microsoft Outlook 2016 V2R2.
* Updated for Microsoft IIS 8.5 Site V2R5.
* Updated for Microsoft IIS 10.0 Server V2R5.
* Updated for Microsoft IIS 10.0 Site V2R5.
* Updated for Microsoft SQL Server 2014 Instance V2R2.
* Updated for Microsoft SQL Server 2016 Database V2R3.
* Updated for Microsoft SQL Server 2016 Instance V2R6.
* Updated for RHEL 7 V3R6.
* Updated for RHEL 8 V1R5.
* Updated for Ubuntu 18.04 V2R6.
* Updated for Ubuntu 20.04 V1R3.
* Applied GNU General Public License v3.0 to project.

### Other Changes

* Deprecated *-ComputerList*.  Use *-ComputerName* with comma separation.
* Deprecated *-SmartCardCredential*.  Use *-AltCredential* instead.
* Deprecated *-UPCredential*.  Use *-AltCredential* instead.
* Modifed *-Update* feature.  If any expected file is missing or fails a hash check or an unexpected file is found, local content will be removed and synced up with upstream content.  AnswerFiles content is excluded.
* Updated progress bars to be color coded based on *-ScanType* (green for Unclassified and red for Classified)
* Bug fixes

## **1.2110.2**

### What's New

* Updated for Active Directory Domain V3R1
* Updated for Microsoft OneDrive V2R2
* Updated for Microsoft Windows Defender Antivirus V2R3
* Updated for Microsoft Windows Firewall with Advanced Security V2R1
* Updated for Microsoft Windows Server 2012/2012 R2 Domain Controller V3R3
* Updated for Microsoft Windows Server 2012/2012 R2 Member Server V3R3
* Updated for Microsoft Windows Server 2016 V2R3
* Updated for Microsoft Windows Server 2019 V2R3
* Updated for Windows 10 V2R3

### Other Changes

* Updated remote scan process to compress files for transport and reduce scan times.
* Bug fixes

## **1.2110.1**

### What's New

* Added support for Ubuntu 16.04 STIG

### Other Changes

* Bug fixes

## **1.2110.0**

### What's New

* Added support for Ubuntu 20.04 STIG
* Updated for Microsoft Edge V1R3
* Updated for Microsoft IIS 10.0 Server V2R4
* Updated for Microsoft IIS 10.0 Site V2R4
* Updated for Microsoft IIS 8.5 Server V2R3
* Updated for Microsoft IIS 8.5 Site V2R4
* Updated for Microsoft Internet Explorer 11 V2R1
* Updated for Microsoft SQL Server 2016 Database V2R2
* Updated for Microsoft SQL Server 2016 Instance V2R5
* Updated for Ubuntu 18.04 V2R5
* Updated for RHEL 7 V3R5
* Updated for RHEL 8 V1R4

### Other Changes

* Re-saved all CKL templates with STIG Viewer 2.15.  STIG Viewer 2.15 or greater will be required to view completed CKLs.
* Answer file schema failures now have detail logged to console and Evaluate-STIG.log.
* Windows Server (V-205624 (2019 DC), V-224848 (2016 DC), V-226259 (2012 R2 DC)) updated to verify any account with an expiration set is set to expire within 72 hours of its creation date.
* V-205646 (2019 DC), V-224992 (2016 DC), V-226265 (2012 R2 DC) updated to verify all certificates are from an approved CA per <https://crl.gds.disa.mil/>
* Windows 10 V-220705 updated to ensure Appx, Exe, and Msi rules are enabled before setting Status to Not A Finding.
* Bug fixes

## **1.2107.2**

### What's New

### Other Changes

* Adjusted Answer File validation process.  Will now flag and exclude .xml files that do not validate against the answer file schema.
* Bug fixes.

## **1.2107.1**

### What's New

* Added support for RHEL 8 STIG

### Other Changes

* Added validation code to *-AFPath* and *-OutputPath* parameters to ensure they point to a directory.
* Updated output CKL file naming convention.  Now uses STIG ShortName and appends timestamp:

  * Most CKLs: **[HOSTNAME]\_[STIGShortName]\_[STIGVER]\_[yyyyMMdd]-[HHmmss].ckl**
  * WebDB CKLs: **[HOSTNAME]\_[STIGShortName]\_[(Site)]\_[STIGVER]\_[yyyyMMdd]-[HHmmss].ckl**
   \
   \
Examples:
  * CA1294NB05613_DotNET4_V2R1_20210812-072419.ckl
  * CA1294NB05613_IISSite_(Default Web Site)_V2R3_20210812-143842.ckl
* Previous checklist selection for administrator comments no longer based on partial file name match.  Previous checklist will now be selected when all of the below attributes match the CKL being currently generated.  If multiple previous CKLs meet this criteria, then the most recently modified one is used.
  * HOST_NAME
  * WEB_OR_DATABASE
  * WEB_DB_SITE
  * WEB_DB_INSTANCE
* Answer Files will now accept STIG **ShortName** or **Name** in the *\<STIGComments Name\>* element.  Use *-ListSupportedProducts* to display valid **ShortName** and **Name** for each supported STIG.
* Bug fixes.

## **1.2107.0**

### What's New

***IMPORTANT: Answer File format has changed to allow for different Status/Comment based on [ValidationCode] output.  Refer to documentation for more.  A separate script, Maintain-AnswerFiles.ps1, can be used to convert your answer files to the new schema.  This script is available at***<br />
<https://spork.navsea.navy.mil/nswc-crane-division/evaluate-stig/-/tree/master/PowerShell/Auxiliary/pub>

* New options added:
  * **-AFPath** : To specify path to answer files.  If not selected, will default to 'AnswerFiles' folder in Evaluate-STIG path.
  * **-ListSupportedProducts** : List products supported by Evaluate-STIG.
* Overhauled answer file format and processing.  Review documentation for more.

### Other Changes

* Updated for Adobe Acrobat Reader DC Continuous Track V2R1.
* Updated for Adobe Acrobat Professional DC Continuous Track V2R1.
* Updated for Google Chrome Current Windows V2R4.
* Updated for Microsoft Edge V1R2.
* Updated for Microsoft IIS 8.5 Site V2R3.
* Updated for Microsoft IIS 10.0 Server V2R3.
* Updated for Microsoft IIS 10.0 Site V2R3.
* Updated for Microsoft Office 365 ProPlus V2R3.
* Updated for Microsoft Office System 2016 V2R1.
* Updated for Microsoft SQL Server 2014 Instance V2R1.
* Updated for Microsoft SQL Server 2016 Instance V2R3.
* Updated for Mozilla FireFox V5R2.
* Updated for RHEL 7 V3R4.
* Updated for Ubuntu 18.04 V2R4.
* Removed "Enabled" attribute from STIGList.xml.  Use -ExcludeSTIG to exclude STIG(s) from a scan.
* Bug fixes.

## **1.2104.2**

### What's New

### Other Changes

* Remote scans will now attempt a WinRM connection over HTTPS first and fallback to HTTP if secure connection fails.
* Added support for V-218822 (IIS 10 Server) and V-214437 (IIS 8.5 Server).
* Bug fixes.

## **1.2104.1**

### What's New

* New options added:
  * **-GenerateOQE** : Currently Windows only.  Save Group Policy report, AppLocker Policy report, and Security Policy export to output path as objective quality evidence (OQE).  Previously, GPO and AppLocker reports were created by default.  Now, they are optional.

### Other Changes

* Bug fixes.

## **1.2104.0**

### What's New

* New options added:
  * **-SelectSTIG** : To selectively specify which STIG(s) to scan.  Use Tab or CTRL+SPACE to properly select a STIG by its short name.  For multiple STIGs, separate with commas.  Cannot be specified with *-ExcludeSTIG*.
  * **-ExcludeSTIG** : To selectively specify which STIG(s) to exclude from the scan.  Use Tab or CTRL+SPACE to properly exclude a STIG by its short name.  For multiple STIGs, separate with commas.  Cannot be specified with *-SelectSTIG*.
* Added support for Microsoft Active Directory Forest STIG
* Added support for Microsoft Active Directory Domain STIG
* Added support for Microsoft Edge STIG
* Added support for Microsoft Office 365 ProPlus STIG
* Added support for Microsoft Access 2013 STIG
* Added support for Microsoft Excel 2013 STIG
* Added support for Microsoft Groove 2013 STIG
* Added support for Microsoft InfoPath 2013 STIG
* Added support for Microsoft Lync 2013 STIG
* Added support for Microsoft Office System 2013 STIG
* Added support for Microsoft OneNote 2013 STIG
* Added support for Microsoft Outlook 2013 STIG
* Added support for Microsoft PowerPoint 2013 STIG
* Added support for Microsoft Project 2013 STIG
* Added support for Microsoft Publisher 2013 STIG
* Added support for Microsoft Visio 2013 STIG
* Added support for Microsoft Word 2013 STIG

### Other Changes

* Updated for Google Chrome Current Windows STIG V2R3.
* Updated for Microsoft IIS 8.5 Server and Site STIG V2R2.
* Updated for Microsoft IIS 10.0 Server and Site STIG V2R2.
* Updated for Windows 10 V2R2
* Updated for RHEL/CentOS 7 STIG V3R3.
* Updated for Ubuntu 18.04 STIG V2R3.
* Updated to record version of Evaluate-STIG used in Finding Details and canned Comments (issue #154).
* Improved logging of Answer File activity.
* Various bug fixes.

## **1.2101.1**

### Other Changes

* Changed Evaluate-STIG versioning. ***Those using configuration management tools to deploy, note that this also changes the Version value in the registry tattoo so please update your deployments accordingly.***
  * Format is **[Major].[YYMM].[Revision]**
  * **YYMM** will be the year and month of the STIG quarter that Evaluate-STIG supports.
  * **Revision** will be incremented between STIG quarters as necessary for bug fixes and STIGs released out of cycle with DISA's quarterly schedule (e.g. Windows OS).
* Updated method for obtaining network adapter info (IP/MAC) on Windows.
* Fixed issue #114. Updated to check for SqlServer and WebAdministration modules if SQL or IIS STIGs are required.  If the modules are not available, log a warning but continue processing.
* Fixed issue #120. Updated Windows Server OS scan modules to correct issue with LockoutDuration evaluation.
* Fixed issue #121. Updated Windows OS scan modules to correct issues with SeDenyRemoteInteractiveLogonRight user right evaluation.
* Fixed issues #122, #127, and #144. Updated Mozilla Firefox module to address several bugs.
* Fixed issue #125. Corrected problem in Windows 10 module that was creating a false positive.
* Fixed issue #126. Corrected problem in Windows 10 module that was creating a false positive on workgroup systems.
* Fixed issue #131. Updated Java JRE module. Reworked to dynamically get location of deployment.properties file from deployment.config. Deployment.config now selected in the following order 1) **\<Windows Directory\>\Sun\Java\Deployment**, 2) **\<64-bit JRE Install Directory\>\lib**, 3) **\<32-bit JRE Install Directory\>\lib**
* Fixed issue #132. Path updated for remote scanning.
* Fixed issue #142. Updated all IIS modules for correct camelCase of IIS elements to help prevent false positives in some configurations.
* Fixed issue #147. Updated to check ScanType and not DomainRole.

## **02-04-2021**

***IMPORTANT: Linux support requires PowerShell 7.1 be installed on Linux systems***<br />
<https://docs.microsoft.com/en-us/powershell/scripting/install/installing-powershell-core-on-linux>

### What's New

* Added support for Adobe Acrobat Professional DC Continuous
* Added support for RHEL/CentOS 7
* Added support for Mozilla FireFox on Linux systems
* New options added:
  * **-ComputerName** : To scan a remote computer.  This replaced *-RemoteComputer* option.
    * **-SmartCardCredential** : To pass a smart card credential to *-ComputerName*.  Windows only.
    * **-UPCredential** : To pass a username/password credential to *-ComputerName*  Windows only.
  * **-ComputerList** : To scan a batch of remote computers.  Windows only.

### Other Changes

* Updated for Oracle Java JRE8 STIG V2R1
* Updated for Canonical Ubuntu 18.04 STIG V2R2
* Updated for Microsoft .NET Framework 4.0 STIG V2R1
* Updated for Mozilla Firefox STIG V5R1
* Updated for Google Chrome Current Windows STIG V2R2
* Fixed issue #67 - Windows 10 V-220705 (AppLocker)
* Fixed issue #70 - Convert all uses of hexadecimal values to decimal values in all Windows Server modules
* Fixed issue #71 - Remove Confirm-SecureBootUEFI output from the console when unsupported in Windows Server modules
* Fixed issue #72 - Fix integer based Security Policy checks where values are evaluate as strings in Windows Server Modules
* Fixed issue #73 - Windows 10 V-220708 - Unformatted Disks and Empty USB Card Readers False Positive
* Fixed issue #74 - Add "BUILTIN\Remote Desktop Users" to SeRemoteInteractiveLogonright in Windows Server modules
* Fixed issue #80 - Server 2012 Member Server (V-225532)
* Fixed issue #81 - -Update option prompting for ESPath
* Fixed issue #82 - Server 2012 Modules: Typo of "Service" needs to be changed to "Service"
* Fixed issue #83 - Windows Server Modules - Convert checks to use newer Confirm-DefaultACL logic
* Fixed issue #84 - Windows Server Modules (2012 & 2016) - Edit Finding Details for clarity regarding PowerShell 7 limitations on some checks
* Fixed issue #85 - Windows Server Modules - Edit file system permission ACL checks to use Confirm-DefaultACL
* Fixed issue #86 - Windows Server Modules - Edit User Rights checks to allow for less than the specified accounts
* Fixed issue #87 - Windows 10 V-220972 - Finding Details Lists Incorrect URA Setting
* Fixed issue #88 - Firefox - Update checks to allow for no space between setting name and value
* Fixed issue #89 - Firefox V-102883 - Enclose setting value in quotes
* Fixed issue #90 - IIS Modules not Working in PS 7.  Updated all checks to call PowerShell.exe if PowerShell session is 7.x.
* Fixed issue #91 - SQL Server - Exclude SQL Server Express 2014.  Updated SQL Server detection to exclude SQL Server Express 2014.  SQL Server Express 2016 and greater should have CKLs produced per DISA.
* Fixed issue #92 - Summary Report Displaying Unexpected Characters.
* Fixed issue #95 - Anti-Virus Listed as Open.  Adjusted Windows Server modules to better detect antivirus products and status.
* Fixed issue #96 - Windows Server 2016 V-224898 and V-224899.  Updated check to determine if VM before determining Status.  If VM, Finding Details will include additional documentation.
* Fixed issue #97 - Windows Server 2012 DC V-226105 and V-226106.  Updated check to determine if VM before determining Status.  If VM, Finding Details will include additional documentation.
* Fixed issue #98 - Windows Server 2012 MS V-225290 and V-225291.  Updated check to determine if VM before determining Status.  If VM, Finding Details will include additional documentation.
* Fixed issue #99 - Windows Server 2019 V-205840 and V-205841.  Updated check to determine if VM before determining Status.  If VM, Finding Details will include additional documentation.
* Fixed issue #100 - Windows Server 2012 DC V-226263 - Should be NA for Classified Systems.
* Fixed issue #101 - Windows Server 2012 MS V-225443 - Should be NA for Classified Systems.
* Fixed issue #108 - Windows Server 2016 V-224829 - Missing "+" for adding to Finding Details.
* Fixed issue #109 - Windows Server 2012 MS V-225444 - Returning incorrect ACL.
* Fixed issue #110 - Windows Server 2012 MS V-225445 - Returning incorrect ACL.
* Fixed issue #111 - Windows Server 2012 MS V-225447 - Returning incorrect ACL.
* Fixed issue #112 - Windows Server 2012 DC V-226268 - Returning incorrect ACL.
* Fixed issue #113 - Windows Server 2012 DC V-226269 - Returning incorrect ACL.
* Fixed issue #117 - Windows Server 2016 V-224835 - HKLM:\SOFTWARE Permissions.
* Fixed issue #118 - Windows Server 2019 V-205737 - HKLM:\SOFTWARE Permissions.
* Removed *-RemoteComputer* option.  This has been replaced by *-ComputerName*.
* Removed *-RunSYSTEM* option.
* Updated logic for detecting user profile to scan.  Profiles that are domain accounts and where the last group policy update is less than 15 days ago will be preferred in selection.
* Updated user registry hive import code for better memory management.
* Updated IIS 8.5 Server check for V-214409 to better detect compliance.
* Updated IIS 10.0 Server check for V-218794 to better detect compliance.
* Updated SummaryReport.xml to include CKL timestamps.

## **12-10-2020**

### What's New

* Added support for Ubuntu 18.04 (requires PowerShell 7.1 be installed on Ubuntu systems)<br />
  <https://docs.microsoft.com/en-us/powershell/scripting/install/installing-powershell-core-on-linux>

### Other Changes

* Updated for Microsoft OneDrive STIG V2R1.
* Updated for Windows 10 STIG V2R1.
* Updated for Windows Defender Antivirus STIG V2R1.
* Updated for Windows Server 2012 R2 DC V3R1.
* Updated for Windows Server 2012 R2 MS V3R1.
* Updated for Windows Server 2016 V2R1.
* Updated for Windows Server 2019 V2R1.
* Updated to better handle ACLs where Windows splits a single 'This key and subkeys' rule into two rules - one for 'This key only' and another for 'Subkeys only'.
* Added functionality to verify 'WebAdministration' and/or 'SqlServer' module is available to PowerShell if required before proceeding.
* Fixed issue #48 - IIS 8.5 Site (V-214478) - If only ports 80 or 443 are used, status should be marked as Not A Finding
* Fixed issue #49 - IIS 10.0 Site (V-218766) - If only ports 80 or 443 are used, status should be marked as Not A Finding
* Fixed issue #54 - SQL 2016 Detection Code in STIGList.xml
* Fixed issue #58 - Remove Scan-WindowsServer2012R2_MS_and_DC_Checks Module
* Fixed issue #66 - Windows 10 V-220715 (V-63367): Non-Compliant Accounts Enabled Field

## **11-25-2020**

***IMPORTANT: STIG Viewer 2.10 or greater now required for opening output checklists***

***IMPORTANT: HKLM:\SOFTWARE\NSWC Crane\Application\Evaluate-STIG_Version registry deprecated.  Replaced with -ApplyTattoo option.  If you are deploying with a configuration management tool, you may need to update the deployment accordingly.***

### What's New

* New option *-ApplyTattoo* added to write optional tattoo info to asset:
  * Windows location: HKLM:\SOFTWARE\Evaluate-STIG
* New option *-Update* added to download updated Evaluate-STIG code from SPORK.  Excludes AnswerFiles content.
* All scripts now digitally signed with a DoD issued code signing certificate.  Recommend the included .cer file be imported to Trusted Publishers store(preferably for the machine) in order for PowerShell to properly trust.
* Added Prerequisite folder with scripts to assist in verifying prerequisites to Evaluate-STIG are met:
  * **Import-Certificates.bat**: For importing the certificates to trust the digital signature.  Useful if PowerShell execution policy is RemoteSigned or AllSigned.
  * **Test-Prerequisites.bat**: For verifying that the digital signature certificate is in the proper certificate store and that current PowerShell execution policy is supported.
* Added initial support for Microsoft SQL Server Database 2014 STIG.
* Added initial support for Microsoft SQL Server Instance 2014 STIG.
* Added initial support for Microsoft SQL Server Database 2016 STIG.  Will be used for SQL Server 2016 and greater.
* Added initial support for Microsoft SQL Server Instance 2016 STIG.  Will be used for SQL Server 2016 and greater.

### Removed

* Removed requirement for SCAP Compliance Checker tool.  All checks are now performed as PowerShell code.
* Removed benchmarks for Windows Server OS STIGs.
* Removed code related to SCAP Compliance Checker command line (CSCC.exe) tool.
* Removed Config.ini

### Other Changes

* Updated Evaluate-STIG documentation and Cost Avoidance Calculator.
* Updated for Google Chrome Current Windows STIG V2R1.
* Updated for Microsoft IIS 8.5 Server STIG V2R1.
* Updated for Microsoft IIS 8.5 Site STIG V2R1.
* Updated for Microsoft IIS 10.0 Server STIG V2R1.
* Updated for Microsoft IIS 10.0 Site STIG V2R1.
* Updated for Microsoft Outlook 2016 STIG V2R1.
* Updated Windows 10 scan module to include WMI fallback checks for Windows features.
* Updated STIGList.xml detection of Internet Explorer 11 to match SCAP detection.  Evaluate-STIG will now check the existence and value of "svcVersion" under HKLM:\SOFTWARE\Microsoft\Internet Explorer.
* Updated Windows 10 V-63675 to be more flexible in detection when multiple white space exists.
* Updated Windows Server 2019 V-93147 to be more flexible in detection when multiple white space exists.
* Updated IIS 8.5 Server V-76771 to mark as NA if system is hosting SharePoint.
* Updated IIS 8.5 Site V-76865, V-76867, V-76869, and V-76871 to mark as NA if system is hosting SharePoint.
* Updated IIS 10.0 Site V-100263, V-100265, V-100267, V-100269, V-100271, V-100275, and V-100277 to mark as NA if system is hosting Sharepoint.
* Separated Windows Server 2012 R2 scan module into two separate modules - once for DC and the other for MS.  Makes sustainment easier.
* Fixed issue #29 - Windows 10 (V-63359).  Ignored accounts were not properly being ignored.  Also updated check to ensure built-in SIDs identified in the STIG Check Text are disabled.
* Fixed issue #32 - IIS 8.5 Server (V-76771) & IIS 10.0 Server (V-100185).  Per conversation with DISA, if ASP.NET is not enabled, this should be NA.  "Administrators" role is compliant.  "Administrator" user will never be valid since OS STIG has us rename the built-in "Administrator" account".
* Fixed issue #33 - IIS 10.0 Server (V-100189).  Updated code to mark as Not A Finding if the Windows Server 2016 version is not 1709 or greater.  HTST support start with version 1709.
* Fixed issue #34 - Windows 10 (V-63871, V-63873, V-63875, V-63877, V-63879).  Updated to better support configurations where multiple domains or bastion forests exist.
* Fixed issue #35 - IIS 10.0 Server (V-100177).  Corrected bad paths to TLS 1.0, TLS 1.1, SSL 2.0, and SSL 3.0 settings.
* Fixed issue #36 - Required Legal Notice: Windows Server 1012 (V-1089)/Windows Server 2016 (V-73647).  Updated to be more flexible in detection when multiple white space exists.
* Fixed issue #37 - Windows Server 2016 (V-90357).  Changed to get firmware type from Get-ComputerInfo.
* Fixed issue #39 - IIS 8.5 Server (V-76759).  Corrected registry paths and value.
* Fixed issue #40 - IIS 8.5 Server and IIS 10.0 Server incorrectly flagging folders with ".java" in the name as a finding.
* Fixed issue #41 - Get-UserToEval updated to look in both the user's profile and the ProgramData folder for NTUser.pol.

## **08-12-2020**

* Changed versioning format from YYYYMMDD to YYYY.MM.DD for easier reading.  Those deploying Evaluate-STIG as a SCCM Application, update your detection method to check the registry value as a File Version.
* Updated for Google Chrome Current Windows V1R19 STIG.
* Updated for Microsoft Internet Explorer 11 V1R19 STIG.
* Updated for Microsoft IIS 8.5 Server V1R11 STIG.
* Updated for Microsoft IIS 8.5 Site V1R11 STIG.
* Updated for Microsoft IIS 10.0 Server V1R2 STIG.
* Updated for Microsoft IIS 10.0 Site V1R2 STIG.
* Updated for Microsoft Windows 10 V1R23 STIG.
* Updated for Microsoft Windows Server 2012 R2 DC V2R22 STIG.
* Updated for Microsoft Windows Server 2012 R2 MS V2R19 STIG.
* Updated for Microsoft Windows Server 2016 V1R12 STIG.
* Updated for Microsoft Windows Server 2019 V1R5 STIG.
* Updated for Mozilla Firefox V4R29 STIG.
* -RemoteComputer will now fallback to SMB/WMI connectivity if WinRM fails.
* Fixed issue 20 - Windows 10 V-63589.  Check Text from STIG was missing a space in Issuer.  Check Text states "O=U.S.Government" when actual Issuer is "O=U.S. Government"
* Fixed issue 22 - Windows 10 V-63349, V-63659, V-63699, V-63701, V-63709, V-63713, V-74417, V-74699, and V-82139.  Checks now properly test for LTSB/LTSC editions of Windows 10.
* Fixed issue 23 - Windows 10 V-63577.  Check now properly marks status as NA if not a domain member.
* Fixed issue 24 - Windows 10 V-63591.  Check now properly marks status as NA if Windows 10 version is 1803 or greater.
* Fixed issue 25 - Windows 10 V-77083.  Check will now start the WinRM service before running Get-ComputerInfo.
* Fixed issue 26 - Windows Server 2016 V-90355.  Check will now start the WinRM service before running Get-ComputerInfo.
* Fixed issue 27 - Windows Server 2019 V-93229.  Check will now start the WinRM service before running Get-ComputerInfo.
* Fixed issue 28 - Windows 10 V-63681.  Check now records proper policy setting name and allows for values "DoD Notice and Consent Banner" and "US Department of Defense Warning Statement" as compliant values.
* Modified check code for V-76771 in the IIS 8.5 Server module to check if URL Authorization feature is enabled.  Cannot enumerate rules without this.  Also changed query to /system.web/authorization.
* Modified check code for V-100185 in the IIS 10.0 Server module to check if URL Authorization feature is enabled.  Cannot enumerate rules without this.
* Added check code for V-1089 and V-26359 in the Windows Server 2012 R2 module.
* Added check code for V-73647 and V-73649 in the Windows Server 2016 module.
* Added check code for V-93147 and V-93149 in the Windows Server 2019 module.

## **06-16-2020**

* Updated for Microsoft Windows 10 V1R22 STIG.
* Updated for Microsoft Windows Defender Antivirus V1R9 STIG.
* Updated for Microsoft Windows Server 2012 R2 DC V1R20 STIG.
* Updated for Microsoft Windows Server 2012 R2 MS V1R18 STIG.
* Updated for Microsoft Windows Server 2016 V1R11 STIG.
* Updated for Microsoft Windows Server 2019 V1R4 STIG.
* Updated Evaluate-STIG_Savings_Calculator_and_CKL_Metrics.xlsx with current CKL metrics.
* Fixed issue 17 - Microsoft PowerPoint 2016 v-70669.  Check was only validating that the registry value name did not exist and not a proper value if exists.
* Fixed issue 18 - Microsoft Word 2016 V-71083.  Check was only validating that the registry value name did not exist and not a proper value if exists.  Also check was not validating secondary registry value.

## **05-12-2020**

* Added new option "-RemoteComputer".  This will copy the Evaluate-STIG content to the remote computer and execute the scan as the SYSTEM account.  Requires WinRM and admin rights on remote system.
* Added support for McAFee VirusScan 8.8 Local Client STIG.
* Added support for Windows Server 2019 STIG.  This requires SCC for now.  Thanks to Leith Tussing for providing the scan module.
* Added support for Microsoft IIS 10.0 Server and Site STIGs.  Thanks to Leith Tussing for providing the scan modules.
* Added Test-XmlValidation function to validate xml against xsd.  Created .xsd files for STIGList.xml and answer files.  Evaluate-STIG will pre-validate these files before running.
* Updated STIGList.xml by replacing **\<Name\>** element with "Name" attribute for each STIG.  This was required to properly validate it against the defined schema.
* Updated STIGList.xml by replacing "True" with "true" in the Enabled attribute for each STIG.  Lower case "true"/"false" is required to validate a boolean value in the .xsd standard.
* Updated for One Drive for Business 2016 V1R3
* Updated for Windows 10 V1R21
* Updated for IIS 8.5 Server V1R10
* Updated for IIS 8.5 Site V1R10
* Updated for Windows Defender Antivirus V1R8
* Fixed issue in IIS 8.5 Server V-76689 where Evaluate-STIG was incorrectly looking for a custom field named "User-Agent".
* Fixed issue in IIS 8.5 Server V-76765 where if PasswordLastSet is null, the check would fail.
* Fixed issue in IIS 8.5 Site V-76791 where the log format was not being documented in Finding Details.
* Fixed issue in IIS 8.5 Site V-76801 where file extensions were not being properly enumerated.
* Fixed issue in IIS 8.5 Site V-76849 where Evaluate-STIG would not find the certificate if it was not in the machine's Personal store.
* Fixed issue in IIS 8.5 Site V-76885, V-76887, and V-76889 where the check would fail if the virtual folder still existed but the physical path did not.
* Fixed issue in Mozilla Firefox V-15772 not parsing the configured setting correctly.
* Fixed issue in Windows Server 2016 V-73249 where status may not be properly set.
* Fixed issue in Windows Server 2016 V-73251 where status may not be properly set.
* Fixed issue in Windows Server 2016 V-73253 where status may not be properly set.
* Updated all scripts to support PowerShell 7.  Note that PowerShell 6 is not supported.
* Updated to remove Evaluate-STIG modules from memory after completion.
* Updated .NET 4 V-7055 to look for the existence of any values instead of keys.  This is how SCAP is checking it.
* Updated IIS 8.5 Server V-76755 to mark as Open if any one of the values is not configured.
* Updated IIS 8.5 Site V-76885, V-76887, and V-76889 to only check the web site being scanned instead of enumerating all web sites.
* Updated Windows 10 V-63353 to only evaluate drive types of "2" (removable disk) and "3" (local disk).
* Updated Windows 10 V-63373 by reverting back to icacls for permission check.  This is how the STIG has us check and is consistent with similar checks in Server 2016 and Server 2019.
* Updated Windows 10 V-63399 to consider Windows Defender Firewall profile states if no 3rd-party firewall is registered.
* Updated Windows 10 V-63533, V-63537, and V-63541 to get event log path from Get-WinEvent and better detect location of the log files.
* Updated Windows 10 V-77083 to include the -NoProfile option to prevent the user profile from being loaded.
* Updated Windows 10 Exploit Protection checks (V-77091 through V-77269) to mark as NA if scantype is not "Unclassified".
* Updated Windows 10 V-94719 to properly check both registry values identified in the STIG.
* Updated Windows 10 V-99555 to mark as Open if PasswordLastSet is empty meaning it has never been set and to check all enabled local accounts that are in the Administrators group.
* Updated Windows Server 2016 V-73241 to consider Windows Defender Antivirus as a valid antivirus solution.
* Updated Windows Server 2016 V-90355 to include the -NoProfile option to prevent the user profile from being loaded.
* Updated to pass $UserSID variable to Get-CorporateComment.  You can instruct Answer Files to validate registry values for the user profile being scanned by using "HKLM:\SOFTWARE\Evaluate-STIG_UserHive\$($UserSID)\" as the beginning of the registry path.  "$UserSID" can also be included in the ApprovedComment and Evaluate-STIG will convert that to the SID of the profile that was scanned.
* Updated user registry import process to hopefully better perform on larger registry files.
* Updated Internet Explorer 11 detection code in STIGList.xml to look for the existence of iexplore.exe instead of the registry.  Removing Internet Explorer 11 from Windows Server 2016 using DISM removes the file but the registry value remains causing Evaluate-STIG from falsely detecting IE11 STIG as required.
* Changed working directory from %windir%\temp to %windir%\temp\Evaluate-STIG.  Note that the Evaluate-STIG log for troubleshooting will be found here now.
* Created workaround for issue where -DeleteExpiredTaskAfter is not removing the scheduled task on Windows Server 2016.  The "Evaluate-STIG (As SYSTEM)" task will now be removed directly after script completion instead of 9 hours after task creation.  Appears to be a bug in Server 2016 - <https://github.com/dahall/TaskScheduler/issues/840>
* Reformatted code to Stroustrup style and removed unnecessary whitespace.
* Renamed "Send-CheckResults" to "Send-CheckResult"
* Renamed "New-CKL" to "Write-CKL"
* Updated aliases to full command names ('Where-Object' instead of 'Where', etc.)
* Removed unused variables
* Replaced 'Get-WmiObject' with 'Get-CimInstance'

## **03-12-2020**

***IMPORTANT: Answer File format and usage has changed:***

* ScanType no longer drives answer file decisions and has been replaced with [AnswerKey].
* [AnswerKey Name="abc123"] is a user defined name to allow Comments to be segregated to specific environments.  Multiple [AnswerKey] elements can be specified for each Vuln ID to allow for single answer files to be used across multiple environments (e.g. RDT&E, COI, SDREN, etc.)
* A new switch, "-AnswerKey", can be used to instruct Evaluate-STIG which AnswerKey to use during its scan.  If not specified, "DEFAULT" will be used.
* You can create an AnswerKey named "DEFAULT" within an answer file that Evaluate-STIG will fall back to in the event that there is not another matching AnswerKey for the Vuln ID.  This is good for global Comments that may apply to all of your environments.
* In the event that an answer file has a Vuln ID where both a named answer key and a "DEFAULT" key exist, the named answer key will be the winner.
* [STIGComments Name] must match the [Name] element for the STIG in STIGList.xml.  Evaluate-STIG will automatically use the answer file that matches the STIG name.  Configuring the AnswerFile file name in STIGList.xml is no longer needed.

***IMPORTANT: STIGList.xml changes:***

* [STIG Enabled] added to globally enabled/disable a STIG.  Set to TRUE/FALSE.  STIGs are no longer disabled by Config.ini.  Typically all STIGs should be Enabled="TRUE" and let Evaluate-STIG detect applicability.  Only set to "FALSE" if you never want a checklist for the STIG.
* [AnswerFile] element removed.  Answer file will be automatically selected if the [Name] in STIGList.xml matches [STIGComment Name] in an answer file.

### Other Changes

* Updated for Windows 10 V1R20 (NOTE: Exploit Protection Mitigation "check text" were all updated in the STIG except for V-77245.  But, the DOD_EP_V3.xml file included with the Windows 10 v1r20 STIG is configuring the setting similar to the updated checks.  Evaluate-STIG assumes the text for V-77245 not being updated was an error on DISA and views the setting that DOD_EP_V3.xml configures as compliant.)
* Removed Crane's Answer Files from the archive.  Only those with "DEFAULT" answer keys are included now.  Crane's will be moved to a separate Sample Answer Files folder on the SPORK page.
* Removed Documentation folder from the archive.  Documentation will be moved to a separate Documentation folder on the SPORK page.
* Removed SCCM folder from the archive.  SCCM folder will be moved to a separate Deployment folder on the SPORK page.
* Removed SCCM section from Evaluate-STIG_Documentation.pdf.  This is being rewritten and will be uploaded as a separate document in the future.
* Updated to support SCC 5.3 for SCAP scans.
* Changed -ScanType switch to only accept "Classified" or "Unclassified".  Unclassified is the default if not specified.
* Added comment based help to Evaluate-STIG.ps1.  To view, run "Get-Help .\Evaluate-STIG.ps1 -Full"
* Added -OutputPath switch to set where Evaluate-STIG saves results.
* Added function Get-GroupMembership.  Get-LocalGroupMember has a bug where it can fail on domain systems not currently connected to the network.
* Changed default output path to be "C:\Users\Public\Documents\STIG_Compliance" to help better retain Comments when multiple admins are responsible for a system.
* Updated prerequisite check to only require SCC if an applicable STIG has the Benchmark element configured in STIGList.xml.
* Updated AppLocker policy export process to continue if the AppLocker module is not available.  Some editions of Windows do not support configuring AppLocker with group policy and the PowerShell module is not available.
* Updated Evaluate-STIG documentation to identify SCC as a requirement for Windows Server OS only.
* Updated Evaluate-STIG documentation to identify STIG Viewer 2.9.1 or greater as a requirement for opening resultant checklist files.
* Updated Evaluate-STIG documentation to identify PowerShell 5.1 only.  Evaluate-STIG will eventually be updated to support PowerShell 7.
* Updated Evaluate-STIG documentation to reflect core usage changes.
* Updated to include Standalone Workstation (0) and Standalone Server (2) as valid domain roles when writing to Evaluate-STIG.log.
* Updated Java JRE 8 V-66959 to better support exception.sites path formats.
* Updated Windows 10 V-63405.  When Account Lockout Duration is configured to 0, SecEdit.exe reports it as "-1".  Updated this check to replace "-1" with 0 so that the status will be reported correctly.
* Updated Windows 10 V-72765 and V-72767 to temporarily enable and start the "bthserv" service so that radio state can be determined.  Service will be returned to previous state after the check is complete.
* Updated Windows 10 V-72769 to check HKCU\SOFTWARE\Microsoft\BluetoothAuthenticationAgent\AcceptIncomingRequests.  A value of '0' means the option is not checked and would be a finding.  Any other value or if the valuename does not exist means the option is checked and not a finding.
* Updated Windows 10 checks that used Get-LocalGroupMember to use Get-GroupMembership instead.
* Updated Server 2016 checks that used Get-LocalGroupMember to use Get-GroupMembership instead.
* Fixed issue where a space in the user profile being scanned would cause multiple failures.
* Fixed Windows 10 V-63581.  Was checking for a value of '0' instead of '1'.
* Fixed Server 2016 V-73227 to mark as NA if Backup Operators has no members.
* Fixed Server 2016 V-73235 to mark as NA if ScanType is not "Unclassified".
* Fixed Server 2016 V-73237 to mark servers that are not domain systems (domain role 3, 4, or 5) as NA.
* Fixed Server 2016 V-73513 to mark servers that are not domain systems (domain role 3, 4, or 5) as NA.
* Fixed Server 2016 V-73515 to mark servers that are not domain Member Server (domain role 3) as NA.
* Removed Version from Config.ini.  Version is coded in Evaluate-STIG.ps1
* Removed [STIGsToEval] section from Config.ini.  STIGs are now enabled/disabled through STIGList.xml.
* Removed Divisions feature from Evaluate-STIG.
* Removed ResultsPath from Config.ini.  Use -OutputPath switch to set output path.
* Consolidated [xxxxScanOptions] in Config.ini to [UnclassifiedScanOptions] and [ClassifiedScanOptions].

## **02-03-2020**

* Updated for Google Chrome V1R18
* Updated for Windows Defender Antivirus V1R7
* Updated for Windows Server 2012 and 2012 R2 DC V2R19
* Updated benchmark for Windows Server 2012 and 2012 R2 MS V2R18
* Updated for Windows Server 2016 MS DC V1R10
* Updated for Mozilla Firefox V4R28
* Added check to ensure only one instance of Evaluate-STIG is running at a time.
* Added support for Mozilla Firefox V-15770.  Will check pluginreg.dat of the user profile being processed.
* Added support for Mozilla Firefox V-15773.  Will check pluginreg.dat of the user profile being processed.
* Added Scan-WindowsFirewall_Checks module which includes all Windows Firewall SCAP checks.
* Added Scan-Scan-WindowsDefenderAntivirus_Checks module which includes all Windows Defender Antivirus SCAP checks.
* Added limited support for Windows Firewall V-36440.  If system is not a domain workstation, finding will be marked as NA per the STIG.
* Added sample answer file for Mozilla Firefox.
* Added function Confirm-DefaultAcl to compare current file system and registry ACLs to expected defaults.
* Added Rule ID to all Scan Module checks.  This is for internal use to assist in future updates for STIG releases.
* Updated how manual check functions are detected which greatly reduces scan times.
* Updated documentation to include step-by-step instructions on creating and updating Evaluate-STIG as a Microsoft SCCM Application for a NetworkUnclass ScanType deployment.
* Updated STIGList.xml to perform registry checks for Office 2016 detection.
* Updated STIGList.xml to better target systems where Windows Defender Antivirus could be installed (Windows 10 or Server 2016 and greater).
* Updated all checks that use Get-RegistryResult function to display both hex and decimal values for DWORD items in Finding Details.
* Updated Scan-MozillaFirefox_Checks module to include Mozilla Firefox SCAP checks.
* Updated Scan-GoogleChrome_Checks module to include Google Chrome SCAP checks.
* Updated Scan-IE11_Checks module to include Internet Explorer 11 SCAP checks.
* Updated Scan-Windows10_Checks module to include Windows 10 SCAP checks.
* Updated Internet Explorer 11 V-46477 to mark as NA if classified ScanType.
* Updated Java JRE 8 V-66965 to list all Java 8 JRE's installed in Finding Details and mark as Open if more than one DisplayVersion is found.
* Updated Windows 10 V-63323 to mark as NA if system is not domain joined.
* Updated Windows 10 V-63337 to include additional BitLocker detail.
* Updated Windows 10 V-63367 to include account Enabled flag.
* Updated Windows 10 V-63373 to use Confirm-DefaultAcl.  Validated default file permissions against non-modified/non-STIG'd instances of Windows 10 version 1709-1909.
* Updated Windows 10 V-63593 to use Confirm-DefaultAcl.  Validated default registry permissions against non-modified/non-STIG'd instances of Windows 10 version 1709-1909.  Note that HKLM:\SOFTWARE, OS seems to override GPO settings for CREATOR OWNER and once "SubKeys only" is set, it doesn't appear possible to revert back to "This key and subkeys".  Because of this, either will be considered compliant for this finding.
* Updated Windows 10 V-63599 to mark as NA if system is not domain joined.
* Updated Windows Server 2012 V-3245 to allow for share type of "3221225472".  These are system created shares for clustered disks.
* Updated Windows Server 2016 V-73267 to allow for share type of "3221225472".  These are system created shares for clustered disks.
* Updated Scan-Access2016_Checks module to include setting sub-state in Finding Details where applicable.
* Updated Scan-Excel2016_Checks module to include setting sub-state in Finding Details where applicable.
* Updated Scan-OfficeSystem2016_Checks module to include setting sub-state in Finding Details where applicable.
* Updated Scan-OneDriveForBusiness2016_Checks module to include setting sub-state in Finding Details where applicable.
* Updated Scan-OneNote2016_Checks module to include setting sub-state in Finding Details where applicable.
* Updated Scan-Outlook2016_Checks module to include setting sub-state in Finding Details where applicable.
* Updated Scan-PowerPoint2016_Checks module to include setting sub-state in Finding Details where applicable.
* Updated Scan-Project2016_Checks module to include setting sub-state in Finding Details where applicable.
* Updated Scan-Publisher2016_Checks module to include setting sub-state in Finding Details where applicable.
* Updated Scan-Visio2016_Checks module to include setting sub-state in Finding Details where applicable.
* Updated Scan-Word2016_Checks module to include setting sub-state in Finding Details where applicable.
* Fixed IE 11 V-46815 was not checking for "FormSuggest PW Ask" registry value.
* Fixed spelling errors in answer files.
* Fixed issue when passing Answer File paths that contain spaces.
* Fixed issue where standard comments were being incorrectly preserved as administrator comments on SCAP-based items marked as Open.
* Fixed progress bar calculation issue.
* Fixed issue in Get-InstalledSoftware function where a corrupt registry value causes Get-ItemProperty failures.
* Removed benchmark content for Internet Explorer 11.  All checks performed as code now.
* Removed benchmark content for Google Chrome.  All checks performed as code now.
* Removed benchmark content for Mozilla Firefox.  All checks performed as code now.
* Removed benchmark content for Windows 10.  All checks performed as code now.
* Removed benchmark content for Windows Defender Antivirus.  All checks performed as code now.
* Removed benchmark content for Windows Firewall.  All checks performed as code now.

## **12-11-2019**

* Fixed issue where STIG detection was not working correctly on some configurations.

## **12-09-2019**

* PowerShell 5.1 or greater now required for Evaluate-STIG.
* Included a time/cost saving spreadsheet to calculate estimated annual savings.
* Begin to remove SCAP dependency from Evaluate-STIG.  This will be an ongoing process as Evaluate-STIG moves to pure code-based checks.
* Added step to generate a list of the machine.config and *.exe.config files under %WINDIR%\Temp\Evaluate-STIG_Net4FileList.txt.  All .NET 4 checks will reference this list for files to process which should reduce scan times.
* Added standard comment for all checks determined as Not A Finding or Not Applicable by either benchmark or scan module.  Note that any comment configured in an Answer File will overwrite this standard comment.
* Changed $FindingResults variable to $FindingDetails in all scripts to match the field name in the checklist.
* Updated Scan-AdobeReaderDC_Checks module to include Adobe Reader DC SCAP checks and removed the benchmark content.
* Updated Scan-NETFramework4_Checks module to include .NET Framework 4 SCAP checks and removed the benchmark content.
* Updated .NET Framework 4 V-7067 to set to NA if only the operating system (COTS) default StrongName keys are configured.
* Updated Java JRE 8 V-66723 to mark as NA if classified ScanType.
* Updated Java JRE 8 V-66949 to mark as NA if classified ScanType.
* Updated Java JRE 8 V-66951 to mark as NA if classified ScanType.
* Updated Java JRE 8 V-66953 to mark as NA if classified ScanType.
* Updated Java JRE 8 V-66959 to mark as NA if classified ScanType.
* Updated Java JRE 8 V-66961 to mark as NA if classified ScanType.
* Updated IIS 8.5 Server V-76701 to use Get-InstalledSoftware function for software list.
* Updated IIS 8.5 Server V-76751 to use Get-InstalledSoftware function for software list.
* Updated Windows 10 V-63359 to get LAPS account name from registry and add it to ignore list.
* Updated Windows 10 V-63365 to detect common 3rd-party hypervisors.  If any are found, they will be listed and the status marked as Not_Reviewed
* Updated Windows 10 V-63367 to view any local user account that is a member of local Administrators as a compliant account.
* Updated Windows 10 V-77083 to get BIOS mode from Get-ComputerInfo.  SCCM client no longer required for this check.
* Updated Windows 10 V-77085 to get Secure Boot from Confirm-SecureBootUEFI.  SCCM client no longer required for this check.
* Updated Windows Server 2016 V-73227 to use Get-ADGroupMember on domain controllers.
* Updated Windows Server 2016 V-90355 to get BIOS mode from Get-ComputerInfo.  SCCM client no longer required for this check.
* Updated Windows Server 2016 V-90357 to get Secure Boot from Confirm-SecureBootUEFI.  SCCM client no longer required for this check.
* Fixed issue where STIG items not supported by benchmark and scan module were not verifying ExpectedStatus in Answer File against status in checklist before applying Comment.
* Fixed .NET Framework 4 V-7070 looking for incorrect file data.
* Fixed .NET Framework 4 V-30926 looking for incorrect file data.
* Fixed .NET Framework 4 V-30935 not looking for both registry values on 64-bit systems.
* Fixed .NET Framework 4 V-30937 looking for incorrect file data.
* Fixed .NET Framework 4 V-30968 looking for incorrect file data.
* Fixed .NET Framework 4 V-30972 looking for incorrect file data.
* Fixed .NET Framework 4 V-31026 looking for incorrect file data.
* Fixed .NET Framework 4 V-32025 looking for incorrect file data.
* Fixed IIS 8.5 Site V-76789 looking for incorrect Custom Fields.
* Fixed IIS 8.5 Site V-76791 looking for incorrect Custom Fields.
* Fixed IIS 8.5 Site V-76885 not being set to NotAFinding when no script files are found.
* Removed .NET Framework 4 V-7069 custom check.  Moved to a sample Answer File.
* Removed .NET Framework 4 V-30986 custom check.  Moved to Answer File and will set to Open as no feasible process has been identified to meet the STIG requirement.

## **11-07-2019**

* Updated for Google Chrome V1R13
* Updated for Microsoft .NET Framework 4 V1R9
* Updated for Microsoft IIS 8.5 Server V1R9
* Updated for Microsoft IIS 8.5 Site V1R9
* Updated for Microsoft Internet Explorer 11 V1R18
* Updated for Windows 10 V1R19
* Updated for Windows Server 2012 R2 DC V2R18
* Updated for Windows Server 2012 R2 MS V2R17
* Updated for Mozilla FireFox Windows V4R27
* Added -RunSYSTEM switch to run Evaluate-STIG as a Scheduled Task under the SYSTEM account.  This is a workaround for some SPAWAR hosted systems not being able to properly run cscc.exe.  Scheduled task will be automatically deleted 9 hours after creation.
* Replaced Config_STIGtoTemplateMap.xml with STIGList.xml  STIGList.xml is now the master file for linking all of the components to each STIG.  See documentation for details.
* Improved code to detect which STIGs are applicable to the system before running.  This way, benchmarks for non-applicable STIGs will no longer be installed/scanned.
* Removed Generate-Ckl.psm1 as it is no longer required.
* Added [STIGsToEval] section in Config.ini to allow for selectively disabling STIGs that environments may not require (e.g. Windows Firewall).
* Code improvements and consolidation.
* STIGs are now processed from start to finish before moving to the next * benchmark (if available), then importing the SCAP results, then running check code for each Not Reviewed finding.
* Improved logging.
* Updated all functions to conform to PowerShell's Verb-Noun formatting.
* Benchmark name and release info now added to Finding Details for SCAP checked items.
* Added XML load and parse check step during initialization to identify any malformed XML content before continuing.

## **09-26-2019**

* Changed benchmark installation process to hopefully get around SCC install failures

## **09-24-2019**

* Added progress bars while script is running to provide user feedback when ran interactively.
* Changed several checks that relied on root\cimv2\SMS WMI calls.  This class is only available with the Microsoft SCCM client is installed.  This change should allow more checks to happen on systems without SCCM.
* Updated user detection to prefer profile that processed GPO, then profile last used, then as last resort use the .DEFAULT profile.  .DEFAULT will most likely result in a lot of opens.
* Cleaned up some output to the console that was confusing.
* Updated documentation to include special notes about certain checks.
* Improved error handling.
* Fixed issue with answer files not detecting the vuln ID/scantype properly.

## **08-08-2019**

* Updated for Adobe Acrobat Reader DC Continuous V1R6
* Updated for Google Chrome V1R16
* Updated for Mozilla FireFox V4R26
* Updated for .NET Framework 4 V1R8
* Updated for Internet Explorer 11 V1R17
* Updated for IIS 8.5 Server V1R8
* Updated for IIS 8.5 Site V1R8
* Updated for Windows 10 V1R18
* Updated for Windows Server 2012 R2 DC V2R17
* Updated for Windows Server 2012 R2 MS V2R16
* Updated for Windows Server 2016 V1R9
* Updated for Windows Defender Antivirus V1R6

## **08-05-2019**

* Tool now requires SCAP Compliance Checker (SCC) 5.2.
* Changed how registry permissions are read.  Get-Acl does not work when run as user on a properly configured HKLM:\SECURITY.
* Improved code for Windows 10 V-63393 to validate detected files are actually certificate files.
* Improved code for Windows 10 V-63357 to better detect system-created shares.
* Improved code for Windows 10 V-72765 to better detect NA status.
* Improved code for Windows Server 2012 V-3245 to better detect system-created shares.
* Improved code for Windows Server 2016 V-73267 to better detect system-created shares.
* Added checks for Windows 10:
  * V-72767, V-72769
* Added checks for Windows Server 2012:
  * V-42420, V-57637
* Added checks for Windows Server 2016:
  * V-73279
* Added checks for Mozilla Firefox
  * V-6318 (if configured in .cfg file)
* Added ability to inject standardized comments through answer files.
* Added answer files for:
  * Adobe Acrobat Reader DC Continuous Track
  * Google Chrome Current Windows
  * IIS 8.5 Server
  * Oracle JRE 8
  * Windows 10
  * Windows 2012 DC
  * Windows 2012 MS
  * Windows Server 2016
* Added manual check modules for Office 2016 products.  DISA pulled the benchmarks and some of the old benchmarks crash SCC 5.2.
* Changed how users settings are evaluated as RSoP was showing inconsistencies in testing.  User's hive will now be exported and imported to HKLM:\SOFTWARE\Evaluate-STIG_UserHive and evaluation performed there.

## **06-12-2019**

* Re-created all checklist templates with STIG Viewer 2.9
* Added checks for Adobe Reader DC Continuos:
  * V-65673, V-65675, V-65679
* Added checks for Internet Explorer 11:
  * V-46477, V-46807, V-46815
* Added checks for Windows 10:
  * V-63345, V-63365, V-63839, V-63841, V-82137
* Added checks for Windows Server 2012/2012R2:
  * V-3481, V-14268, V-14269, V-14270, V-15727, V-16021, V-16048, V-36656, V-36657, V-36776, V-36777
* Added checks for Windows Server 2016:
  * V-73235, V-73727
* Added support for Mozilla FireFox Windows V4R25.
* Fixed issue with Windows 10 V-63359 incorrectly detecting disabled accounts as enabled.
* Updated for Microsoft Windows Server 2016 MS DC V1R8.
* Updated for Microsoft Windows Server 2012 and 2012 R2 DC V1R16.
* Updated for Microsoft Windows Server 2012 and 2012 R2 MS V1R15.
* Updated for Microsoft IIS 8.5 Server V1R7.
* Updated for Microsoft IIS 8.5 Site V1R7.
* Updated for Microsoft Internet Explorer V1R17.
* Updated for Microsoft .NET Framework 4 V1R7.
* Updated for Microsoft Windows 10 v1r17.
* Updated for Microsoft Windows Defender Antivirus V1R5.
* Benchmarks are now processed/scanned individually as a workaround for some scans terminating unexpectedly.
* Tool will force a group policy refresh before starting scan to ensure GPO is applying successfully.
* Tool can support user-based checks by parsing RSoP.
* Tool now identifies user with most recent NTUSER.pol file for user checks.
* Tool generates GPResult reports for detection of user checks and as A&A artifact.
* Tool generates AppLocker policy XML report for Windows 10/Server 2016 checks and as A&A artifact.
* SCC options are now set individually.
* Tool will now only preserve one set of previous scan history to prevent disk bloat.
* Files not created during the scan process will be moved to the Previous folder.  E.g. .ckl files no longer applicable.
* Checklists are now worked in %WINDIR%\Temp until complete then moved to final destination.
* Script options moved to Config.ini to reduce modifications to PowerShell code.
* Increased timeouts for some processes.

## **03-21-2019**

* Added exit codes...
  * [10009995] - A timeout occurred.  Check %WINDIR%\Temp\Evaluate-STIG.log
  * [10009996] - Results destination path not found.
  * [10010000] - CSCC.exe encountered an error.  Check %WINDIR%\Temp\Evaluate-STIG.log
  * [10010001] - An error occurred.  Check %WINDIR%\Temp\Evaluate-STIG.log
* Fixed issue where some checks could cause a System.OutOfMemoryException error.

## **03-01-2019**

* Updated exit codes for easier troubleshooting...
  * [10009990] - Unable to connect to domain (RDTE/SRDTE scans only).
  * [10009991] - Active Directory craneLabOU attribute does not contain valid data.
  * [10009992] - Powershell version is not supported.
  * [10009993] - SCAP Compliance Checker not installed.
  * [10009994] - SCAP Compliance Checker version not supported.

## **02-01-2019**

* Fixed issue in detecting IIS version if InetMgr.exe does not exist.  Changed to registry check instead.

## **01-30-2019**

* Fixed issue with StandAloneUnclass switch
* Updated for Google Chrome STIG V1R15
* Updated for Microsoft IIS 8.5 Server STIG V1R6
* Updated for Microsoft IIS 8.5 Site STIG V1R6
* Updated for Microsoft Windows 10 V1R16
* Updated for Microsoft Windows 2012 and 2012 R2 DC STIG V2R15
* Updated for Microsoft Windows Server 2016 MS DC V1R7

## **01-09-2019**

* Added checklist template for IIS 8.5 Server
* Added checklist template for IIS 8.5 Site
* Added Scan-IIS85_Server_ManualChecks.psm1 for IIS 8.5 Server STIG V1R5
* Added Scan-IIS85_Site_ManualChecks.psm1 for IIS 8.5 Site STIG V1R5
* Added ability to run scan for StandAlone, RDTE, or SRDTE.  Run the script with the -ScanType parameter:

## **12-17-2018**

* Added benchmark and checklist template for Google Chrome
* Added Scan-GoogleChrome_ManualChecks.psm1 for Google Chrome STIG V1R14
* Updated benchmark content for 2018_11 STIGs
* Updated Scan-Windows10_ManualChecks.psm1 for Windows 10 STIG V1R15

## **11-01-2018**

* Fixed issue with CKL output files truncating part of the STIG version
* Updated benchmark content for 2018_10 STIGs
* Updated CKL templates recreated with STIG Viewer 2.8
* Updated Scan-NETFramework4_ManualChecks.psm1 for .NET Framework 4 STIG V1R6
* Updated Scan-WindowsServer2016_ManualChecks.psm1 for Windows Server 2016 STIG V1R6

## **09-10-2018**

* Initial release
