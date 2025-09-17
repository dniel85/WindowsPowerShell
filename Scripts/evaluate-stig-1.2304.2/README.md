# **Evaluate-STIG**

**Note:** SIPR download location for Evaluate-STIG is <https://intelshare.intelink.sgov.gov/sites/NAVSEA-RMF>

Evaluate-STIG is available for use by United States federal agencies and their supporting contractors (foreign and domestic) that are required to comply with STIG guidelines.

Evaluate-STIG is a suite of PowerShell scripts intended to automate the creation of Security Technical
Implementation Guide (**STIG**) checklists. Use of Evaluate-STIG can greatly reduce or eliminate the manual
efforts typically required when documenting compliance into STIG Viewer compatible checklist files (**CKL**) while
providing more complete, accurate, and consistent results. It will automatically detect which STIGs are
required for the asset being scanned ensuring the applicable CKLs are created. Documentation that used to
take hours or days can now be completed in minutes.

Finding Details for each STIG item will be populated with the system's actual configuration and the appropriate
Status determined for the Check. To increase automation, user-defined Answer Files may be configured to
insert standardized verbiage into the Comments section for STIG items that are policy based or mitigation
and/or justification documentation for known open items.

Each run of the Evaluate-STIG will automatically create a backup of existing checklists and preserve previous
administrator Comments for Open and Not Reviewed items. Unless defined in an Answer File, STIG checks that
are not supported by Evaluate-STIG will remain as Not Reviewed regardless of the previous checklist's status
but the administrator comments will be retained. This is to ensure that Not Reviewed items are validated each
quarter and identify configuration drift.

Evaluate-STIG can validate both computer and user settings. For user settings, the script identifies the most
recent user profile that group policy was updated or the last user to log on and creates a temporary copy of
the user's registry hive to HKLM:\Evaluate-STIG_UserHive\<SID>. The script searches this temporary copy to
validate if the setting is configured per STIG. The temporary copy will be removed at the end of processing.

## **Requirements**

* ### **Supported Operating Systems**

  * **Windows**
    * Windows 10
    * Windows 11
    * Windows Server 2008 R2
    * Windows Server 2012
    * Windows Server 2012 R2
    * Windows Server 2016
    * Windows Server 2019
    * Windows Server 2022
  * **Linux**
    *Note: Requires* **libicu** *and* **lshw** *be installed.* `apt install libicu lshw -y` *or* `yum install libicu lshw -y` *or* `dnf install libicu lswh -y`
    * Oracle Linux 7
    * Oracle Linux 8
    * RHEL/CentOS 7
    * RHEL 8
    * Ubuntu 16.04 LTS
    * Ubuntu 18.04 LTS
    * Ubuntu 20.04 LTS

* ### **PowerShell**

* PowerShell 5.1 | PowerShell 7.x or greater (PowerShell 6 is not supported)
  * *Note: Using* **Evaluate-STIG_Bash.sh**, *PowerShell is not required to be "installed" on Linux systems.*

* ### **SQLPS or SqlServer PowerShell Module**

  * SQLPS typically installed by default on SQL servers
  * Evaluate-STIG will use either
  * Only required on systems with SQL installed

* ### **STIG Viewer** (for viewing completed checklists)

  * STIG Viewer 2.17 or greater

## **Supported STIGs**

* Adobe Acrobat Pro XI
* Adobe Acrobat Professional DC Classic Track
* Adobe Acrobat Professional DC Continuous Track
* Adobe Reader DC Classic Track
* Adobe Reader DC Continuous Track
* Apache Server 2.4 UNIX Server
* Apache Server 2.4 UNIX Site
* Apache Server 2.4 Windows Server
* Apache Server 2.4 Windows Site
* Cisco IOS XE Router NDM
* Cisco IOS XE Switch L2S
* Cisco IOS XE Switch NDM
* Google Chrome Current Windows
* McAfee ENS 10.x Local Client ++
* McAfee VirusScan 8.8 Local Client
* Microsoft .NET Framework 4
* Microsoft Access 2013
* Microsoft Access 2016
* Microsoft Active Directory Domain
* Microsoft Active Directory Forest
* Microsoft Defender Antivirus
* Microsoft Edge
* Microsoft Excel 2013
* Microsoft Excel 2016
* Microsoft Exchange 2016 Edge Transport Server
* Microsoft Exchange 2016 Mailbox Server
* Microsoft Groove 2013
* Microsoft IIS 8.5 Server
* Microsoft IIS 8.5 Site
* Microsoft IIS 10.0 Server
* Microsoft IIS 10.0 Site
* Microsoft InfoPath 2013
* Microsoft Internet Explorer 11
* Microsoft Lync 2013
* Microsoft Office 365 ProPlus
* Microsoft Office System 2013
* Microsoft Office System 2016
* Microsoft One Drive for Business 2016
* Microsoft OneNote 2013
* Microsoft OneNote 2016
* Microsoft Outlook 2013
* Microsoft Outlook 2016
* Microsoft PowerPoint 2013
* Microsoft PowerPoint 2016
* Microsoft Project 2013
* Microsoft Project 2016
* Microsoft Publisher 2013
* Microsoft Publisher 2016
* Microsoft SharePoint Designer 2013
* Microsoft Skype for Business 2016
* Microsoft SQL Server 2014 Database (excluding Express Edition)
* Microsoft SQL Server 2014 Instance (excluding Express Edition)
* Microsoft SQL Server 2016 Database (and greater)
* Microsoft SQL Server 2016 Instance (and greater)
* Microsoft Visio 2013
* Microsoft Visio 2016
* Microsoft Windows 10
* Microsoft Windows 11
* Microsoft Windows Firewall
* Microsoft Windows Server 2008 R2 MS
* Microsoft Windows Server 2012 and 2012 R2 DC
* Microsoft Windows Server 2012 and 2012 R2 MS
* Microsoft Windows Server 2016
* Microsoft Windows Server 2019
* Microsoft Windows Server 2022
* Microsoft Word 2013
* Microsoft Word 2016
* Mozilla FireFox (Linux and Windows)
* Oracle JRE 8 for Unix
* Oracle JRE 8 for Windows
* Oracle Linux 7
* Oracle Linux 8
* PostgreSQL 9.x
* RHEL/CentOS 7 (using RHEL 7 STIG)
* RHEL 8
* Ubuntu 16.04 LTS
* Ubuntu 18.04 LTS
* Ubuntu 20.04 LTS
* VMWare Horizon 7.13 Agent
* VMWare Horizon 7.13 Client
* VMWare Horizon 7.13 Connection Server

++ Separate download not included in Evaluate-STIG distributable.  May be downloaded from:

* NIPR - <https://intelshare.intelink.gov/sites/NAVSEA-RMF>
* SIPR - <https://intelshare.intelink.sgov.gov/sites/NAVSEA-RMF>
