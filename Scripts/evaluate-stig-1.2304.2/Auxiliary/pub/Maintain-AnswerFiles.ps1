<#
    .Synopsis
    Performs maintenance on Evaluate-STIG answer files.
    .DESCRIPTION
    Performs simple maintenance on Evaluate-STIG Answer Files.  Updates Vuln IDs to new STIGs that have been converted to DISA's new conten management system.  It also identifies and optionally removes answers for Vuln IDs that have been removed from the STIG.  Finally, it will convert answer files from previous format to new format compatible with 1.2104.3 and greater.

    Unless -NoBackup is specified, a backup of an answer file that is determined to need updating is automatically created with a .bak extension and stored in the same path as the answer file.
    .EXAMPLE
    PS C:\> .\Maintain-AnswerFiles.ps1 -ESPath 'C:\Evaluate-STIG'

    This will analyze all answer files found in ESPath\AnswerFiles and update Vuln IDs to new STIG Vuln IDs if required.  Answers for Vuln IDs no longer in the STIG will be noted but not changed.
    .EXAMPLE
    PS C:\> .\Maintain-AnswerFiles.ps1 -ESPath 'C:\Evaluate-STIG' -RemoveMissingVulnIDs

    This will analyze all answer files found in ESPath\AnswerFiles and update Vuln IDs to new STIG Vuln IDs if required.  Answers for Vuln IDs no longer in the STIG will be omitted from the updated answer file.
    .EXAMPLE
    PS C:\> .\Maintain-AnswerFiles.ps1 -ESPath 'C:\Evaluate-STIG' -RemoveMissingVulnIDs -NoBackup

    This will analyze all answer files found in ESPath\AnswerFiles and update Vuln IDs to new STIG Vuln IDs if required.  Answers for Vuln IDs no longer in the STIG will be omitted from the updated answer file.  Disables backup of answer files that are updated.
    .EXAMPLE
    PS C:\> .\Maintain-AnswerFiles.ps1 -ESPath 'C:\Evaluate-STIG' -AFPath '\\Server1\AnswerFiles' -RemoveMissingVulnIDs -NoBackup

    This will analyze all answer files found in \\Server1\AnswerFiles and update Vuln IDs to new STIG Vuln IDs if required.  Answers for Vuln IDs no longer in the STIG will be omitted from the updated answer file.  Disables backup of answer files that are updated.
    .INPUTS
    -ESPath
    Path to the Evaluate-STIG directory.  This is a required parameter.

    -AFPath
    Path that contains XML answer files.  If not specified, defaults to <ESPath>\AnswerFiles.

    -NoBackup
    Disables the creation of a backup file (.bak) for answer files that are updated.

    -RemoveMissingVulnIDs
    When specified, will automatically omit any vuln IDs in the current Answer File that is not in the STIG from the new Answer File.  Useful for cleaning up answers for STIG items that have been removed.  This parameter is optional.
    .LINK
    Evaluate-STIG
    https://spork.navsea.navy.mil/nswc-crane-division/evaluate-stig
#>
[CmdletBinding(DefaultParameterSetName='None')]
Param (
    [Parameter(Mandatory=$true)]
    [String]$ESPath,

    [Parameter(Mandatory = $false)]
    [String]$AFPath,

    [Parameter(Mandatory=$false)]
    [Switch]$NoBackup,

    [Parameter(Mandatory=$false)]
    [Switch]$RemoveMissingVulnIDs
    )

Function Test-XmlValidation {
    # Based on code samples from https://stackoverflow.com/questions/822907/how-do-i-use-powershell-to-validate-xml-files-against-an-xsd

    Param (
        [Parameter(Mandatory = $true)]
        [String] $XmlFile,

        [Parameter(Mandatory = $true)]
        [String] $SchemaFile
    )

    Try {
        Get-ChildItem $XmlFile -ErrorAction Stop | Out-Null
        Get-ChildItem $SchemaFile -ErrorAction Stop | Out-Null

        $XmlErrors = New-Object System.Collections.Generic.List[System.Object]
        [Scriptblock] $ValidationEventHandler = {
            If ($_.Exception.LineNumber) {
                $Message = "$($_.Exception.Message) Line $($_.Exception.LineNumber), position $($_.Exception.LinePosition)."
            }
            Else {
                $Message = ($_.Exception.Message)
            }

            $NewObj = [PSCustomObject]@{
                Message = $Message
            }
            $XmlErrors.Add($NewObj)
        }

        $ReaderSettings = New-Object -TypeName System.Xml.XmlReaderSettings
        $ReaderSettings.ValidationType = [System.Xml.ValidationType]::Schema
        $ReaderSettings.ValidationFlags = [System.Xml.Schema.XmlSchemaValidationFlags]::ProcessIdentityConstraints -bor [System.Xml.Schema.XmlSchemaValidationFlags]::ProcessSchemaLocation -bor [System.Xml.Schema.XmlSchemaValidationFlags]::ReportValidationWarnings
        $ReaderSettings.Schemas.Add($null, $SchemaFile) | Out-Null
        $readerSettings.add_ValidationEventHandler($ValidationEventHandler)

        Try {
            $Reader = [System.Xml.XmlReader]::Create($XmlFile, $ReaderSettings)
            While ($Reader.Read()) {
            }
        }
        Catch {
            $NewObj = [PSCustomObject]@{
                Message = ($_.Exception.Message)
            }
            $XmlErrors.Add($NewObj)
        }
        Finally {
            $Reader.Close()
        }

        If ($XmlErrors) {
            Return $XmlErrors
        }
        Else {
            Return $true
        }
    }
    Catch {
        Return $_.Exception.Message
    }
}

Function New-OldSchemaFile {
    $OldSchema = '<xs:schema attributeFormDefault="unqualified" elementFormDefault="qualified" xmlns:xs="http://www.w3.org/2001/XMLSchema">' | Out-String
    $OldSchema += '  <xs:element name="STIGComments">' | Out-String
    $OldSchema += '    <xs:complexType>' | Out-String
    $OldSchema += '      <xs:sequence>' | Out-String
    $OldSchema += '        <xs:element name="Vuln" maxOccurs="unbounded" minOccurs="0">' | Out-String
    $OldSchema += '          <xs:complexType>' | Out-String
    $OldSchema += '            <xs:sequence>' | Out-String
    $OldSchema += '              <xs:element name="AnswerKey"  maxOccurs="unbounded" minOccurs="1">' | Out-String
    $OldSchema += '                <xs:complexType>' | Out-String
    $OldSchema += '                  <xs:sequence>' | Out-String
    $OldSchema += '                    <xs:element type="xs:string" name="ApprovedComment" maxOccurs="1" minOccurs="1"/>' | Out-String
    $OldSchema += '                    <xs:element name="ExpectedStatus">' | Out-String
    $OldSchema += '                      <xs:simpleType>' | Out-String
    $OldSchema += '                        <xs:restriction base="xs:string">' | Out-String
    $OldSchema += '                          <xs:enumeration value="Not_Reviewed"/>' | Out-String
    $OldSchema += '                          <xs:enumeration value="Open"/>' | Out-String
    $OldSchema += '                          <xs:enumeration value="NotAFinding"/>' | Out-String
    $OldSchema += '                          <xs:enumeration value="Not_Applicable"/>' | Out-String
    $OldSchema += '                        </xs:restriction>' | Out-String
    $OldSchema += '                      </xs:simpleType>' | Out-String
    $OldSchema += '                    </xs:element>' | Out-String
    $OldSchema += '                    <xs:element name="FinalStatus">' | Out-String
    $OldSchema += '                      <xs:simpleType>' | Out-String
    $OldSchema += '                        <xs:restriction base="xs:string">' | Out-String
    $OldSchema += '                          <xs:enumeration value="Not_Reviewed"/>' | Out-String
    $OldSchema += '                          <xs:enumeration value="Open"/>' | Out-String
    $OldSchema += '                          <xs:enumeration value="NotAFinding"/>' | Out-String
    $OldSchema += '                          <xs:enumeration value="Not_Applicable"/>' | Out-String
    $OldSchema += '                        </xs:restriction>' | Out-String
    $OldSchema += '                      </xs:simpleType>' | Out-String
    $OldSchema += '                    </xs:element>' | Out-String
    $OldSchema += '                    <xs:element type="xs:string" name="ValidationCode"/>' | Out-String
    $OldSchema += '                  </xs:sequence>' | Out-String
    $OldSchema += '                  <xs:attribute type="xs:string" name="Name" use="required"/>' | Out-String
    $OldSchema += '                </xs:complexType>' | Out-String
    $OldSchema += '              </xs:element>' | Out-String
    $OldSchema += '            </xs:sequence>' | Out-String
    $OldSchema += '            <xs:attribute type="xs:string" name="ID" use="required"/>' | Out-String
    $OldSchema += '          </xs:complexType>' | Out-String
    $OldSchema += '          <xs:unique name="AnswerKeyUniqueKey">' | Out-String
    $OldSchema += '            <xs:selector xpath="AnswerKey"/>' | Out-String
    $OldSchema += '            <xs:field xpath="@Name"/>' | Out-String
    $OldSchema += '          </xs:unique>' | Out-String
    $OldSchema += '        </xs:element>' | Out-String
    $OldSchema += '      </xs:sequence>' | Out-String
    $OldSchema += '      <xs:attribute type="xs:string" name="Name" use="required"/>' | Out-String
    $OldSchema += '    </xs:complexType>' | Out-String
    $OldSchema += '    <xs:unique name="VulnIdUniqueKey">' | Out-String
    $OldSchema += '      <xs:selector xpath="Vuln"/>' | Out-String
    $OldSchema += '      <xs:field xpath="@ID"/>' | Out-String
    $OldSchema += '    </xs:unique>' | Out-String
    $OldSchema += '  </xs:element>' | Out-String
    $OldSchema += '</xs:schema>' | Out-String
    $OldSchema | Out-File "$($env:temp)\ES_OldSchema.xsd"
}

Try {
    $ErrorActionPreference = "Stop"

    If (-Not($AFPath)) {
        $AFPath = Join-Path -Path $ESPath -ChildPath "AnswerFiles"
    }

    # Verify version of Evaluate-STIG is supported version.
    $SupportedVer = [Version]"1.2107.0"
    Get-Content (Join-Path -Path $ESPath -ChildPath "Evaluate-STIG.ps1") | ForEach-Object {
        If ($_ -like '*$EvaluateStigVersion = *') {
            $Version = [Version]((($_ -split "=")[1]).Trim() -replace '"','')
            Return
        }
    }
    If (-Not($Version -ge $SupportedVer)) {
        Throw "Error: Evaluate-STIG $SupportedVer or greater required.  Found $Version.  Please update Evaluate-STIG to a supported version before using this script."
    }

    # Validate STIGList.xml and answer file for proper schema usage.
    $STIGList_xsd = Join-Path -Path $ESPath -ChildPath "xml" | Join-Path -ChildPath "Schema_STIGList.xsd"
    $AnswerFile_xsd = Join-Path -Path $ESPath -ChildPath "xml" | Join-Path -ChildPath "Schema_AnswerFile.xsd"

    # STIGList.xml validation
    $XmlFile = Join-Path -Path $ESPath -ChildPath "xml" | Join-Path -ChildPath "STIGList.xml"
    If (-Not(Test-Path $XmlFile)) {
        Throw "Error: '$XmlFile' - file not found.  Cannot continue."
    }
    ElseIf (-Not(Test-Path $STIGList_xsd)) {
        Throw "Error: '$STIGList_xsd' - file not found.  Cannot continue."
    }
    ElseIf (-Not(Test-Path $AnswerFile_xsd)) {
        Throw "Error: '$AnswerFile_xsd' - file not found.  Cannot continue."
    }

    $Result = Test-XmlValidation -XmlFile $XmlFile -SchemaFile $STIGList_xsd
    If ($Result -ne $true) {
        ForEach ($Item in $Result.Message) {
            $Message += $Item | Out-String
        }
        Throw $Message
    }

    # Get list of supported STIGs
    [XML]$STIGList = Get-Content (Join-Path -Path $ESPath -ChildPath "xml" | Join-Path -ChildPath "STIGList.xml")
    $STIGsToProcess = New-Object System.Collections.Generic.List[System.Object]
    ForEach ($Node in $STIGList.List.ChildNodes) {
        $NewObj = [PSCustomObject]@{
            Name       = $Node.Name
            ShortName  = $Node.ShortName
            Template   = $Node.Template
        }
        $STIGsToProcess.Add($NewObj)
    }

    # Get STIG AnswerFiles
    $AnswerFileList = New-Object System.Collections.Generic.List[System.Object]
    ForEach ($Item in (Get-ChildItem -Path $AFPath | Sort-Object LastWriteTime | Where-Object Extension -eq ".xml")) {
        Try {
            If ((Test-XmlValidation -XmlFile $Item.FullName -SchemaFile $AnswerFile_xsd) -ne $true) {
                If (-Not(Test-Path "$($env:temp)\ES_OldSchema.xsd")) {
                    New-OldSchemaFile
                }

                If ((Test-XmlValidation -XmlFile $Item.FullName -SchemaFile "$($env:temp)\ES_OldSchema.xsd") -ne $true) {
                    Throw "'$($Item.FullName)' does not meet current or previous schema validation.  Will ignore this Answer file."
                }
                Else {
                    $CurrentSchema = $false
                }
            }
            Else {
                $CurrentSchema = $true
            }

            [XML]$Content = Get-Content $Item.FullName
            If ($Content.STIGComments.Name) {
                If (-Not(($Content.STIGComments.Name -in $STIGsToProcess.Name) -or ($Content.STIGComments.Name -in $STIGsToProcess.ShortName))) {
                    Write-Host "'$($Item.Name)' is for '$($Content.STIGComments.Name)' which is not listed in -ListSupportedProducts.  Will ignore this Answer file." -ForegroundColor Yellow
                }
                Else {
                    $Template = ($STIGsToProcess | Where-Object {($_.Name -eq $Content.STIGComments.Name) -or ($_.ShortName -eq $Content.STIGComments.Name)}).Template
                    $CKLTemplate = Join-Path -Path $ESPath -ChildPath "CKLTemplates" | Join-Path -ChildPath $Template
                    $NewObj = [PSCustomObject]@{
                        STIG           = $Content.STIGComments.Name
                        AnswerFile     = $Item.Name
                        AnswerFilePath = $Item.FullName
                        CKLTemplate    = $CKLTemplate
                        CurrentSchema  = $CurrentSchema
                    }
                    $AnswerFileList.Add($NewObj)
                }
            }
            Else {
                Write-Host "'$($Item.FullName)' is a duplicate Answer File for '$($Content.STIGComments.Name)'.  Will ignore this Answer File." -ForegroundColor Yellow
            }
        }
        Catch {
            Write-Host "$($_.Exception.Message)" -ForegroundColor Red -BackgroundColor Black
        }
    }

    ForEach ($File in $AnswerFileList) {
        Write-Host ""
        Write-Host "Processing $($File.AnswerFilePath) ..." -ForegroundColor Gray
        $AnswerFileText = [XML](Get-Content $File.AnswerFilePath)
        $ChecklistXML = [XML](Get-Content $File.CKLTemplate)
        $STIGItems = New-Object System.Collections.Generic.List[System.Object]
        ForEach ($Object in $ChecklistXML.CHECKLIST.STIGS.iSTIG.VULN) {
            $LegacyIDs = $Object.SelectNodes('./STIG_DATA[VULN_ATTRIBUTE="LEGACY_ID"]/ATTRIBUTE_DATA').InnerText
            $NewObj = [PSCustomObject]@{
                RuleTitle = $Object.SelectSingleNode('./STIG_DATA[VULN_ATTRIBUTE="Rule_Title"]/ATTRIBUTE_DATA').InnerText
                LegacyVulnID = (Select-String -InputObject $LegacyIDS -Pattern "V-\d{4,}" | ForEach-Object {$_.Matches}).Value
                VulnID = $Object.SelectSingleNode('./STIG_DATA[VULN_ATTRIBUTE="Vuln_Num"]/ATTRIBUTE_DATA').InnerText
                }
            $STIGItems.Add($NewObj)
            }

        $UpdateAnswerFile = $false
        ForEach ($Element in $AnswerFileText.STIGComments.Vuln) {
            If ($Element.ID -in $STIGItems.LegacyVulnID) {
                $UpdateAnswerFile = $true
                Write-Host "  Converting '$($Element.ID)' in Answer File to '$(($STIGItems | Where-Object LegacyVulnID -eq $Element.ID).VulnID)'" -ForegroundColor Gray
                $Element.ID = "$(($STIGItems | Where-Object LegacyVulnID -eq $Element.ID).VulnID)"
                If ($Element.'#comment' -ne ($STIGItems | Where-Object VulnID -eq $Element.ID).RuleTitle) {
                    $UpdateAnswerFile = $true
                    Write-Host "  Adding Rule Title as comment to '$($Element.ID)'" -ForegroundColor Gray
                }
            }
            ElseIf ($Element.ID -notin $STIGItems.VulnID) {
                If ($RemoveMissingVulnIDs) {
                    $UpdateAnswerFile = $true
                    Write-Host "  '$($Element.ID)' is not found in the STIG and has been removed from '$($File.AnswerFile)'" -ForegroundColor Yellow
                    $null = $Element.ParentNode.RemoveChild($Element)
                }
                Else {
                    Write-Host "  '$($Element.ID)' is not found in the STIG and may be removed from '$($File.AnswerFile)'" -ForegroundColor Yellow
                }
            }
            ElseIf ($Element.'#comment' -ne ($STIGItems | Where-Object VulnID -eq $Element.ID).RuleTitle) {
                $UpdateAnswerFile = $true
                If ($Element.ID -in $STIGItems.VulnID) {
                    Write-Host "  Adding Rule Title as comment to '$($Element.ID)'" -ForegroundColor Gray
                }
            }
        }
        If ($UpdateAnswerFile -eq $true -or $File.CurrentSchema -ne $true) {
            If (-Not($NoBackup)) {
                $BackupPath = Join-Path -Path $AFPath -ChildPath "Backup"
                If (-Not(Test-Path $BackupPath)) {
                    Write-Host "  Creating backup folder" -ForegroundColor Gray
                    New-Item -Path $BackupPath -ItemType Directory | Out-Null
                }
                Write-Host "  Creating copy of $($File.AnswerFile) under $($BackupPath)" -ForegroundColor Gray
                $BackupPath = Join-Path -Path $AFPath -ChildPath "Backup"
                Copy-Item $File.AnswerFilePath -Destination "$($BackupPath)\$($File.AnswerFile).bak" | Out-Null
            }

            If ($File.CurrentSchema -ne $true) {
                Write-Host "  Converting Answer File to new schema" -ForegroundColor Gray
            }

            # Write new Answer File
            $NewAnswerFile = $File.AnswerFilePath

            $Encoding = [System.Text.Encoding]::UTF8
            $XmlWriter = New-Object System.Xml.XmlTextWriter($NewAnswerFile, $Encoding)
            $XmlWriter.Formatting = "Indented"
            $XmlWriter.Indentation = 2

            $XmlWriter.WriteStartDocument()

            # Add Comment section
            $XmlWriter.WriteComment('**************************************************************************************
This file contains answers for known opens and findings that cannot be evaluated through technical means.
<STIGComments Name> must match the STIG ShortName or Name in -ListSupportedProducts.  When a match is found, this answer file will automatically for the STIG.
<Vuln ID> is the STIG VulnID.  Multiple Vuln ID sections may be specified in a single Answer File.
<AnswerKey Name> is the name of the key assigned to the answer.  "DEFAULT" can be used to apply the comment to any asset.  Multiple AnswerKey Name sections may be configured within a single Vuln ID section.
<ExpectedStatus> is the initial status after the checklist is created.  Valid entries are "Not_Reviewed", "Open", "NotAFinding", and "Not_Applicable".
<ValidationCode> must be Powershell code that returns a True/False value.  If blank, "true" is assumed.
<ValidTrueStatus> is the status the check should be set to if ValidationCode returns "true".  Valid entries are "Not_Reviewed", "Open", "NotAFinding", and "Not_Applicable".  If blank, <ExpectedStatus> is assumed.
<ValidTrueComment> is the verbiage to add to the Comments section if ValidationCode returns "true".
<ValidFalseStatus> is the status the check should be set to if ValidationCode DOES NOT return "true".  Valid entries are "Not_Reviewed", "Open", "NotAFinding", and "Not_Applicable".  If blank, <ExpectedStatus> is assumed.
<ValidFalseComment> is the verbiage to add to the Comments section if ValidationCode DOES NOT return "true".
**************************************************************************************')

            # Create STIGComments node
            $att_Name = $AnswerFileText.STIGComments.Name
            $XmlWriter.WriteStartElement("STIGComments")
            $XmlWriter.WriteAttributeString("Name", $att_Name)

            # Create Vuln nodes
            ForEach ($Vuln in $AnswerFileText.STIGComments.Vuln) {
                $att_ID = $Vuln.ID
                $XmlWriter.WriteStartElement("Vuln")
                $XmlWriter.WriteAttributeString("ID", $att_ID)
                If ($STIGItems | Where-Object VulnID -eq $Vuln.ID) {
                    $XmlWriter.WriteComment(($STIGItems | Where-Object VulnID -eq $Vuln.ID).RuleTitle)
                }
                Else {
                    $XmlWriter.WriteComment("WARNING: $($Vuln.ID) is not part of the STIG and may be removed from this answer file.")
                }

                # Create AnswerKey nodes
                ForEach ($Key in $Vuln.AnswerKey) {
                    $att_Name = $Key.Name
                    $XmlWriter.WriteStartElement("AnswerKey")
                    $XmlWriter.WriteAttributeString("Name", $att_Name)

                    #Create sub nodes
                    $XmlWriter.WriteStartElement("ExpectedStatus")
                    $XmlWriter.WriteString($Key.ExpectedStatus)
                    $XmlWriter.WriteFullEndElement()

                    $XmlWriter.WriteStartElement("ValidationCode")
                    If ($Key.ValidationCode) {
                        $XmlWriter.WriteString($Key.ValidationCode)
                    }
                    Else {
                        $XmlWriter.WriteWhitespace("")
                    }
                    $XmlWriter.WriteFullEndElement()

                    $XmlWriter.WriteStartElement("ValidTrueStatus")
                    If ($File.CurrentSchema -eq $true) {
                        If ($Key.ValidTrueStatus) {
                            $XmlWriter.WriteString($Key.ValidTrueStatus)
                        }
                        Else {
                            $XmlWriter.WriteWhitespace("")
                        }
                    }
                    Else {
                        $XmlWriter.WriteString($Key.FinalStatus)
                    }
                    $XmlWriter.WriteFullEndElement()

                    $XmlWriter.WriteStartElement("ValidTrueComment")
                    If ($File.CurrentSchema -eq $true) {
                        If ($Key.ValidTrueComment) {
                            $XmlWriter.WriteString($Key.ValidTrueComment)
                        }
                        Else {
                            $XmlWriter.WriteWhitespace("")
                        }
                    }
                    Else {
                        $XmlWriter.WriteString($Key.ApprovedComment)
                    }
                    $XmlWriter.WriteFullEndElement()

                    $XmlWriter.WriteStartElement("ValidFalseStatus")
                    If ($Key.ValidFalseStatus) {
                        $XmlWriter.WriteString($Key.ValidFalseStatus)
                    }
                    Else {
                        $XmlWriter.WriteWhitespace("")
                    }
                    $XmlWriter.WriteFullEndElement()

                    $XmlWriter.WriteStartElement("ValidFalseComment")
                    If ($Key.ValidFalseComment) {
                        $XmlWriter.WriteString($Key.ValidFalseComment)
                    }
                    Else {
                        $XmlWriter.WriteWhitespace("")
                    }
                    $XmlWriter.WriteFullEndElement()

                    # Close AnswerKey node
                    $XmlWriter.WriteEndElement()
                }
                # Close Vuln node
                $XmlWriter.WriteEndElement()
            }
            $XmlWriter.WriteEndElement()

            $XmlWriter.WriteEnddocument()
            $XmlWriter.Flush()
            $XmlWriter.Close()

            Write-Host "  $($File.AnswerFile) successfully updated." -ForegroundColor DarkGreen
        }
        Else {
            Write-Host "  $($File.AnswerFile) does not require updating." -ForegroundColor Cyan
        }
    }
    If (Test-Path "$($env:temp)\ES_OldSchema.xsd") {
        Remove-Item "$($env:temp)\ES_OldSchema.xsd"
    }
    Write-Host
    Write-Host "Processing complete!" -ForegroundColor Green
}
Catch {
    Write-Host "$($_.Exception.Message)" -ForegroundColor Red -BackgroundColor Black
}

# SIG # Begin signature block
# MIIL1AYJKoZIhvcNAQcCoIILxTCCC8ECAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUN+Qq5xP0sS6VCR/L7wApPFb6
# /fmgggk7MIIEejCCA2KgAwIBAgIEAwIE1zANBgkqhkiG9w0BAQsFADBaMQswCQYD
# VQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0Qx
# DDAKBgNVBAsTA1BLSTEVMBMGA1UEAxMMRE9EIElEIENBLTU5MB4XDTIwMDcxNTAw
# MDAwMFoXDTI1MDQwMjEzMzgzMlowaTELMAkGA1UEBhMCVVMxGDAWBgNVBAoTD1Uu
# Uy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9EMQwwCgYDVQQLEwNQS0kxDDAKBgNV
# BAsTA1VTTjEWMBQGA1UEAxMNQ1MuTlNXQ0NELjAwMTCCASIwDQYJKoZIhvcNAQEB
# BQADggEPADCCAQoCggEBANv2fdTmx2dNPQ47F8kmvU+g20/sFoF+DS3k2GcMduuI
# XxYFJyMMPAvTJuobeJlX6P6sr5jAKhXXsoV4lT2boWw583Snl6cuSfqMbVowIJ1s
# CffN7N0VXsLVdOt1u5GCKs4/jXH7MeEOE0oJsgEjjE1IZc5tEqj++s1N1EUY+jf/
# zc8QHDjy5X88XBTzKVhwvczZVbRahrcmYv0k4we3ndwTl5nXYizSwi96CZuqzrIn
# WbLSsRLNyNZZVo7J5bZ+30dv/hZvq6FqxfAeM3pEDrvbfFkWXzaISqF1bVbsMlAC
# UBf/JFbSGtmMsU1ABfXKPalTWYJKP58dICHcUocZhL0CAwEAAaOCATcwggEzMB8G
# A1UdIwQYMBaAFHUJphUTroc8+nOUAPLw9Xm5snIUMEEGA1UdHwQ6MDgwNqA0oDKG
# MGh0dHA6Ly9jcmwuZGlzYS5taWwvY3JsL0RPRElEQ0FfNTlfTkNPREVTSUdOLmNy
# bDAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0gBA8wDTALBglghkgBZQIBCyowHQYDVR0O
# BBYEFFbrF3OpzfdsZkN1zTfv++oaLCRRMGUGCCsGAQUFBwEBBFkwVzAzBggrBgEF
# BQcwAoYnaHR0cDovL2NybC5kaXNhLm1pbC9zaWduL0RPRElEQ0FfNTkuY2VyMCAG
# CCsGAQUFBzABhhRodHRwOi8vb2NzcC5kaXNhLm1pbDAfBgNVHSUEGDAWBgorBgEE
# AYI3CgMNBggrBgEFBQcDAzANBgkqhkiG9w0BAQsFAAOCAQEAQknaIAXDnyqshmyh
# uOZS4nBtSydnZrdB8Je0JCq2TTRA4dkNvrswe0kZgA7UjlY1X/9PtQeIwaMrcvdF
# i+dqzD1bbW/LX5tH/1oMOp4s+VkGfl4xUUxUGjO6QTVOeLyN2x+DBQU11DhKEq9B
# RCxUGgclFn1iqxi5xKmLaQ3XuRWRGCkb+rXejWR+5uSTognxCuoLp95bqu3JL8ec
# yF46+VSoafktAGot2Uf3qmwWdMHFBdwzmJalbC4j09I1qJqcJH0p8Wt34zRw/hSr
# 3f+xDEDP8GNL2ciDm7aN0GKy67ugjgMmPXAv7A4/keCuN/dsNS1naNyqzc5AhTAF
# +o/21jCCBLkwggOhoAMCAQICAgMFMA0GCSqGSIb3DQEBCwUAMFsxCzAJBgNVBAYT
# AlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsTA0RvRDEMMAoG
# A1UECxMDUEtJMRYwFAYDVQQDEw1Eb0QgUm9vdCBDQSAzMB4XDTE5MDQwMjEzMzgz
# MloXDTI1MDQwMjEzMzgzMlowWjELMAkGA1UEBhMCVVMxGDAWBgNVBAoTD1UuUy4g
# R292ZXJubWVudDEMMAoGA1UECxMDRG9EMQwwCgYDVQQLEwNQS0kxFTATBgNVBAMT
# DERPRCBJRCBDQS01OTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMwX
# hJ8twQpXrRFNNVc/JEcvHA9jlr27cDE8rpxWkobvpCJOoOVUbJ724Stx6OtTAZpR
# iXNaS0jjRgYaW6cq9pdnjjQM5ovHPPde1ewaZyWb2I+uqhkZmOBV1+lGUOhnQCyi
# nnSSqzEH1PC5nASfyxnCdBeOt+UKHBrPVKBUuYS4Fcn5Q0wv+sfBD24vyV5Ojeoq
# HeSSAMTaeqlv+WQb4YrjKNfaGF+S7lMvQelu3ANHEcoL2HMCimCvnCHQaMQI9+Ms
# NhySPEULePdEDxgpWYc9FmBbjUp1CYEx7HYdlTRJ9gBHts2ITxTZQrt4Epjkqeb8
# aWVmzCEPHE7+KUVhuO8CAwEAAaOCAYYwggGCMB8GA1UdIwQYMBaAFGyKlKJ3sYBy
# HYF6Fqry3M5m7kXAMB0GA1UdDgQWBBR1CaYVE66HPPpzlADy8PV5ubJyFDAOBgNV
# HQ8BAf8EBAMCAYYwZwYDVR0gBGAwXjALBglghkgBZQIBCyQwCwYJYIZIAWUCAQsn
# MAsGCWCGSAFlAgELKjALBglghkgBZQIBCzswDAYKYIZIAWUDAgEDDTAMBgpghkgB
# ZQMCAQMRMAwGCmCGSAFlAwIBAycwEgYDVR0TAQH/BAgwBgEB/wIBADAMBgNVHSQE
# BTADgAEAMDcGA1UdHwQwMC4wLKAqoCiGJmh0dHA6Ly9jcmwuZGlzYS5taWwvY3Js
# L0RPRFJPT1RDQTMuY3JsMGwGCCsGAQUFBwEBBGAwXjA6BggrBgEFBQcwAoYuaHR0
# cDovL2NybC5kaXNhLm1pbC9pc3N1ZWR0by9ET0RST09UQ0EzX0lULnA3YzAgBggr
# BgEFBQcwAYYUaHR0cDovL29jc3AuZGlzYS5taWwwDQYJKoZIhvcNAQELBQADggEB
# ADkFG9IOpz71qHNXCeYJIcUshgN20CrvB5ym4Pr7zKTBRMKNqd9EXWBxrwP9xhra
# 5YcQagHDqnmBeU3F2ePhWvQmyhPwIJaArk4xGLdv9Imkr3cO8vVapO48k/R9ZRSA
# EBxzd0xMDdZ6+xxFlZJIONRlxcVNNVB30e74Kk08/t82S9ogqgA1Q7KZ2tFuaRes
# jJWuoJ+LtE5lrtknqgaXLb3XH0hV5M0AWRk9Wg/1thb9NCsKEIAdpdnolZOephIz
# fzHiOSqeJ+e5qURLB7rT+F5y0NNWTdqoJ/vOOCUa8z0NKWsz2IkpeD3iNhVCLRKw
# Ojm/wzxdG2tst5OHRZFEwKcxggIDMIIB/wIBATBiMFoxCzAJBgNVBAYTAlVTMRgw
# FgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsTA0RvRDEMMAoGA1UECxMD
# UEtJMRUwEwYDVQQDEwxET0QgSUQgQ0EtNTkCBAMCBNcwCQYFKw4DAhoFAKB4MBgG
# CisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcC
# AQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYE
# FPHN8fEJ2JlQCmkTXZBxxMIxC5C2MA0GCSqGSIb3DQEBAQUABIIBADMxdD6cRFR+
# 9QfZSu2INL0bS+6XIps96+kFla4POniMU/KiVWnAuA+/RSoijhtMDbkiq6Q5tf9d
# WC0NbFYORGm2u3LauH/Y+08gEWsvc2dgL7MsBtAo69fGnHxDqpKWmgRJvQ2xDd2f
# rX55a16nDzgsKJ6ItTAEs1n9kUEr+tYh2sY5BA8cA70L3qXTFtVOk8Rf2fpWJsga
# 3b3ViOHKzwiFn8IPuJyyB5PuTs3vS/90/OT3AvsujkFf73AEu6nIuyFwFsG2KKt1
# wQS8tV3ErMYPm5RnzNMNtdaM1USSPnmKdUQArw6cP7kjj6jbEqbF0vgMHtLSTebs
# yb01eFqLnN0=
# SIG # End signature block
