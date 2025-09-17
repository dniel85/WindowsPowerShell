<#
.Synopsis
    List key fields from a STIG checklist file (.ckl)
.DESCRIPTION
    Enumerates a given .ckl file into a PowerShell array object with the following fields:
        - STIG Name
        - Checklist File Name
        - HostName
        - Vuln ID
        - Rule ID
        - Rule Title
        - Status
        - Severity
        - Documentable
        - Check Content
        - Finding Details
        - Comments
.EXAMPLE
    .\Get-CklData.ps1 -CklFile C:\Checklists\Windows10.ckl

    Lists all checks in the checklist.
.EXAMPLE
    .\Get-CklData.ps1 -CklFile C:\Checklists\Windows10.ckl | Where Status -eq "Open"

    Lists just Open checks in the checklist.
.INPUTS
    -CklFile
        Required.  Path to .ckl file.
.OUTPUTS
    Outputs to an array object.
.LINK
    https://spork.navsea.navy.mil/nswc-crane-division/evaluate-stig
#>

Param (
    [Parameter(Mandatory=$true)]
    [String]$CklFile
    )

Try {
    $FileInfo = Get-Item $CklFile -ErrorAction Stop
    If ($FileInfo.Extension -ne ".ckl") {
        Throw "'$($CklFile)' is not a .ckl file type."
        }

    $CklContent = (Select-XML -XPath / -Path $CklFile -ErrorAction Stop).Node   # Read file into an XmlDocument object
    $STIG = $CklContent.CHECKLIST.stigs.iSTIG.STIG_INFO.SelectSingleNode('./SI_DATA[SID_NAME="stigid"]/SID_DATA').InnerText   # Extract the STIG ID from the .ckl
    $HostName = $CklContent.CHECKLIST.ASSET.HOST_NAME
    $Output = New-Object System.Collections.ArrayList
    ForEach($Vuln in $CklContent.CHECKLIST.STIGS.iSTIG.VULN){
        Switch ($Vuln.SelectSingleNode('./STIG_DATA[VULN_ATTRIBUTE="Severity"]/ATTRIBUTE_DATA').InnerText) {   # Convert the Severity into a CAT level
            "high"     {$Severity = "CAT_I"}
            "medium"   {$Severity = "CAT_II"}
            "low"      {$Severity = "CAT_III"}
            Default    {$Severity = $_}
            }

        $NewObj = [PSCustomObject]@{
            STIG = $STIG
            Checklist = $FileInfo.Name
            HostName = $HostName
            VulnID = ($Vuln.SelectSingleNode('./STIG_DATA[VULN_ATTRIBUTE="Vuln_Num"]/ATTRIBUTE_DATA').InnerText)   # Extract the Vuln ID of the STIG item
            RuleID = ($Vuln.SelectSingleNode('./STIG_DATA[VULN_ATTRIBUTE="Rule_ID"]/ATTRIBUTE_DATA').InnerText)   # Extract the Rule ID of the STIG item
            RuleTitle = ($Vuln.SelectSingleNode('./STIG_DATA[VULN_ATTRIBUTE="Rule_Title"]/ATTRIBUTE_DATA').InnerText)   # Extract the Rule Title of the STIG item
            Status =$Vuln.Status
            Severity = $Severity
            Documentable = ($Vuln.SelectSingleNode('./STIG_DATA[VULN_ATTRIBUTE="Documentable"]/ATTRIBUTE_DATA').InnerText)   # Extract the Documentable of the STIG item
            CheckContent = ($Vuln.SelectSingleNode('./STIG_DATA[VULN_ATTRIBUTE="Check_Content"]/ATTRIBUTE_DATA').InnerText)   # Extract the Check Content of the STIG item
            FindingDetails = $Vuln.FINDING_DETAILS
            Comments = $Vuln.COMMENTS
            }
        $Output.Add($NewObj) | Out-Null
        }
    Return $Output
    }
Catch {
    Write-Host $_.Exception.Message -ForegroundColor Red
    }

# SIG # Begin signature block
# MIIL1AYJKoZIhvcNAQcCoIILxTCCC8ECAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUXbvrSUBAloHIoprcAlgvew7Y
# 2Aqgggk7MIIEejCCA2KgAwIBAgIEAwIE1zANBgkqhkiG9w0BAQsFADBaMQswCQYD
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
# FINUrotYXiEDqISR+rLJnZGH2+7NMA0GCSqGSIb3DQEBAQUABIIBAMU5mEPzSYpX
# FbIc0F+PMzExuzpGhXKPv163YGbmVk+WnREt8rCc7Ic1ZnPsaqd7qjm4TIqRJwjc
# Ha4bbrFObWEF6p8+zg6/gOG/bBAx5GUE+Oiw6IYco47xE7aBeMI0Dy7RpmTrL45D
# hrXHe6cqVsVqVv2qknyyFQM5jhDdtkkUxbp7QwatzQrDggLLET0O0g3dNgL89JsO
# xpbaMnfzryjI6mbCplTm60V1ZQk7LYhDcrSkZnGaUpF/AZV+4DFM+8hCvvs64Cpy
# fKJpqjD1HqKUgjzTbA3Sncv/lz/ULdTayr1uJRcMSL4uGfOhqMeqYT4mvg9T53Ft
# GBJQN8z/wrw=
# SIG # End signature block
