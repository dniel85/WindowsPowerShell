<#
    .Synopsis
    Creates a report of any discrepancies found in Evaluate-STIG results.
    .DESCRIPTION
    Creates a report of any discrepancies found in Evaluate-STIG results.
    .EXAMPLE
    PS C:\> Validate-Results.ps1 -ESResultsPath C:\Results
    .INPUTS
    -ESResultsPath
        Path to the Evaluate-STIG directory.  Minimum required for the report to run.
#>

Param (
    [Parameter(Mandatory = $false)]
    [String]$ESResultsPath
)

If (-Not($ESResultsPath)) {
    If ($IsLinux) {
        $ESResultsPath = "/opt/STIG_Compliance"
    }
    Else {
        $ESResultsPath = "$env:PUBLIC\Documents\STIG_Compliance"
    }
}

$Validation = New-Object System.Collections.Generic.List[System.Object]

Write-Host "Validating Evaluate-STIG results..."

$AllResults = Get-ChildItem -Path $ESResultsPath
ForEach ($Item in $AllResults) {
    $ResultPath = ($Item.FullName)
    If (-Not(Test-Path "$($Item.FullName)\SummaryReport.xml" -ErrorAction SilentlyContinue)) {
        $NewObj = [PSCustomObject]@{
            AssetName = $Item.Name
            Path = $ResultPath
            Status = "Fail"
            Message = "SummaryReport.xml missing"
        }
        $Validation.Add($NewObj)
    }
    Else {
        [XML]$SummaryXML = Get-Content "$($Item.FullName)\SummaryReport.xml"
        $ChecklistFiles = Get-ChildItem -Path "$($Item.FullName)\Checklist\*.ckl" -Exclude "*Previous*"
        ForEach ($Checklist in $SummaryXML.Summary.Checklists.Checklist.CklFile) {
            If ($Checklist -in $ChecklistFiles.Name) {
                $NewObj = [PSCustomObject]@{
                    AssetName = $SummaryXML.Summary.Computer.Name
                    Path = $ResultPath
                    Checklist = $Checklist
                    Status = "Pass"
                    Message = "No Discrepancies found."
                }
                $Validation.Add($NewObj)
            }
            Else {
                $NewObj = [PSCustomObject]@{
                    AssetName = $SummaryXML.Summary.Computer.Name
                    Path = $ResultPath
                    Checklist = $Checklist
                    Status = "Fail"
                    Message = "Expected checklist file not found."
                }
                $Validation.Add($NewObj)
            }
        }
        ForEach ($Checklist in $ChecklistFiles) {
            If ($Checklist.Name -notin $SummaryXML.Summary.Checklists.Checklist.CklFile) {
                $NewObj = [PSCustomObject]@{
                    AssetName = $SummaryXML.Summary.Computer.Name
                    Path = $ResultPath
                    Checklist = $Checklist.Name
                    Status = "Fail"
                    Message = "Unexpected checklist file found."
                }
                $Validation.Add($NewObj)
            }
        }
    }
}

Return $Validation

# SIG # Begin signature block
# MIIL1AYJKoZIhvcNAQcCoIILxTCCC8ECAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUIDuiyP3vW42NDKOYaWNQC/hW
# gGSgggk7MIIEejCCA2KgAwIBAgIEAwIE1zANBgkqhkiG9w0BAQsFADBaMQswCQYD
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
# FB8N64qVFTMHZGNcaG2Vq3BMVdrhMA0GCSqGSIb3DQEBAQUABIIBANT1naxdpVxr
# ZoH45l384HKytMuYbCC24aCGBqNEMVinoixAQJEX8stDsHIQWfdWe7MxFo0oMAPh
# oLIzL5qL/Eb9sK/ugs69mA8ubr838sixSUcMy/qX4dhzuG/YgxZkQQvE/VuN10mJ
# 5pUsmzYrQaf9VHuxC8W6RLkGO0zoUhh+bgYugven6tpCtoTHsHLiTsN4GATsU0wj
# SQ5OFhI6kBm45s6nLG757iWexph1NvYgPwRluTFQEvWwkVIGozoJLgAs2qdtBK6y
# aH+RB7GlVOmOL+YNpghAZwX3Gf0qv2gxpmPtY4ndz6ES8iwVrv/L6wNZFvB+HSz8
# 3hv1qSt2IhA=
# SIG # End signature block
