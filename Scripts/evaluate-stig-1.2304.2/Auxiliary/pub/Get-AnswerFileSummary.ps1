<#
    .Synopsis
    Create a HTML report for specified Answer File(S)
    .DESCRIPTION
    Creates a HTML report from Evaluate-STIG Answer Files.
    .EXAMPLE
    PS C:\> Get-AnswerfileSummary.ps1 -AFPath C:\Evaluate-STIG\AnswerFiles
    .EXAMPLE
    PS C:\> Get-AnswerfileSummary.ps1 -AFFile C:\Evaluate-STIG\AnswerFiles\Windows_10_Answerfile.xml
    .INPUTS
    -AFPath
        Path to the Evaluate-STIG Answer File directory.
    .INPUTS
    -AFFile
        Path to the Evaluate-STIG Answer File.
    .INPUTS
    -OutputPath
        Path to location to save Summary Report.
#>

Param (
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [String[]]$AFPath,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [String[]]$AFFile,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [String]$OutPutpath
)

Function Convert-AFFile {
    Param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$AFFile,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$OutPutpath
    )

    [xml]$AFTransform = @'
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
     <xsl:template match="/STIGComments">
          <html>
               <head>
                    <style type="text/css">
                         .styled-table {
                              border-collapse: collapse;
                              margin: 25px 0;
                              font-size: 0.9em;
                              font-family: sans-serif;
                              min-width: 400px;
                              box-shadow: 0 0 20px rgba(0, 0, 0, 0.15);
                              width: 100%
                         }
                         .styled-table thead tr {
                              background-color: #2E86C1;
                              color: #ffffff;
                              text-align: left;
                         }
                         .styled-table th,
                         .styled-table td {
                              padding: 12px 15px;
                         }
                         .styled-table tbody tr {
                              border-bottom: thin solid #dddddd;
                         }
                         .styled-table tbody tr:last-of-type {
                              border-bottom: 2px solid #3498DB;
                         }
                         .styled-table tbody tr.active-row {
                              font-weight: bold;
                              color: #3498DB;
                         }
                         .hidden {
                              visibility: hidden;
                         }
                         .button {
                              color: #494949 !important;
                              text-align: center;
                              text-transform: uppercase;
                              text-decoration: none;
                              backgrond: #AED6F1;
                              background-color: #AED6F1;
                              padding: 20px;
                              border: 4px solid #494949 !important;
                              display: inline-block;
                              transition: all 0.4s ease 0s;
                              width: 250px;
                              height: 20px;
                              margin: 5px;
                         }
                         .stig_button {
                              color: #494949 !important;
                              text-align: center;
                              text-transform: uppercase;
                              text-decoration: none;
                              backgrond: #ffffff;
                              padding: 20px;
                              border: 4px solid #494949 !important;
                              display: inline-block;
                              transition: all 0.4s ease 0s;
                              width: 450px;
                              height: 10px;
                         }
                         .button:hover{
                              color: #ffffff !important;
                              background: #f6b93b;
                              border-color: #f6b93b !important;
                              transition: all 0.4s ease 0s;
                              cursor: pointer;
                         }
                         .stig_button:hover{
                              color: #ffffff !important;
                              background: #f6b93b;
                              border-color: #f6b93b !important;
                              transition: all 0.4s ease 0s;
                              cursor: pointer;
                         }
                         #topbtn{
                              position: fixed;
                              bottom: 20px;
                              right: 30px;
                              z-index: 99;
                              font-size: 18px;
                              border: none;
                              outline: none;
                              background-color: red;
                              color: white;
                              cursor: pointer;
                              padding: 15px;
                              border-radius: 4px;
                         }
                         #topbtn:hover{
                              background-color: #555;
                         }
                         code {
                             background-color: #eef;
                             display: block;
                         }
                    </style>
                    <script>
                         var topbutton = document.getElementById("topbtn");
                         window.onscroll = function() {scrollFunction()};

                         function scrollFunction() {
                              if (document.body.scrollTop > 20 || document.documentElement.scrollTop > 20) {
                                   topbutton.style.display = "block";
                              } else {
                                   topbutton.style.display = "none";
                              }
                         }
                         function topFunction() {
                              document.body.scrollTop = 0;
                              document.documentElement.scrollTop = 0;
                         }
                         function change(table_value) {
                              var x = document.getElementById(table_value);
                              if (x.style.display === "none") {
                                   x.style.display = "table";
                              } else {
                                   x.style.display = "none";
                              }
                         }
                    </script>
               </head>
               <body>
                    <button onclick="topFunction()" id="topbtn" title="Go to Top">Top</button>
                    <h1 align="center"><xsl:value-of select="@Name" /> STIG Answer File</h1>
                    <p>**************************************************************************************<br />
                        <br />
                        This file contains answers for known opens and findings that cannot be evaluated through technical means.<br />
                        <br />
                        <b>&lt;STIGComments Name&gt;</b> must match the STIG name in STIGList.xml.  When a match is found, this answer file will automatically for the STIG.<br />
                        <b>&lt;Vuln ID&gt;</b> is the STIG VulnID.  Multiple Vuln ID sections may be specified in a single Answer File.<br />
                        <b>&lt;AnswerKey Name&gt;</b> is the name of the key assigned to the answer.  "DEFAULT" can be used to apply the comment to any asset.  Multiple AnswerKey Name sections may be configured within a single Vuln ID section.<br />
                        <b>&lt;ExpectedStatus&gt;</b> is the initial status after the checklist is created.  Valid entries are "Not_Reviewed", "Open", "NotAFinding", and "Not_Applicable".<br />
                        <b>&lt;ValidationCode&gt;</b> must be Powershell code that returns a True/False value.  If blank, "true" is assumed.<br />
                        <b>&lt;ValidTrueStatus&gt;</b> is the status the check should be set to if ValidationCode returns "true".  Valid entries are "Not_Reviewed", "Open", "NotAFinding", and "Not_Applicable".  If blank, <b>&lt;ExpectedStatus&gt;</b> is assumed.<br />
                        <b>&lt;ValidTrueComment&gt;</b> is the verbiage to add to the Comments section if ValidationCode returns "true".<br />
                        <b>&lt;ValidFalseStatus&gt;</b> is the status the check should be set to if ValidationCode DOES NOT return "true".  Valid entries are "Not_Reviewed", "Open", "NotAFinding", and "Not_Applicable".  If blank, <b>&lt;ExpectedStatus&gt;</b> is assumed.<br />
                        <b>&lt;ValidFalseComment&gt;</b> is the verbiage to add to the Comments section if ValidationCode DOES NOT return "true".<br />
                        <br />
                        **************************************************************************************</p>
                </body>
            </html>
        <xsl:for-each select="Vuln">
                <tbody><tr>
                    <td><div class="button_cont"><a class="stig_button" id="button" onclick="change('{@ID}')" title="Show/Hide {@ID}"><xsl:value-of select="@ID" /></a></div></td>
                </tr></tbody>
                    <td><table id="{@ID}" class="styled-table" style="display:none">
                        <thead><tr>
                            <th>Name</th>
                            <th>Expected Status</th>
                            <th>Validation Code</th>
                            <th>Valid True Status</th>
                            <th>Valid True Comment</th>
                            <th>Valid False Status</th>
                            <th>Valid False Comment</th>
                        </tr></thead>
                        <xsl:for-each select="AnswerKey">
                            <tbody><tr>
                                    <td><xsl:value-of select="@Name" /></td>
                                    <td><xsl:value-of select="ExpectedStatus" /></td>
                                    <td><code><xsl:value-of select="ValidationCode" /></code></td>
                                    <td><xsl:value-of select="ValidTrueStatus" /></td>
                                    <td><xsl:value-of select="ValidTrueComment" /></td>
                                    <td><xsl:value-of select="ValidFalseStatus" /></td>
                                    <td><xsl:value-of select="ValidFalseComment" /></td>
                            </tr></tbody>
                        </xsl:for-each>
                    </table></td>
        </xsl:for-each>
     </xsl:template>
</xsl:stylesheet>
'@

    $AFxslt = New-Object System.Xml.Xsl.XslCompiledTransform
    $AFxslt.load($AFTransform)
    $AFxslt.Transform($AFFile, $(Join-Path $OutPutpath -ChildPath "$($(Split-Path $AFFile -Leaf).replace('.xml','')).html"))

}

if (!($OutPutpath)) {
    $OutPutpath = $PSScriptRoot
}

$Answerfiles = New-Object -TypeName "System.Collections.ArrayList"
$Answerfiles = [System.Collections.ArrayList]@()

if ($AFPath){
    $Answerfiles += $(Get-ChildItem -Path $AFPath -File).FullName
}

if ($AFFile){
    $AFFile | ForEach-Object {
        if ($(Split-Path $_ -Leaf) -notin $(Split-Path $Answerfiles -Leaf)) {
            $Answerfiles += ($_)
        }
        else{
            Write-Host "Duplicate $(Split-Path $_ -Leaf) found in $AFPath.  Skipping."
        }
    }
}

$Answerfiles | Foreach-Object {
    Convert-AFFile -AFFile $_ -OutPutpath $OutPutpath
}

# SIG # Begin signature block
# MIIL1AYJKoZIhvcNAQcCoIILxTCCC8ECAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUkAu46qRpb177oRJ/WZqtfdZL
# 556gggk7MIIEejCCA2KgAwIBAgIEAwIE1zANBgkqhkiG9w0BAQsFADBaMQswCQYD
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
# FBRe5FCqN8ZTOAv+kOWX9wR+qqyqMA0GCSqGSIb3DQEBAQUABIIBAJr+fDFg9uAo
# 91VHlHObTPIReplVJ/iYq0/v68sdjlCrKS+QtrzxHsqbnPQbBDiqltEoT+GG+PwO
# ylXpw/kpx1mGe4WmJcbq7Yip8BSVD1pMmHK8idutmqS9xR6OUuWFIe3YSmzvcHHo
# s9QikIUCR/1fPtzkbPpiCQyR4Ccu74IdhAs5jis0nAVQbvy8GqJIQUPgN1ziOZFX
# 4hzGGKgfWD9LjD3oodgUyYbN6kHnArNSBxCKIa34ymgIfaa3x7T4IYoXSrZL7mP8
# Yh7Gj8Gf6oqZrdFOuGfRUw3ZsZxoSQTnTf3wMDcA8Ac1GKKYBQPXGS5nPUjDSNz6
# u8ENP5XD34s=
# SIG # End signature block
