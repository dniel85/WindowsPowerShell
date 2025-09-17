<#
    .Synopsis
    Manage Evaluate-STIG via GUI
    .DESCRIPTION
    Launches an Evaluate-STIG GUI to more easily execute Evaluate-STIG.ps1
    .EXAMPLE
    PS C:\> Manage-Evaluate-STIG.ps1
#>

param (
  [Parameter(Mandatory = $false)]
  [String]$ESPath
)

Function Invoke-PowerShell {
  param (
    [Parameter(Mandatory = $true)]
    [String]$ESPath,

    [Parameter(Mandatory = $false)]
    [String]$ArgumentList,

    [Parameter(Mandatory = $false)]
    [Switch]$NoNewWindow
  )

  $ESDataBox.Text = "Generating data from $(Join-Path $ESPath -ChildPath Evaluate-STIG.ps1) $ArgumentList.  `n`nPlease wait"
  Start-Sleep 1 #Give the GUI time to update

  if ($ArgumentList -eq "GetHelp"){
    Write-Verbose "Executing: Start-Process powershell ""Get-Help $(Join-Path $ESPath -ChildPath Evaluate-STIG.ps1) -Full"" -NoNewWindow -Wait"
    $output = Start-Process powershell "Get-Help `"$(Join-Path $ESPath -ChildPath Evaluate-STIG.ps1)`" -Full" -NoNewWindow -Wait
  }
  else{
    If (($PsVersionTable.PSVersion -join ".") -gt [Version]"7.0") {
      Write-Verbose "Executing: Start-Process pwsh ""-NoProfile -File $(Join-Path $ESPath -ChildPath Evaluate-STIG.ps1) $ArgumentList"" -Wait -NoNewWindow"
      $output = Start-Process pwsh "-NoProfile -File `"$(Join-Path $ESPath -ChildPath Evaluate-STIG.ps1)`" $ArgumentList" -Wait -NoNewWindow
    }
    else{
      Write-Verbose "Executing: Start-Process powershell ""-NoProfile -File $(Join-Path $ESPath -ChildPath Evaluate-STIG.ps1) $ArgumentList"" -Wait -NoNewWindow"
      $output = Start-Process powershell "-NoProfile -File `"$(Join-Path $ESPath -ChildPath Evaluate-STIG.ps1)`" $ArgumentList" -Wait -NoNewWindow
    }
  }
  Return $output
}

function Get-Path {
  Param (
    [Parameter(Mandatory = $true)]
    [String]$Description
  )

  $foldername = New-Object System.Windows.Forms.FolderBrowserDialog
  $foldername.Description = $Description
  $foldername.rootfolder = "MyComputer"

  if($foldername.ShowDialog() -eq "OK")
  {
    return $foldername.SelectedPath
  }
  else{
    return "no_path"
  }
}

function Get-File {

  $FileBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{
    InitialDirectory = [Environment]::GetFolderPath("MyComputer")
    Filter           = "TXT Files (*.txt)|*.txt"
  MultiSelect      = $true}

  if ($FileBrowser.ShowDialog() -eq "OK") {
    return $FileBrowser.FileNames
  }
  else {
    return "no_path"
  }
}

Function Get-Arguments {

  If ($SelectedSTIGS) {
    $ESArgs = "-SelectSTIG $($SelectedSTIGS -join ',')"

    If ($SelectedVulns) {
      $ESArgs += " -SelectVuln $($SelectedVulns -join ',' -replace(' ',''))"
    }
    If ($ExcludedVulns) {
      $ESArgs += " -ExcludeVuln $($ExcludedVulns -join ',' -replace(' ',''))"
    }
  }
  ElseIf ($ExcludedSTIGS) {
    $ESArgs = "-ExcludeSTIG $($ExcludedSTIGS -join ',')"
  }

  if ($AltCredential.Checked -eq $true) {
    $ESArgs += " -AltCredential"
  }
  if ($GenerateOQE.Checked -eq $true) {
    $ESArgs += " -GenerateOQE"
  }
  if ($NoPrevious.Checked -eq $true) {
    $ESArgs += " -NoPrevious"
  }
  if ($ApplyTattoo.Checked -eq $true) {
    $ESArgs += " -ApplyTattoo"
  }
  if ($VulnTimeoutBox.Text) {
    $ESArgs += " -VulnTimeout $($VulnTimeoutBox.Text)"
  }
  if ($ThrottleLimitBox.Text) {
    $ESArgs += " -ThrottleLimit $($ThrottleLimitBox.Text)"
  }
  if ($MarkingBox.Text) {
    $ESArgs += " -Marking ""$($MarkingBox.Text)"""
  }
  if ($ScanType.SelectedItem) {
    $ESArgs += " -ScanType $($ScanType.SelectedItem)"
  }
  if ($AFKeys.SelectedItem) {
    $ESArgs += " -AnswerKey $($AFKeys.SelectedItem)"
  }

  $ESArgs += " -AFPath ""$ESAFPath"""

  $ESArgs += " -OutputPath ""$ESOutputPath"""

  If ($ComputerNames -and $ComputerList){
    $ESArgs += " -ComputerName $($ComputerNames -join ',' -replace(' ','')),""$($ComputerList -join '","' -replace(' ',''))"""
  }
  elseif($ComputerNames){
    $ESArgs += " -ComputerName $($ComputerNames -join ',' -replace(' ',''))"
  }
  elseif ($ComputerList) {
    $ESArgs += " -ComputerName $($ComputerList -join '","' -replace(' ',''))"
  }

  if ($CiscoFileList -and $CiscoDirectory){
    $ESArgs += " -CiscoConfig ""$CiscoDirectory"",""$($CiscoFileList -join '","' -replace(' ',''))"""
  }
  elseif ($CiscoFileList) {
    $ESArgs += " -CiscoConfig ""$($CiscoFileList -join ',' -replace(' ',''))"""
  }
  elseif($CiscoDirectory){
    $ESArgs += " -CiscoConfig ""$CiscoDirectory"""
  }


  return $ESArgs
}

Function Set-Initial {

  $form1.Controls | Where-Object { $_ -is [System.Windows.Forms.ComboBox] } | ForEach-Object { $_.Items.Clear() }

  @("Unclassified", "Classified") | ForEach-Object { $null = $ScanType.Items.Add($_) }

  $AFXMLs = Get-ChildItem -Path $(Join-Path $ESFolder -ChildPath AnswerFiles) -Filter *.xml

  Foreach ($AFXML in $AFXMLS) {
    [xml]$XML = Get-Content $AFXML.FullName
    $AllAFKeys += $XML.STIGComments.Vuln.AnswerKey.Name
  }

  $AllAFKeys | Sort-Object -Unique | ForEach-Object { $null = $AFKeys.Items.Add($_) }

  If (!(IsAdministrator)) {
    $ListApplicableProductsButton.Enabled = $false
  }

  $SelectSTIGButton.Enabled = $true
  $ExcludeSTIGButton.Enabled = $true
  $ExcludeVulnButton.Enabled = $false
  $SelectVulnButton.Enabled = $false
  $AltCredential.Enabled = $false
  $ThrottleLimitBox.Enabled = $false

  $Script:ESAFPath = $(Join-Path $ESFolder -ChildPath AnswerFiles)
  $AFPathLabel.Text = "AFPath:             $ESAFPath"

  $Script:ESOutputPath = "C:\Users\Public\Documents\STIG_Compliance"
  $OutputPathLabel.Text = "OutputPath:         $ESOutputPath"

  $UpdateProxy.Checked = $false
  $AltCredential.Checked = $false
  $GenerateOQE.Checked = $false
  $NoPrevious.Checked = $false
  $ApplyTattoo.Checked = $false

  $VulnTimeoutBox.Text = ""
  $ThrottleLimitBox.Text = ""
  $MarkingBox.Text = ""
  $ESDataBox.Text = ""

  $Script:SelectedSTIGS = New-Object System.Collections.ArrayList
  $Script:ExcludedSTIGS = New-Object System.Collections.ArrayList

  $Script:SelectedVulns = ""
  $Script:ExcludedVulns = ""
  $Script:ComputerNames = ""
  $Script:ComputerList = ""
  $Script:CiscoFileList = ""
  $Script:CiscoDirectory = ""
}

Function Close-Form {
  Param (
    [Parameter(Mandatory = $true)]
    [String]$Message
  )

  [System.Windows.MessageBox]::Show($Message, "Manage Evaluate-STIG Error", "OK", "Error")
  &$handler_formclose
}

function IsAdministrator {
  $Identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
  $Principal = New-Object System.Security.Principal.WindowsPrincipal($Identity)
  $Principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName Microsoft.VisualBasic
Add-Type -AssemblyName PresentationFramework
Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;
public class ProcessDPI {
    [DllImport("user32.dll", SetLastError=true)]
    public static extern bool SetProcessDPIAware();
}
'@

$null = [ProcessDPI]::SetProcessDPIAware()

$InitialFormWindowState = New-Object System.Windows.Forms.FormWindowState

$form1 = New-Object System.Windows.Forms.Form
[Windows.Forms.Application]::EnableVisualStyles()

$TitleFont = New-Object System.Drawing.Font("Consolas", 24, [Drawing.FontStyle]::Bold)
$BodyFont = New-Object System.Drawing.Font("Consolas", 18, [Drawing.FontStyle]::Bold)
$BoxFont = New-Object System.Drawing.Font("Consolas", 12, [Drawing.FontStyle]::Regular)
$BoldBoxFont = New-Object System.Drawing.Font("Consolas", 14, [Drawing.FontStyle]::Bold)

$VLineLeft = New-Object System.Windows.Forms.Label
$HLineTop = New-Object System.Windows.Forms.Label
$HLineOptionBottom = New-Object System.Windows.Forms.Label
$HLineBottom = New-Object System.Windows.Forms.Label
$ScanTypeLabel = New-Object System.Windows.Forms.Label
$AFKeysLabel = New-Object System.Windows.Forms.Label
$AFPathLabel = New-Object System.Windows.Forms.Label
$ESPathLabel = New-Object System.Windows.Forms.Label
$OutputPathLabel = New-Object System.Windows.Forms.Label
$VulnTimeoutLabel = New-Object System.Windows.Forms.Label
$ThrottleLimitLabel = New-Object System.Windows.Forms.Label
$MarkingLabel = New-Object System.Windows.Forms.Label

$BottomLine = New-Object System.Windows.Forms.Label
$BottomLineVersion = New-Object System.Windows.Forms.Label
$Title = New-Object System.Windows.Forms.Label
$ToolsLabel = New-Object System.Windows.Forms.Label
$OptionsLabel = New-Object System.Windows.Forms.Label

$UpdateProxy = New-Object System.Windows.Forms.Checkbox
$AltCredential = New-Object System.Windows.Forms.Checkbox
$GenerateOQE = New-Object System.Windows.Forms.Checkbox
$NoPrevious = New-Object System.Windows.Forms.Checkbox
$ApplyTattoo = New-Object System.Windows.Forms.Checkbox

$ScanType= New-Object System.Windows.Forms.ComboBox
$AFKeys = New-Object System.Windows.Forms.ComboBox

$STIGSelectList = New-Object System.Windows.Forms.CheckedListBox

$VulnTimeoutBox = New-Object System.Windows.Forms.TextBox
$ThrottleLimitBox = New-Object System.Windows.Forms.TextBox
$MarkingBox = New-Object System.Windows.Forms.TextBox

$ListSupportedProductsButton = New-Object System.Windows.Forms.Button
$ListApplicableProductsButton = New-Object System.Windows.Forms.Button
$UpdateESButton = New-Object System.Windows.Forms.Button
$GetHelpButton = New-Object System.Windows.Forms.Button
$ContactUsButton = New-Object System.Windows.Forms.Button
$PreviewESButton = New-Object System.Windows.Forms.Button
$ExecuteESButton = New-Object System.Windows.Forms.Button
$ResetESButton = New-Object System.Windows.Forms.Button
$AFPAthButton = New-Object System.Windows.Forms.Button
$SelectSTIGButton = New-Object System.Windows.Forms.Button
$ExcludeSTIGButton = New-Object System.Windows.Forms.Button
$SelectVulnButton = New-Object System.Windows.Forms.Button
$ExcludeVulnButton = New-Object System.Windows.Forms.Button
$OutputPathButton = New-Object System.Windows.Forms.Button
$ComputerNameButton = New-Object System.Windows.Forms.Button
$ComputerListButton = New-Object System.Windows.Forms.Button
$CiscoFilesButton = New-Object System.Windows.Forms.Button
$CiscoDirectoryButton = New-Object System.Windows.Forms.Button

$ESDataBox = New-Object -TypeName System.Windows.Forms.RichTextBox

#----------------------------------------------
#Generated Event Script Blocks
#----------------------------------------------

$OnLoadForm_StateCorrection =
{ #Correct the initial state of the form to prevent the .Net maximized form issue
  $form1.WindowState = $InitialFormWindowState

  If ($ESPath){
    $script:ESFolder = $ESPath
  }
  else{
    $script:ESFolder = $(Get-Path -Description "Select Evaluate-STIG directory")
  }

  if (Test-Path $ESFolder){
    If (Test-Path (Join-Path -Path $ESFolder -ChildPath "xml" | Join-Path -ChildPath "FileList.xml")) {
      [XML]$FileListXML = Get-Content -Path (Join-Path -Path $ESFolder -ChildPath "xml" | Join-Path -ChildPath "FileList.xml")
      ForEach ($File in $FileListXML.FileList.File) {
        if ($File.ScanReq -eq "Required") {
          $Path = (Join-Path -Path $ESFolder -ChildPath $File.Path | Join-Path -ChildPath $File.Name)
          If (!(Test-Path $Path)) {
            $Verified = $false
          }
        }
      }
      If ($Verified -eq $False) {
        Write-Host "ERROR: One or more Evaluate-STIG files were not found.  Unable to continue." -ForegroundColor Yellow
        Close-Form -Message "ERROR: One or more Evaluate-STIG files were not found.  Unable to continue."
      }
    }
    Else {
      Write-Host "ERROR: 'FileList.xml' not found.  Unable to verify content integrity." -ForegroundColor Red
      Close-Form -Message "ERROR: 'FileList.xml' not found.  Unable to verify content integrity."
    }
    $evalSTIGVersionNumber = ((Get-Content $(Join-Path $ESFolder -ChildPath Evaluate-STIG.ps1) | Select-String -Pattern ('EvaluateStigVersion = ')) -split ("="))[1]
    $BottomLine.Text = "Evaluate-STIG Version = $evalSTIGVersionNumber"

    $ESPathLabel.Text = "Evaluate-STIG Path: $ESFolder"
  }
  else{
    
    Close-Form -Message "Evaluate-STIG Path not found"
  }

  #Initial Setup
  Set-Initial
}

$handler_ListSupportedProductsButton_Click =  {
  $ESDataBox.Text = (Invoke-PowerShell -ESPath $ESFolder -ArgumentList "-ListSupportedProducts" -NoNewWindow) | Format-Table -AutoSize | Out-String
}

$handler_ListApplicableProductsButton_Click = {
  $ESDataBox.Text = Invoke-PowerShell -ESPath $ESFolder -ArgumentList "-ListApplicableProducts" | Format-Table -AutoSize | Out-String
}

$handler_UpdateESButton_Click = {
  If ($UpdateProxy.Checked -eq $true){
    $title = "Proxy"
    $msg = "Enter a Proxy for -Update:"

    $Proxy = [Microsoft.VisualBasic.Interaction]::InputBox($msg, $title)
    $ESDataBox.Text = Invoke-PowerShell -ESPath $ESFolder -ArgumentList "-Update -Proxy $Proxy"
  }
  else{
    $ESDataBox.Text = Invoke-PowerShell -ESPath $ESFolder -ArgumentList "-Update"
  }

  $evalSTIGVersionNumber = ((Get-Content $(Join-Path $ESFolder -ChildPath Evaluate-STIG.ps1) | Select-String -Pattern ('EvaluateStigVersion = ')) -split("="))[1]
  $BottomLine.Text = "Evaluate-STIG Version = $evalSTIGVersionNumber"
}

$handler_GetHelpButton_Click = {
  $ESDataBox.Text = Invoke-PowerShell -ESPath $ESFolder -ArgumentList "GetHelp" -NoNewWindow | Format-Table -AutoSize | Out-String
}

$handler_ContactUsButton_Click = {
  [System.Windows.MessageBox]::Show("Evaluate-STIG Contact methods:`n`n  email:`t`tEval-STIG_spt@us.navy.mil`n`n  MS Teams:`tNAVSEA_RMF `n`n  Fusion:`t`t#evaluate-stig", "Evaluate-STIG Contact Us", "OK", "Question")
}

$handler_PreviewESButton_Click = {
  $ESDataBox.Text = "Command Line to Execute:`n`n$(Join-Path $ESFolder -ChildPath Evaluate-STIG.ps1) $(Get-Arguments)" | Format-Table -AutoSize | Out-String
}

$handler_AFPathButton_Click = {
  $AFKeys | ForEach-Object {$_.Items.Clear() }

  $GetPath = Get-Path -Description "Select Answer File directory"

  if ($GetPath -ne "no_path") {
    $Script:ESAFPath = $GetPath
  }

  $AFXMLs = Get-ChildItem -Path $ESAFPath -Filter *.xml

  Foreach ($AFXML in $AFXMLS) {
    [xml]$XML = Get-Content $AFXML.FullName
    $AllAFKeys += $XML.STIGComments.Vuln.AnswerKey.Name
  }

  $AllAFKeys | Sort-Object -Unique | ForEach-Object { $null = $AFKeys.Items.Add($_) }

  $AFPathLabel.Text = "AFPath:             $ESAFPath"
  &$handler_PreviewESButton_Click
}

$handler_OutputPathButton_Click = {
  $GetPath = Get-Path -Description "Select Output Path directory"

  if ($GetPath -ne "no_path") {
    $Script:ESOutputPath = $GetPath
  }

  $OutputPathLabel.Text = "OutputPath:         $ESOutputPath"
  &$handler_PreviewESButton_Click
}

$handler_SelectVulnButton_Click = {
  $title = "Select Vuln(s)"
  $msg = "Enter Vulnerability IDs (format V-XXXXXX), separate with commas (no spaces):"

  $Script:SelectedVulns = [Microsoft.VisualBasic.Interaction]::InputBox($msg, $title)
  &$handler_PreviewESButton_Click
}

$handler_ExcludeVulnButton_Click = {
  $title = "Exclude Vuln(s)"
  $msg = "Enter Vulnerability IDs (format V-XXXXXX), separate with commas (no spaces):"

  $Script:ExcludedVulns = [Microsoft.VisualBasic.Interaction]::InputBox($msg, $title)
  &$handler_PreviewESButton_Click
}

$handler_ComputerNameButton_Click = {
  $title = "Select Computers"
  $msg = "Enter Computer names, separate with commas (no spaces):"

  $Script:ComputerNames = [Microsoft.VisualBasic.Interaction]::InputBox($msg, $title)

  $AltCredential.Enabled = $true
  $ThrottleLimitBox.Enabled = $true
  &$handler_PreviewESButton_Click
}

$handler_ComputerListButton_Click = {
  $GetPath = Get-File

  if ($GetPath -ne "no_path") {
    $Script:ComputerList = $GetPath
  }

  $AltCredential.Enabled = $true
  $ThrottleLimitBox.Enabled = $true
  &$handler_PreviewESButton_Click
}

$handler_CiscoFilesButton_Click = {
  $GetPath = Get-File

  if ($GetPath -ne "no_path") {
    $Script:CiscoFileList = $GetPath
  }
  &$handler_PreviewESButton_Click
}

$handler_CiscoDirectoryButton_Click = {
  $GetPath = Get-Path -Description "Select Cisco config directory"

  if ($GetPath -ne "no_path") {
    $Script:CiscoDirectory = $GetPath
  }

  $OutputPathLabel.Text = "OutputPath:         $ESOutputPath"
  &$handler_PreviewESButton_Click
}

$handler_ExecuteESButton_Click = {
  $ESDataBox.Text = Invoke-PowerShell -ESPath $ESFolder -ArgumentList $(Get-Arguments) | Format-Table -AutoSize | Out-String
  Write-Host "Manage Evaluate-STIG GUI Execution Complete" -ForegroundColor Green
  Set-Initial
}

$handler_ResetESButton_Click = {
  Set-Initial
}

$handler_SelectSTIGButton_Click = {

  $ExcludeSTIGButton.Enabled = $false
  $ExcludeVulnButton.Enabled = $true
  $SelectVulnButton.Enabled = $true

  $handler_form2close =
  {
    1..3 | ForEach-Object { [GC]::Collect() }

    $form2.Dispose()
    if ($SelectedSTIGS.count -eq 0) {
      $ExcludeSTIGButton.Enabled = $true
    }
    &$handler_PreviewESButton_Click
  }

  $handler_OKButton_Click = {
    $Script:SelectedSTIGS = $STIGSelectList.Items | Where-Object { $STIGSelectList.CheckedItems -contains $_ }
    &$handler_form2close
  }

  $handler_CancelButton_Click = {
    &$handler_form2close
  }

  $form2 = New-Object System.Windows.Forms.Form

  $form2.Text = "Select STIG(s)"
  $form2.Name = "form2"
  $form2.SuspendLayout()

  $form2.AutoScaleDimensions = New-Object System.Drawing.SizeF(96, 96)
  $form2.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::Dpi

  $STIGSelectList = New-Object System.Windows.Forms.CheckedListBox

  $OKButton = New-Object System.Windows.Forms.Button
  $CancelButton = New-Object System.Windows.Forms.Button

  $form2.FormBorderStyle = "Fixed3D"
  $form2.StartPosition = "CenterParent"
  $form2.DataBindings.DefaultDataSourceUpdateMode = 0
  $System_Drawing_Size = New-Object System.Drawing.Size
  $System_Drawing_Size.Width = 1200
  $System_Drawing_Size.Height = 650
  $form2.ClientSize = $System_Drawing_Size

  $System_Drawing_Size = New-Object System.Drawing.Size
  $System_Drawing_Size.Width = 1280
  $System_Drawing_Size.Height = 600
  $STIGSelectList.Size = $System_Drawing_Size
  $STIGSelectList.Font = $BoxFont
  $STIGSelectList.Name = "STIGSelectList"
  $STIGSelectList.MultiColumn = $true
  $STIGSelectList.CheckOnClick = $true
  $STIGSelectList.ColumnWidth = 400
  $System_Drawing_Point = New-Object System.Drawing.Point
  $System_Drawing_Point.X = 10
  $System_Drawing_Point.Y = 10
  $STIGSelectList.Location = $System_Drawing_Point
  $form2.Controls.Add($STIGSelectList)

  $OKButton.Name = "OKButton"
  $System_Drawing_Size = New-Object System.Drawing.Size
  $System_Drawing_Size.Width = 100
  $System_Drawing_Size.Height = 50
  $OKButton.Size = $System_Drawing_Size
  $OKButton.UseVisualStyleBackColor = $True
  $OKButton.Text = "OK"
  $OKButton.Font = $BoxFont
  $System_Drawing_Point = New-Object System.Drawing.Point
  $System_Drawing_Point.X = 495
  $System_Drawing_Point.Y = 600
  $OKButton.Location = $System_Drawing_Point
  $OKButton.DataBindings.DefaultDataSourceUpdateMode = 0
  $OKButton.add_Click($handler_OKButton_Click)
  $form2.Controls.Add($OKButton)

  $CancelButton.Name = "CancelButton"
  $System_Drawing_Size = New-Object System.Drawing.Size
  $System_Drawing_Size.Width = 100
  $System_Drawing_Size.Height = 50
  $CancelButton.Size = $System_Drawing_Size
  $CancelButton.UseVisualStyleBackColor = $True
  $CancelButton.Text = "Cancel"
  $CancelButton.Font = $BoxFont
  $System_Drawing_Point = New-Object System.Drawing.Point
  $System_Drawing_Point.X = 605
  $System_Drawing_Point.Y = 600
  $CancelButton.Location = $System_Drawing_Point
  $CancelButton.DataBindings.DefaultDataSourceUpdateMode = 0
  $CancelButton.add_Click($handler_CancelButton_Click)
  $form2.Controls.Add($CancelButton)

  $STIGListXML = Join-Path -Path $ESFolder -ChildPath "xml" | Join-Path -ChildPath "STIGList.xml"
  $STIGs = ([XML](Get-Content $STIGListXML)).List.STIG | Select-Object ShortName -Unique
  ForEach ($STIG in $STIGs) {
    $STIGSelectList.Items.Add($STIG.Shortname)
  }

  $SelectedSTIGS | ForEach-Object {
    if ($STIGSelectList.Items -contains $_) {
      $index = $STIGSelectList.Items.Indexof($_)
      $STIGSelectList.SetItemChecked($index, $true)
    }
  }

  $form2.Add_FormClosed($handler_form2close)

  $null = $form2.ShowDialog()
}

$handler_ExcludeSTIGButton_Click = {

  $SelectSTIGButton.Enabled = $false

  $handler_form3close =
  {
    1..3 | ForEach-Object { [GC]::Collect() }

    $form3.Dispose()
    &$handler_PreviewESButton_Click
  }

  $handler_OKButton_Click = {
    $Script:ExcludedSTIGS = $STIGExcludeList.Items | Where-Object { $STIGExcludeList.CheckedItems -contains $_ }
    if ($ExcludedSTIGS.count -eq 0){
      $SelectSTIGButton.Enabled = $true
    }
    &$handler_form3close
  }

  $handler_CancelButton_Click = {
    &$handler_form3close
  }

  $form3 = New-Object System.Windows.Forms.Form

  $form3.Text = "Select STIG(s)"
  $form3.Name = "form3"
  $form3.SuspendLayout()

  $form3.AutoScaleDimensions = New-Object System.Drawing.SizeF(96, 96)
  $form3.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::Dpi

  $STIGExcludeList = New-Object System.Windows.Forms.CheckedListBox

  $OKButton = New-Object System.Windows.Forms.Button
  $CancelButton = New-Object System.Windows.Forms.Button

  $form3.FormBorderStyle = "FixedDialog"
  $form3.StartPosition = "CenterParent"
  $form3.DataBindings.DefaultDataSourceUpdateMode = 0
  $System_Drawing_Size = New-Object System.Drawing.Size
  $System_Drawing_Size.Width = 1200
  $System_Drawing_Size.Height = 650
  $form3.ClientSize = $System_Drawing_Size

  $System_Drawing_Size = New-Object System.Drawing.Size
  $System_Drawing_Size.Width = 1280
  $System_Drawing_Size.Height = 600
  $STIGExcludeList.Size = $System_Drawing_Size
  $STIGExcludeList.Font = $BoxFont
  $STIGExcludeList.Name = "STIGExcludeList"
  $STIGExcludeList.MultiColumn = $true
  $STIGExcludeList.CheckOnClick = $true
  $STIGExcludeList.ColumnWidth = 400
  $System_Drawing_Point = New-Object System.Drawing.Point
  $System_Drawing_Point.X = 10
  $System_Drawing_Point.Y = 10
  $STIGExcludeList.Location = $System_Drawing_Point
  $form3.Controls.Add($STIGExcludeList)

  $OKButton.Name = "OKButton"
  $System_Drawing_Size = New-Object System.Drawing.Size
  $System_Drawing_Size.Width = 100
  $System_Drawing_Size.Height = 50
  $OKButton.Size = $System_Drawing_Size
  $OKButton.UseVisualStyleBackColor = $True
  $OKButton.Text = "OK"
  $OKButton.Font = $BoxFont
  $System_Drawing_Point = New-Object System.Drawing.Point
  $System_Drawing_Point.X = 495
  $System_Drawing_Point.Y = 600
  $OKButton.Location = $System_Drawing_Point
  $OKButton.DataBindings.DefaultDataSourceUpdateMode = 0
  $OKButton.add_Click($handler_OKButton_Click)
  $form3.Controls.Add($OKButton)

  $CancelButton.Name = "CancelButton"
  $System_Drawing_Size = New-Object System.Drawing.Size
  $System_Drawing_Size.Width = 100
  $System_Drawing_Size.Height = 50
  $CancelButton.Size = $System_Drawing_Size
  $CancelButton.UseVisualStyleBackColor = $True
  $CancelButton.Text = "Cancel"
  $CancelButton.Font = $BoxFont
  $System_Drawing_Point = New-Object System.Drawing.Point
  $System_Drawing_Point.X = 605
  $System_Drawing_Point.Y = 600
  $CancelButton.Location = $System_Drawing_Point
  $CancelButton.DataBindings.DefaultDataSourceUpdateMode = 0
  $CancelButton.add_Click($handler_CancelButton_Click)
  $form3.Controls.Add($CancelButton)

  $STIGListXML = Join-Path -Path $ESFolder -ChildPath "xml" | Join-Path -ChildPath "STIGList.xml"
  $STIGs = ([XML](Get-Content $STIGListXML)).List.STIG | Select-Object ShortName -Unique
  ForEach ($STIG in $STIGs) {
    $STIGExcludeList.Items.Add($STIG.Shortname)
  }

  $ExcludedSTIGS | ForEach-Object {
    if ($STIGExcludeList.Items -contains $_) {
      $index = $STIGExcludeList.Items.Indexof($_)
      $STIGExcludeList.SetItemChecked($index, $true)
    }
  }

  $form3.Add_FormClosed($handler_form3close)

  $null = $form3.ShowDialog()
}

$handler_formclose =
{
    1..3 | ForEach-Object { [GC]::Collect() }

    $form1.Dispose()
}

#----------------------------------------------
#region Generated Form Code
#----------------------------------------------

$form1.Text = "Manage Evaluate-STIG"
$form1.Name = "form1"
$ManageESVerson = "1.0"
$form1.SuspendLayout()

$form1.AutoScaleDimensions = New-Object System.Drawing.SizeF(96, 96)
$form1.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::Dpi

$form1.FormBorderStyle = "FixedDialog"
$form1.StartPosition = "CenterScreen"
$form1.DataBindings.DefaultDataSourceUpdateMode = 0
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 1750
$System_Drawing_Size.Height = 800
$form1.ClientSize = $System_Drawing_Size

$Title.Text = "Manage Evaluate-STIG"
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 1750
$System_Drawing_Size.Height = 55
$Title.Size = $System_Drawing_Size
$Title.Font = $TitleFont
$Title.TextAlign = "TopCenter"
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 0
$System_Drawing_Point.Y = 5
$Title.Location = $System_Drawing_Point
$form1.Controls.Add($Title)

$ToolsLabel.Text = "Evaluate-STIG Tools"
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 400
$System_Drawing_Size.Height = 40
$ToolsLabel.Size = $System_Drawing_Size
$ToolsLabel.Font = $BodyFont
$ToolsLabel.TextAlign = "TopCenter"
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 30
$System_Drawing_Point.Y = 70
$ToolsLabel.Location = $System_Drawing_Point
$form1.Controls.Add($ToolsLabel)

$OptionsLabel.Text = "Evaluate-STIG Options"
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 1140
$System_Drawing_Size.Height = 40
$OptionsLabel.Size = $System_Drawing_Size
$OptionsLabel.Font = $BodyFont
$OptionsLabel.TextAlign = "TopCenter"
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 500
$System_Drawing_Point.Y = 70
$OptionsLabel.Location = $System_Drawing_Point
$form1.Controls.Add($OptionsLabel)

$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 1730
$System_Drawing_Size.Height = 150
$ESDataBox.Size = $System_Drawing_Size
$ESDataBox.Name = "ESDataBox"
$ESDataBox.Font = $BoxFont
$ESDataBox.ReadOnly = $True
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 10
$System_Drawing_Point.Y = 625
$ESDataBox.Location = $System_Drawing_Point
$form1.Controls.Add($ESDataBox)

$ListSupportedProductsButton.Name = "ListSupportedProductsButton"
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 350
$System_Drawing_Size.Height = 30
$ListSupportedProductsButton.Size = $System_Drawing_Size
$ListSupportedProductsButton.UseVisualStyleBackColor = $True
$ListSupportedProductsButton.Text = "List Supported Products"
$ListSupportedProductsButton.Font = $BoxFont
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 55
$System_Drawing_Point.Y = 125
$ListSupportedProductsButton.Location = $System_Drawing_Point
$ListSupportedProductsButton.DataBindings.DefaultDataSourceUpdateMode = 0
$ListSupportedProductsButton.add_Click($handler_ListSupportedProductsButton_Click)
$form1.Controls.Add($ListSupportedProductsButton)

$ListApplicableProductsButton.Name = "ListApplicableProductsButton"
$ListApplicableProductsButton.Size = $System_Drawing_Size
$ListApplicableProductsButton.UseVisualStyleBackColor = $True
$ListApplicableProductsButton.Text = "List Applicable Products"
$ListApplicableProductsButton.Font = $BoxFont
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 55
$System_Drawing_Point.Y = 165
$ListApplicableProductsButton.Location = $System_Drawing_Point
$ListApplicableProductsButton.DataBindings.DefaultDataSourceUpdateMode = 0
$ListApplicableProductsButton.add_Click($handler_ListApplicableProductsButton_Click)
$form1.Controls.Add($ListApplicableProductsButton)

$UpdateESButton.Name = "UpdateESButton"
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 350
$System_Drawing_Size.Height = 30
$UpdateESButton.Size = $System_Drawing_Size
$UpdateESButton.UseVisualStyleBackColor = $True
$UpdateESButton.Text = "Update Evaluate-STIG"
$UpdateESButton.Font = $BoxFont
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 55
$System_Drawing_Point.Y = 205
$UpdateESButton.Location = $System_Drawing_Point
$UpdateESButton.DataBindings.DefaultDataSourceUpdateMode = 0
$UpdateESButton.add_Click($handler_UpdateESButton_Click)
$form1.Controls.Add($UpdateESButton)

$GetHelpButton.Name = "GetHelp"
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 350
$System_Drawing_Size.Height = 30
$GetHelpButton.Size = $System_Drawing_Size
$GetHelpButton.UseVisualStyleBackColor = $True
$GetHelpButton.Text = "Get Evaluate-STIG Help"
$GetHelpButton.Font = $BoxFont
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 55
$System_Drawing_Point.Y = 285
$GetHelpButton.Location = $System_Drawing_Point
$GetHelpButton.DataBindings.DefaultDataSourceUpdateMode = 0
$GetHelpButton.add_Click($handler_GetHelpButton_Click)
$form1.Controls.Add($GetHelpButton)

$ContactUsButton.Name = "ContactUs"
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 350
$System_Drawing_Size.Height = 30
$ContactUsButton.Size = $System_Drawing_Size
$ContactUsButton.UseVisualStyleBackColor = $True
$ContactUsButton.Text = "Contact Us"
$ContactUsButton.Font = $BoxFont
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 55
$System_Drawing_Point.Y = 325
$ContactUsButton.Location = $System_Drawing_Point
$ContactUsButton.DataBindings.DefaultDataSourceUpdateMode = 0
$ContactUsButton.add_Click($handler_ContactUsButton_Click)
$form1.Controls.Add($ContactUsButton)

$PreviewESButton.Name = "PreviewESButton"
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 150
$System_Drawing_Size.Height = 50
$PreviewESButton.Size = $System_Drawing_Size
$PreviewESButton.UseVisualStyleBackColor = $True
$PreviewESButton.Text = "Preview"
$PreviewESButton.Font = $BoxFont
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 10
$System_Drawing_Point.Y = 385
$PreviewESButton.Location = $System_Drawing_Point
$PreviewESButton.DataBindings.DefaultDataSourceUpdateMode = 0
$PreviewESButton.add_Click($handler_PreviewESButton_Click)
$form1.Controls.Add($PreviewESButton)

$ExecuteESButton.Name = "ExecuteESButton"
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 150
$System_Drawing_Size.Height = 50
$ExecuteESButton.Size = $System_Drawing_Size
$ExecuteESButton.UseVisualStyleBackColor = $True
$ExecuteESButton.Text = "Execute"
$ExecuteESButton.Font = $BoxFont
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 160
$System_Drawing_Point.Y = 385
$ExecuteESButton.Location = $System_Drawing_Point
$ExecuteESButton.DataBindings.DefaultDataSourceUpdateMode = 0
$ExecuteESButton.add_Click($handler_ExecuteESButton_Click)
$form1.Controls.Add($ExecuteESButton)

$ResetESButton.Name = "ResetESButton"
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 150
$System_Drawing_Size.Height = 50
$ResetESButton.Size = $System_Drawing_Size
$ResetESButton.UseVisualStyleBackColor = $True
$ResetESButton.Text = "Reset"
$ResetESButton.Font = $BoxFont
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 310
$System_Drawing_Point.Y = 385
$ResetESButton.Location = $System_Drawing_Point
$ResetESButton.DataBindings.DefaultDataSourceUpdateMode = 0
$ResetESButton.add_Click($handler_ResetESButton_Click)
$form1.Controls.Add($ResetESButton)

$SelectSTIGButton.Name = "SelectSTIGButton"
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 270
$System_Drawing_Size.Height = 50
$SelectSTIGButton.Size = $System_Drawing_Size
$SelectSTIGButton.UseVisualStyleBackColor = $True
$SelectSTIGButton.Text = "Select STIG(s)"
$SelectSTIGButton.Font = $BoxFont
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 1200
$System_Drawing_Point.Y = 130
$SelectSTIGButton.Location = $System_Drawing_Point
$SelectSTIGButton.DataBindings.DefaultDataSourceUpdateMode = 0
$SelectSTIGButton.add_Click($handler_SelectSTIGButton_Click)
$form1.Controls.Add($SelectSTIGButton)

$SelectVulnButton.Name = "SelectVulnButton"
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 270
$System_Drawing_Size.Height = 50
$SelectVulnButton.Size = $System_Drawing_Size
$SelectVulnButton.UseVisualStyleBackColor = $True
$SelectVulnButton.Text = "Select Vuln(s)"
$SelectVulnButton.Font = $BoxFont
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 1200
$System_Drawing_Point.Y = 190
$SelectVulnButton.Location = $System_Drawing_Point
$SelectVulnButton.DataBindings.DefaultDataSourceUpdateMode = 0
$SelectVulnButton.add_Click($handler_SelectVulnButton_Click)
$form1.Controls.Add($SelectVulnButton)

$ExcludeSTIGButton.Name = "ExcludeSTIGButton"
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 270
$System_Drawing_Size.Height = 50
$ExcludeSTIGButton.Size = $System_Drawing_Size
$ExcludeSTIGButton.UseVisualStyleBackColor = $True
$ExcludeSTIGButton.Text = "Exclude STIG(s)"
$ExcludeSTIGButton.Font = $BoxFont
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 1470
$System_Drawing_Point.Y = 130
$ExcludeSTIGButton.Location = $System_Drawing_Point
$ExcludeSTIGButton.DataBindings.DefaultDataSourceUpdateMode = 0
$ExcludeSTIGButton.add_Click($handler_ExcludeSTIGButton_Click)
$form1.Controls.Add($ExcludeSTIGButton)

$ExcludeVulnButton.Name = "ExcludeVulnButton"
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 270
$System_Drawing_Size.Height = 50
$ExcludeVulnButton.Size = $System_Drawing_Size
$ExcludeVulnButton.UseVisualStyleBackColor = $True
$ExcludeVulnButton.Text = "Exclude Vuln(s)"
$ExcludeVulnButton.Font = $BoxFont
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 1470
$System_Drawing_Point.Y = 190
$ExcludeVulnButton.Location = $System_Drawing_Point
$ExcludeVulnButton.DataBindings.DefaultDataSourceUpdateMode = 0
$ExcludeVulnButton.add_Click($handler_ExcludeVulnButton_Click)
$form1.Controls.Add($ExcludeVulnButton)

$OutputPathButton.Name = "OutputPathButton"
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 270
$System_Drawing_Size.Height = 50
$OutputPathButton.Size = $System_Drawing_Size
$OutputPathButton.UseVisualStyleBackColor = $True
$OutputPathButton.Text = "Select OutputPath"
$OutputPathButton.Font = $BoxFont
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 1200
$System_Drawing_Point.Y = 250
$OutputPathButton.Location = $System_Drawing_Point
$OutputPathButton.DataBindings.DefaultDataSourceUpdateMode = 0
$OutputPathButton.add_Click($handler_OutputPathButton_Click)
$form1.Controls.Add($OutputPathButton)

$ComputerNameButton.Name = "ComputerNameButton"
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 270
$System_Drawing_Size.Height = 50
$ComputerNameButton.Size = $System_Drawing_Size
$ComputerNameButton.UseVisualStyleBackColor = $True
$ComputerNameButton.Text = "Input Computer(s)"
$ComputerNameButton.Font = $BoxFont
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 1470
$System_Drawing_Point.Y = 250
$ComputerNameButton.Location = $System_Drawing_Point
$ComputerNameButton.DataBindings.DefaultDataSourceUpdateMode = 0
$ComputerNameButton.add_Click($handler_ComputerNameButton_Click)
$form1.Controls.Add($ComputerNameButton)

$ComputerListButton.Name = "ComputerListButton"
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 540
$System_Drawing_Size.Height = 50
$ComputerListButton.Size = $System_Drawing_Size
$ComputerListButton.UseVisualStyleBackColor = $True
$ComputerListButton.Text = "Select Computer List Files(s)"
$ComputerListButton.Font = $BoxFont
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 1200
$System_Drawing_Point.Y = 320
$ComputerListButton.Location = $System_Drawing_Point
$ComputerListButton.DataBindings.DefaultDataSourceUpdateMode = 0
$ComputerListButton.add_Click($handler_ComputerListButton_Click)
$form1.Controls.Add($ComputerListButton)

$CiscoFilesButton.Name = "CiscoFilesButton"
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 540
$System_Drawing_Size.Height = 50
$CiscoFilesButton.Size = $System_Drawing_Size
$CiscoFilesButton.UseVisualStyleBackColor = $True
$CiscoFilesButton.Text = "Select Cisco File(s)"
$CiscoFilesButton.Font = $BoxFont
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 1200
$System_Drawing_Point.Y = 380
$CiscoFilesButton.Location = $System_Drawing_Point
$CiscoFilesButton.DataBindings.DefaultDataSourceUpdateMode = 0
$CiscoFilesButton.add_Click($handler_CiscoFilesButton_Click)
$form1.Controls.Add($CiscoFilesButton)

$CiscoDirectoryButton.Name = "CiscoDirectoryButton"
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 540
$System_Drawing_Size.Height = 50
$CiscoDirectoryButton.Size = $System_Drawing_Size
$CiscoDirectoryButton.UseVisualStyleBackColor = $True
$CiscoDirectoryButton.Text = "Select Cisco Directory"
$CiscoDirectoryButton.Font = $BoxFont
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 1200
$System_Drawing_Point.Y = 440
$CiscoDirectoryButton.Location = $System_Drawing_Point
$CiscoDirectoryButton.DataBindings.DefaultDataSourceUpdateMode = 0
$CiscoDirectoryButton.add_Click($handler_CiscoDirectoryButton_Click)
$form1.Controls.Add($CiscoDirectoryButton)

$UpdateProxy.Name = "UpdateProxy"
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 200
$System_Drawing_Size.Height = 50
$UpdateProxy.Size = $System_Drawing_Size
$UpdateProxy.Text = "Use Proxy"
$UpdateProxy.Font = $BoxFont
$UpdateProxy.Checked = $false
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 260
$System_Drawing_Point.Y = 235
$UpdateProxy.Location = $System_Drawing_Point
$UpdateProxy.UseVisualStyleBackColor = $True
$form1.Controls.Add($UpdateProxy)

$AltCredential.Name = "AltCredential"
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 275
$System_Drawing_Size.Height = 50
$AltCredential.Size = $System_Drawing_Size
$AltCredential.Text = " AltCredential"
$AltCredential.Font = $BoldBoxFont
$AltCredential.Checked = $false
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 500
$System_Drawing_Point.Y = 130
$AltCredential.Location = $System_Drawing_Point
$AltCredential.UseVisualStyleBackColor = $True
$form1.Controls.Add($AltCredential)

$GenerateOQE.Name = "GenerateOQE"
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 230
$System_Drawing_Size.Height = 50
$GenerateOQE.Size = $System_Drawing_Size
$GenerateOQE.Text = " GenerateOQE"
$GenerateOQE.Font = $BoldBoxFont
$GenerateOQE.Checked = $false
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 500
$System_Drawing_Point.Y = 180
$GenerateOQE.Location = $System_Drawing_Point
$GenerateOQE.UseVisualStyleBackColor = $True
$form1.Controls.Add($GenerateOQE)

$NoPrevious.Name = "NoPrevious"
$NoPrevious.Size = $System_Drawing_Size
$NoPrevious.Text = " NoPrevious"
$NoPrevious.Font = $BoldBoxFont
$NoPrevious.Checked = $false
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 500
$System_Drawing_Point.Y = 230
$NoPrevious.Location = $System_Drawing_Point
$NoPrevious.UseVisualStyleBackColor = $True
$form1.Controls.Add($NoPrevious)

$ApplyTattoo.Name = "ApplyTattoo"
$ApplyTattoo.Size = $System_Drawing_Size
$ApplyTattoo.Text = " ApplyTattoo"
$ApplyTattoo.Font = $BoldBoxFont
$ApplyTattoo.Checked = $false
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 500
$System_Drawing_Point.Y = 280
$ApplyTattoo.Location = $System_Drawing_Point
$ApplyTattoo.UseVisualStyleBackColor = $True
$form1.Controls.Add($ApplyTattoo)

$VulnTimeoutLabel.Text = "VulnTimeout"
$VulnTimeoutLabel.Size = $System_Drawing_Size
$VulnTimeoutLabel.Font = $BoldBoxFont
$VulnTimeoutLabel.TextAlign = "TopLeft"
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 780
$System_Drawing_Point.Y = 135
$VulnTimeoutLabel.Location = $System_Drawing_Point
$form1.Controls.Add($VulnTimeoutLabel)

$ThrottleLimitLabel.Text = "ThrottleLimit"
$ThrottleLimitLabel.Size = $System_Drawing_Size
$ThrottleLimitLabel.Font = $BoldBoxFont
$ThrottleLimitLabel.TextAlign = "TopLeft"
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 780
$System_Drawing_Point.Y = 185
$ThrottleLimitLabel.Location = $System_Drawing_Point
$form1.Controls.Add($ThrottleLimitLabel)

$MarkingLabel.Text = "Marking"
$MarkingLabel.Size = $System_Drawing_Size
$MarkingLabel.Font = $BoldBoxFont
$MarkingLabel.TextAlign = "TopLeft"
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 780
$System_Drawing_Point.Y = 235
$MarkingLabel.Location = $System_Drawing_Point
$form1.Controls.Add($MarkingLabel)

$VulnTimeoutBox.Name = "VulnTimeoutBox"
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 150
$System_Drawing_Size.Height = 50
$VulnTimeoutBox.Size = $System_Drawing_Size
$VulnTimeoutBox.Font = $BoxFont
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 1020
$System_Drawing_Point.Y = 135
$VulnTimeoutBox.Location = $System_Drawing_Point
$form1.Controls.Add($VulnTimeoutBox)

$ThrottleLimitBox.Name = "ThrottleLimitBox"
$ThrottleLimitBox.Size = $System_Drawing_Size
$ThrottleLimitBox.Font = $BoxFont
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 1020
$System_Drawing_Point.Y = 185
$ThrottleLimitBox.Location = $System_Drawing_Point
$form1.Controls.Add($ThrottleLimitBox)

$MarkingBox.Name = "MarkingBox"
$MarkingBox.Size = $System_Drawing_Size
$MarkingBox.Font = $BoxFont
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 1020
$System_Drawing_Point.Y = 235
$MarkingBox.Location = $System_Drawing_Point
$form1.Controls.Add($MarkingBox)

$ScanTypeLabel.Text = "ScanType"
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 175
$System_Drawing_Size.Height = 50
$ScanTypeLabel.Size = $System_Drawing_Size
$ScanTypeLabel.Font = $BoldBoxFont
$ScanTypeLabel.TextAlign = "TopLeft"
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 780
$System_Drawing_Point.Y = 285
$ScanTypeLabel.Location = $System_Drawing_Point
$form1.Controls.Add($ScanTypeLabel)

$AFKeysLabel.Text = "AF Keys"
$AFKeysLabel.Size = $System_Drawing_Size
$AFKeysLabel.Font = $BoldBoxFont
$AFKeysLabel.TextAlign = "TopLeft"
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 780
$System_Drawing_Point.Y = 335
$AFKeysLabel.Location = $System_Drawing_Point
$form1.Controls.Add($AFKeysLabel)

$ScanType.Name = "ScanType"
$ScanType.Font = $BoxFont
$ScanType.Width = 200
$ScanType.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 970
$System_Drawing_Point.Y = 285
$ScanType.Location = $System_Drawing_Point
$form1.Controls.Add($ScanType)

$AFPathButton.Name = "AFPathButton"
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 250
$System_Drawing_Size.Height = 50
$AFPathButton.Size = $System_Drawing_Size
$AFPathButton.UseVisualStyleBackColor = $True
$AFPathButton.Text = "Select AFPath"
$AFPathButton.Font = $BoxFont
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 500
$System_Drawing_Point.Y = 330
$AFPathButton.Location = $System_Drawing_Point
$AFPathButton.DataBindings.DefaultDataSourceUpdateMode = 0
$AFPathButton.add_Click($handler_AFPathButton_Click)
$form1.Controls.Add($AFPathButton)

$AFKeys.Name = "AF Keys"
$AFKeys.Font = $BoxFont
$AFKeys.Width = 200
$AFKeys.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 970
$System_Drawing_Point.Y = 335
$AFKeys.Location = $System_Drawing_Point
$form1.Controls.Add($AFKeys)

$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 1270
$System_Drawing_Size.Height = 30
$ESPathLabel.Size = $System_Drawing_Size
$ESPathLabel.Font = $BoxFont
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 5
$System_Drawing_Point.Y = 520
$ESPathLabel.Location = $System_Drawing_Point
$form1.Controls.Add($ESPathLabel)

$AFPathLabel.Size = $System_Drawing_Size
$AFPathLabel.Font = $BoxFont
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 5
$System_Drawing_Point.Y = 550
$AFPathLabel.Location = $System_Drawing_Point
$form1.Controls.Add($AFPathLabel)

$OutputPathLabel.Size = $System_Drawing_Size
$OutputPathLabel.Font = $BoxFont
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 5
$System_Drawing_Point.Y = 580
$OutputPathLabel.Location = $System_Drawing_Point
$form1.Controls.Add($OutputPathLabel)

$VLineLeft.Text = ""
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 2
$System_Drawing_Size.Height = 450
$VLineLeft.Size = $System_Drawing_Size
$VLineLeft.BorderStyle = "Fixed3D"
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 475
$System_Drawing_Point.Y = 60
$VLineLeft.Location = $System_Drawing_Point
$form1.Controls.Add($VLineLeft)

$HLineTop.Text = ""
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 1920
$System_Drawing_Size.Height = 2
$HLineTop.Size = $System_Drawing_Size
$HLineTop.BorderStyle = "Fixed3D"
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 0
$System_Drawing_Point.Y = 60
$HLineTop.Location = $System_Drawing_Point
$form1.Controls.Add($HLineTop)

$HLineOptionBottom.Text = ""
$HLineOptionBottom.Size = $System_Drawing_Size
$HLineOptionBottom.BorderStyle = "Fixed3D"
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 0
$System_Drawing_Point.Y = 510
$HLineOptionBottom.Location = $System_Drawing_Point
$form1.Controls.Add($HLineOptionBottom)

$HLineBottom.Text = ""
$HLineBottom.Size = $System_Drawing_Size
$HLineBottom.BorderStyle = "Fixed3D"
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 0
$System_Drawing_Point.Y = 775
$HLineBottom.Location = $System_Drawing_Point
$form1.Controls.Add($HLineBottom)

$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 860
$System_Drawing_Size.Height = 20
$BottomLine.Size = $System_Drawing_Size
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 5
$System_Drawing_Point.Y = 780
$BottomLine.Location = $System_Drawing_Point
$form1.Controls.Add($BottomLine)

$BottomLineVersion.Text = "v $ManageESVerson"
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 50
$System_Drawing_Size.Height = 20
$BottomLineVersion.Size = $System_Drawing_Size
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 1700
$System_Drawing_Point.Y = 780
$BottomLineVersion.Location = $System_Drawing_Point
$form1.Controls.Add($BottomLineVersion)

$form1.ResumeLayout()

#Init the OnLoad event to correct the initial state of the form
$InitialFormWindowState = $form1.WindowState

#Save the initial state of the form
$form1.add_Load($OnLoadForm_StateCorrection)

$form1.Add_FormClosed($handler_formclose)
#Show the Form
$null = [Windows.Forms.Application]::Run($form1)

# SIG # Begin signature block
# MIIL+QYJKoZIhvcNAQcCoIIL6jCCC+YCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDSc2xjxWYGNat7
# VTtgW5+Z1LUSWTI6qS/ALZCMfGf846CCCTswggR6MIIDYqADAgECAgQDAgTXMA0G
# CSqGSIb3DQEBCwUAMFoxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVy
# bm1lbnQxDDAKBgNVBAsTA0RvRDEMMAoGA1UECxMDUEtJMRUwEwYDVQQDEwxET0Qg
# SUQgQ0EtNTkwHhcNMjAwNzE1MDAwMDAwWhcNMjUwNDAyMTMzODMyWjBpMQswCQYD
# VQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0Qx
# DDAKBgNVBAsTA1BLSTEMMAoGA1UECxMDVVNOMRYwFAYDVQQDEw1DUy5OU1dDQ0Qu
# MDAxMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2/Z91ObHZ009DjsX
# ySa9T6DbT+wWgX4NLeTYZwx264hfFgUnIww8C9Mm6ht4mVfo/qyvmMAqFdeyhXiV
# PZuhbDnzdKeXpy5J+oxtWjAgnWwJ983s3RVewtV063W7kYIqzj+Ncfsx4Q4TSgmy
# ASOMTUhlzm0SqP76zU3URRj6N//NzxAcOPLlfzxcFPMpWHC9zNlVtFqGtyZi/STj
# B7ed3BOXmddiLNLCL3oJm6rOsidZstKxEs3I1llWjsnltn7fR2/+Fm+roWrF8B4z
# ekQOu9t8WRZfNohKoXVtVuwyUAJQF/8kVtIa2YyxTUAF9co9qVNZgko/nx0gIdxS
# hxmEvQIDAQABo4IBNzCCATMwHwYDVR0jBBgwFoAUdQmmFROuhzz6c5QA8vD1ebmy
# chQwQQYDVR0fBDowODA2oDSgMoYwaHR0cDovL2NybC5kaXNhLm1pbC9jcmwvRE9E
# SURDQV81OV9OQ09ERVNJR04uY3JsMA4GA1UdDwEB/wQEAwIHgDAWBgNVHSAEDzAN
# MAsGCWCGSAFlAgELKjAdBgNVHQ4EFgQUVusXc6nN92xmQ3XNN+/76hosJFEwZQYI
# KwYBBQUHAQEEWTBXMDMGCCsGAQUFBzAChidodHRwOi8vY3JsLmRpc2EubWlsL3Np
# Z24vRE9ESURDQV81OS5jZXIwIAYIKwYBBQUHMAGGFGh0dHA6Ly9vY3NwLmRpc2Eu
# bWlsMB8GA1UdJQQYMBYGCisGAQQBgjcKAw0GCCsGAQUFBwMDMA0GCSqGSIb3DQEB
# CwUAA4IBAQBCSdogBcOfKqyGbKG45lLicG1LJ2dmt0Hwl7QkKrZNNEDh2Q2+uzB7
# SRmADtSOVjVf/0+1B4jBoyty90WL52rMPVttb8tfm0f/Wgw6niz5WQZ+XjFRTFQa
# M7pBNU54vI3bH4MFBTXUOEoSr0FELFQaByUWfWKrGLnEqYtpDde5FZEYKRv6td6N
# ZH7m5JOiCfEK6gun3luq7ckvx5zIXjr5VKhp+S0Aai3ZR/eqbBZ0wcUF3DOYlqVs
# LiPT0jWompwkfSnxa3fjNHD+FKvd/7EMQM/wY0vZyIObto3QYrLru6COAyY9cC/s
# Dj+R4K4392w1LWdo3KrNzkCFMAX6j/bWMIIEuTCCA6GgAwIBAgICAwUwDQYJKoZI
# hvcNAQELBQAwWzELMAkGA1UEBhMCVVMxGDAWBgNVBAoTD1UuUy4gR292ZXJubWVu
# dDEMMAoGA1UECxMDRG9EMQwwCgYDVQQLEwNQS0kxFjAUBgNVBAMTDURvRCBSb290
# IENBIDMwHhcNMTkwNDAyMTMzODMyWhcNMjUwNDAyMTMzODMyWjBaMQswCQYDVQQG
# EwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxDDAK
# BgNVBAsTA1BLSTEVMBMGA1UEAxMMRE9EIElEIENBLTU5MIIBIjANBgkqhkiG9w0B
# AQEFAAOCAQ8AMIIBCgKCAQEAzBeEny3BCletEU01Vz8kRy8cD2OWvbtwMTyunFaS
# hu+kIk6g5VRsnvbhK3Ho61MBmlGJc1pLSONGBhpbpyr2l2eONAzmi8c8917V7Bpn
# JZvYj66qGRmY4FXX6UZQ6GdALKKedJKrMQfU8LmcBJ/LGcJ0F4635QocGs9UoFS5
# hLgVyflDTC/6x8EPbi/JXk6N6iod5JIAxNp6qW/5ZBvhiuMo19oYX5LuUy9B6W7c
# A0cRygvYcwKKYK+cIdBoxAj34yw2HJI8RQt490QPGClZhz0WYFuNSnUJgTHsdh2V
# NEn2AEe2zYhPFNlCu3gSmOSp5vxpZWbMIQ8cTv4pRWG47wIDAQABo4IBhjCCAYIw
# HwYDVR0jBBgwFoAUbIqUonexgHIdgXoWqvLczmbuRcAwHQYDVR0OBBYEFHUJphUT
# roc8+nOUAPLw9Xm5snIUMA4GA1UdDwEB/wQEAwIBhjBnBgNVHSAEYDBeMAsGCWCG
# SAFlAgELJDALBglghkgBZQIBCycwCwYJYIZIAWUCAQsqMAsGCWCGSAFlAgELOzAM
# BgpghkgBZQMCAQMNMAwGCmCGSAFlAwIBAxEwDAYKYIZIAWUDAgEDJzASBgNVHRMB
# Af8ECDAGAQH/AgEAMAwGA1UdJAQFMAOAAQAwNwYDVR0fBDAwLjAsoCqgKIYmaHR0
# cDovL2NybC5kaXNhLm1pbC9jcmwvRE9EUk9PVENBMy5jcmwwbAYIKwYBBQUHAQEE
# YDBeMDoGCCsGAQUFBzAChi5odHRwOi8vY3JsLmRpc2EubWlsL2lzc3VlZHRvL0RP
# RFJPT1RDQTNfSVQucDdjMCAGCCsGAQUFBzABhhRodHRwOi8vb2NzcC5kaXNhLm1p
# bDANBgkqhkiG9w0BAQsFAAOCAQEAOQUb0g6nPvWoc1cJ5gkhxSyGA3bQKu8HnKbg
# +vvMpMFEwo2p30RdYHGvA/3GGtrlhxBqAcOqeYF5TcXZ4+Fa9CbKE/AgloCuTjEY
# t2/0iaSvdw7y9Vqk7jyT9H1lFIAQHHN3TEwN1nr7HEWVkkg41GXFxU01UHfR7vgq
# TTz+3zZL2iCqADVDspna0W5pF6yMla6gn4u0TmWu2SeqBpctvdcfSFXkzQBZGT1a
# D/W2Fv00KwoQgB2l2eiVk56mEjN/MeI5Kp4n57mpREsHutP4XnLQ01ZN2qgn+844
# JRrzPQ0pazPYiSl4PeI2FUItErA6Ob/DPF0ba2y3k4dFkUTApzGCAhQwggIQAgEB
# MGIwWjELMAkGA1UEBhMCVVMxGDAWBgNVBAoTD1UuUy4gR292ZXJubWVudDEMMAoG
# A1UECxMDRG9EMQwwCgYDVQQLEwNQS0kxFTATBgNVBAMTDERPRCBJRCBDQS01OQIE
# AwIE1zANBglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3AgEMMQowCKACgAChAoAA
# MBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgor
# BgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBBcv+I6P8KtAaKtKOi0AsXMuc2hZrd
# U4/7KDMOl3UsajANBgkqhkiG9w0BAQEFAASCAQCMVk2KAXr23RsAVONYV1GdVTiJ
# zmJpKab6LyYgWJY696vNsr76qHNOtH2v93bhdN+IUwraTAHZzoCmyJch0BT4vHzY
# AhoKOFX5ubnMJ1S465CldDZX1QgsLTEkvrdJpaMubpuPYvZizH/eEEEcR/Y3evoz
# 3lxMT8raf3N7MNnyOJ/QYFXmzktmoxFYxOzxTEjYyfpVnsedZb5zouS1R3dV78mu
# vSaXh8fB+tA4fQpj+zGOoiP2xRY3cibnnyHeUgIHREFipacSpDZ50Bkl8dqimxNj
# E01P7IebUF3y4YCRROhZEnmdt05uk7nUa1AFwf82Fl6Huw40RGPD3jsPj57Q
# SIG # End signature block
