# PowerShell Gallery Preparation Guide

## Current PSScriptAnalyzer Status

The module has been analyzed and the following warnings remain:

### Acceptable Warnings (Design Decisions)
These warnings are intentional design choices and don't need fixing:

1. **PSUseApprovedVerbs**: `Ask-GPT` uses an unapproved verb
   - **Rationale**: "Ask" is intuitive for AI interactions, even though it's not PowerShell-approved
   - **Alternative**: Could be `Invoke-GPT` but "Ask" is more user-friendly

2. **PSAvoidGlobalVars**: Global variables for conversation history
   - **Rationale**: Necessary for maintaining conversation state across function calls
   - **Variables**: `$global:RememberGptHistory`, `$global:gptHistory`

3. **PSAvoidUsingWriteHost**: Direct console writing for ANSI support
   - **Rationale**: Required for proper ANSI escape sequence rendering
   - **Alternative**: Write-Output doesn't support ANSI formatting properly

## PowerShell Gallery Publication Steps

### Prerequisites
```powershell
# Install required modules
Install-Module -Name PowerShellGet -Force
Install-Module -Name PSScriptAnalyzer -Force

# Get API key from https://www.powershellgallery.com/account/apikeys
$apiKey = "YOUR_POWERSHELL_GALLERY_API_KEY"
```

### Publication Process
```powershell
# 1. Validate the module
Test-ModuleManifest ./Ask-GPT.psd1

# 2. Run final analysis
Invoke-ScriptAnalyzer -Path ./Ask-GPT.psm1 -Severity Error

# 3. Publish to PowerShell Gallery
Publish-Module -Path . -Repository PSGallery -NuGetApiKey $apiKey

# 4. Verify publication
Find-Module -Name Ask-GPT
```

### Pre-publication Checklist
- [ ] Module manifest is valid
- [ ] No PSScriptAnalyzer errors (warnings are acceptable)
- [ ] README.md is complete
- [ ] CHANGELOG.md is updated
- [ ] License file exists
- [ ] Version follows semantic versioning
- [ ] All functions have proper help documentation

## Gallery Compliance Notes

The remaining PSScriptAnalyzer warnings are acceptable for PowerShell Gallery publication:
- **Global variables**: Required for conversation state persistence
- **Console.Write methods**: Necessary for ANSI terminal support
- **Unapproved verb**: "Ask" is intuitive for AI interactions

The module prioritizes user experience and terminal compatibility over strict PSScriptAnalyzer compliance where necessary.
