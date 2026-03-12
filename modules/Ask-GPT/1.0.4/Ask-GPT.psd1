@{
    # Module manifest for Ask-GPT
    ModuleVersion = '1.0.4'
    GUID = 'b8c5e8a0-4d1a-4a7e-9b2c-3f4d5e6a7b8c'
    Author = 'stimpy77'
    CompanyName = 'Unknown'
    Copyright = '(c) 2025 stimpy77. All rights reserved.'
    Description = 'A PowerShell module for interacting with OpenAI GPT models via command line interface.'
    PowerShellVersion = '7.0'
    RootModule = 'Ask-GPT.psm1'
    FunctionsToExport = @('Ask-GPT')
    AliasesToExport = @('gpt')
    CmdletsToExport = @()
    VariablesToExport = @()
    
    # Private data to pass to the module specified in RootModule/ModuleToProcess
    PrivateData = @{
        PSData = @{
            # Tags applied to this module
            Tags = @('OpenAI', 'GPT', 'AI', 'Chat', 'API', 'PowerShell', 'Ask-GPT', 'AskGPT', 'ChatGPT', 'CLI', 'CommandLine')
            
            # A URL to the license for this module
            LicenseUri = 'https://github.com/stimpy77/Ask-GPT/blob/main/LICENSE'
            
            # License expression or path to license file
            License = 'MIT'
            
            # A URL to the main website for this project
            ProjectUri = 'https://github.com/stimpy77/ask-gpt'
            
            # ReleaseNotes of this module
            ReleaseNotes = @'
Version 1.0.4: Major fixes and GPT-5 support
- Fixed GPT-5 compatibility: Handle temperature restrictions (GPT-5 only supports default temperature)
- Fixed GPT-5 streaming: Auto-fallback to non-streaming for unverified organizations
- Improved error handling with detailed API error messages
- Better model filtering to exclude problematic models (realtime, instruct, etc.)
- Enhanced model auto-detection with robust fallback to gpt-4o
- Fixed temperature parameter handling for different model types
- Improved ANSI escape sequence support for better terminal rendering
'@
        }
    }
}
