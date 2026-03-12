# Ask-GPT PowerShell Module

## Overview
Ask-GPT is a PowerShell module that provides a command-line interface to interact with GPT models from OpenAI.

## Features
- Query GPT models using various parameters such as model type, temperature, and more.
- Stream responses directly to the console.
- Maintain history of queries and responses.

## Installation
To install the Ask-GPT module, download the `Ask-GPT.psm1` file and import the module using PowerShell:

```powershell
Import-Module /path/to/Ask-GPT.psm1
```

## Usage

### Piping to GPT

To pipe input directly to Ask-GPT:

```powershell
"what is 2+2?" | Ask-GPT
```

To use the shorter `gpt` alias for piping, first set up an alias in your shell:

```powershell
Set-Alias -Name gpt -Value Ask-GPT
```

Then you can pipe to the alias:

```powershell
"what is 2+2?" | gpt
```

Example command to query GPT:

```powershell
Ask-GPT -Prompt "Your question here" -Model "gpt-4"
```

Or using the shorter alias:

```powershell
gpt "Your question here"
```

## Requirements
- PowerShell 7.5.0 or later
- OpenAI API key set in environment variables:
  - `OPENAI_PERSONAL_API_KEY` (checked first) OR
  - `OPENAI_API_KEY` (fallback if personal key not found)

## API Key Setup
### Step by Step
1. **Obtain an API key** from the [OpenAI platform](https://platform.openai.com).
2. **Set environment variables** using either of the methods below:
   - **Single Session**: Run this in your PowerShell session:
     ```powershell
     $env:OPENAI_PERSONAL_API_KEY = 'YOUR_KEY_HERE'
     ```
   - **Permanent (MacOS/Linux)**: Add the following line to your `.zshrc` or `.bashrc` file:
     ```shell
     export OPENAI_PERSONAL_API_KEY='YOUR_KEY_HERE'
     ```
   - **Permanent (Windows)**: Run the following PowerShell command to set it persistently:
     ```powershell
     [System.Environment]::SetEnvironmentVariable('OPENAI_PERSONAL_API_KEY', 'YOUR_KEY_HERE', [System.EnvironmentVariableTarget]::User)
     ```
3. **Verify the setup**:
   ```powershell
   echo $env:OPENAI_PERSONAL_API_KEY
   ```

### Precedence
- **OPENAI_PERSONAL_API_KEY** is checked first
- **OPENAI_API_KEY** is the fallback option if the personal key isn't set

## Troubleshooting
### Common Issues
- **API Key Errors**:
  - Ensure API keys are correctly set as environment variables. Recheck using:
    ```powershell
    echo $env:OPENAI_PERSONAL_API_KEY
    ```
  - Verify you can access the [OpenAI platform](https://platform.openai.com) directly.
- **Module Issues**:
  - Ensure PowerShell 7.5.0+ for best ANSI support.
  - Run `Invoke-ScriptAnalyzer` for script compliance.

### Contact Support
- Open a GitHub issue with detailed logs.
- Send an email to [jon@jondavis.net](mailto:jon@jondavis.net).

## Contributing
We appreciate your interest in contributing to Ask-GPT!

### How to Contribute
1. **Fork the repository** on GitHub.
2. **Create a new feature branch** from `main`.
3. **Develop your feature** and cross-check against PSScriptAnalyzer.
4. **Submit a pull request** with a clear description of changes.

### Code of Conduct
Please adhere to the [Code of Conduct](https://github.com/stimpy77/ask-gpt/blob/main/CODE_OF_CONDUCT.md) when contributing.

### Suggestions
For suggestions, feel free to open an issue or a discussion on GitHub.
