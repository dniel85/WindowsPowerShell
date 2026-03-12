<#
.SYNOPSIS
    Queries GPT models from OpenAI API.

.DESCRIPTION
    The Ask-GPT function allows you to interact with GPT models from OpenAI.
    It supports streaming responses, conversation history, and various model parameters.

.PARAMETER Prompt
    The prompt to send to the GPT model. Can be provided via pipeline.

.PARAMETER Model
    The GPT model to use. Defaults to "auto" which selects the latest available model.

.PARAMETER RememberHistory
    Whether to remember conversation history. Defaults to $true.

.PARAMETER ClearHistory
    Clears the conversation history before processing the prompt.

.PARAMETER Temperature
    Controls randomness in the response. Range 0.0-2.0. Defaults to 0.3.

.PARAMETER NoTimespan
    Suppresses the display of response time.

.PARAMETER Stream
    Whether to stream the response. Defaults to $true.

.EXAMPLE
    Ask-GPT "What is PowerShell?"
    
.EXAMPLE
    "Explain variables" | Ask-GPT -Model "gpt-4"
    
.EXAMPLE
    Ask-GPT -Prompt "Hello" -Temperature 0.7 -NoTimespan

.NOTES
    Requires an OpenAI API key set in environment variables.
    Environment variable precedence (checked in this order):
    1. OPENAI_PERSONAL_API_KEY (highest priority)
    2. OPENAI_API_KEY (fallback)
    
    PowerShell 7.5.0+ recommended for best ANSI support.
#>
function Ask-GPT {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$Prompt,
        
        [Parameter(Mandatory = $false)]
        [string]$Model,
        
        [Parameter(Mandatory = $false)]
        [bool]$RememberHistory = $true,
        
        [Parameter(Mandatory = $false)]
        [switch]$ClearHistory,
        
        [Parameter(Mandatory = $false)]
        [ValidateRange(0.0, 2.0)]
        [float]$Temperature = 0.3,
        
        [Parameter(Mandatory = $false)]
        [switch]$NoTimespan,
        
        [Parameter(Mandatory = $false)]
        [bool]$Stream = $true
    )

    Begin {
        # Ensure ANSI escape sequences are properly rendered in PowerShell 7.5.0+
        if ($PSVersionTable.PSVersion -ge '7.5.0') {
            $PSStyle.OutputRendering = 'Ansi'
            
            # Force VT processing to be enabled
            $OutputEncoding = [System.Text.Encoding]::UTF8
            
            # Ensure Windows Terminal knows we want to use VT sequences
            if ($Host.UI.SupportsVirtualTerminal) {
                # Force enable VT processing for this session
                [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
            }
        }
        if ($RememberHistory) { $global:RememberGptHistory = $true }
        $RememberHistory = $global:RememberGptHistory
        if ($ClearHistory) { $global:gptHistory = $null }
    }

    Process {
		$DEFAULT_MODEL = "auto"
        if (-not $Prompt) {
            $Prompt = $input | Out-String
            if (-not $Prompt) { Write-Error "Prompt is required"; return }
        }
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

        $Prompt = $Prompt.Trim()
        $defaultModelUsed = $false
        
        if (-not $Model) {
          $Model = $DEFAULT_MODEL
          $defaultModelUsed = $true
        }
        
        # Handle "auto" model selection
        if ($Model -eq "auto" -or $Model -eq "latest") {
            $ModelOrig = $Model
            if ($null -eq $env:OPENAI_PERSONAL_API_KEY -and $null -eq $env:OPENAI_API_KEY) {
                Write-Error "OPENAI_PERSONAL_API_KEY or OPENAI_API_KEY environment variable is required for auto model selection";
                return
            }
            
            $apiKey = $env:OPENAI_PERSONAL_API_KEY
            if ($null -eq $apiKey) {
                $apiKey = $env:OPENAI_API_KEY
            }
            
            Write-Verbose "Detecting latest GPT model..."
            
            try {
                $modelsUrl = "https://api.openai.com/v1/models"
                $modelsHeaders = @{ "Authorization" = "Bearer $apiKey" }
                $modelsResponse = Invoke-RestMethod -Uri $modelsUrl -Method Get -Headers $modelsHeaders
                
                # Filter models to only include those that start with "gpt" and don't contain excluded terms
                # Focus on the most reliable and compatible models
                $filteredModels = $modelsResponse.data | Where-Object { 
                    $_.id -like "gpt*" -and 
                    $_.id -notlike "*image*" -and 
                    $_.id -notlike "*audio*" -and
                    $_.id -notlike "*search*" -and
                    $_.id -notlike "*vision*" -and
                    $_.id -notlike "*tts*" -and
                    $_.id -notlike "*transcri*" -and
                    $_.id -notlike "*nano*" -and
                    $_.id -notlike "*mini*" -and
                    $_.id -notlike "*preview*" -and
                    $_.id -notlike "*realtime*" -and
                    $_.id -notlike "*instruct*"
                }
                
                # Sort by created timestamp (descending) and take the first one
                if ($filteredModels.Count -gt 0) {
                    $latestModel = $filteredModels | Sort-Object -Property created -Descending | Select-Object -First 1
                    $Model = $latestModel.id
                    Write-Verbose "Found: $Model"
                    $defaultModelUsed = $false
                    if ($ModelOrig -eq "auto") { [Console]::WriteLine("(Model: $Model)") }
                } else {
                    Write-Verbose "No suitable models found, using gpt-4o as fallback"
                    $Model = "gpt-4o"
                    $defaultModelUsed = $false
                    if ($ModelOrig -eq "auto") { [Console]::WriteLine("(Model: $Model)") }
                }
            } catch {
                Write-Verbose "Error detecting models, using gpt-4o as fallback"
                Write-Verbose "Error: $_"
                $Model = "gpt-4o"
                $defaultModelUsed = $false
                if ($ModelOrig -eq "auto") { [Console]::WriteLine("(Model: $Model)") }
            }
        }
        
        if ($defaultModelUsed -and (-not $PSBoundParameters.ContainsKey('Verbose'))) { 
            [Console]::WriteLine("(Model: $Model)") 
        }

        if ($null -eq $env:OPENAI_PERSONAL_API_KEY -and $null -eq $env:OPENAI_API_KEY) {
            Write-Error "OPENAI_PERSONAL_API_KEY environment variable is not defined";
            return
        }

        $apiKey = $env:OPENAI_PERSONAL_API_KEY
        if ($null -eq $apiKey) {
            $apiKey = $env:OPENAI_API_KEY
        }
        $apiUrl = "https://api.openai.com/v1/chat/completions"
        $headers = @{ "Authorization" = "Bearer $apiKey"; "Content-Type" = "application/json" }
        $bodyObject = @{ messages = @(); model = $Model; }
        
        # GPT-5 only supports default temperature (1), other models support custom temperature
        if ($Model -notlike "gpt-5*") {
            $bodyObject['temperature'] = $Temperature
        }

        if ($RememberHistory) {
            #echo "Remembering gpt history"
            if ($null -eq $global:gptHistory) { $global:gptHistory = @() }
            $bodyObject['messages'] = @($global:gptHistory)
        }
            
        $windowSize = $Host.UI.RawUI.WindowSize
        $widthHeight = $windowSize.ToString()
        $esc = [char]27
        # Example hyperlink format (referenced in training prompt)
        # $hyperlinkRef = "$esc[1m$esc[34m$esc]8;;https://google.com/search?q=KEYWORD_SEARCH$esc\KEYWORD_TEXT$esc]8;;$esc\$esc[0m"
        $hyperlinkSample = "$esc[1m$esc[34m$esc]8;;https://google.com/search?q=define+1+John+3%3A16$esc\1 John 3:16$esc]8;;$esc\$esc[0m"
        $initialTraining = @{ role = "system"; content = "You are rendering directly in Windows Terminal "`
            +"(dimensions [width,height]:[$widthHeight]) with ANSI escape sequences fully supported. "`
            +"You must word wrap each line at exactly $($windowSize.Width - 10) visible characters or less. "`
            +"Insert a newline (line break) after EVERY $($windowSize.Width - 10) characters or at the closest word boundary before that limit. "`
            +"DO NOT USE MARKDOWN FORMATTING; do not use asterisks (**) for bold, for example. "`
            +"Instead use proper ANSI escape sequences for all formatting: "`
            +"- Use $esc[1m for bold, $esc[0m to reset formatting"`
            +"- Use $esc[31m for red text, $esc[32m for green, etc."`
            +"- For hyperlinks use the format: $esc]8;;URL$esc\VISIBLE_TEXT$esc]8;;$esc\"`
            +"IMPORTANT: ALWAYS RESET COLOR AND STYLE SEQUENCES after each highlighted segment. Each time you change color or style, "`
            +"you MUST terminate it with $esc[0m immediately after the text that should have that style. "`
            +"Example: $esc[34mBlue text$esc[0m followed by normal text. "`
            +"Example: $esc[1mBold$esc[0m $esc[4mUnderlined$esc[0m $esc[31mRed$esc[0m. "`
            +"Failure to properly terminate ANSI sequences will cause all subsequent text to maintain that color/style! "`
            +"Terms and keywords worth Googling should be hyperlinked: $hyperlinkSample "`
            +"REMEMBER: Explicitly reset ALL formatting after EVERY styled segment with $esc[0m." }


        if ($bodyObject['messages'].Count -eq 0) {
            
            $bodyObject['messages'] += $initialTraining
            if ($RememberHistory) {
                $global:gptHistory += $initialTraining
            }
        }
        #$body = $bodyObject | ConvertTo-Json
        #Write-Host $body
        $userMessage = @{ role = "user"; content = $Prompt }
        if ($RememberHistory) {
            $global:gptHistory += $userMessage
        }
        $bodyObject['messages'] += $userMessage
        $body = $bodyObject | ConvertTo-Json
        #echo $body

        # GPT-5 requires organization verification for streaming, fall back to non-streaming
        $useStreaming = $Stream
        if ($Model -like "gpt-5*" -and $Stream) {
            $useStreaming = $false
        }
        
        if ($useStreaming) {
            try {
                $bodyObject["stream"] = $true
                $body = $bodyObject | ConvertTo-Json
        
                $request = [System.Net.HttpWebRequest]::Create($apiUrl)
                $request.Method = "POST"
                $request.Headers.Add("Authorization", "Bearer $apiKey")
                $request.ContentType = "application/json"
        
                $requestStream = $request.GetRequestStream()
                $writer = [System.IO.StreamWriter]::new($requestStream)
                $writer.Write($body)
                $writer.Flush()
                $writer.Close()
        
                try {
                    $response = $request.GetResponse()
                } catch [System.Net.WebException] {
                    if ($_.Exception.Response.StatusCode -eq 404) {
                        Write-Error "Model '$Model' not found. Please check the model name and try again."
                        return  # Stop further execution when model is invalid
                    } else {
                        throw $_
                    }
                }
        
                $responseStream = $response.GetResponseStream()
                $reader = [System.IO.StreamReader]::new($responseStream)
        
                $fullContent = ""
        
                while (-not $reader.EndOfStream) {
                    $line = $reader.ReadLine()
                    if ($line -and $line.StartsWith("data: ")) {
                        $data = $line.Substring(6)
                        if ($data -ne "[DONE]") {
                            try {
                                $chunk = $data | ConvertFrom-Json
                                $content = $chunk.choices[0].delta.content
                                if ($content) {
                                    # Use direct console write to ensure ANSI sequences render correctly
                                    [Console]::Write($content)
                                    $fullContent += $content
                                }
                            } catch {
                                # Ignore parsing errors for incomplete JSON chunks
                                Write-Debug "Skipping malformed JSON chunk: $data"
                            }
                        }
                    }
                }
                [Console]::WriteLine()  # New line after streaming is complete
                $responseContent = $fullContent
        
                $reader.Close()
                $response.Close()
            } catch [System.Net.WebException] {
                $errorResponse = $_.Exception.Response
                if ($errorResponse) {
                    $errorStream = $errorResponse.GetResponseStream()
                    $errorReader = [System.IO.StreamReader]::new($errorStream)
                    $errorBody = $errorReader.ReadToEnd()
                    $errorReader.Close()
                    Write-Error "Error occurred during the request: $errorBody"
                } else {
                    Write-Error "Error occurred during the request: $_"
                }
            }
        } else {
        
            try {
                $response = Invoke-RestMethod -Uri $apiUrl -Method Post -Headers $headers -Body $body
            } catch {
                if ($_.Exception.Response -and $_.Exception.Response.StatusCode -eq 404) {
                    Write-Error "Model '$Model' not found. Please check the model name and try again."
                    return
                } else {
                    # Try to get the actual error response
                    try {
                        $errorStream = $_.Exception.Response.GetResponseStream()
                        $errorReader = [System.IO.StreamReader]::new($errorStream)
                        $errorBody = $errorReader.ReadToEnd()
                        $errorReader.Close()
                        Write-Error "API Error: $errorBody"
                    } catch {
                        Write-Error "Error occurred during the request: $_"
                    }
                    return
                }
            }
            $responseContent = $response.choices[0].message.content
            # Use direct console write to ensure ANSI sequences render correctly
            [Console]::WriteLine($responseContent)
        }
        
        if ($RememberHistory) {
            $global:gptHistory += @{ role = "assistant"; content = $responseContent }
        }

        $stopwatch.Stop()
        $elapsed = $stopwatch.Elapsed.ToString()
        if (-not $NoTimespan) { [Console]::WriteLine("[$elapsed]") }
    }
}

Set-Alias -Name gpt -Value Ask-GPT

# Export the function and alias for module users
Export-ModuleMember -Function Ask-GPT -Alias gpt
