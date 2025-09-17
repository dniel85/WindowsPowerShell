# Requires admin privileges

# Define registry base paths
$protocolsPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
$clientServer = @("Client", "Server")

# TLS versions to configure
$versions = @(
    @{ Name = "TLS 1.0"; Enabled = 0; },
    @{ Name = "TLS 1.2"; Enabled = 1; },
    @{ Name = "TLS 1.3"; Enabled = 1; }
)

foreach ($ver in $versions) {
    foreach ($target in $clientServer) {
        $regPath = Join-Path -Path $protocolsPath -ChildPath "$($ver.Name)\$target"

        # Create the key if it doesn't exist
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }

        # Set the registry values
        New-ItemProperty -Path $regPath -Name "Enabled" -Value $ver.Enabled -PropertyType "DWORD" -Force | Out-Null
        New-ItemProperty -Path $regPath -Name "DisabledByDefault" -Value (1 - $ver.Enabled) -PropertyType "DWORD" -Force | Out-Null
    }
}

Write-Host "TLS configuration updated. A reboot is required for changes to take effect." -ForegroundColor Green