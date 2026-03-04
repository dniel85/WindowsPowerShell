# Import the list of VMs from CSV
$vmList = Import-Csv "C:\xxx"

# Array to store results
$results = @()

foreach ($item in $vmList) {
    
    $vm = Get-SCVirtualMachine -Name $item.VMName -ErrorAction SilentlyContinue

    if (-not $vm) {
        Write-Warning "VM '$($item.VMName)' not found in VMM."
        continue
    }

	$diskInfo = (Get-SCVirtualHardDisk -VM $vm | ForEach-Object {
        "$($_.Name): $([math]::Round($_.MaximumSize/1GB, 2)) GB"
    }) -join "; "

    # Add VM details to results
    $results += [PSCustomObject]@{
        VMName                 = $vm.Name
        ComputerName           = $vm.ComputerName
        Generation             = $vm.Generation
        OperatingSystem        = $vm.OperatingSystem
        CPUCount               = $vm.CPUCount
        'Memory/StartupMemory' = $vm.Memory
        DynamicMemoryEnabled   = $vm.DynamicMemoryEnabled
        DynamicMemoryMinimumMB = $vm.DynamicMemoryMinimumMB
        DynamicMemoryMaximumMB = $vm.DynamicMemoryMaximumMB
        SecureBootEnabled      = $vm.SecureBootEnabled
        SecureBootTemplate     = $vm.SecureBootTemplate
        Disks                  = $diskInfo
    }
}

# Display output as table
$results | Format-Table -AutoSize

# Create Exported CSV variable
$exList = "C:\xxx"

# Export to CSV
$results | Export-Csv $exList -NoTypeInformation -Encoding UTF8

Write-Host "Report exported to $exList" -ForegroundColor Cyan