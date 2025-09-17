# Script to keep Teams status active
# Move the mouse cursor slightly every minute

# Define the interval in seconds
$interval = 60

# Define a small movement distance (in pixels)
$moveDistance = 1

Write-Host "Keeping Teams active. Press Ctrl+C to stop."

try {
    while ($true) {
        # Get the current cursor position
        $cursor = [System.Windows.Forms.Cursor]::Position
        
        # Move the cursor slightly
        [System.Windows.Forms.Cursor]::Position = New-Object System.Drawing.Point(($cursor.X + $moveDistance), $cursor.Y)
        Start-Sleep -Milliseconds 500 # Small pause for the move
        [System.Windows.Forms.Cursor]::Position = $cursor # Return cursor to original position

        # Wait for the defined interval
        Start-Sleep -Seconds $interval
    }
} catch {
    Write-Host "Script terminated."
}