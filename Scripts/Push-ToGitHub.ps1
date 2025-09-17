param(
    [string]$Message = "Auto commit from PowerShell"
)
$currentLocation = (pwd).Path
Set-Location "$env:userprofile\documents\WindowsPowerShell"
# Ensure we are inside a Git repo
if (-not (Test-Path ".git")) {
    Write-Error "This folder is not a Git repository."
    exit 1
}

# Detect the current branch
$branch = git rev-parse --abbrev-ref HEAD

Write-Output "📂 Current branch: $branch"

# Stage all changes
git add .

# Commit changes (only if there are staged changes)
if (git diff --cached --quiet) {
    Write-Output "ℹ️ No changes to commit."
} else {
    git commit -m "$Message"
}

# Pull latest changes with rebase
git pull origin $branch --rebase

# Push to GitHub
git push origin $branch

Write-Output "✅ Changes pushed to GitHub branch '$branch' with message: $Message"
Set-Location -Path $currentLocation