<#
.SYNOPSIS
Automatically commits, pulls, and pushes changes to a Git repository.

.DESCRIPTION
This script automates a common Git workflow by performing the following steps:

1. Changes directory to the user's WindowsPowerShell scripts folder.
2. Verifies the folder is a valid Git repository.
3. Detects the current Git branch.
4. Stages all file changes.
5. Commits changes if any are staged.
6. Pulls the latest changes from the remote repository using rebase.
7. Pushes the committed changes to the remote branch.

This script is useful for quickly syncing PowerShell script repositories
to a remote Git server such as GitHub.

.PARAMETER Message
Specifies the commit message used when committing changes.

If not provided, the default commit message will be:
"Auto commit from PowerShell"

.EXAMPLE
.\AutoCommit.ps1

Stages all changes, commits using the default message, pulls updates from
the remote repository, and pushes the changes.

.EXAMPLE
.\AutoCommit.ps1 -Message "Updated logging module"

Commits staged changes with the specified commit message and pushes them
to the current branch.

.OUTPUTS
None

Displays status messages indicating repository state and Git operations.

.NOTES
Author: Darrell Nielsen

Requires Git to be installed and available in the system PATH.

The script assumes the repository is located in:
$env:USERPROFILE\Documents\WindowsPowerShell

TAGS:
git
commit
powershell
automation
repository
repo


#>

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