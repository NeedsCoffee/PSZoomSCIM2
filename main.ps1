[CmdletBinding()]param()
#Requires -PSEdition Core
Write-Verbose 'Start of script'
. .\functions.ps1

# if no AAD equivalent - deactivate user
# if AAD equivalent is disabled - deactivate user
# if AAD equivalent is enabled and Zoom user is disabled - activate user

[ZoomUser[]]$allZoomUsers = Get-ZoomUsers
[hashtable]$zoomUsersToProcess = Compare-ZoomUsersWithAADUsers -ZoomUsers $allZoomUsers
