[CmdletBinding()]param()
#Requires -PSEdition Core
Write-Verbose 'Start of script'
. .\functions.ps1

$script:simulation = $true

# if no AAD equivalent - deactivate user
# if AAD equivalent is disabled - deactivate user
# if AAD equivalent is enabled and Zoom user is disabled - activate user

[ZoomUser[]]$allZoomUsers = Get-ZoomUsers
[int]$a = 0; [int]$z = $allZoomUsers.count
foreach($zoomUser in $allZoomUsers){
    $a++
    Write-Progress -PercentComplete ($a/$z)*100 -Status "Processing Zoom users" -CurrentOperation $($zoomUser.userName)
    [array]$AADsearcher = Get-ZoomUserFromAAD -zoomUser $zoomUser
    Switch ($AADsearcher){
        {$_.count -eq 0} {
            # handle no AAD account found for Zoom user
            if($zoomUser.active){
                # if Zoom user is active and no AAD user exists: action = Deactivate in Zoom
                Write-Information "Active ZoomUser $($zoomUser.userName) / $($zoomUser.emailAddress) has no equivalent in AAD. Deactivating in Zoom."
                $zoomUser.Deactivate
                if(!($zoomUser.Active)){
                    Write-Information "Zoom user $($zoomUser.userName) deactivated"
                    $zoomUser | Export-Csv -Path .\logs\zoomusers_deactivated.csv -NoTypeInformation
                } else {
                    Write-Warning "Failed to deactivate Zoom user $($zoomUser.userName)"
                }
            } else {
                Write-Information "Inactive ZoomUser $($zoomUser.userName) / $($zoomUser.emailAddress) has no equivalent in AAD. Ignoring."
            }
            break;
        }
        {$_.count -eq 1} {
            if($_.AccountEnabled -and -not $zoomUser.Active){
                # handle AAD account enabled, but Zoom account inactive: action = Activate in Zoom
                Write-Information "Inactive ZoomUser $($zoomUser.userName) has an active equivalent in AAD. Reactivating in Zoom."
                $zoomUser.Activate
                if($zoomUser.Active){
                    Write-Information "Zoom user $($zoomUser.userName) reactivated"
                    $zoomUser | Export-Csv -Path .\logs\zoomusers_reactivated.csv -NoTypeInformation
                } else {
                    Write-Warning "Failed to reactivate Zoom user $($zoomUser.userName)"
                }
            } elseif($zoomUser.Active -and -not $_.AccountEnabled){
                # handle AAD account disabled, but Zoom account active: action = Deactivate in Zoom
                Write-Information "Active ZoomUser $($zoomUser.userName) has an inactive equivalent in AAD. Deactivating in Zoom."
                $zoomUser.Deactivate
                if(!($zoomUser.Active)){
                    Write-Information "Zoom user $($zoomUser.userName) deactivated"
                    $zoomUser | Export-Csv -Path .\logs\zoomusers_deactivated.csv -NoTypeInformation
                } else {
                    Write-Warning "Failed to deactivate Zoom user $($zoomUser.userName)"
                }
            }
            break;
        }
        Default {
            Write-Warning "Multiple AAD users matched found for $($zoomUser.userName) / $($zoomUser.emailAddress)"
        }
    }
}

#[hashtable]$zoomUsersToProcess = Compare-ZoomUsersWithAADUsers -ZoomUsers $allZoomUsers
