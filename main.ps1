[CmdletBinding()]param()
#Requires -PSEdition Core
Write-Verbose 'Start of script'
. .\functions.ps1

$script:simulationMode = $true

# if no AAD equivalent - deactivate user
# if AAD equivalent is disabled - deactivate user
# if AAD equivalent is enabled and Zoom user is disabled - activate user

[array]$allZoomUsers = Get-ZoomUsers
[int]$a = 0; [int]$z = $allZoomUsers.count
foreach($zoomUser in $allZoomUsers){
    $a++
    Write-Progress -Id 0 -PercentComplete (($a/$z)*100) -Activity 'Processing Zoom users' -Status "$a of $z"
    [array]$AADsearcher = @()
    try {
        $AADsearcher += Get-ZoomUserFromAAD -zoomUser $zoomUser
        Switch ($AADsearcher.count){
            0 {
                $zoomUser.isEnabledInAD = -1
                # handle no AAD account found for Zoom user
                if($zoomUser.active){
                    # if Zoom user is active and no AAD user exists: action = Deactivate in Zoom
                    Write-Progress -Id 1 -ParentId 0 "Deactivating: $($zoomUser.userName)"
                    Write-Host "Active ZoomUser $($zoomUser.userName) / $($zoomUser.emailAddress) has no equivalent in AAD. Deactivating in Zoom." -ForegroundColor Magenta
                    $zoomUser.Deactivate | Out-Null
                    if(!($zoomUser.Active)){
                        Write-Host "Orphaned Zoom user $($zoomUser.userName) deactivated" -ForegroundColor Magenta
                        $zoomUser | Export-Csv -Path .\logs\zoomusers_deactivated.csv -NoTypeInformation
                    } elseif($script:simulationMode){
                        Write-Host "SIMULATION: Orphaned Zoom user $($zoomUser.userName) deactivated" -ForegroundColor Magenta
                    } else {
                        Write-Warning "Failed to deactivate Zoom user $($zoomUser.userName)"
                    }
                } else {
                    Write-Host "Inactive ZoomUser $($zoomUser.userName) / $($zoomUser.emailAddress) has no equivalent in AAD. Ignoring." -ForegroundColor Yellow
                }
                break;
            }
            1 {
                if($AADsearcher.AccountEnabled -and -not $zoomUser.active){
                    $zoomUser.isEnabledInAD = 1
                    # handle AAD account enabled, but Zoom account inactive: action = Activate in Zoom
                    Write-Progress -Id 1 -ParentId 0 "Reactivating: $($zoomUser.userName)"
                    Write-Host "Inactive ZoomUser $($zoomUser.userName) has an active equivalent in AAD. Reactivating in Zoom." -ForegroundColor Green
                    $zoomUser.Activate | Out-Null
                    if($zoomUser.Active){
                        Write-Host "Zoom user $($zoomUser.userName) reactivated" -ForegroundColor Green
                        $zoomUser | Export-Csv -Path .\logs\zoomusers_reactivated.csv -NoTypeInformation
                    } elseif($script:simulationMode){
                        Write-Host "SIMULATION: Zoom user $($zoomUser.userName) reactivated" -ForegroundColor Green
                    } else {
                        Write-Warning "Failed to reactivate Zoom user $($zoomUser.userName)"
                    }
                } elseif($zoomUser.active -and -not $AADsearcher.AccountEnabled){
                    $zoomUser.isEnabledInAD = 0
                    # handle AAD account disabled, but Zoom account active: action = Deactivate in Zoom
                    Write-Progress -Id 1 -ParentId 0 "Deactivating: $($zoomUser.userName)"
                    Write-Host "Active ZoomUser $($zoomUser.userName) has an inactive equivalent in AAD. Deactivating in Zoom." -ForegroundColor Cyan
                    $zoomUser.Deactivate | Out-Null
                    if(!($zoomUser.Active)){
                        Write-Host "Zoom user $($zoomUser.userName) deactivated" -ForegroundColor Cyan
                        $zoomUser | Export-Csv -Path .\logs\zoomusers_deactivated.csv -NoTypeInformation
                    } elseif($script:simulationMode){
                        Write-Host "SIMULATION: Zoom user $($zoomUser.userName) deactivated" -ForegroundColor Cyan
                    } else {
                        Write-Warning "Failed to deactivate Zoom user $($zoomUser.userName)"
                    }
                } elseif($zoomUser.active -and $AADsearcher.AccountEnabled){
                    # handle AAD account enabled, and Zoom account active: action = ignore
                    $zoomUser.isEnabledInAD = 1
                }
                break;
            }
            Default {
                Write-Warning "Multiple AAD users matched found for $($zoomUser.userName) / $($zoomUser.emailAddress)"
            }
        }
    } catch {
        Write-Host "Error whilst trying to search for $($zoomUser.userName) in AAD"
        $_ | Write-Error
    }
}

#[hashtable]$zoomUsersToProcess = Compare-ZoomUsersWithAADUsers -ZoomUsers $allZoomUsers
