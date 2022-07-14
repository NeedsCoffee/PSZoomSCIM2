[CmdletBinding()]param()
#Requires -PSEdition Core

Write-Verbose 'Start of script'

. .\functions.ps1

[boolean]$simulationMode = [System.Convert]::ToBoolean($config["SimulationMode"])
if($simulationMode){
    Write-Log -Message 'Script running in simulation mode. No user states will change' -Level INFO
} else {
    Write-Log -Message 'Script started' -Level START
}

if(!($allZoomUsers.count)){
    [array]$allZoomUsers = Get-ZoomUsers
}
[int]$a = 0; [int]$z = $allZoomUsers.count
[int]$deactivated = 0; [int]$reactivated = 0; [int]$errorCount = 0; [int]$tolerance = [System.Convert]::ToInt16($config['ErrorTolerance'])
Write-Log -Message '{0} users retrieved from Zoom API' -Arguments $z -Level INFO
foreach($zoomUser in $allZoomUsers){
    $a++
    if($errorCount -ge $tolerance){
        Write-Log -Message '{0} errors trapped. Tolerance is {1}. Quiting script.' -Arguments @($errorCount,$tolerance) -Level WARNING
        break;
    }
    
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
                    Write-Log -Message 'Active ZoomUser {0} with email {1} has no active equivalent in AAD. Deactivating in Zoom.' -Arguments @($zoomUser.userName,$zoomUser.emailAddress) -Level INFO
                    $zoomUser.Deactivate() | Out-Null
                    $deactivated++
                    if(!($zoomUser.Active)){
                        Write-Log -Message 'Orphaned Zoom user {0} deactivated' -Arguments $zoomUser.userName -Level ACTION
                        $zoomUser | Export-Csv -Path .\logs\zoomusers_deactivated.csv -NoTypeInformation -Encoding utf8 -Append
                    } elseif($script:simulationMode){
                        Write-Log -Message 'SIMULATION: Orphaned Zoom user {0} deactivated' -Arguments $zoomUser.userName -Level INFO
                    } else {
                        Write-Log -Message 'Failed to deactivate Zoom user {0}' -Arguments $zoomUser.userName -Level ERROR
                        $errorCount++
                    }
                } else {
                    Write-Log -Message 'Inactive ZoomUser {0} has no equivalent in AAD. Ignoring.' -Arguments $zoomUser.userName -Level INFO
                }
                break;
            }
            1 {
                if($AADsearcher.AccountEnabled -and -not $zoomUser.active){
                    $zoomUser.isEnabledInAD = 1
                    # handle AAD account enabled, but Zoom account inactive: action = Activate in Zoom
                    Write-Progress -Id 1 -ParentId 0 "Reactivating: $($zoomUser.userName)"
                    Write-Log -Message 'Inactive ZoomUser {0} has an active equivalent in AAD. Reactivating in Zoom.' -Arguments $zoomUser.userName -Level INFO
                    $zoomUser.Activate() | Out-Null
                    $reactivated++
                    if($zoomUser.Active){
                        Write-Log -Message 'Zoom user {0} reactivated' -Arguments $zoomUser.userName -Level ACTION
                        $zoomUser | Export-Csv -Path .\logs\zoomusers_reactivated.csv -NoTypeInformation -Encoding utf8 -Append
                    } elseif($script:simulationMode){
                        Write-Log -Message 'SIMULATION: Zoom user {0} reactivated' -Arguments $zoomUser.userName -Level INFO
                    } else {
                        Write-Log -Message 'Failed to reactivate Zoom user {0}' -Arguments $zoomUser.userName -Level ERROR
                        $errorCount++
                    }
                } elseif($zoomUser.active -and -not $AADsearcher.AccountEnabled){
                    $zoomUser.isEnabledInAD = 0
                    # handle AAD account disabled, but Zoom account active: action = Deactivate in Zoom
                    Write-Progress -Id 1 -ParentId 0 "Deactivating: $($zoomUser.userName)"
                    Write-Log -Message 'Active ZoomUser {0} has an inactive equivalent in AAD. Deactivating in Zoom.' -Arguments $zoomUser.userName -Level INFO
                    $zoomUser.Deactivate() | Out-Null
                    $deactivated++
                    if(!($zoomUser.Active)){
                        Write-Log -Message 'Zoom user {0} deactivated' -Arguments $zoomUser.userName -Level ACTION
                        $zoomUser | Export-Csv -Path .\logs\zoomusers_deactivated.csv -NoTypeInformation -Encoding utf8 -Append
                    } elseif($script:simulationMode){
                        Write-Log -Message 'SIMULATION: Zoom user {0} deactivated' -Arguments $zoomUser.userName -Level INFO
                    } else {
                        Write-Log -Message 'Failed to deactivate Zoom user {0}' -Arguments $zoomUser.userName -Level ERROR
                        $errorCount++
                    }
                } elseif($zoomUser.active -and $AADsearcher.AccountEnabled){
                    # handle AAD account enabled, and Zoom account active: action = ignore
                    $zoomUser.isEnabledInAD = 1
                }
                break;
            }
            Default {
                Write-Log -Message 'Multiple AAD users matched found for user {0} with email {1}' -Arguments @($zoomUser.userName,$zoomUser.emailAddress) -Level WARNING
            }
        }
    } catch {
        Write-Log -Message 'Error whilst trying to search for {0} in AAD. Error Message: ' -Arguments @($zoomUser.userName,$_) -Level ERROR
        $errorCount++
    }
}

if($simulationMode){
    Write-Log -Message 'Script ended' -Level INFO
} else {
    Write-Log -Message 'Script ended: {0} users deactivated, {1} users reactivated, {2} users in tenant, {3} errors' -Arguments @($deactivated,$reactivated,$z,$errorCount) -Level STOP
}

Wait-Logging