#Requires -PSEdition Core
[CmdletBinding()]param()
Write-Verbose 'Start of script. Importing modules.'
'Microsoft.Graph.Authentication','Microsoft.Graph.Users','Microsoft.Graph.Groups','Logging' | `
    ForEach-Object {Import-Module -FullyQualifiedName ".\modules\$_"}
function Initialize-Config {
    [CmdletBinding()]param()
    Write-Verbose 'Function: Initialize-Config'
    if(Test-Path '.\config.txt'){
        Write-Verbose 'Found config file. Script variables values'
        [hashtable]$script:config = Get-Content '.\config.txt' -Raw | ConvertFrom-StringData
        foreach($key in $script:config.Keys){
            Write-Verbose "$key = $($script:config[$key])"
        }
        if($config.Keys -contains 'Client_Secret'){
            $script:config.Add("Client_Secret_Secure",($config['Client_Secret'] | ConvertTo-SecureString -Force -AsPlainText))
        }
    } else {
        throw 'config.txt not found. Unable to continue'
    }
}
function ConvertTo-Base64([string]$text = '') {
    Write-Verbose 'Function: ConvertTo-Base64'
    return ([System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($text)))
}
function Get-ZoomAccessToken {
    [CmdletBinding()]
    param (
        [Parameter(Position=0)][string]$account = $script:config['Account_ID'],
        [Parameter(Position=1)][string]$client = $script:config['Client_ID'],
        [Parameter(Position=2)][securestring]$secret = $script:config['Client_Secret_Secure'],
        [Parameter(Position=3)][switch]$force
    )
    Write-Verbose 'Function: Get-ZoomAccessToken'
    if($script:cached_zatoken.expiry -gt (Get-Date).AddSeconds(300) -and -not $force){
        Write-Verbose 'Cached token found, still valid, not forcing renewal'
        Write-Verbose "Token expiry = $($script:cached_zatoken.expiry)"
        return $script:cached_zatoken.access_token_secure
    } else {
        Write-Verbose "Acquiring new access token for account $account"
        [string]$uri = 'https://zoom.us/oauth/token?grant_type={0}&account_id={1}'
        [string]$grant = 'account_credentials'
        [hashtable]$splat = @{
            Uri = ($uri -f $grant,$account)
            Method = 'Post'
            Authentication = 'Basic'
            Credential = New-Object System.Management.Automation.PSCredential ($client,$secret)
        }
        try {
            [PSCustomObject]$script:cached_zatoken = Invoke-RestMethod @splat -ErrorAction:Stop
            $script:cached_zatoken | Add-Member -Value ((Get-Date).AddSeconds($script:cached_zatoken.expires_in)) -MemberType NoteProperty -Name expiry
            $script:cached_zatoken | Add-Member -Value ($script:cached_zatoken.access_token | ConvertTo-SecureString -AsPlainText -Force) -MemberType NoteProperty -Name access_token_secure
            return $script:cached_zatoken.access_token_secure
        } catch {
            Write-Output 'Failure trying to get an access token'
            Write-Output $_
        }
    }
}
function Get-ZoomUsers {
    [CmdletBinding()]
    param ()
    # discover how many users there are
    Write-Verbose 'Function: Get-ZoomUsers'
    $query = 'https://api.zoom.us/scim2/Users?count={0}&startIndex={1}'
    $discovery = Invoke-RestMethod -uri ($query -f 1,1) -Method Get -Authentication Bearer -Token (Get-ZoomAccessToken)
    [int]$total = $discovery.totalResults
    [array]$data = @()
    [int]$pageSize = 100
    [int]$startIndex = 1
    do {
        if($startIndex + $pageSize -gt $total){
            $pageSize = $total - $startIndex
        }
        Write-Host "Collecting users $startIndex - $($startIndex+$pageSize-1)"
        $splat = @{
            Uri = ($query -f $pageSize,$startIndex)
            Method = 'Get'
            Authentication = 'Bearer'
            Token = (Get-ZoomAccessToken)
            MaximumRetryCount = 3
            RetryIntervalSec = 5
            WarningAction = 'Continue'
            ErrorAction = 'Continue'
        }
        $response = Invoke-RestMethod @splat
        $data += Invoke-ZoomUserDataParse -data $response.Resources
        $startIndex += $pageSize
    } until ($startIndex -ge $total)
    if ($data.count -lt $total){
        Throw "Ambiguous user list received from Zoom. Expected $total records, $($data.count) retrieved."
    } elseif ($data.count -eq 0){
        Throw "No records returned from Zoom."
    } else {return $data}
}
function Invoke-ZoomUserDataParse {
    [CmdletBinding()]
    param([array]$data)
    Write-Verbose 'Function: Invoke-ZoomUserDataParse'
    [array]$parsedData = $data | Select-Object id,@{N='uri';E={$_.meta.location}},@{N='givenName';E={$_.name.givenName}},@{N='familyName';E={$_.name.familyName}},@{N='emailAddress';E={($_.emails | ? Primary -eq True).value}},displayName,userName,active,userType
    return $parsedData
}
function Compare-ZoomUsersWithAADUsers {
    [CmdletBinding()]
    param([array]$ZoomUsers)

    [X509Certificate]$certificate = Get-ChildItem -Path "Cert:\*$($script:config['AAD_Cert_Thumb'])" -Recurse | Where-Object HasPrivateKey | Sort-Object -Descending NotAfter | Select-Object -First 1
    if(!$certificate){
        Throw "Can't initiate Graph connection. Certificate not found."
    }

    [hashtable]$splat = @{
        ClientId = $script:config['AAD_Client_ID']
        Certificate = $certificate
        TenantId = $script:config['AAD_Tenant_ID']
    }
    [hashtable]$workingSet = @{}
    [int]$x = 0; [int]$y = $ZoomUsers.count
    Connect-MgGraph @splat | Out-Null
    foreach($zoomUser in $ZoomUsers){
        $x++
        [array]$aadUser = Get-MgUser -Filter "UserPrincipalName eq '$($zoomUser.UserName)' or ProxyAddresses/any(c:c eq 'smtp:$($zoomUser.emailAddress)')" -Property AccountEnabled,ProxyAddresses,UserPrincipalName
        [int]$foundCount = $aadUser.count
        if($foundCount -eq 1){
            if($zoomUser.active -and -not $aadUser.AccountEnabled){
                # user is disabled in AD and needs deactivating in Zoom
                Write-Host "$x of $y $($zoomUser.UserName) : Disabled in AAD, Enabled in Zoom" -ForegroundColor Yellow
                $workingSet.Add($zoomUser.UserName,1)
            }elseif(-not $zoomUser.active -and $aadUser.AccountEnabled){
                # user is enabled in AD and needs reactivating in Zoom
                Write-Host "$x of $y $($zoomUser.UserName) : Enabled in AAD, Disabled in Zoom" -ForegroundColor Green
                $workingSet.Add($zoomUser.UserName,0)
            }
        }elseif($foundCount -gt 1){
            Write-Host "$x of $y $($zoomUser.UserName) : more than 1 account found in AAD - skipping" -ForegroundColor Red
        }else{
            Write-Host "$x of $y $($zoomUser.UserName) : Not found in AAD, Enabled in Zoom" -ForegroundColor Cyan
            $workingSet.Add($zoomUser.UserName,2)
        }
    }
    Disconnect-MgGraph | Out-Null
    return $workingSet
}
Initialize-Config
#Get-ZoomAccessToken

#. get all users
# compare all those users with their AAD equivalent
# if no AAD equivalent - deactivate user
# if AAD equivalent is disabled - deactivate user

[array]$allZoomUsers = Get-ZoomUsers
[hashtable]$zoomUsersToProcess = Compare-ZoomUsersWithAADUsers -ZoomUsers $allZoomUsers


function Disable-ZoomUser {
    [CmdletBinding()]
    param($user)
    # contruct a rather stupid packet to send to the scim2 api which disables a user
    [PSCustomObject]$packet = @{
        schemas = @('urn:ietf:params:scim:api:messages:2.0:ListResponse');
        Operations = @(@{'op'='replace';'value'=@{'active'=$false}});
    }
    [string]$jsonPacket = $packet | ConvertTo-Json -Depth 3 -Compress

    [PSCustomObject]$splat = @{
        uri = ('https://api.zoom.us/scim2/Users/{0}' -f $user.Id);
        method = 'Patch';
        body = $jsonPacket;
        authentication = 'Bearer';
        token = (Get-ZoomAccessToken);
        maximumretrycount = 3;
        retryintervalsec = 5;
    }
    $response = Invoke-RestMethod @splat -StatusCodeVariable statusCode
    if($statusCode = 200){
        Write-Host "Disabled Zoom user $($user.UserName)"
    } else {
        Write-Host $response
        throw "Failed to disable user $($user.UserName). Status code = $statusCode"
    }
}
