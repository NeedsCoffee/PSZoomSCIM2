[CmdletBinding()]param()
#Requires -PSEdition Core

Write-Verbose 'Initialize Script'

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
foreach($folder in (Get-ChildItem '.\modules\' -Directory)){
    if(!(Get-Module -Name $folder.BaseName)){
        Write-Verbose "Loading module $($folder.BaseName)"
        Import-Module -FullyQualifiedName $folder.FullName
    } else {
        Write-Verbose "Module $($folder.BaseName) already loaded"
    }
}

class ZoomUser {
         [string]$id
            [uri]$uri
         [string]$givenName
         [string]$familyName
    [mailaddress]$emailAddress
         [string]$displayName
         [string]$userName
        [boolean]$active
         [string]$userType
        [boolean]$loginWorkEmail
        [boolean]$loginSSO
         [string]$department
    [void]Activate(){
        Update-ZoomUserState -UserId $this.id -Enable
    }
    [void]Deactivate(){
        Update-ZoomUserState -UserId $this.id -Disable
    }
    [void]FlipState(){
        Update-ZoomUserState -UserId $this.id
    }
    [string]ToString(){
        return $this.id
    }
}
#
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
function Invoke-ZoomSCIM2APICall {
    [CmdletBinding()]
    param ([string]$query,[string]$method = 'Get',[string]$body)
    [uri]$uri = 'https://api.zoom.us/scim2/{0}' -f $query
    Invoke-RestMethod -Uri $uri -Method Get -Authentication Bearer -Token (Get-ZoomAccessToken)
}
function Get-ZoomUsers {
    [CmdletBinding()]
    param ()
    # discover how many users there are
    Write-Verbose 'Function: Get-ZoomUsers'
    $query = 'https://api.zoom.us/scim2/Users?count={0}&startIndex={1}'
    $discovery = Invoke-RestMethod -uri ($query -f 1,1) -Method Get -Authentication Bearer -Token (Get-ZoomAccessToken)
    [int]$total = $discovery.totalResults
    [ZoomUser[]]$data = @()
    [int]$pageSize = 100
    [int]$index = 1
    do {
        if(($index+$pageSize) -gt $total){
            $pageSize = ($total-$index)+1
        }
        Write-Host "Collecting users $('{0:00000}' -f $index) - $('{0:00000}' -f ($index+$pageSize-1)) / $('{0:00000}' -f $total)"
        
        $splat = @{
            Uri = ($query -f $pageSize,$index)
            Method = 'Get'
            Authentication = 'Bearer'
            Token = (Get-ZoomAccessToken)
            MaximumRetryCount = 3
            RetryIntervalSec = 5
            WarningAction = 'Continue'
            ErrorAction = 'Continue'
        }
        $response = Invoke-RestMethod @splat
        $data += Format-ZoomUserData -data $response.Resources
        $index += $pageSize
    } until ($index -ge $total)
    if ($data.count -lt $total){
        Throw "Ambiguous user list received from API. Records expected: $total | Records received: $($data.count)"
    } elseif ($data.count -eq 0){
        Throw "No records returned from Zoom."
    } else {return $data}
}

function Format-ZoomUserData {
    [CmdletBinding()]
    param([array]$data)
    Write-Verbose 'Function: Format-ZoomUserData'
    $splat = @{
        Property = @(
            'id',
            @{N='uri';E={$_.meta.location}},
            @{N='givenName';E={$_.name.givenName}},
            @{N='familyName';E={$_.name.familyName}},
            @{N='emailAddress';E={($_.emails | Where-Object Primary).value}},
            'displayName',
            'userName',
            'active',
            'userType',
            @{N='loginWorkEmail';E={$_.'urn:us:zoom:scim:schemas:extension:1.0:ZoomUser'.loginType.workEmail}},
            @{N='loginSSO';E={$_.'urn:us:zoom:scim:schemas:extension:1.0:ZoomUser'.loginType.sso}},
            @{N='department';E={$_.'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User'.department}}
        )
    }
    [ZoomUser[]]$parsedData = $data | Select-Object @splat
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
        [array]$aadUser = Get-MgUser -Filter "UserPrincipalName eq '$($zoomUser.UserName)' or ProxyAddresses/any(c:c eq 'smtp:$($zoomUser.emailAddress)')" -Property AccountEnabled,ProxyAddresses,UserPrincipalName,Mail
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
function Update-ZoomUserState {
    [CmdletBinding(DefaultParameterSetName = 'UserIdDisable')]
    param(
        [Parameter(ParameterSetName='ZoomObjDisable', Mandatory = $true, ValueFromPipeline = $true)]
        [Parameter(ParameterSetName='ZoomObjEnable', Mandatory = $true, ValueFromPipeline = $true)]
        [Alias('ZoomUser','UserObj','ZoomUserObj','Object')]
        [ZoomUser]$UserObject,

        [Parameter(ParameterSetName='UserIdDisable', Mandatory = $true, ValueFromPipeline = $true)]
        [Parameter(ParameterSetName='UserIdEnable', Mandatory = $true, ValueFromPipeline = $true)]
        [Alias('Id','ZoomId','UniqueId')]
        [string]$UserId,

        [Parameter(ParameterSetName='UserIdDisable')]
        [Parameter(ParameterSetName='ZoomObjDisable')]
        [Alias('Deactivate','Block')]
        [switch]$Disable,

        [Parameter(ParameterSetName='UserIdEnable')]
        [Parameter(ParameterSetName='ZoomObjEnable')]
        [Alias('Activate','Allow','Reactivate','Reenable')]
        [switch]$Enable
    )
    if($UserObject){$UserId = $UserObject.Id}

    [boolean]$targetState = $Enable -or !$Disable
    if(!($Enable -or $Disable)){
        # switch not passed to function - we're being asked to flip the state
        # first need to discover what state the user is in
        #$targetSate = -not (Get-ZoomUser -Id $UserId).active
    }
    
    # contruct a rather stupid packet to send to the scim2 api which disables a user
    [PSCustomObject]$packet = @{
        schemas = @('urn:ietf:params:scim:api:messages:2.0:ListResponse');
        Operations = @(@{'op'='replace';'value'=@{'active'=$targetState}});
    }
    [string]$jsonPacket = $packet | ConvertTo-Json -Depth 3 -Compress
    [PSCustomObject]$splat = @{
        uri = ('https://api.zoom.us/scim2/Users/{0}' -f $UserId);
        method = 'Patch';
        body = $jsonPacket;
        authentication = 'Bearer';
        token = (Get-ZoomAccessToken);
        maximumretrycount = 3;
        retryintervalsec = 5;
    }
    $response = Invoke-RestMethod @splat -StatusCodeVariable statusCode
    if($statusCode = 200 -and !$targetState){
        Write-Host "Disabled Zoom user $UserId"
    } elseif ($statusCode = 200 -and $targetState){
        Write-Host "Enabled Zoom user $UserId"
    } else {
        Write-Host $response
        throw "Failed to alter state of user $UserId. Status code: $statusCode"
    }
}
function Enable-ZoomUser {
    [CmdletBinding()]
    param($id)
    # contruct a rather stupid packet to send to the scim2 api which enables a user
    [PSCustomObject]$packet = @{
        schemas = @('urn:ietf:params:scim:api:messages:2.0:ListResponse');
        Operations = @(@{'op'='replace';'value'=@{'active'=$true}});
    }
    [string]$jsonPacket = $packet | ConvertTo-Json -Depth 3 -Compress
    [PSCustomObject]$splat = @{
        uri = ('https://api.zoom.us/scim2/Users/{0}' -f $id);
        method = 'Patch';
        body = $jsonPacket;
        authentication = 'Bearer';
        token = (Get-ZoomAccessToken);
        maximumretrycount = 3;
        retryintervalsec = 5;
    }
    $response = Invoke-RestMethod @splat -StatusCodeVariable statusCode
    if($statusCode = 200){
        Write-Host "Enabled Zoom user $($user.UserName)"
    } else {
        Write-Host $response
        throw "Failed to enable user $($user.UserName). Status code = $statusCode"
    }
}
