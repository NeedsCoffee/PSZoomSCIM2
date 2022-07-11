[CmdletBinding()]param()
#Requires -version 5.1

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
    $isEnabledInAD
    [void]Activate(){
        $ret = Update-ZoomUserState -UserId $this.id -Enable
        if($ret -eq 1){$this.active = $true}
    }
    [void]Deactivate(){
        $ret = Update-ZoomUserState -UserId $this.id -Disable
        if($ret -eq -1){$this.active = $false}
    }
    [void]FlipState(){
        $ret = Update-ZoomUserState -UserId $this.id
        Switch ($ret) {
            1  {$this.active = $true}
            -1 {$this.active = $false}
        }
    }
    [string]ToString(){
        return $this.id
    }
}
#
function ConvertTo-Base64([string]$text = '') {
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
            ErrorAction = 'Stop'
            Headers = @{}
        }

        if($PSEdition -eq 'Core'){
            # On Core edition use IRM
            $splat.Add('Authentication','Basic')
            $splat.Add('Credential',(New-Object System.Management.Automation.PSCredential ($client,$secret)))
            $splat.Add('RetryIntervalSec',5)
            $splat.Add('MaximumRetryCount',3)
            try {
                [PSCustomObject]$response = Invoke-RestMethod @splat
            } catch {
                Write-Output 'Failure trying to get an access token'
                Write-Output $_
            }
        } else {
            # When not on Core edition use IWR as IRM is not complete
            $splat.Add('UseBasicParsing',$True)
            $AuthZtoken = ConvertTo-Base64 -text ($client+':'+$(Get-DecryptedString -secureString $secret))
            $splat.Headers.Add('Authorization',"Basic $AuthZtoken")
            try {
                [PSCustomObject]$response = Invoke-WebRequest @splat | ConvertFrom-Json
                
            } catch {
                Write-Output 'Failure trying to get an access token'
                Write-Output $_
            }
        }
        $script:cached_zatoken = $response | Select-Object -Property * -ExcludeProperty access_token,expires_in
        if($script:cached_zatoken){
            $script:cached_zatoken | Add-Member -Value ((Get-Date).AddSeconds($response.expires_in)) -MemberType NoteProperty -Name expiry
            $script:cached_zatoken | Add-Member -Value ($response.access_token | ConvertTo-SecureString -AsPlainText -Force) -MemberType NoteProperty -Name access_token_secure
        }
        return $script:cached_zatoken.access_token_secure
    }
}
function Invoke-ZoomAPI_userSCIM2List {
    [CmdletBinding(DefaultParameterSetName = 'userSCIM2ListByIndex')]
    param (
        [Parameter(ParameterSetName='userSCIM2ListAll')]
        [switch]
        $All,

        [Parameter(ParameterSetName='userSCIM2ListByIndex')]
        [Parameter(ParameterSetName='userSCIM2ListFilter')]
        [ValidatePattern('^\d+$')]
        [int]
        $startIndex = 1,

        [Parameter(ParameterSetName='userSCIM2ListFilter')]
        [Parameter(ParameterSetName='userSCIM2ListByIndex')]
        [Parameter(ParameterSetName='userSCIM2ListLicense')]
        [ValidateRange(1,100)]
        [int]
        $count = 10,

        [Parameter(ParameterSetName='userSCIM2ListFilter')]
        [Parameter(ParameterSetName='userSCIM2ListAll')]
        [Alias('Filter','SearchQuery')]
        [string]
        $RawFilter,

        [Parameter(ParameterSetName='userSCIM2ListLicense')]
        [Alias('LisenseType','License','Lisense')]
        [ValidateSet('Basic','Licensed','On-Prem')]
        [string]
        $LicenseType,

        [Parameter(ParameterSetName='userSCIM2ListUser')]
        [Alias('User','UPN','UserPrincipalName','Email','LoginId')]
        [ValidatePattern("^\w+([-+.']\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*$")]
        [string]
        $UserName,

        [Parameter(ParameterSetName='userSCIM2ListId')]
        [Alias('Id','UserId','ZoomId','uid')]
        [string]
        $ExternalId,

        [Parameter(ParameterSetName='userSCIM2ListFilter')]
        [Parameter(ParameterSetName='userSCIM2ListByIndex')]
        [Parameter(ParameterSetName='userSCIM2ListLicense')]
        [Parameter(ParameterSetName='userSCIM2ListAll')]
        [Parameter(ParameterSetName='userSCIM2ListUser')]
        [Parameter(ParameterSetName='userSCIM2ListId')]
        [securestring]
        $Token = (Get-ZoomAccessToken),

        [Parameter(ParameterSetName='userSCIM2ListFilter')]
        [Parameter(ParameterSetName='userSCIM2ListByIndex')]
        [Parameter(ParameterSetName='userSCIM2ListLicense')]
        [Parameter(ParameterSetName='userSCIM2ListAll')]
        [Parameter(ParameterSetName='userSCIM2ListUser')]
        [Parameter(ParameterSetName='userSCIM2ListId')]
        [switch]
        $ReturnRaw
    )

    [hashtable]$queryHash = @{
        count = $count
        startIndex = $startIndex
        filter = $RawFilter
    }

    if ($ExternalId){
        # search by zoom unique id
        $queryHash.Filter  ='externalId eq {0}' -f $ExternalId
    } elseif ($UserName){
        # search by zoom username
        $queryHash.filter = 'userName eq {0}' -f $UserName
    } elseif ($LicenseType -and -not $All){
        # search by zoom license
        $queryHash.filter = "license type"
        Throw 'License type query not implemented yet'
    } elseif ($RawFilter){
        # search using custom filter
        Throw 'Custom filter not implemented yet'
    }

    [hashtable]$splat = @{
        Uri = 'https://api.zoom.us/scim2/users'
        Method = 'Get'
        Body = $queryHash
        Headers = @{
            Accept = 'application/scim+json'
        }
        TimeoutSec = 30
        ErrorAction = 'Continue'
    }

    if($PSEdition -eq 'Core'){
        # add PowerShell Core-only features for Invoke-RestMethod
        $splat.Add('Authentication','Bearer')
        $splat.Add('Token',$Token)
        $splat.Add('RetryIntervalSec',5)
        $splat.Add('MaximumRetryCount',3)
        $response = Invoke-RestMethod @splat
    } else {
        # decrypt the token
        $decryptedToken = Get-DecryptedString -secureString $Token
        # PowerShell 5.1 IRM doesn't return a status code so use Invoke-WebRequest instead
        $splat.Headers.Add('Authorization','Bearer '+$decryptedToken)
        $splat.Add('UseBasicParsing',$True)
        $splat.Add('ContentType','application/json')
        $response = Invoke-WebRequest @splat | ConvertFrom-Json
    }
    if($ReturnRaw){
        return $response
    } else {
        return $response.Resources
    }
}

function Get-DecryptedString ([secureString]$secureString){
    $ptrString = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securestring)
    [string]$decryptedString = [Runtime.InteropServices.Marshal]::PtrToStringAuto($ptrString)
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptrString)
    return $decryptedString
}

function Invoke-ZoomSCIM2APICall {
    [CmdletBinding()]
    param (
        [Parameter(ParameterSetName='userSCIM2List','userSCIM2ListAll','userSCIM2Create','userSCIM2Get','userSCIM2Update','userSCIM2Delete','userADSCIM2Deactivate')]
        [ValidateSet('userSCIM2List','userSCIM2Create','userSCIM2Get','userSCIM2Update','userSCIM2Delete','userADSCIM2Deactivate')]
        [Alias('Method')]
        [string]
        $ApiMethod = 'userSCIM2List',

        [Parameter(ParameterSetName='userSCIM2ListAll')]
        [switch]
        $All,

        [Parameter(ParameterSetName='userSCIM2List')]
        [int]
        $startIndex = 1,

        [Parameter(ParameterSetName='userSCIM2List')]
        [int]
        $count = 100,

        [Parameter(ParameterSetName='userSCIM2List','userSCIM2ListAll')]
        [string]
        $filter,

        [Parameter(ParameterSetName='userSCIM2List','userSCIM2ListAll','userSCIM2Create','userSCIM2Get','userSCIM2Update','userSCIM2Delete','userADSCIM2Deactivate')]
        [string]
        $token = (Get-ZoomAccessToken)
    )]
    [string]$protocol = 'https'
    [string]$apihost = 'api.zoom.us'
    [string]$api = 'scim2'
    [uri]$RestUri = '{0}://{1}/{2}/{3}' -f ($protocol,$apihost,$api,$ApiMethod)
    [hashtable]$RestHeaders = @{Accept = 'application/scim+json'}
    switch ($ApiMethod) {
        userSCIM2List         {[string]$RestMethod = 'Get'}
        userSCIM2Get          {[string]$RestMethod = 'Get'}
        userSCIM2Create       {[string]$RestMethod = 'Post'}
        userSCIM2Update       {[string]$RestMethod = 'Put'}
        userSCIM2Delete       {[string]$RestMethod = 'Delete'}
        userADSCIM2Deactivate {[string]$RestMethod = 'Patch'}
    }
    [hashtable]$splat = {
        Uri = $RestUri
        Method = $RestMethod
        Authentication = 'Bearer'
        Token = $token
        Headers = $RestHeaders
        StatusCodeVariable = statusCode
        TimeoutSec = 60
        RetryIntervalSec = 5
        MaximumRetryCount = 3
        ErrorAction = 'Continue'
    }
    try {
        $response = Invoke-RestMethod @splat
    } catch {

    }
    
}
function Get-ZoomUsers {
    [CmdletBinding()]
    param ()
    # discover how many users there are
    Write-Verbose 'Function: Get-ZoomUsers'
    $discovery = Invoke-ZoomAPI_userSCIM2List -ReturnRaw -count 1
    [int]$total = $discovery.totalResults
    [ZoomUser[]]$data = @()
    [int]$pageSize = 100
    [int]$index = 1
    do {
        if(($index+$pageSize) -gt $total){
            $pageSize = ($total-$index)+1
        }
        Write-Progress -Activity 'Collecting Zoom users' -PercentComplete ((($index+$pageSize-1)/$total)*100) -Status "$index : $($index+$pageSize-1)"
        $response = Invoke-ZoomAPI_userSCIM2List -startIndex $index -count $pageSize
        $data += Format-ZoomUserData -data $response
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
function Get-ZoomUserFromAAD {
    [CmdletBinding()]
    param($zoomUser)
    [string[]]$properties = @('Id','AccountEnabled','ProxyAddresses','UserPrincipalName','Mail')
    Invoke-GraphConnection
    [string]$query = "UserPrincipalName eq '{0}' or ProxyAddresses/any(c:c eq 'smtp:{1}')" -f ($zoomUser.UserName,$zoomUser.emailAddress)
    Write-Verbose "Calling Get-MgUser with query `"$query`""
    [array]$aadUser = Get-MgUser -Filter $query -Property $properties
    Write-Verbose "$($aadUser.count) AAD objects found: $($aadUser.Id -join(','))"
    return ($aadUser | Select-Object -Property $properties)
}

function Invoke-GraphConnection {
    [CmdletBinding()]
    param()

    if(!(Get-Module 'Microsoft.Graph.Authentication')){
        Import-Module -FullyQualifiedName .\modules\Microsoft.Graph.Authentication
    }
    if(!(Get-MgContext)){
        Write-Verbose "No existing connection to Microsoft Graph. Will try to connect."
        Write-Verbose "Trying to get authentiction certificate"
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$certificate = Get-ChildItem -Path "Certificate::*\My\$($script:config['AAD_Cert_Thumb'])" | Where-Object HasPrivateKey | Sort-Object -Descending NotAfter | Select-Object -First 1
        if(!$certificate){
            Throw "Can't initiate Graph connection. Certificate not found."
        }
        [hashtable]$splat = @{
            ClientId = $script:config['AAD_Client_ID']
            Certificate = $certificate
            TenantId = $script:config['AAD_Tenant_ID']
        }
        Write-Verbose "Connecting to Microsoft Graph"
        Connect-MgGraph @splat | Out-Null
    } else {
        # connection already active
    }
}
function Compare-ZoomUsersWithAADUsers {
    [CmdletBinding()]
    param([array]$ZoomUsers)

    [X509Certificate]$certificate = Get-ChildItem -Path "Certificate::*\My\$($script:config['AAD_Cert_Thumb'])" -Recurse | Where-Object HasPrivateKey | Sort-Object -Descending NotAfter | Select-Object -First 1
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
    if($script:simulationMode){
        $statusCode = 200
    } else {
        $response = Invoke-RestMethod @splat -StatusCodeVariable statusCode
    }
    if($statusCode = 200 -and !$targetState){
        Write-Verbose "Disabled Zoom user $UserId"
        return -1
    } elseif ($statusCode = 200 -and $targetState){
        Write-Verbose "Enabled Zoom user $UserId"
        return 1
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
