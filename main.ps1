[CmdletBinding()]param()
Write-Verbose 'Start of script'
function Initialize-Config {
    [CmdletBinding()]param()
    Write-Verbose 'Function: Initialize-Config'
    if(Test-Path '.\config.txt'){
        Write-Verbose 'Found config file. Loading OAuth app values'
        [hashtable]$config = Get-Content '.\config.txt' -Raw | ConvertFrom-StringData -Delimiter '='
        if($config.Keys -contains 'Account_ID'){
            Write-Verbose "Account_ID = $($config['Account_ID'])"
            [string]$script:Account_ID = $config['Account_ID']
            if($config.Keys -contains 'Client_ID'){
                Write-Verbose "Client_ID = $($config['Client_ID'])"
                [string]$script:Client_ID = $config['Client_ID']
                if($config.Keys -contains 'Client_Secret'){
                    Write-Verbose "Client_Secret = $($config['Client_Secret'])"
                    [securestring]$script:Client_Secret = $config['Client_Secret'] | ConvertTo-SecureString -Force -AsPlainText
                } else {
                    throw 'Unable to load Client_Secret value from config.txt'
                }
            } else {
                throw 'Unable to load Client_ID value from config.txt'
            }
        } else {
            throw 'Unable to load Account_ID value from config.txt'
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
        [Parameter(Position=0)][string]$account = $script:Account_ID,
        [Parameter(Position=1)][string]$client = $script:Client_ID,
        [Parameter(Position=2)][securestring]$secret = $script:Client_Secret,
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
            Write-Output "Failure trying to get an access token"
            Write-Output $_
        }
    }
}
function Get-ZoomUsers {
    [CmdletBinding()]
    param ()
    # discover how many users there are
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
        $response = Invoke-RestMethod -uri ($query -f $pageSize,$startIndex) -Method Get -Authentication Bearer -Token (Get-ZoomAccessToken) -MaximumRetryCount 3 -RetryIntervalSec 5
        $data += Invoke-ZoomUserDataParse -data $response.Resources
        $startIndex += $pageSize
        Start-Sleep -Seconds 1 # rate limiting will kick in if we don't do this
    } until ($startIndex -ge $total)
    return $data
}
function Invoke-ZoomUserDataParse {
    [CmdletBinding()]
    param([array]$data)
    [array]$parsedData = $data | Select-Object id,@{N='uri';E={$_.meta.location}},@{N='givenName';E={$_.name.givenName}},@{N='familyName';E={$_.name.familyName}},@{N='emailAddress';E={($_.emails | ? Primary -eq True).value}},displayName,userName,active,userType
    return $parsedData
}

Initialize-Config
#Get-ZoomAccessToken
