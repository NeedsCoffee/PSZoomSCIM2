[CmdletBinding()]param()
function Initialize-Config {
    [CmdletBinding()]param()
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
                    Write-Error 'Unable to load Client_Secret value from config.txt'
                    exit 1
                }
            } else {
                Write-Error 'Unable to load Client_ID value from config.txt'
                exit 1
            }
        } else {
            Write-Error 'Unable to load Account_ID value from config.txt'
            exit 1
        }
    } else {
        Write-Error 'config.txt not found. Unable to continue'
        exit 1
    }
}
function ConvertTo-Base64([string]$text = '') {
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
    if($script:cached_zatoken.expiry -gt (Get-Date).AddSeconds(-300) -and -not $force){
        Write-Verbose 'Cached token found, still valid, not forcing renewal'
        Write-Verbose "Token expiry = $($script:cached_zatoken.expiry)"
        return $script:cached_zatoken.access_token
    } else {
        Write-Verbose "Acquiring new access token for account $account"
        [string]$uri = 'https://zoom.us/oauth/token?grant_type={0}&account_id={1}'
        [string]$grant = 'account_credentials'
        [hashtable]$splat = @{
            Uri = ($uri -f $grant,$account)
            Method = 'Post'
            Authentication = 'Basic'
            Credential = New-Object System.Management.Automation.PSCredential ($client,$secret)
            ContentType = 'application/x-www-form-urlencoded'
        }
        try {
            [PSCustomObject]$script:cached_zatoken = Invoke-RestMethod @splat -ErrorAction:Stop
            # should validate token here
            $script:cached_zatoken | Add-Member -Value ((Get-Date).AddSeconds($response.expires_in)) -MemberType NoteProperty -Name expiry
            return $script:cached_zatoken.access_token
        } catch {
            Write-Output "Failure trying to get an access token"
            Write-Output $_
        }
    }
}

Initialize-Config
Get-ZoomAccessToken
