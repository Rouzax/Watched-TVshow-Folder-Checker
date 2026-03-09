<#
.SYNOPSIS
    Lists TV shows with Trakt watch status and disk usage for cleanup decisions.

.DESCRIPTION
    Cross-references local TV show folders with Trakt watch history to identify
    fully watched, partially watched, and unwatched content with accurate size accounting.

    Features:
    - Trakt OAuth with automatic token refresh
    - Result caching with configurable TTL and smart invalidation
    - Show metadata (series status, network, next episode)
    - Multiple output formats (GridView, CSV, JSON)
    - Configuration file support
    - Cleanup actions with Recycle Bin support (show or season level)
    - Exclusion patterns for samples/trailers
    - Summary statistics
    - Multiple root folder support

.PARAMETER RootFolder
    One or more root folders containing TV show subfolders.
    Can also be set in config.json.

.PARAMETER ClientId
    Trakt API Client ID. Optional if tokens.json or config.json exists.

.PARAMETER ClientSecret
    Trakt API Client Secret. Optional if tokens.json or config.json exists.

.PARAMETER OutputFormat
    Output format: GridView (default), CSV, JSON, or Console.

.PARAMETER OutputPath
    File path for CSV/JSON output. Required when OutputFormat is CSV or JSON.

.PARAMETER CacheTTLHours
    Hours before cached Trakt data expires. Default: 720 (30 days).
    Note: Cache is automatically invalidated when disk content changes,
    so this TTL mainly affects shows where you watched more on Trakt
    without downloading new episodes.

.PARAMETER ForceRefresh
    Bypass cache entirely and fetch fresh data from Trakt.

.PARAMETER RefreshInProgress
    Force refresh for shows not marked "Fully Watched".

.PARAMETER ExcludePattern
    File name patterns to exclude from size calculations.

.PARAMETER CleanupFullyWatched
    Delete or move shows that are fully watched (entire show folder).

.PARAMETER CleanupWatchedSeasons
    Delete or move only fully watched season folders, keeping unwatched seasons.
    Useful for ongoing shows where you want to free space from completed seasons.

.PARAMETER MoveToPath
    Move shows/seasons to this path instead of deleting. Creates archive folders.
    For seasons, creates: MoveToPath\ShowName\SeasonFolder

.PARAMETER SkipRecycleBin
    Permanently delete instead of sending to Recycle Bin.
    Default behavior uses Recycle Bin for safety.

.PARAMETER CreateConfig
    Generate a default config.json file and exit.

.PARAMETER Interactive
    Use Out-GridView to select shows for cleanup interactively.

.EXAMPLE
    .\Watched-TVshow-Folder-Checker.ps1 -RootFolder "E:\TVSeries"

.EXAMPLE
    .\Watched-TVshow-Folder-Checker.ps1 -CleanupFullyWatched -WhatIf

.EXAMPLE
    .\Watched-TVshow-Folder-Checker.ps1 -CleanupWatchedSeasons -WhatIf
    # Preview removing fully watched season folders while keeping unwatched seasons

.EXAMPLE
    .\Watched-TVshow-Folder-Checker.ps1 -CleanupFullyWatched -CleanupWatchedSeasons -WhatIf
    # Preview removing both fully watched shows AND watched seasons from partial shows

.EXAMPLE
    .\Watched-TVshow-Folder-Checker.ps1 -CleanupFullyWatched -CleanupWatchedSeasons -MoveToPath "X:\Archive"
    # Move both fully watched shows and watched seasons to archive

.EXAMPLE
    .\Watched-TVshow-Folder-Checker.ps1 -Interactive

.EXAMPLE
    .\Watched-TVshow-Folder-Checker.ps1 -CreateConfig

.NOTES
    Configuration is loaded from config.json if present. Command-line parameters override config values.
    Requires Windows PowerShell 5.1+ or PowerShell 7+ with Microsoft.PowerShell.GraphicalTools for GridView.
#>
#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param (
    [Parameter(Mandatory = $false)]
    [string[]]$RootFolder,

    [Parameter(Mandatory = $false)]
    [string]$ClientId,

    [Parameter(Mandatory = $false)]
    [string]$ClientSecret,

    [Parameter(Mandatory = $false)]
    [ValidateSet('GridView', 'CSV', 'JSON', 'Console')]
    [string]$OutputFormat,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 8760)]
    [int]$CacheTTLHours,

    [Parameter(Mandatory = $false)]
    [switch]$ForceRefresh,

    [Parameter(Mandatory = $false)]
    [switch]$RefreshInProgress,

    [Parameter(Mandatory = $false)]
    [string[]]$ExcludePattern,

    [Parameter(Mandatory = $false)]
    [switch]$CleanupFullyWatched,

    [Parameter(Mandatory = $false)]
    [switch]$CleanupWatchedSeasons,

    [Parameter(Mandatory = $false)]
    [string]$MoveToPath,

    [Parameter(Mandatory = $false)]
    [switch]$SkipRecycleBin,

    [Parameter(Mandatory = $false)]
    [switch]$CreateConfig,

    [Parameter(Mandatory = $false)]
    [switch]$Interactive
)

#region ===== CONFIGURATION =====

$script:Paths = @{
    Config  = Join-Path -Path $PSScriptRoot -ChildPath 'config.json'
    Tokens  = Join-Path -Path $PSScriptRoot -ChildPath 'tokens.json'
    Cache   = Join-Path -Path $PSScriptRoot -ChildPath 'trakt-cache.json'
}

$script:Defaults = @{
    RootFolders      = @()
    ExcludePatterns  = @('Sample', 'Trailer', 'SAMPLE')
    CacheTTLHours    = 720   # 30 days - size changes trigger automatic refresh
    MetadataTTLHours = 168   # 7 days - series status rarely changes
    OutputFormat     = 'GridView'
    VideoExtensions  = @('.mkv', '.mp4', '.avi', '.mov', '.m4v', '.wmv', '.ts', '.flv', '.webm')
    RequestDelayMs   = 200
}

$script:TraktApi = @{
    Version     = '2'
    RedirectUri = 'urn:ietf:wg:oauth:2.0:oob'
    BaseUrl     = 'https://api.trakt.tv'
    AuthUrl     = 'https://trakt.tv/oauth/authorize'
}

# Watch status constants
$script:WatchStatus = @{
    FullyWatched = 'Fully Watched'
    Unwatched    = 'Unwatched'
    Unknown      = 'Unknown'
    NoMatch      = 'Unknown (no Trakt match)'
    Error        = 'Unknown (error)'
}

# Series status mapping (Trakt API values to display values)
$script:SeriesStatusMap = @{
    'returning series' = 'Returning'
    'in production'    = 'In Production'
    'planned'          = 'Planned'
    'canceled'         = 'Canceled'
    'ended'            = 'Ended'
}

# Episode regex pattern (compiled once for performance)
$script:EpisodePattern = [regex]::new('S(?<S>\d{1,2})E(?<E1>\d{1,2})(?:[-.\s]*E?(?<E2>\d{1,2}))?', 'IgnoreCase, Compiled')

# Runtime state
$script:State = @{
    AccessToken = $null
    ClientId    = $null
    Cache       = @{}
    Config      = @{}
}

#endregion

#region ===== CONFIGURATION FILE =====

function New-DefaultConfig {
    <#
    .SYNOPSIS
        Creates a default configuration file.
    #>
    $defaultConfig = [ordered]@{
        rootFolders       = @('C:\TVSeries')
        excludePatterns   = $script:Defaults.ExcludePatterns
        cacheTTLHours     = $script:Defaults.CacheTTLHours
        metadataTTLHours  = $script:Defaults.MetadataTTLHours
        outputFormat      = $script:Defaults.OutputFormat
        videoExtensions   = $script:Defaults.VideoExtensions
        clientId          = ''
        clientSecret      = ''
        manualMappings    = @{
            '_Example Show Name (2020)' = @{
                trakt_id   = 0
                trakt_slug = 'example-slug'
            }
        }
    }

    $json = $defaultConfig | ConvertTo-Json -Depth 5
    $json | Set-Content -LiteralPath $script:Paths.Config -Encoding UTF8

    Write-Host "Created default config file: $($script:Paths.Config)" -ForegroundColor Green
    Write-Host "Please edit the file to configure your settings." -ForegroundColor Yellow
}

function Import-Configuration {
    <#
    .SYNOPSIS
        Loads configuration from config.json, with command-line overrides.
    #>
    param(
        [hashtable]$ScriptParameters
    )

    $config = @{
        RootFolders      = $script:Defaults.RootFolders
        ExcludePatterns  = $script:Defaults.ExcludePatterns
        CacheTTLHours    = $script:Defaults.CacheTTLHours
        MetadataTTLHours = $script:Defaults.MetadataTTLHours
        OutputFormat     = $script:Defaults.OutputFormat
        VideoExtensions  = $script:Defaults.VideoExtensions
        ManualMappings   = @{}
        ClientId         = $null
        ClientSecret     = $null
    }

    # Load from config file if exists
    if (Test-Path -LiteralPath $script:Paths.Config) {
        try {
            $fileConfig = Get-Content -LiteralPath $script:Paths.Config -Raw | ConvertFrom-Json

            if ($null -ne $fileConfig.rootFolders) { $config.RootFolders = @($fileConfig.rootFolders) }
            if ($null -ne $fileConfig.excludePatterns) { $config.ExcludePatterns = @($fileConfig.excludePatterns) }
            if ($null -ne $fileConfig.cacheTTLHours) {
                $parsed = 0; if ([int]::TryParse($fileConfig.cacheTTLHours, [ref]$parsed)) { $config.CacheTTLHours = $parsed }
                else { Write-Warning "Invalid cacheTTLHours value '$($fileConfig.cacheTTLHours)' in config.json, using default" }
            }
            if ($null -ne $fileConfig.metadataTTLHours) {
                $parsed = 0; if ([int]::TryParse($fileConfig.metadataTTLHours, [ref]$parsed)) { $config.MetadataTTLHours = $parsed }
                else { Write-Warning "Invalid metadataTTLHours value '$($fileConfig.metadataTTLHours)' in config.json, using default" }
            }
            if ($null -ne $fileConfig.outputFormat) { $config.OutputFormat = $fileConfig.outputFormat }
            if ($null -ne $fileConfig.videoExtensions) { $config.VideoExtensions = @($fileConfig.videoExtensions) }
            if ($fileConfig.clientId) { $config.ClientId = $fileConfig.clientId }
            if ($fileConfig.clientSecret) { $config.ClientSecret = $fileConfig.clientSecret }

            # Load manual mappings (skip example entries starting with _)
            if ($fileConfig.manualMappings) {
                foreach ($prop in $fileConfig.manualMappings.PSObject.Properties) {
                    if (-not $prop.Name.StartsWith('_')) {
                        $config.ManualMappings[$prop.Name.ToLowerInvariant()] = @{
                            trakt_id   = $prop.Value.trakt_id
                            trakt_slug = $prop.Value.trakt_slug
                        }
                    }
                }
            }

            Write-Verbose "Loaded configuration from config.json"
        }
        catch {
            Write-Warning "Could not parse config.json: $_"
        }
    }

    # Command-line parameters override config file
    if ($ScriptParameters.ContainsKey('RootFolder') -and $ScriptParameters.RootFolder) {
        $config.RootFolders = @($ScriptParameters.RootFolder)
    }
    if ($ScriptParameters.ContainsKey('ExcludePattern') -and $ScriptParameters.ExcludePattern) {
        $config.ExcludePatterns = @($ScriptParameters.ExcludePattern)
    }
    if ($ScriptParameters.ContainsKey('CacheTTLHours') -and $ScriptParameters.CacheTTLHours) {
        $config.CacheTTLHours = $ScriptParameters.CacheTTLHours
    }
    if ($ScriptParameters.ContainsKey('OutputFormat') -and $ScriptParameters.OutputFormat) {
        $config.OutputFormat = $ScriptParameters.OutputFormat
    }
    if ($ScriptParameters.ContainsKey('ClientId') -and $ScriptParameters.ClientId) {
        $config.ClientId = $ScriptParameters.ClientId
    }
    if ($ScriptParameters.ContainsKey('ClientSecret') -and $ScriptParameters.ClientSecret) {
        $config.ClientSecret = $ScriptParameters.ClientSecret
    }

    return $config
}

#endregion

#region ===== TOKEN MANAGEMENT =====

function Import-TraktTokens {
    <#
    .SYNOPSIS
        Loads saved tokens from disk.
    #>
    if (-not (Test-Path -LiteralPath $script:Paths.Tokens)) {
        return $null
    }
    try {
        $content = Get-Content -LiteralPath $script:Paths.Tokens -Raw -ErrorAction Stop
        return $content | ConvertFrom-Json
    }
    catch {
        Write-Warning "Could not parse tokens.json: $_"
        return $null
    }
}

function Export-TraktTokens {
    <#
    .SYNOPSIS
        Saves tokens to disk.
    #>
    param(
        [Parameter(Mandatory)][string]$AccessToken,
        [Parameter(Mandatory)][string]$RefreshToken,
        [Parameter(Mandatory)][string]$ClientId,
        [Parameter(Mandatory)][string]$ClientSecret
    )

    $data = [ordered]@{
        access_token  = $AccessToken
        refresh_token = $RefreshToken
        client_id     = $ClientId
        client_secret = $ClientSecret
        saved_at_utc  = (Get-Date).ToUniversalTime().ToString('o')
    }

    $data | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $script:Paths.Tokens -Encoding UTF8
}

function Initialize-TraktAuth {
    <#
    .SYNOPSIS
        Ensures valid authentication is available, prompting if necessary.
    #>
    $stored = Import-TraktTokens

    # Use stored credentials if available
    if ($stored -and $stored.access_token -and $stored.refresh_token) {
        $script:State.AccessToken = $stored.access_token
        $script:State.ClientId = if ($script:State.Config.ClientId) { $script:State.Config.ClientId } else { $stored.client_id }

        if ($script:State.ClientId -and $stored.client_secret) {
            Write-Verbose "Loaded existing tokens from tokens.json"
            return
        }
    }

    # Use config values or prompt with helpful instructions
    if (-not $script:State.Config.ClientId -or -not $script:State.Config.ClientSecret) {
        Write-Host ""
        Write-Host ("=" * 70) -ForegroundColor Cyan
        Write-Host "TRAKT API SETUP" -ForegroundColor Cyan
        Write-Host ("=" * 70) -ForegroundColor Cyan
        Write-Host ""
        Write-Host "To use this script, you need a Trakt API application:" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  1. Go to: https://trakt.tv/oauth/applications/new" -ForegroundColor White
        Write-Host "  2. Fill in the form:" -ForegroundColor White
        Write-Host "     - Name: Any name (e.g., 'TV Show Cleanup Script')" -ForegroundColor Gray
        Write-Host "     - Redirect URI: urn:ietf:wg:oauth:2.0:oob" -ForegroundColor Gray
        Write-Host "     - Leave other fields default" -ForegroundColor Gray
        Write-Host "  3. Click 'Save App'" -ForegroundColor White
        Write-Host "  4. Copy the Client ID and Client Secret shown" -ForegroundColor White
        Write-Host ""
        Write-Host "Tip: Add these to config.json to skip this step next time." -ForegroundColor DarkGray
        Write-Host ""
    }

    $cid = if ($script:State.Config.ClientId) { $script:State.Config.ClientId } else {
        do { $input = Read-Host "Enter your Trakt API Client ID" } while ([string]::IsNullOrWhiteSpace($input))
        $input
    }
    $csec = if ($script:State.Config.ClientSecret) { $script:State.Config.ClientSecret } else {
        do { $input = Read-Host "Enter your Trakt API Client Secret" } while ([string]::IsNullOrWhiteSpace($input))
        $input
    }

    $script:State.ClientId = $cid

    # Build authorization URL
    $authUrl = "{0}?response_type=code&client_id={1}&redirect_uri={2}" -f `
        $script:TraktApi.AuthUrl, $cid, [uri]::EscapeDataString($script:TraktApi.RedirectUri)

    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "AUTHORIZATION REQUIRED" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""
    Write-Host "This script needs permission to access your Trakt watch history." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  1. Open this URL in your browser:" -ForegroundColor White
    Write-Host "     $authUrl" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  2. Log in to Trakt if prompted" -ForegroundColor White
    Write-Host "  3. Click 'Accept' to authorize the app" -ForegroundColor White
    Write-Host "  4. Copy the PIN code shown on the page" -ForegroundColor White
    Write-Host ""
    $authCode = Read-Host "Enter the PIN code from Trakt"

    # Exchange code for tokens
    $tokenBody = @{
        code          = $authCode
        client_id     = $cid
        client_secret = $csec
        redirect_uri  = $script:TraktApi.RedirectUri
        grant_type    = 'authorization_code'
    }

    try {
        $resp = Invoke-TraktRequest -Endpoint '/oauth/token' -Method POST -Body $tokenBody -SkipAuth
        $script:State.AccessToken = $resp.access_token
        Export-TraktTokens -AccessToken $resp.access_token -RefreshToken $resp.refresh_token `
            -ClientId $cid -ClientSecret $csec
        Write-Host "Authentication successful. Tokens saved." -ForegroundColor Green
    }
    catch {
        throw "Failed to authenticate with Trakt: $_"
    }
}

function Update-TraktAccessToken {
    <#
    .SYNOPSIS
        Refreshes the access token using the stored refresh token.
    #>
    $stored = Import-TraktTokens
    if (-not $stored -or -not $stored.refresh_token) {
        throw "No refresh token available. Please re-authenticate."
    }

    $refreshBody = @{
        refresh_token = $stored.refresh_token
        client_id     = $stored.client_id
        client_secret = $stored.client_secret
        redirect_uri  = $script:TraktApi.RedirectUri
        grant_type    = 'refresh_token'
    }

    try {
        $resp = Invoke-TraktRequest -Endpoint '/oauth/token' -Method POST -Body $refreshBody -SkipAuth
        $script:State.AccessToken = $resp.access_token
        Export-TraktTokens -AccessToken $resp.access_token -RefreshToken $resp.refresh_token `
            -ClientId $stored.client_id -ClientSecret $stored.client_secret
        Write-Verbose "Access token refreshed successfully"
        return $resp.access_token
    }
    catch {
        throw "Failed to refresh access token: $_"
    }
}

#endregion

#region ===== CACHE MANAGEMENT =====

function Import-TraktCache {
    <#
    .SYNOPSIS
        Loads the Trakt results cache from disk.
    #>
    if (-not (Test-Path -LiteralPath $script:Paths.Cache)) {
        return @{}
    }
    try {
        $content = Get-Content -LiteralPath $script:Paths.Cache -Raw -ErrorAction Stop
        $parsed = $content | ConvertFrom-Json

        # Convert PSObject to hashtable
        $cache = @{}
        foreach ($prop in $parsed.PSObject.Properties) {
            $cache[$prop.Name] = $prop.Value
        }
        return $cache
    }
    catch {
        Write-Warning "Could not parse cache file: $_"
        return @{}
    }
}

function Export-TraktCache {
    <#
    .SYNOPSIS
        Saves the Trakt results cache to disk.
    #>
    param([Parameter(Mandatory)][hashtable]$Cache)

    $Cache | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $script:Paths.Cache -Encoding UTF8
}

function Sync-TraktCache {
    <#
    .SYNOPSIS
        Removes cache entries for shows whose folders no longer exist on disk.
    #>
    param(
        [Parameter(Mandatory)][hashtable]$Cache
    )

    $keysToRemove = [System.Collections.Generic.List[string]]::new()

    foreach ($key in $Cache.Keys) {
        $entry = $Cache[$key]
        
        # If entry has a folder path, verify it still exists
        if ($entry.folder_path) {
            if (-not (Test-Path -LiteralPath $entry.folder_path -PathType Container)) {
                $keysToRemove.Add($key)
            }
        }
        # Entries without folder_path are legacy - keep them until they get updated
    }

    foreach ($key in $keysToRemove) {
        $Cache.Remove($key)
        Write-Verbose "Removed stale cache entry (folder deleted): $key"
    }

    if ($keysToRemove.Count -gt 0) {
        Write-Verbose "Pruned $($keysToRemove.Count) stale cache entries"
    }

    return $keysToRemove.Count
}

function ConvertTo-DateTime {
    <#
    .SYNOPSIS
        Robustly parses a datetime string, handling multiple formats.
    #>
    param([string]$DateString)

    if ([string]::IsNullOrWhiteSpace($DateString)) {
        return $null
    }

    # Try parsing with various methods
    try {
        return [datetime]::ParseExact($DateString, 'o', [System.Globalization.CultureInfo]::InvariantCulture)
    }
    catch { }

    try {
        return [datetime]::Parse($DateString, [System.Globalization.CultureInfo]::InvariantCulture)
    }
    catch { }

    try {
        return [datetime]::Parse($DateString)
    }
    catch { }

    try {
        return Get-Date -Date $DateString
    }
    catch {
        return $null
    }
}

function Test-CacheValid {
    <#
    .SYNOPSIS
        Checks if a cache entry is still valid based on TTL and status.
    #>
    param(
        $CacheEntry,
        [Parameter(Mandatory)][int]$TTLHours,
        [switch]$RefreshPartial
    )

    if ($null -eq $CacheEntry) {
        return $false
    }

    if (-not $CacheEntry.cached_at) {
        return $false
    }

    # Always refresh if requested for partial watches
    if ($RefreshPartial -and $CacheEntry.status -ne $script:WatchStatus.FullyWatched) {
        return $false
    }

    # Check TTL
    $cachedAt = ConvertTo-DateTime -DateString $CacheEntry.cached_at
    if (-not $cachedAt) {
        return $false
    }
    $expiresAt = $cachedAt.AddHours($TTLHours)

    return (Get-Date).ToUniversalTime() -lt $expiresAt
}

function Test-MetadataCacheValid {
    <#
    .SYNOPSIS
        Checks if metadata cache is still valid (uses longer TTL).
    #>
    param($CacheEntry)

    if ($null -eq $CacheEntry -or -not $CacheEntry.metadata_cached_at) {
        return $false
    }

    $cachedAt = ConvertTo-DateTime -DateString $CacheEntry.metadata_cached_at
    if (-not $cachedAt) {
        return $false
    }

    $ttlHours = $script:State.Config.MetadataTTLHours
    if (-not $ttlHours) { $ttlHours = $script:Defaults.MetadataTTLHours }

    $expiresAt = $cachedAt.AddHours($ttlHours)
    return (Get-Date).ToUniversalTime() -lt $expiresAt
}

function Get-CacheKey {
    <#
    .SYNOPSIS
        Generates a consistent cache key for a show folder.
    #>
    param([Parameter(Mandatory)][string]$FolderName)

    return $FolderName.Trim().ToLowerInvariant()
}

#endregion

#region ===== TRAKT API =====

function New-TraktHeaders {
    <#
    .SYNOPSIS
        Builds standard Trakt API headers.
    #>
    param([switch]$IncludeAuth)

    $headers = @{
        'Content-Type'      = 'application/json'
        'trakt-api-version' = $script:TraktApi.Version
        'trakt-api-key'     = $script:State.ClientId
    }

    if ($IncludeAuth -and $script:State.AccessToken) {
        $headers['Authorization'] = "Bearer $($script:State.AccessToken)"
    }

    return $headers
}

function Invoke-TraktRequest {
    <#
    .SYNOPSIS
        Makes a request to the Trakt API with automatic retry on 401.
    #>
    param(
        [Parameter(Mandatory)][string]$Endpoint,
        [ValidateSet('GET', 'POST')][string]$Method = 'GET',
        [object]$Body = $null,
        [switch]$SkipAuth
    )

    # Rate limiting
    Start-Sleep -Milliseconds $script:Defaults.RequestDelayMs

    $uri = if ($Endpoint.StartsWith('http')) { $Endpoint } else { $script:TraktApi.BaseUrl + $Endpoint }
    $headers = New-TraktHeaders -IncludeAuth:(-not $SkipAuth)

    $invokeParams = @{
        Uri         = $uri
        Method      = $Method
        Headers     = $headers
        ErrorAction = 'Stop'
    }

    if ($Body) {
        $invokeParams['Body'] = $Body | ConvertTo-Json -Depth 10
    }

    try {
        return Invoke-RestMethod @invokeParams
    }
    catch {
        $statusCode = $null
        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
        }

        # Retry once on 401 with refreshed token
        if (-not $SkipAuth -and $statusCode -eq 401) {
            Write-Verbose "Token expired, refreshing..."
            $null = Update-TraktAccessToken

            # Rebuild headers with new token and retry
            $invokeParams['Headers'] = New-TraktHeaders -IncludeAuth
            return Invoke-RestMethod @invokeParams
        }

        throw
    }
}

function Find-TraktShow {
    <#
    .SYNOPSIS
        Searches Trakt for a show and returns the best match.
        Checks manual mappings first.
    #>
    param(
        [Parameter(Mandatory)][string]$Title,
        [int]$Year,
        [string]$FolderName
    )

    # Check manual mappings first
    $cacheKey = Get-CacheKey -FolderName $FolderName
    if ($script:State.Config.ManualMappings.ContainsKey($cacheKey)) {
        $mapping = $script:State.Config.ManualMappings[$cacheKey]
        Write-Verbose "  Using manual mapping for: $FolderName"
        return @{
            show = @{
                ids = @{
                    trakt = $mapping.trakt_id
                    slug  = $mapping.trakt_slug
                }
                title = $Title
                year  = $Year
            }
        }
    }

    $encoded = [uri]::EscapeDataString($Title)
    Write-Verbose "  Searching Trakt for: $Title"
    $results = Invoke-TraktRequest -Endpoint "/search/show?query=$encoded"

    if (-not $results) {
        return $null
    }

    $candidates = @($results)

    # Priority: exact title+year > year match > title match > first result
    if ($Year) {
        $exact = $candidates | Where-Object { $_.show.title -eq $Title -and $_.show.year -eq $Year }
        if ($exact) { return $exact[0] }

        $yearMatch = $candidates | Where-Object { $_.show.year -eq $Year }
        if ($yearMatch) { return $yearMatch[0] }
    }

    $titleMatch = $candidates | Where-Object { $_.show.title -eq $Title }
    if ($titleMatch) { return $titleMatch[0] }

    return $candidates[0]
}

function Get-TraktShowProgress {
    <#
    .SYNOPSIS
        Gets watched progress for a show.
    #>
    param([Parameter(Mandatory)][int]$TraktShowId)

    Write-Verbose "  Fetching watch progress..."
    return Invoke-TraktRequest -Endpoint "/shows/$TraktShowId/progress/watched?hidden=false&specials=false&count_specials=true"
}

function Get-TraktShowDetails {
    <#
    .SYNOPSIS
        Gets extended show details (status, network, etc.).
    #>
    param([Parameter(Mandatory)][int]$TraktShowId)

    Write-Verbose "  Fetching show details (status, network)..."
    return Invoke-TraktRequest -Endpoint "/shows/$TraktShowId`?extended=full"
}

function Get-TraktNextEpisode {
    <#
    .SYNOPSIS
        Gets the next episode to air for a show.
    #>
    param([Parameter(Mandatory)][int]$TraktShowId)

    Write-Verbose "  Fetching next episode..."
    try {
        return Invoke-TraktRequest -Endpoint "/shows/$TraktShowId/next_episode?extended=full"
    }
    catch {
        # No next episode or show ended
        return $null
    }
}

#endregion

#region ===== FOLDER & FILE PROCESSING =====

function ConvertFrom-FolderName {
    <#
    .SYNOPSIS
        Parses "Show Name (YYYY)" format into title and year components.
    #>
    param([Parameter(Mandatory)][string]$FolderName)

    if ($FolderName -match '^(?<title>.+?)\s*\((?<year>\d{4})\)\s*$') {
        return [PSCustomObject]@{
            Title = $Matches['title'].Trim()
            Year  = [int]$Matches['year']
        }
    }

    return [PSCustomObject]@{
        Title = $FolderName.Trim()
        Year  = $null
    }
}

function Get-VideoFiles {
    <#
    .SYNOPSIS
        Gets all video files in a folder, optionally excluding patterns.
    #>
    param(
        [Parameter(Mandatory)][System.IO.DirectoryInfo]$Folder,
        [string[]]$ExcludePatterns
    )

    $extensions = $script:State.Config.VideoExtensions
    if (-not $extensions) { $extensions = $script:Defaults.VideoExtensions }
    $extensions = $extensions | ForEach-Object { $_.ToLowerInvariant() }

    $files = Get-ChildItem -Path $Folder.FullName -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $extensions -contains $_.Extension.ToLowerInvariant() }

    if ($ExcludePatterns) {
        foreach ($pattern in $ExcludePatterns) {
            $files = $files | Where-Object { $_.Name -notmatch $pattern }
        }
    }

    return $files
}

function Get-ShowSizeMetrics {
    <#
    .SYNOPSIS
        Calculates total and watched byte counts for a show folder.
    #>
    param(
        [Parameter(Mandatory)][System.IO.DirectoryInfo]$ShowFolder,
        $Seasons,
        [string[]]$ExcludePatterns,
        $VideoFiles = $null
    )

    # Use provided video files or fetch them
    if (-not $VideoFiles) {
        $VideoFiles = Get-VideoFiles -Folder $ShowFolder -ExcludePatterns $ExcludePatterns
    }

    if (-not $VideoFiles) {
        return [PSCustomObject]@{
            TotalBytes   = 0L
            WatchedBytes = 0L
        }
    }

    $totalBytes = ($VideoFiles | Measure-Object -Property Length -Sum).Sum
    if (-not $totalBytes) { $totalBytes = 0L }

    if (-not $Seasons) {
        return [PSCustomObject]@{
            TotalBytes   = [long]$totalBytes
            WatchedBytes = 0L
        }
    }

    # Build watched episode set
    $watchedSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($s in $Seasons) {
        if ($null -eq $s.number) { continue }
        $sNum = [int]$s.number
        foreach ($e in $s.episodes) {
            if ($e.completed -and $null -ne $e.number) {
                $epId = "S{0:D2}E{1:D2}" -f $sNum, ([int]$e.number)
                $null = $watchedSet.Add($epId)
            }
        }
    }

    if ($watchedSet.Count -eq 0) {
        return [PSCustomObject]@{
            TotalBytes   = [long]$totalBytes
            WatchedBytes = 0L
        }
    }

    # Calculate watched bytes
    $watchedBytes = 0L
    $pattern = $script:EpisodePattern

    foreach ($file in $VideoFiles) {
        $fileMatches = $pattern.Matches($file.Name)
        if ($fileMatches.Count -eq 0) { continue }

        $fileEpisodes = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

        foreach ($m in $fileMatches) {
            $sNum = [int]$m.Groups['S'].Value
            $e1 = [int]$m.Groups['E1'].Value
            $e2 = if ($m.Groups['E2'].Success) { [int]$m.Groups['E2'].Value } else { $null }

            if ($e2 -and $e2 -ge $e1 -and ($e2 - $e1) -le 50) {
                foreach ($en in $e1..$e2) {
                    $epId = "S{0:D2}E{1:D2}" -f $sNum, $en
                    $null = $fileEpisodes.Add($epId)
                }
            }
            else {
                $epId = "S{0:D2}E{1:D2}" -f $sNum, $e1
                $null = $fileEpisodes.Add($epId)
            }
        }

        foreach ($ep in $fileEpisodes) {
            if ($watchedSet.Contains($ep)) {
                $watchedBytes += $file.Length
                break
            }
        }
    }

    return [PSCustomObject]@{
        TotalBytes   = [long]$totalBytes
        WatchedBytes = [long][Math]::Min($watchedBytes, $totalBytes)
    }
}

#endregion

#region ===== STATUS FORMATTING =====

function Get-WatchedStatus {
    <#
    .SYNOPSIS
        Determines friendly watch status from Trakt progress data.
    #>
    param($Progress)

    if (-not $Progress -or -not $Progress.seasons) {
        return $script:WatchStatus.Unwatched
    }

    $totalAired = 0
    $totalCompleted = 0

    foreach ($season in $Progress.seasons) {
        $totalAired += [int]$season.aired
        $totalCompleted += [int]$season.completed
    }

    if ($totalCompleted -eq 0) {
        return $script:WatchStatus.Unwatched
    }

    if ($totalAired -gt 0 -and $totalCompleted -ge $totalAired) {
        return $script:WatchStatus.FullyWatched
    }

    # Find the exact watch position
    $lastFullSeason = 0
    $partialSeason = $null
    $partialEpisode = $null

    foreach ($season in ($Progress.seasons | Sort-Object number)) {
        $sNum = [int]$season.number
        $completed = [int]$season.completed
        $aired = [int]$season.aired

        if ($completed -eq 0) {
            break
        }
        elseif ($aired -gt 0 -and $completed -ge $aired) {
            $lastFullSeason = $sNum
        }
        else {
            $partialSeason = $sNum
            $partialEpisode = $completed
            break
        }
    }

    if ($partialSeason) {
        $statusText = "Watched till S{0:D2}E{1:D2}" -f $partialSeason, $partialEpisode
        return $statusText
    }
    elseif ($lastFullSeason -gt 0) {
        $statusText = "Watched till Season {0}" -f $lastFullSeason
        return $statusText
    }

    $statusText = "Watched {0}/{1} episodes" -f $totalCompleted, $totalAired
    return $statusText
}

function Get-LastWatchedDate {
    <#
    .SYNOPSIS
        Extracts the most recent watched timestamp from progress data.
    #>
    param($Progress)

    if (-not $Progress -or -not $Progress.seasons) {
        return $null
    }

    $lastWatched = $null

    foreach ($season in $Progress.seasons) {
        foreach ($episode in $season.episodes) {
            if ($episode.completed -and $episode.last_watched_at) {
                $dt = ConvertTo-DateTime -DateString $episode.last_watched_at
                if ($dt -and (-not $lastWatched -or $dt -gt $lastWatched)) {
                    $lastWatched = $dt
                }
            }
        }
    }

    return $lastWatched
}

function Format-SeriesStatus {
    <#
    .SYNOPSIS
        Converts Trakt series status to friendly display value.
    #>
    param([string]$TraktStatus)

    if ([string]::IsNullOrWhiteSpace($TraktStatus)) {
        return 'Unknown'
    }

    $key = $TraktStatus.ToLowerInvariant()
    if ($script:SeriesStatusMap.ContainsKey($key)) {
        return $script:SeriesStatusMap[$key]
    }

    # Capitalize first letter as fallback
    return (Get-Culture).TextInfo.ToTitleCase($TraktStatus)
}

#endregion

#region ===== SHOW PROCESSING =====

function Get-ShowData {
    <#
    .SYNOPSIS
        Processes a single show folder, using cache when valid.
    #>
    param(
        [Parameter(Mandatory)][System.IO.DirectoryInfo]$Folder,
        [Parameter(Mandatory)][hashtable]$Cache,
        [int]$CacheTTLHours,
        [switch]$ForceRefresh,
        [switch]$RefreshPartial,
        [string[]]$ExcludePatterns
    )

    $cacheKey = Get-CacheKey -FolderName $Folder.Name
    $parsed = ConvertFrom-FolderName -FolderName $Folder.Name
    $displayTitle = if ($parsed.Year) { "{0} ({1})" -f $parsed.Title, $parsed.Year } else { $parsed.Title }

    Write-Verbose "Processing: $displayTitle"

    # Check cache
    $cached = $Cache[$cacheKey]
    
    # Quick size check - get current total bytes from disk
    $currentTotalBytes = 0L
    $videoFiles = Get-VideoFiles -Folder $Folder -ExcludePatterns $ExcludePatterns
    if ($videoFiles) {
        $sum = ($videoFiles | Measure-Object -Property Length -Sum).Sum
        if ($sum) { $currentTotalBytes = [long]$sum }
    }
    
    # Invalidate cache if disk size changed (new episodes or deletions)
    $sizeChanged = $false
    if ($cached -and $cached.total_bytes -and $cached.total_bytes -ne $currentTotalBytes) {
        $sizeChanged = $true
        Write-Verbose "  Disk content changed (cached: $($cached.total_bytes) bytes, current: $currentTotalBytes bytes)"
    }
    
    $useCache = -not $ForceRefresh -and -not $sizeChanged -and (Test-CacheValid -CacheEntry $cached -TTLHours $CacheTTLHours -RefreshPartial:$RefreshPartial)
    $useMetadataCache = -not $ForceRefresh -and (Test-MetadataCacheValid -CacheEntry $cached)

    $traktMatch = $null
    $progress = $null
    $status = $script:WatchStatus.Unknown
    $lastWatched = $null
    $traktUrl = $null

    # Metadata fields
    $seriesStatus = 'Unknown'
    $network = $null
    $nextEpisodeDate = $null

    if ($useCache) {
        Write-Verbose "  Using cached data"
        $status = $cached.status
        $lastWatched = if ($cached.last_watched) { ConvertTo-DateTime -DateString $cached.last_watched } else { $null }
        $traktUrl = $cached.trakt_url

        if ($cached.progress_json) {
            $progress = $cached.progress_json | ConvertFrom-Json
        }

        # Load cached metadata
        if ($useMetadataCache) {
            $seriesStatus = if ($cached.series_status) { $cached.series_status } else { 'Unknown' }
            $network = $cached.network
            $nextEpisodeDate = if ($cached.next_episode_date) { ConvertTo-DateTime -DateString $cached.next_episode_date } else { $null }
        }
    }

    # Fetch from Trakt if needed (either no cache or need metadata refresh)
    $needsFetch = -not $useCache
    $needsMetadataFetch = -not $useMetadataCache -and $cached.trakt_id

    if ($needsFetch -or $needsMetadataFetch) {
        try {
            $traktId = $null

            if ($needsFetch) {
                $traktMatch = Find-TraktShow -Title $parsed.Title -Year $parsed.Year -FolderName $Folder.Name

                if ($traktMatch) {
                    $show = $traktMatch.show
                    Write-Verbose "  Matched: $($show.title) ($($show.year))"

                    $traktId = $show.ids.trakt
                    $traktUrl = "https://trakt.tv/shows/$($show.ids.slug)"
                    $progress = Get-TraktShowProgress -TraktShowId $traktId
                    $status = Get-WatchedStatus -Progress $progress
                    $lastWatched = Get-LastWatchedDate -Progress $progress
                }
                else {
                    Write-Warning "  No Trakt match found for: $($parsed.Title)"
                    $status = $script:WatchStatus.NoMatch
                }
            }
            else {
                # We have cached progress but need to refresh metadata
                $traktId = $cached.trakt_id
                $traktUrl = $cached.trakt_url
            }

            # Fetch metadata if we have a Trakt ID
            if ($traktId) {
                $details = Get-TraktShowDetails -TraktShowId $traktId
                $seriesStatus = Format-SeriesStatus -TraktStatus $details.status
                $network = $details.network

                # Only fetch next episode for non-ended shows
                if ($details.status -and $details.status -ne 'ended' -and $details.status -ne 'canceled') {
                    $nextEp = Get-TraktNextEpisode -TraktShowId $traktId
                    if ($nextEp -and $nextEp.first_aired) {
                        $nextEpisodeDate = ConvertTo-DateTime -DateString $nextEp.first_aired
                    }
                }

                # Update cache with metadata (skip if full fetch will rebuild everything below)
                $nextEpStr = if ($nextEpisodeDate) { $nextEpisodeDate.ToString('o') } else { $null }
                $metadataCachedAt = (Get-Date).ToUniversalTime().ToString('o')

                if (-not $needsFetch) {
                    $existingEntry = $Cache[$cacheKey]
                    if ($existingEntry) {
                        # Metadata-only refresh: rebuild existing entry as hashtable with new metadata
                        $Cache[$cacheKey] = @{
                            trakt_id           = $existingEntry.trakt_id
                            trakt_slug         = $existingEntry.trakt_slug
                            trakt_url          = $existingEntry.trakt_url
                            status             = $existingEntry.status
                            last_watched       = $existingEntry.last_watched
                            progress_json      = $existingEntry.progress_json
                            cached_at          = $existingEntry.cached_at
                            total_bytes        = $currentTotalBytes
                            folder_path        = $Folder.FullName
                            series_status      = $seriesStatus
                            network            = $network
                            next_episode_date  = $nextEpStr
                            metadata_cached_at = $metadataCachedAt
                        }
                    }
                }
            }

            # Update full cache entry if we fetched everything
            if ($needsFetch -and $traktMatch) {
                $Cache[$cacheKey] = @{
                    trakt_id           = $traktMatch.show.ids.trakt
                    trakt_slug         = $traktMatch.show.ids.slug
                    trakt_url          = $traktUrl
                    status             = $status
                    last_watched       = if ($lastWatched) { $lastWatched.ToString('o') } else { $null }
                    progress_json      = ($progress | ConvertTo-Json -Depth 10 -Compress)
                    cached_at          = (Get-Date).ToUniversalTime().ToString('o')
                    total_bytes        = $currentTotalBytes
                    folder_path        = $Folder.FullName
                    series_status      = $seriesStatus
                    network            = $network
                    next_episode_date  = if ($nextEpisodeDate) { $nextEpisodeDate.ToString('o') } else { $null }
                    metadata_cached_at = (Get-Date).ToUniversalTime().ToString('o')
                }
            }
        }
        catch {
            Write-Error "  Failed to fetch Trakt data for $($Folder.Name): $_"
            if (-not $useCache) {
                $status = $script:WatchStatus.Error
            }
        }
    }

    # Always update folder_path and total_bytes in cache to track current state
    $existingEntry = $Cache[$cacheKey]
    if ($existingEntry -and ($existingEntry.folder_path -ne $Folder.FullName -or $existingEntry.total_bytes -ne $currentTotalBytes)) {
        # Entry exists but path or size changed - need to rebuild as hashtable
        $Cache[$cacheKey] = @{
            trakt_id           = $existingEntry.trakt_id
            trakt_slug         = $existingEntry.trakt_slug
            trakt_url          = $existingEntry.trakt_url
            status             = $existingEntry.status
            last_watched       = $existingEntry.last_watched
            progress_json      = $existingEntry.progress_json
            cached_at          = $existingEntry.cached_at
            total_bytes        = $currentTotalBytes
            folder_path        = $Folder.FullName
            series_status      = $existingEntry.series_status
            network            = $existingEntry.network
            next_episode_date  = $existingEntry.next_episode_date
            metadata_cached_at = $existingEntry.metadata_cached_at
        }
    }

    # Calculate sizes using pre-fetched video files
    $metrics = Get-ShowSizeMetrics -ShowFolder $Folder -Seasons $progress.seasons -ExcludePatterns $ExcludePatterns -VideoFiles $videoFiles

    $totalGB = [math]::Round($metrics.TotalBytes / 1GB, 2)
    $watchedGB = [math]::Round($metrics.WatchedBytes / 1GB, 2)
    $unwatchedGB = [math]::Round(($metrics.TotalBytes - $metrics.WatchedBytes) / 1GB, 2)
    $watchedPct = if ($metrics.TotalBytes -gt 0) {
        [math]::Round(100.0 * $metrics.WatchedBytes / $metrics.TotalBytes, 1)
    }
    else { 0 }

    return [PSCustomObject]@{
        Title           = $Folder.Name
        Status          = $status
        SeriesStatus    = $seriesStatus
        Network         = $network
        NextEpisode     = $nextEpisodeDate
        LastWatched     = $lastWatched
        WatchedSizeGB   = $watchedGB
        UnwatchedSizeGB = $unwatchedGB
        TotalSizeGB     = $totalGB
        WatchedPct      = $watchedPct
        TraktUrl        = $traktUrl
        FolderPath      = $Folder.FullName
    }
}

#endregion

#region ===== CLEANUP =====

function Remove-ToRecycleBin {
    <#
    .SYNOPSIS
        Moves a folder to the Recycle Bin.
    #>
    param([Parameter(Mandatory)][string]$Path)

    Add-Type -AssemblyName Microsoft.VisualBasic
    [Microsoft.VisualBasic.FileIO.FileSystem]::DeleteDirectory(
        $Path,
        [Microsoft.VisualBasic.FileIO.UIOption]::OnlyErrorDialogs,
        [Microsoft.VisualBasic.FileIO.RecycleOption]::SendToRecycleBin
    )
}

function Get-FullyWatchedSeasons {
    <#
    .SYNOPSIS
        Returns list of fully watched season numbers from Trakt progress data.
    #>
    param($Progress)

    $watchedSeasons = [System.Collections.Generic.List[int]]::new()

    if (-not $Progress -or -not $Progress.seasons) {
        return $watchedSeasons
    }

    foreach ($season in $Progress.seasons) {
        $sNum = [int]$season.number
        $aired = [int]$season.aired
        $completed = [int]$season.completed

        # Season is fully watched if all aired episodes are completed
        if ($aired -gt 0 -and $completed -ge $aired) {
            $watchedSeasons.Add($sNum)
        }
    }

    return $watchedSeasons
}

function Find-SeasonFolder {
    <#
    .SYNOPSIS
        Finds the filesystem folder for a given season number.
        Handles various naming conventions: "Season 1", "Season 01", "S01", "Specials"
    #>
    param(
        [Parameter(Mandatory)][string]$ShowPath,
        [Parameter(Mandatory)][int]$SeasonNumber
    )

    $subfolders = Get-ChildItem -LiteralPath $ShowPath -Directory -ErrorAction SilentlyContinue

    if (-not $subfolders) {
        return $null
    }

    # Build patterns for this season number
    $patterns = @(
        "^Season\s*0*$SeasonNumber$"           # "Season 1", "Season 01", "Season1"
        "^S0*$SeasonNumber$"                    # "S1", "S01"
    )

    # Special case for season 0 (Specials)
    if ($SeasonNumber -eq 0) {
        $patterns += "^Specials?$"              # "Special", "Specials"
    }

    foreach ($folder in $subfolders) {
        foreach ($pattern in $patterns) {
            if ($folder.Name -match $pattern) {
                return $folder
            }
        }
    }

    return $null
}

function Get-SeasonFolderSize {
    <#
    .SYNOPSIS
        Calculates total size of a season folder in GB.
    #>
    param([Parameter(Mandatory)][System.IO.DirectoryInfo]$Folder)

    $totalBytes = 0L
    $files = Get-ChildItem -LiteralPath $Folder.FullName -Recurse -File -ErrorAction SilentlyContinue
    
    if ($files) {
        $sum = ($files | Measure-Object -Property Length -Sum).Sum
        if ($sum) {
            $totalBytes = [long]$sum
        }
    }

    return [math]::Round($totalBytes / 1GB, 2)
}

function Get-WatchedSeasonCandidates {
    <#
    .SYNOPSIS
        Gets all fully watched season folders across all shows.
        Returns objects with show info and season folder details.
    #>
    param(
        [Parameter(Mandatory)][array]$Shows,
        [Parameter(Mandatory)][hashtable]$Cache
    )

    $candidates = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($show in $Shows) {
        # Skip shows without Trakt match
        if ($show.Status -eq $script:WatchStatus.NoMatch -or $show.Status -eq $script:WatchStatus.Error) {
            continue
        }

        # Skip fully watched shows (use CleanupFullyWatched for those)
        if ($show.Status -eq $script:WatchStatus.FullyWatched) {
            continue
        }

        # Get cache entry for progress data
        $cacheKey = Get-CacheKey -FolderName $show.Title
        $cached = $Cache[$cacheKey]

        if (-not $cached -or -not $cached.progress_json) {
            continue
        }

        $progress = $cached.progress_json | ConvertFrom-Json
        $watchedSeasons = Get-FullyWatchedSeasons -Progress $progress

        foreach ($seasonNum in $watchedSeasons) {
            $seasonFolder = Find-SeasonFolder -ShowPath $show.FolderPath -SeasonNumber $seasonNum

            if ($seasonFolder) {
                $sizeGB = Get-SeasonFolderSize -Folder $seasonFolder
                $dispName = "{0} - {1}" -f $show.Title, $seasonFolder.Name

                $candidates.Add([PSCustomObject]@{
                    ShowTitle      = $show.Title
                    ShowPath       = $show.FolderPath
                    SeasonNumber   = $seasonNum
                    SeasonFolder   = $seasonFolder.Name
                    SeasonPath     = $seasonFolder.FullName
                    SizeGB         = $sizeGB
                    DisplayName    = $dispName
                })
            }
        }
    }

    return $candidates
}

function Invoke-SeasonCleanup {
    <#
    .SYNOPSIS
        Performs cleanup actions on selected season folders.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][array]$Seasons,
        [string]$MoveToPath,
        [switch]$SkipRecycleBin
    )

    $cleanedCount = 0
    $cleanedSize = 0.0

    foreach ($season in $Seasons) {
        $seasonPath = $season.SeasonPath

        if (-not (Test-Path -LiteralPath $seasonPath)) {
            Write-Warning "Season folder not found: $seasonPath"
            continue
        }

        $actionDescription = if ($MoveToPath) { "Move" } else { "Delete" }
        $targetDescription = if ($MoveToPath) { " to $MoveToPath" } else { "" }

        if ($PSCmdlet.ShouldProcess("$($season.DisplayName) ($($season.SizeGB) GB)", "$actionDescription$targetDescription")) {
            try {
                if ($MoveToPath) {
                    # Move to archive, preserving show folder structure
                    $archiveShowPath = Join-Path -Path $MoveToPath -ChildPath (Split-Path $season.ShowPath -Leaf)
                    $destination = Join-Path -Path $archiveShowPath -ChildPath $season.SeasonFolder

                    if (-not (Test-Path -LiteralPath $archiveShowPath)) {
                        $null = New-Item -Path $archiveShowPath -ItemType Directory -Force
                    }

                    if (Test-Path -LiteralPath $destination) {
                        Write-Warning "  Skipped move (already exists at destination): $destination"
                        continue
                    }
                    Move-Item -LiteralPath $seasonPath -Destination $destination
                    Write-Host "  Moved: $($season.DisplayName)" -ForegroundColor Green
                }
                elseif ($SkipRecycleBin) {
                    # Permanent delete
                    Remove-Item -LiteralPath $seasonPath -Recurse -Force
                    Write-Host "  Deleted: $($season.DisplayName)" -ForegroundColor Yellow
                }
                else {
                    # Recycle Bin
                    Remove-ToRecycleBin -Path $seasonPath
                    Write-Host "  Recycled: $($season.DisplayName)" -ForegroundColor Green
                }

                $cleanedCount++
                $cleanedSize += $season.SizeGB
            }
            catch {
                Write-Error "  Failed to process $($season.DisplayName): $_"
            }
        }
    }

    return [PSCustomObject]@{
        Count  = $cleanedCount
        SizeGB = $cleanedSize
    }
}

function Invoke-ShowCleanup {
    <#
    .SYNOPSIS
        Performs cleanup actions on selected shows.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][array]$Shows,
        [string]$MoveToPath,
        [switch]$SkipRecycleBin
    )

    $cleanedCount = 0
    $cleanedSize = 0.0

    foreach ($show in $Shows) {
        $folderPath = $show.FolderPath

        if (-not (Test-Path -LiteralPath $folderPath)) {
            Write-Warning "Folder not found: $folderPath"
            continue
        }

        $actionDescription = if ($MoveToPath) { "Move" } else { "Delete" }
        $targetDescription = if ($MoveToPath) { " to $MoveToPath" } else { "" }

        if ($PSCmdlet.ShouldProcess("$($show.Title) ($($show.TotalSizeGB) GB)", "$actionDescription$targetDescription")) {
            try {
                if ($MoveToPath) {
                    # Move to archive
                    $destination = Join-Path -Path $MoveToPath -ChildPath (Split-Path $folderPath -Leaf)
                    if (-not (Test-Path -LiteralPath $MoveToPath)) {
                        $null = New-Item -Path $MoveToPath -ItemType Directory -Force
                    }
                    if (Test-Path -LiteralPath $destination) {
                        Write-Warning "  Skipped move (already exists at destination): $destination"
                        continue
                    }
                    Move-Item -LiteralPath $folderPath -Destination $destination
                    Write-Host "  Moved: $($show.Title)" -ForegroundColor Green
                }
                elseif ($SkipRecycleBin) {
                    # Permanent delete
                    Remove-Item -LiteralPath $folderPath -Recurse -Force
                    Write-Host "  Deleted: $($show.Title)" -ForegroundColor Yellow
                }
                else {
                    # Recycle Bin
                    Remove-ToRecycleBin -Path $folderPath
                    Write-Host "  Recycled: $($show.Title)" -ForegroundColor Green
                }

                $cleanedCount++
                $cleanedSize += $show.TotalSizeGB
            }
            catch {
                Write-Error "  Failed to process $($show.Title): $_"
            }
        }
    }

    return [PSCustomObject]@{
        Count  = $cleanedCount
        SizeGB = $cleanedSize
    }
}

function Get-CleanupCandidates {
    <#
    .SYNOPSIS
        Filters shows based on cleanup criteria.
    #>
    param(
        [Parameter(Mandatory)][array]$Shows,
        [switch]$FullyWatched
    )

    $candidates = $Shows

    if ($FullyWatched) {
        $candidates = $candidates | Where-Object { $_.Status -eq $script:WatchStatus.FullyWatched }
    }

    return $candidates
}

#endregion

#region ===== OUTPUT =====

function Write-Summary {
    <#
    .SYNOPSIS
        Displays summary statistics.
    #>
    param([Parameter(Mandatory)][array]$ShowsData)

    $totalShows = $ShowsData.Count
    $fullyWatched = ($ShowsData | Where-Object { $_.Status -eq $script:WatchStatus.FullyWatched }).Count
    $partial = ($ShowsData | Where-Object { $_.Status -like "Watched till*" -or $_.Status -like "Watched */*" }).Count
    $unwatched = ($ShowsData | Where-Object { $_.Status -eq $script:WatchStatus.Unwatched }).Count

    $endedShows = ($ShowsData | Where-Object { $_.SeriesStatus -eq 'Ended' }).Count
    $returningShows = ($ShowsData | Where-Object { $_.SeriesStatus -eq 'Returning' }).Count

    $totalSize = ($ShowsData | Measure-Object -Property TotalSizeGB -Sum).Sum
    $watchedSize = ($ShowsData | Measure-Object -Property WatchedSizeGB -Sum).Sum
    $unwatchedSize = ($ShowsData | Measure-Object -Property UnwatchedSizeGB -Sum).Sum

    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "SUMMARY" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ("Shows:  {0} total | {1} fully watched | {2} partial | {3} unwatched" -f $totalShows, $fullyWatched, $partial, $unwatched)
    Write-Host ("Series: {0} ended | {1} returning" -f $endedShows, $returningShows)
    Write-Host ("Size:   {0:N2} TB total | {1:N2} TB watched | {2:N2} TB unwatched" -f ($totalSize / 1024), ($watchedSize / 1024), ($unwatchedSize / 1024))
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""
}

function Export-Results {
    <#
    .SYNOPSIS
        Exports results in the specified format.
    #>
    param(
        [Parameter(Mandatory)][array]$ShowsData,
        [Parameter(Mandatory)][string]$Format,
        [string]$Path,
        [switch]$Interactive
    )

    # Sort by last watched (oldest first), then by size (largest first)
    $sorted = $ShowsData | Sort-Object @{Expression = 'LastWatched'; Ascending = $true }, @{Expression = 'TotalSizeGB'; Descending = $true }

    # Select columns for display (exclude FolderPath from normal view)
    $displayColumns = @('Title', 'Status', 'SeriesStatus', 'Network', 'NextEpisode', 'LastWatched', 'WatchedSizeGB', 'UnwatchedSizeGB', 'TotalSizeGB', 'WatchedPct', 'TraktUrl')

    switch ($Format) {
        'GridView' {
            if ($sorted.Count -gt 0) {
                if ($Interactive) {
                    return $sorted | Select-Object $displayColumns | Out-GridView -Title 'Select shows for cleanup (Ctrl+Click for multiple)' -PassThru
                }
                else {
                    $sorted | Select-Object $displayColumns | Out-GridView -Title 'TV Shows - Trakt Watch Status & Disk Usage'
                    return $null
                }
            }
            else {
                Write-Warning "No shows to display."
                return $null
            }
        }
        'CSV' {
            if (-not $Path) {
                throw "OutputPath is required for CSV format."
            }
            $sorted | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
            Write-Host "Results exported to: $Path" -ForegroundColor Green
            return $null
        }
        'JSON' {
            if (-not $Path) {
                throw "OutputPath is required for JSON format."
            }
            $sorted | ConvertTo-Json -Depth 5 | Set-Content -Path $Path -Encoding UTF8
            Write-Host "Results exported to: $Path" -ForegroundColor Green
            return $null
        }
        'Console' {
            $sorted | Format-Table -AutoSize -Property Title, Status, SeriesStatus, LastWatched, WatchedSizeGB, UnwatchedSizeGB, TotalSizeGB
            return $null
        }
    }
}

#endregion

#region ===== MAIN =====

# Handle -CreateConfig first
if ($CreateConfig) {
    New-DefaultConfig
    return
}

try {
    # Load configuration (config file + parameter overrides)
    $script:State.Config = Import-Configuration -ScriptParameters $PSBoundParameters

    # Validate we have root folders
    if (-not $script:State.Config.RootFolders -or $script:State.Config.RootFolders.Count -eq 0) {
        throw "No root folders specified. Use -RootFolder parameter or configure rootFolders in config.json"
    }

    # Initialize authentication
    Initialize-TraktAuth

    # Load cache
    $script:State.Cache = Import-TraktCache

    # Collect all show folders from all root paths
    $allShowFolders = [System.Collections.Generic.List[System.IO.DirectoryInfo]]::new()

    foreach ($root in $script:State.Config.RootFolders) {
        if (-not (Test-Path -LiteralPath $root)) {
            Write-Warning "Root folder not found: $root"
            continue
        }

        $folders = Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue
        if ($folders) {
            foreach ($f in $folders) {
                $allShowFolders.Add($f)
            }
        }
    }

    if ($allShowFolders.Count -eq 0) {
        Write-Warning "No show folders found in the specified root folder(s)."
        return
    }

    Write-Host "Processing $($allShowFolders.Count) shows..." -ForegroundColor Cyan

    # Process shows
    $showsData = [System.Collections.Generic.List[PSCustomObject]]::new()
    $total = $allShowFolders.Count
    $idx = 0

    foreach ($folder in $allShowFolders) {
        $idx++
        Write-Progress -Activity "Processing TV Shows" -Status "$idx of $total" -PercentComplete (100 * $idx / $total)

        $showResult = Get-ShowData -Folder $folder -Cache $script:State.Cache `
            -CacheTTLHours $script:State.Config.CacheTTLHours -ForceRefresh:$ForceRefresh -RefreshPartial:$RefreshInProgress `
            -ExcludePatterns $script:State.Config.ExcludePatterns

        $showsData.Add($showResult)
    }

    Write-Progress -Activity "Processing TV Shows" -Completed

    # Prune cache entries for shows that no longer exist on disk, then save
    $null = Sync-TraktCache -Cache $script:State.Cache
    Export-TraktCache -Cache $script:State.Cache

    # Display summary
    Write-Summary -ShowsData $showsData

    # Handle cleanup operations
    $showCleanupRequested = $CleanupFullyWatched -or $Interactive
    $seasonCleanupRequested = $CleanupWatchedSeasons

    # Show-level cleanup (fully watched shows) - runs first
    if ($CleanupFullyWatched) {
        $candidates = Get-CleanupCandidates -Shows $showsData -FullyWatched

        if ($candidates.Count -gt 0) {
            $totalSize = ($candidates | Measure-Object -Property TotalSizeGB -Sum).Sum
            Write-Host ""
            Write-Host "Fully watched show candidates: $($candidates.Count) shows ($([math]::Round($totalSize, 2)) GB)" -ForegroundColor Yellow

            $result = Invoke-ShowCleanup -Shows $candidates -MoveToPath $MoveToPath -SkipRecycleBin:$SkipRecycleBin

            if ($result.Count -gt 0) {
                Write-Host ""
                Write-Host "Show cleanup complete: $($result.Count) shows ($([math]::Round($result.SizeGB, 2)) GB)" -ForegroundColor Green
            }
        }
        else {
            Write-Host ""
            Write-Host "No fully watched shows found." -ForegroundColor Yellow
        }
    }

    # Season-level cleanup (watched seasons from partial shows)
    if ($seasonCleanupRequested) {
        Write-Host ""
        Write-Host "Analyzing watched seasons..." -ForegroundColor Cyan
        $seasonCandidates = Get-WatchedSeasonCandidates -Shows $showsData -Cache $script:State.Cache

        if ($seasonCandidates.Count -gt 0) {
            $totalSize = ($seasonCandidates | Measure-Object -Property SizeGB -Sum).Sum
            $showCount = ($seasonCandidates | Select-Object -Property ShowTitle -Unique).Count

            Write-Host ""
            Write-Host "Season cleanup candidates: $($seasonCandidates.Count) seasons across $showCount shows ($([math]::Round($totalSize, 2)) GB)" -ForegroundColor Yellow
            Write-Host ""

            # List what will be cleaned
            $seasonCandidates | Group-Object ShowTitle | ForEach-Object {
                $showSeasons = $_.Group | Sort-Object SeasonNumber
                $seasonsText = ($showSeasons | ForEach-Object { $_.SeasonFolder }) -join ", "
                $showSize = ($showSeasons | Measure-Object -Property SizeGB -Sum).Sum
                Write-Host "  $($_.Name): $seasonsText ($([math]::Round($showSize, 2)) GB)" -ForegroundColor Gray
            }

            Write-Host ""
            $result = Invoke-SeasonCleanup -Seasons $seasonCandidates -MoveToPath $MoveToPath -SkipRecycleBin:$SkipRecycleBin

            if ($result.Count -gt 0) {
                Write-Host ""
                Write-Host "Season cleanup complete: $($result.Count) seasons ($([math]::Round($result.SizeGB, 2)) GB)" -ForegroundColor Green
            }
        }
        else {
            Write-Host ""
            Write-Host "No fully watched seasons found (that aren't part of fully watched shows)." -ForegroundColor Yellow
            if (-not $CleanupFullyWatched) {
                Write-Host "Tip: Use -CleanupFullyWatched for shows where all seasons are complete." -ForegroundColor Gray
            }
        }
    }

    # Interactive mode (standalone - when neither cleanup flag is set)
    if ($Interactive -and -not $CleanupFullyWatched -and -not $CleanupWatchedSeasons) {
        Write-Host "Opening interactive selection..." -ForegroundColor Cyan
        $selected = Export-Results -ShowsData $showsData -Format 'GridView' -Interactive

        if ($selected) {
            $candidates = $showsData | Where-Object { $selected.Title -contains $_.Title }

            if ($candidates.Count -gt 0) {
                $totalSize = ($candidates | Measure-Object -Property TotalSizeGB -Sum).Sum
                Write-Host ""
                Write-Host "Selected shows: $($candidates.Count) shows ($([math]::Round($totalSize, 2)) GB)" -ForegroundColor Yellow

                $result = Invoke-ShowCleanup -Shows $candidates -MoveToPath $MoveToPath -SkipRecycleBin:$SkipRecycleBin

                if ($result.Count -gt 0) {
                    Write-Host ""
                    Write-Host "Cleanup complete: $($result.Count) shows ($([math]::Round($result.SizeGB, 2)) GB)" -ForegroundColor Green
                }
            }
        }
    }

    # Normal output (no cleanup requested)
    if (-not $showCleanupRequested -and -not $seasonCleanupRequested) {
        Export-Results -ShowsData $showsData -Format $script:State.Config.OutputFormat -Path $OutputPath
    }
}
catch {
    Write-Error "Script failed: $_"
    exit 1
}

#endregion