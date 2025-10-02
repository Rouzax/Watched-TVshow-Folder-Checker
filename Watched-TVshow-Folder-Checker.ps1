<# 
.SYNOPSIS
  Lists TV shows found under a root folder with Trakt watch status
  and disk usage so you can clean up. Includes watched, partially watched,
  and **unwatched** shows.

.DESCRIPTION
  - Uses Trakt OAuth (device-style “out of band” redirect URI).
  - Caches access/refresh tokens to tokens.json next to the script.
  - Automatically refreshes expired tokens and retries once on 401.
  - Searches Trakt for each folder's show (prefers exact Title + Year match when available).
  - Pulls watched progress per show; infers a friendly status (Fully Watched / Partially Watched / Unwatched).
  - Totals the on-disk size:
        * WatchedSizeGB  — sum of files matching watched SxxExx episodes
        * TotalSizeGB    — all video files in the show folder
        * UnwatchedSizeGB = Total - Watched
  - Displays results in Out-GridView.

.PARAMETER clientId
  Trakt API Client ID. Optional if tokens.json already exists.
  Get yours at: https://trakt.tv/oauth/applications

.PARAMETER clientSecret
  Trakt API Client Secret. Optional if tokens.json already exists.

.PARAMETER rootFolder
  The root folder containing TV show folders, e.g. E:\Data\TVSeries\EN

.NOTES
  - Save as UTF-8 (no BOM) if you prefer (recommended).
  - Be mindful of Trakt rate limits; a small delay is included between calls.
  - Requires Windows PowerShell with Out-GridView (part of PowerShell ISE/RSAT) or PowerShell 7 + Microsoft.PowerShell.GraphicalTools module.

#>

param (
    [Parameter(Mandatory = $false)]
    [string]$clientId,         # Trakt API Client ID

    [Parameter(Mandatory = $false)]
    [string]$clientSecret,     # Trakt API Client Secret

    [Parameter(Mandatory = $true)]
    [string]$rootFolder        # Root folder with TV show folders
)

#region ----- Config & Globals -----

# Where tokens are stored (next to this script)
$script:tokenFilePath = Join-Path -Path $PSScriptRoot -ChildPath 'tokens.json'

# Global bearer (updated on refresh)
$script:accessToken = $null

# Trakt constants
$script:TraktApiVersion = '2'
$script:RedirectUri = 'urn:ietf:wg:oauth:2.0:oob'
$script:AuthUrlFmt = 'https://trakt.tv/oauth/authorize?response_type=code&client_id={0}&redirect_uri={1}'
$script:TokenUrl = 'https://api.trakt.tv/oauth/token'
$script:SearchShowUrl = 'https://api.trakt.tv/search/show?query={0}'
$script:ShowProgressFmt = 'https://api.trakt.tv/shows/{0}/progress/watched?hidden=false&specials=false&count_specials=true'

# API pacing (be gentle)
$script:PerRequestDelayMs = 200

# Video file extensions to count in sizes
$script:VideoExtensions = @('.mkv', '.mp4', '.avi', '.mov', '.m4v', '.wmv')

#endregion

#region ----- Helpers -----

function Save-Tokens {
    param(
        [Parameter(Mandatory)]
        [string]$AccessToken,
        [Parameter(Mandatory)]
        [string]$RefreshToken,
        [Parameter(Mandatory)]
        [string]$ClientId,
        [Parameter(Mandatory)]
        [string]$ClientSecret
    )
    $tokens = [ordered]@{
        access_token  = $AccessToken
        refresh_token = $RefreshToken
        client_id     = $ClientId
        client_secret = $ClientSecret
        saved_at_utc  = (Get-Date).ToUniversalTime().ToString('o')
    }
    $json = $tokens | ConvertTo-Json -Depth 5
    $json | Set-Content -LiteralPath $script:tokenFilePath -Encoding UTF8
}

function Load-Tokens {
    if (-not (Test-Path -LiteralPath $script:tokenFilePath)) {
        return $null 
    }
    try {
        return Get-Content -LiteralPath $script:tokenFilePath -Raw | ConvertFrom-Json
    } catch {
        Write-Warning "Could not read/parse tokens.json. You may need to authenticate again. Details: $_"
        return $null
    }
}

function Invoke-Trakt {
    <#
      .SYNOPSIS
        Wrapper for Invoke-RestMethod with Trakt headers, 401 retry, and pacing.
      .PARAMETER Uri
        Target URI.
      .PARAMETER Method
        GET/POST (default GET).
      .PARAMETER Body
        Optional hashtable/body for POST.
      .PARAMETER UseAuth
        If true (default), adds Authorization header with current access token.
    #>
    param(
        [Parameter(Mandatory)] [string]$Uri,
        [ValidateSet('GET', 'POST')] [string]$Method = 'GET',
        [object]$Body = $null,
        [bool]$UseAuth = $true
    )

    Start-Sleep -Milliseconds $script:PerRequestDelayMs

    $headers = @{
        'Content-Type'      = 'application/json'
        'trakt-api-version' = $script:TraktApiVersion
        'trakt-api-key'     = $clientId
    }
    if ($UseAuth -and $script:accessToken) {
        $headers['Authorization'] = "Bearer $($script:accessToken)"
    }

    try {
        if ($Method -eq 'POST') {
            return Invoke-RestMethod -Uri $Uri -Method Post -Headers $headers `
                -Body ($Body | ConvertTo-Json) -ErrorAction Stop
        } else {
            return Invoke-RestMethod -Uri $Uri -Method Get -Headers $headers -ErrorAction Stop
        }
    } catch {
        $statusCode = $_.Exception.Response.StatusCode.Value__
        if ($UseAuth -and $statusCode -eq 401) {
            Write-Host "Access token expired or invalid. Refreshing token..."
            $null = Refresh-TraktAccessToken
            Start-Sleep -Milliseconds 150
            if ($Method -eq 'POST') {
                return Invoke-RestMethod -Uri $Uri -Method Post -Headers @{
                    'Content-Type'      = 'application/json'
                    'trakt-api-version' = $script:TraktApiVersion
                    'trakt-api-key'     = $clientId
                    'Authorization'     = "Bearer $($script:accessToken)"
                } -Body ($Body | ConvertTo-Json) -ErrorAction Stop
            } else {
                return Invoke-RestMethod -Uri $Uri -Method Get -Headers @{
                    'Content-Type'      = 'application/json'
                    'trakt-api-version' = $script:TraktApiVersion
                    'trakt-api-key'     = $clientId
                    'Authorization'     = "Bearer $($script:accessToken)"
                } -ErrorAction Stop
            }
        }
        throw
    }
}

#endregion

#region ----- OAuth -----

function Get-TraktAccessToken {
    <#
      .SYNOPSIS
        Ensures we have an access token (and client creds) available.
      .OUTPUTS
        [void] — sets $script:accessToken and saves tokens.json as needed.
    #>

    $stored = Load-Tokens

    if ($stored -and $stored.access_token -and $stored.refresh_token -and $stored.client_id -and $stored.client_secret) {
        $script:accessToken = $stored.access_token
        if (-not $clientId) {
            $script:clientId = $stored.client_id 
        } else {
            $script:clientId = $clientId 
        }
        if (-not $clientSecret) {
            $script:clientSecret = $stored.client_secret 
        } else {
            $script:clientSecret = $clientSecret 
        }
        return
    }

    if (-not $clientId -or -not $clientSecret) {
        $clientId = Read-Host "Enter your Trakt API Client ID"
        $clientSecret = Read-Host "Enter your Trakt API Client Secret"
    }
    $script:clientId = $clientId
    $script:clientSecret = $clientSecret

    $authUrl = [string]::Format($script:AuthUrlFmt, $clientId, [uri]::EscapeDataString($script:RedirectUri))
    Write-Host "Please visit this URL to authorize the app, then paste the code below:`n$authUrl`n"

    $authCode = Read-Host "Enter the authorization code provided by Trakt"

    $tokenBody = @{
        code          = $authCode
        client_id     = $clientId
        client_secret = $clientSecret
        redirect_uri  = $script:RedirectUri
        grant_type    = 'authorization_code'
    }

    try {
        $resp = Invoke-Trakt -Uri $script:TokenUrl -Method POST -Body $tokenBody -UseAuth:$false
        $script:accessToken = $resp.access_token
        Save-Tokens -AccessToken $resp.access_token -RefreshToken $resp.refresh_token `
            -ClientId $clientId -ClientSecret $clientSecret
    } catch {
        Write-Error "Failed to retrieve tokens. $_"
        exit 1
    }
}

function Refresh-TraktAccessToken {
    <#
      .SYNOPSIS
        Refreshes the access token using tokens.json and updates globals.
      .OUTPUTS
        [string] — the new access token.
    #>
    $stored = Load-Tokens
    if (-not $stored) {
        throw "No tokens.json available to refresh. Run the initial authorization first."
    }

    $refreshBody = @{
        refresh_token = $stored.refresh_token
        client_id     = $stored.client_id
        client_secret = $stored.client_secret
        redirect_uri  = $script:RedirectUri
        grant_type    = 'refresh_token'
    }

    try {
        $resp = Invoke-Trakt -Uri $script:TokenUrl -Method POST -Body $refreshBody -UseAuth:$false
        $script:accessToken = $resp.access_token
        Save-Tokens -AccessToken $resp.access_token -RefreshToken $resp.refresh_token `
            -ClientId $stored.client_id -ClientSecret $stored.client_secret
        return $script:accessToken
    } catch {
        Write-Error "Failed to refresh tokens. $_"
        exit 1
    }
}

#endregion

#region ----- Trakt queries -----

function Find-TraktShow {
    <#
      .SYNOPSIS
        Searches Trakt for a show by title (and optional year) and returns the best match.
      .PARAMETER Title
        The show title (folder name, normalized).
      .PARAMETER Year
        Optional 4-digit year parsed from folder name.
      .OUTPUTS
        The chosen search result (with .show and .show.ids.trakt), or $null if none.
    #>
    param(
        [Parameter(Mandatory)] [string]$Title,
        [int]$Year
    )

    $encoded = [System.Web.HttpUtility]::UrlEncode($Title)
    $uri = [string]::Format($script:SearchShowUrl, $encoded)

    $results = $null
    try {
        $results = Invoke-Trakt -Uri $uri -Method GET
    } catch {
        throw "Failed to search Trakt for '$Title'. $_"
    }

    if (-not $results) {
        return $null 
    }

    $candidates = @($results)

    if ($Year) {
        $exact = $candidates | Where-Object { $_.show.title -eq $Title -and $_.show.year -eq $Year }
        if ($exact) {
            return $exact[0] 
        }
        $yearOnly = $candidates | Where-Object { $_.show.year -eq $Year }
        if ($yearOnly) {
            return $yearOnly[0] 
        }
    }

    $titleOnly = $candidates | Where-Object { $_.show.title -eq $Title }
    if ($titleOnly) {
        return $titleOnly[0] 
    }

    return $candidates[0]
}

function Get-TraktShowProgress {
    <#
      .SYNOPSIS
        Returns watched progress object for a trakt show id.
      .PARAMETER TraktShowId
        The numeric trakt show id.
    #>
    param(
        [Parameter(Mandatory)] [int]$TraktShowId
    )
    $uri = [string]::Format($script:ShowProgressFmt, $TraktShowId)
    try {
        return Invoke-Trakt -Uri $uri -Method GET
    } catch {
        throw "Failed to retrieve show progress for trakt id $TraktShowId. $_"
    }
}

#endregion

#region ----- Folder & Size logic -----

function Parse-FolderAsTitleYear {
    <#
      .SYNOPSIS
        Parses a typical "Show Name (YYYY)" folder into Title + Year.
      .OUTPUTS
        [pscustomobject] with Title, Year (nullable)
    #>
    param(
        [Parameter(Mandatory)] [string]$FolderName
    )

    if ($FolderName -match '^(?<title>.+?)\s\((?<year>\d{4})\)\s*$') {
        return [pscustomobject]@{
            Title = $matches['title'].Trim()
            Year  = [int]$matches['year']
        }
    } else {
        return [pscustomobject]@{
            Title = $FolderName.Trim()
            Year  = $null
        }
    }
}

function Get-WatchedBytesForShow {
    <#
      .SYNOPSIS
        Sum sizes of unique video files whose episode(s) are marked watched.
        Handles multi-episode files like: S11E17E18, S11E17-E18, S11E17 E18, etc.
      .PARAMETER ShowFolder
        DirectoryInfo of the show folder.
      .PARAMETER Seasons
        The .seasons array from Trakt progress response (with .episodes etc.).
      .OUTPUTS
        [long] total bytes
    #>
    param(
        [Parameter(Mandatory)] [System.IO.DirectoryInfo]$ShowFolder,
        [Parameter(Mandatory)] $Seasons
    )

    # Build a set of watched episode IDs like "S11E17"
    $watchedSet = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($s in $Seasons) {
        $sNum = [int]$s.number
        foreach ($e in $s.episodes) {
            if ($e.completed) {
                $watchedSet.Add(("S{0:D2}E{1:D2}" -f $sNum, [int]$e.number)) | Out-Null
            }
        }
    }

    if ($watchedSet.Count -eq 0) {
        return 0L 
    }

    # Gather all video files once
    $videoFiles = Get-ChildItem -Path $ShowFolder.FullName -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $script:VideoExtensions -contains $_.Extension.ToLower() }

    if (-not $videoFiles) {
        return 0L 
    }

    # Regex handles:
    #   S11E17
    #   S11E17E18
    #   S11E17-E18
    #   S11E17 E18
    #   S11E17 - 18
    $rx = [regex]'S(?<S>\d{1,2})E(?<E1>\d{2})(?:[-\.\s]*E?(?<E2>\d{2}))?'

    $total = 0L
    foreach ($file in $videoFiles) {
        $name = $file.Name
        $matches = $rx.Matches($name)
        if ($matches.Count -eq 0) {
            continue 
        }

        # Build the set of episode IDs this file represents
        $fileEps = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($m in $matches) {
            $sNum = [int]$m.Groups['S'].Value
            $e1 = [int]$m.Groups['E1'].Value
            $e2 = if ($m.Groups['E2'].Success) {
                [int]$m.Groups['E2'].Value 
            } else {
                $null 
            }

            if ($e2 -and $e2 -ge $e1) {
                foreach ($en in $e1..$e2) {
                    $fileEps.Add(("S{0:D2}E{1:D2}" -f $sNum, $en)) | Out-Null
                }
            } else {
                $fileEps.Add(("S{0:D2}E{1:D2}" -f $sNum, $e1)) | Out-Null
            }
        }

        # Count the file once if ANY of its episodes are watched
        $isWatchedFile = $false
        foreach ($id in $fileEps) {
            if ($watchedSet.Contains($id)) {
                $isWatchedFile = $true; break 
            }
        }
        if ($isWatchedFile) {
            $total += $file.Length
        }
    }

    return $total
}



function Get-TotalBytesForShow {
    <#
      .SYNOPSIS
        Totals the sizes of *all* video files in the show folder (regardless of watched status).
      .PARAMETER ShowFolder
        DirectoryInfo of the show folder.
      .OUTPUTS
        [long] total bytes
    #>
    param(
        [Parameter(Mandatory)] [System.IO.DirectoryInfo]$ShowFolder
    )

    $total = 0L
    foreach ($ext in $script:VideoExtensions) {
        $files = Get-ChildItem -Path $ShowFolder.FullName -Recurse -Include "*$ext" -File -ErrorAction SilentlyContinue
        if ($files) {
            $sum = ($files | Measure-Object -Property Length -Sum).Sum
            if ($sum) {
                $total += [int64]$sum 
            }
        }
    }
    return $total
}

function Format-WatchedStatus {
    <#
      .SYNOPSIS
        Builds a friendly status string from the progress object.
      .OUTPUTS
        [string]
    #>
    param(
        [Parameter(Mandatory)] $Progress
    )

    if (-not $Progress -or -not $Progress.seasons) {
        return 'Unwatched' 
    }

    $highestFull = 0
    $partial = $null
    $hasWatched = $false

    foreach ($season in $Progress.seasons | Sort-Object number) {
        $aired = [int]$season.aired
        $complete = [int]$season.completed

        if ($complete -gt 0) {
            $hasWatched = $true
            if ($aired -gt 0 -and $complete -eq $aired) {
                if ([int]$season.number -gt $highestFull) {
                    $highestFull = [int]$season.number
                }
            } else {
                $partial = "Watched till Season $($season.number) Episode $complete of $aired"
            }
        }
    }

    if (-not $hasWatched) {
        return 'Unwatched' 
    }

    $seasonCount = ($Progress.seasons | Measure-Object).Count
    if ($highestFull -eq $seasonCount -and -not $partial) {
        return 'Fully Watched'
    }

    if ($partial) {
        return $partial 
    }
    if ($highestFull -gt 0) {
        return "Watched till Season $highestFull" 
    }
    return 'Partially Watched'
}

#endregion

#region ----- Main -----

# Ensure we can authenticate
Get-TraktAccessToken

# Validate root folder
if (-not (Test-Path -LiteralPath $rootFolder)) {
    Write-Error "Root folder not found: $rootFolder"
    exit 1
}

$showFolders = Get-ChildItem -LiteralPath $rootFolder -Directory -ErrorAction Stop
if (-not $showFolders) {
    Write-Warning "No subfolders found in '$rootFolder'."
    return
}

$showsData = New-Object System.Collections.Generic.List[object]
$total = $showFolders.Count
$idx = 0

foreach ($folder in $showFolders) {
    $idx++
    Write-Progress -Activity "Processing TV Shows" `
        -Status "$idx of $total folders processed" `
        -PercentComplete (([double]$idx / [double]$total) * 100)

    $parsed = Parse-FolderAsTitleYear -FolderName $folder.Name
    $title = $parsed.Title
    $year = $parsed.Year

    Write-Host ("Source Show Title:  {0}{1}" -f $title, $(if ($year) {
                " ($year)" 
            } else {
                "" 
            }))

    $match = $null
    $progress = $null
    $status = 'Unknown'
    $lastWatched = $null

    try {
        $match = Find-TraktShow -Title $title -Year $year
        if ($match) {
            Write-Host ("Trakt Show Title:   {0}" -f $match.show.title)
            Write-Host ('-' * 66)

            $progress = Get-TraktShowProgress -TraktShowId $match.show.ids.trakt

            # Determine last watched timestamp across episodes
            foreach ($s in $progress.seasons) {
                foreach ($e in $s.episodes) {
                    if ($e.completed -and $e.last_watched_at) {
                        $dt = [datetime]$e.last_watched_at
                        if (-not $lastWatched -or $dt -gt $lastWatched) {
                            $lastWatched = $dt
                        }
                    }
                }
            }

            $status = Format-WatchedStatus -Progress $progress
        } else {
            Write-Warning "No Trakt match found for '$title'."
            $status = 'Unknown (no Trakt match)'
        }
    } catch {
        Write-Error "Failed to retrieve show information for $($folder.Name). $_"
        # We still want to compute local sizes even if Trakt fails for this show
        if (-not $status) {
            $status = 'Unknown (error)' 
        }
    }

    # Sizes (always computed so we can include Unwatched / Unknown rows)
    $totalBytes = Get-TotalBytesForShow -ShowFolder $folder
    $watchedBytes = 0L
    if ($progress -and $progress.seasons) {
        $watchedBytes = Get-WatchedBytesForShow -ShowFolder $folder -Seasons $progress.seasons
    }

    if ($watchedBytes -gt $totalBytes) {
        $watchedBytes = $totalBytes 
    }

    $totalGB = [math]::Round(($totalBytes / 1GB), 2)
    $watchedGB = [math]::Round(($watchedBytes / 1GB), 2)
    $unwatchedG = [math]::Round((([int64]$totalBytes - [int64]$watchedBytes) / 1GB), 2)
    $pct = if ($totalBytes -gt 0) {
        [math]::Round((100.0 * $watchedBytes / $totalBytes), 1) 
    } else {
        0 
    }

    $showsData.Add([pscustomobject]@{
            Title           = $folder.Name
            Status          = $status                         # Fully Watched / Partially Watched / Unwatched / Unknown
            LastWatched     = $lastWatched
            WatchedSizeGB   = $watchedGB
            UnwatchedSizeGB = $unwatchedG
            TotalSizeGB     = $totalGB
            WatchedPct      = $pct
        })
}

# Suggested sort: least recently watched first, then biggest total size
$sorted = $showsData | Sort-Object @{Expression = 'LastWatched'; Ascending = $true }, @{Expression = 'TotalSizeGB'; Ascending = $false }

if ($sorted.Count -gt 0) {
    # Use only ASCII in strings to avoid encoding-related parser issues
    $sorted | Out-GridView -Title 'Shows (Trakt + Disk Usage) - Watched / Unwatched'
} else {
    Write-Host ("No shows found under '{0}'." -f $rootFolder)
}


#endregion
