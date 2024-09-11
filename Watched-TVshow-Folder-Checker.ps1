<#
.SYNOPSIS
    Main script to check watched TV shows using Trakt API.
.DESCRIPTION
    This script interacts with the Trakt API to check the watched status 
    of TV shows. It handles token authentication, token refreshing, and 
    retrieves the progress of each show based on the information in the 
    specified root folder. Shows are filtered to display only those with 
    watched episodes.
.PARAMETER clientId
    Client ID of the Trakt API application.
.PARAMETER clientSecret
    Client Secret of the Trakt API application.
.PARAMETER rootFolder
    Root folder path where TV show directories are located.
.INPUTS
    None. The script processes directories based on the root folder path.
.OUTPUTS
    String output indicating the watched status of each show.
.EXAMPLE
    .\Check-WatchedShows.ps1 -clientId "yourClientId" -clientSecret "yourClientSecret" -rootFolder "C:\TVShows"
    This example runs the script with the specified client ID, client secret, and root folder.
#>

param (
    [Parameter(Mandatory = $false)]
    [string]$clientId, # Client ID of API for Trakt.tv

    [Parameter(Mandatory = $false)]
    [string]$clientSecret, # Client Secret of API for Trakt.tv

    [Parameter(Mandatory = $true)]
    [string]$rootFolder    # Root folder to search for watched TV shows
)

<#
.SYNOPSIS
    Retrieves the Trakt access token from the token file or prompts for 
    authorization if the token file does not exist.
.DESCRIPTION
    This function checks for an existing token file. If found, it reads 
    and returns the access and refresh tokens. If the token file does not 
    exist, it prompts the user to authorize the application and retrieves 
    new tokens, saving them to the file.
.INPUTS
    None. The function reads tokens from a file or prompts for user input.
.OUTPUTS
    Tuple of strings representing the access and refresh tokens.
.EXAMPLE
    $accessToken, $refreshToken = Get-TraktAccessToken
    This example retrieves the Trakt access and refresh tokens.
#>
function Get-TraktAccessToken {
    param (
        [string]$clientId,
        [string]$clientSecret
    )
    if (Test-Path $tokenFilePath) {
        $tokens = Get-Content $tokenFilePath | ConvertFrom-Json
        return $tokens.access_token, $tokens.refresh_token, $tokens.client_Id
    } else {
        if (-not $clientId -or -not $clientSecret) {
            $clientId = Read-Host "Enter your Trakt API Client ID"
            $clientSecret = Read-Host "Enter your Trakt API Client Secret"
        }

        $redirectUri = "urn:ietf:wg:oauth:2.0:oob"

        $authUrl = "https://trakt.tv/oauth/authorize?response_type=code&client_id=$clientId&redirect_uri=$redirectUri"
        Write-Host "Please visit the following URL to authorize the app:"
        Write-Host $authUrl
        
        $authCode = Read-Host "Enter the authorization code provided by Trakt"
        
        $tokenUrl = "https://api.trakt.tv/oauth/token"
        $tokenBody = @{
            code          = $authCode
            client_id     = $clientId
            client_secret = $clientSecret
            redirect_uri  = $redirectUri
            grant_type    = "authorization_code"
        }

        try {
            $tokenResponse = Invoke-RestMethod -Uri $tokenUrl -Method Post -Body ($tokenBody | ConvertTo-Json) -ContentType "application/json"
            $accessToken = $tokenResponse.access_token
            $refreshToken = $tokenResponse.refresh_token

            # Save tokens to a file
            $tokens = @{
                access_token  = $accessToken
                refresh_token = $refreshToken
                client_Id     = $clientId
                client_Secret = $clientSecret
            }
            $tokens | ConvertTo-Json | Set-Content $tokenFilePath

            return $accessToken, $refreshToken, $clientId
        } catch {
            Write-Error "Failed to retrieve tokens. $_"
            exit
        }
    }
}

<#
.SYNOPSIS
    Refreshes the Trakt access token using the refresh token.
.DESCRIPTION
    This function refreshes the Trakt access token using the provided 
    refresh token. The new access and refresh tokens are saved to the token 
    file.
.INPUTS
    None. The function uses the refresh token from the token file.
.OUTPUTS
    String representing the new access token.
.EXAMPLE
    $newAccessToken = Refresh-TraktAccessToken
    This example refreshes the Trakt access token and retrieves the new token.
#>
function Refresh-TraktAccessToken {
    param (
        [string]$clientId,
        [string]$clientSecret
    )
    $tokens = Get-Content $tokenFilePath | ConvertFrom-Json
    $refreshToken = $tokens.refresh_token
    $clientId = $tokens.client_Id
    $clientsecret = $tokens.client_secret
    $redirectUri = "urn:ietf:wg:oauth:2.0:oob"

    $refreshUrl = "https://api.trakt.tv/oauth/token"
    $refreshBody = @{
        refresh_token = $refreshToken
        client_id     = $clientId
        client_secret = $clientSecret
        redirect_uri  = $redirectUri
        grant_type    = "refresh_token"
    }

    try {
        $refreshResponse = Invoke-RestMethod -Uri $refreshUrl -Method Post -Body ($refreshBody | ConvertTo-Json) -ContentType "application/json"
        $accessToken = $refreshResponse.access_token
        $refreshToken = $refreshResponse.refresh_token

        # Save updated tokens
        $tokens.access_token = $accessToken
        $tokens.refresh_token = $refreshToken
        $tokens | ConvertTo-Json | Set-Content $tokenFilePath

        return $accessToken
    } catch {
        Write-Error "Failed to refresh tokens. $_"
        exit
    }
}

<#
.SYNOPSIS
    Retrieves the watched progress of a show from the Trakt API.
.DESCRIPTION
    This function retrieves the watched progress for a specific show by its 
    Trakt ID. It handles token authentication and retries the request if 
    the token has expired.
.PARAMETER accessToken
    The current access token for the Trakt API.
.PARAMETER showId
    The Trakt ID of the show to retrieve progress for.
.INPUTS
    None. The function uses the Trakt ID to request progress information.
.OUTPUTS
    Object representing the progress of the show.
.EXAMPLE
    $showProgress = Get-TraktShowProgress -accessToken $accessToken -showId 245
    This example retrieves the watched progress for the show with ID 245.
#>
function Get-TraktShowProgress {
    param (
        [string]$accessToken,
        [int]$showId
    )

    $progressUrl = "https://api.trakt.tv/shows/$showId/progress/watched?hidden=false&specials=false&count_specials=true"

    try {
        $response = Invoke-RestMethod -Uri $progressUrl -Headers @{
            "Authorization"     = "Bearer $accessToken"
            "Content-Type"      = "application/json"
            "trakt-api-version" = "2"
            "trakt-api-key"     = $clientId
        }
        return $response
    } catch {
        # Check if the token has expired (401 Unauthorized)
        if ($_.Exception.Response.StatusCode -eq 401) {
            Write-Host "Access token expired. Refreshing token..."
            $newAccessToken = Refresh-TraktAccessToken

            # Retry the request with the refreshed token
            try {
                $response = Invoke-RestMethod -Uri $progressUrl -Headers @{
                    "Authorization"     = "Bearer $newAccessToken"
                    "Content-Type"      = "application/json"
                    "trakt-api-version" = "2"
                    "trakt-api-key"     = $clientId
                }
                return $response
            } catch {
                Write-Error "Failed to retrieve show progress after refreshing the token. $_"
                exit
            }
        } else {
            Write-Error "Failed to retrieve show progress. $_"
            exit
        }
    }
}

# Token File Path
$tokenFilePath = "$PSScriptRoot\tokens.json"

# Check token and refresh if needed
$accessToken, $refreshToken, $clientId = Get-TraktAccessToken -clientId $clientId -clientSecret $clientSecret

# Show Folder Processing
$showFolders = Get-ChildItem -Path $rootFolder -Directory

foreach ($folder in $showFolders) {
    $folderName = $folder.Name
    if ($folderName -match "(.+)\s\((\d{4})\)") {
        $showTitle = $matches[1].Trim()
        $showYear = $matches[2]
    } else {
        $showTitle = $folderName
        $showYear = $null
    }

    # Lookup the show via Trakt API
    $showSearchUrl = "https://api.trakt.tv/search/show?query=$showTitle"

    try {
        $searchResponse = Invoke-RestMethod -Uri $showSearchUrl -Headers @{
            "Authorization"     = "Bearer $accessToken"
            "Content-Type"      = "application/json"
            "trakt-api-version" = "2"
            "trakt-api-key"     = $clientId
        }

        if ($searchResponse) {
            # Filter the results based on the year if provided, otherwise take the first result
            $matchedShows = if ($showYear) {
                $searchResponse | Where-Object { $_.show.year -eq [int]$showYear }
            } else {
                $searchResponse
            }

            # Ensure $matchedShows is always an array
            if ($matchedShows -isNot [array]) {
                $matchedShows = @($matchedShows)  # Wrap single object in an array
            }
            if ($matchedShows.Count -gt 0) {
                $showId = $matchedShows[0].show.ids.trakt
                $showProgress = Get-TraktShowProgress -accessToken $accessToken -showId $showId

                # Track overall watched status
                $overallWatchedStatus = $null
                
                # Initialize variables to track the highest fully watched season and detailed status
                $highestFullyWatchedSeason = 0
                $partialWatchedStatus = $null
                $hasWatchedEpisodes = $false

                foreach ($season in $showProgress.seasons) {
                    $totalEpisodes = $season.aired
                    $watchedEpisodes = $season.completed

                    if ($watchedEpisodes -gt 0) {
                        $hasWatchedEpisodes = $true
        
                        if ($watchedEpisodes -eq $totalEpisodes) {
                            # Season is fully watched
                            $highestFullyWatchedSeason = [math]::Max($highestFullyWatchedSeason, $season.number)
                        } else {
                            # Track partial watched status
                            $partialWatchedStatus = "Watched till Season $($season.number) Episode $watchedEpisodes of $totalEpisodes"
                        }
                    }
                }

                # Determine overall watched status
                if ($hasWatchedEpisodes) {
                    if ($highestFullyWatchedSeason -eq $showProgress.seasons.Count) {
                        $overallWatchedStatus = "Fully Watched"
                    } else {
                        if ($partialWatchedStatus) {
                            $overallWatchedStatus = $partialWatchedStatus
                        } else {
                            $overallWatchedStatus = "Watched till Season $highestFullyWatchedSeason"
                        }
                    }
                } else {
                    $overallWatchedStatus = $null
                }

                # Output only if at least one episode was watched
                if ($overallWatchedStatus) {
                    Write-Host "$folderName - $overallWatchedStatus"
                }
            } else {
                Write-Error "No show found for '$showTitle' in year '$showYear'."
            }
        }
    } catch {
        Write-Error "Failed to search or process the show '$showTitle'. $_"
    }
}

# Write-Host "Press any key to continue..."
# $x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
