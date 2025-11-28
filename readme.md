# Watched TV Show Folder Checker

A PowerShell script that cross-references your local TV show library with your Trakt.tv watch history to identify fully watched, partially watched, and unwatched content — helping you make informed decisions about disk space cleanup.

## Features

- **Trakt Integration** — OAuth authentication with automatic token refresh
- **Smart Caching** — Automatic invalidation when disk content changes, plus configurable TTL
- **Accurate Size Tracking** — Calculates watched vs. unwatched disk usage per show
- **Show Metadata** — Displays series status (Returning/Ended), network, and next episode air date
- **Multiple Output Formats** — GridView, CSV, JSON, or Console
- **Flexible Cleanup Options**
  - Delete or move fully watched shows
  - Delete or move watched seasons from partially watched shows
  - Recycle Bin support (default) or permanent deletion
- **Multi-Root Support** — Scan multiple TV show directories
- **Exclusion Patterns** — Skip sample files and trailers
- **Manual Mappings** — Override Trakt matching for problematic show names

## Requirements

- Windows PowerShell 5.1+ or PowerShell 7+
- PowerShell 7 requires [Microsoft.PowerShell.GraphicalTools](https://github.com/PowerShell/GraphicalTools) for GridView output
- A [Trakt.tv](https://trakt.tv) account with watch history
- Trakt API application credentials ([create one here](https://trakt.tv/oauth/applications/new))

## Installation

1. Clone the repository or download the script:
   ```powershell
   git clone https://github.com/yourusername/Watched-TVshow-Folder-Checker.git
   ```

2. (Optional) Create a configuration file:
   ```powershell
   .\Watched-TVshow-Folder-Checker.ps1 -CreateConfig
   ```

3. Edit `config.json` with your settings (see [Configuration](#configuration))

## Quick Start

```powershell
# First run - will prompt for Trakt API credentials and authorization
.\Watched-TVshow-Folder-Checker.ps1 -RootFolder "D:\TV Shows"

# Preview what would be cleaned up
.\Watched-TVshow-Folder-Checker.ps1 -CleanupFullyWatched -WhatIf

# Clean up fully watched shows and watched seasons
.\Watched-TVshow-Folder-Checker.ps1 -CleanupFullyWatched -CleanupWatchedSeasons
```

## Configuration

### Config File (`config.json`)

Run `-CreateConfig` to generate a default configuration file:

```json
{
  "rootFolders": ["D:\\TV Shows", "E:\\Media\\Series"],
  "excludePatterns": ["Sample", "Trailer", "SAMPLE"],
  "cacheTTLHours": 720,
  "metadataTTLHours": 168,
  "outputFormat": "GridView",
  "videoExtensions": [".mkv", ".mp4", ".avi", ".mov", ".m4v", ".wmv", ".ts", ".flv", ".webm"],
  "clientId": "your-trakt-client-id",
  "clientSecret": "your-trakt-client-secret",
  "manualMappings": {
    "Problem Show Name (2020)": {
      "trakt_id": 12345,
      "trakt_slug": "problem-show-name"
    }
  }
}
```

| Setting | Description | Default |
|---------|-------------|---------|
| `rootFolders` | Array of paths containing TV show folders | `[]` |
| `excludePatterns` | Regex patterns to exclude from size calculations | `["Sample", "Trailer", "SAMPLE"]` |
| `cacheTTLHours` | Hours before watch progress cache expires | `720` (30 days) |
| `metadataTTLHours` | Hours before show metadata cache expires | `168` (7 days) |
| `outputFormat` | Default output: `GridView`, `CSV`, `JSON`, `Console` | `GridView` |
| `videoExtensions` | File extensions to include in size calculations | Common video formats |
| `clientId` | Trakt API Client ID | — |
| `clientSecret` | Trakt API Client Secret | — |
| `manualMappings` | Override automatic Trakt matching | `{}` |

### Trakt API Setup

1. Go to [trakt.tv/oauth/applications/new](https://trakt.tv/oauth/applications/new)
2. Fill in the form:
   - **Name**: Any name (e.g., "TV Show Cleanup Script")
   - **Redirect URI**: `urn:ietf:wg:oauth:2.0:oob`
   - Leave other fields as default
3. Click **Save App**
4. Copy the **Client ID** and **Client Secret** to your `config.json`

On first run, the script will open a browser for authorization. After authorizing, enter the PIN code to complete setup. Tokens are saved to `tokens.json` for future use.

## Usage

### Parameters

| Parameter | Description |
|-----------|-------------|
| `-RootFolder` | One or more root folders containing TV show subfolders |
| `-ClientId` | Trakt API Client ID (overrides config) |
| `-ClientSecret` | Trakt API Client Secret (overrides config) |
| `-OutputFormat` | Output format: `GridView`, `CSV`, `JSON`, `Console` |
| `-OutputPath` | File path for CSV/JSON output |
| `-CacheTTLHours` | Hours before cached data expires (1-8760) |
| `-ForceRefresh` | Bypass cache and fetch fresh data from Trakt |
| `-RefreshInProgress` | Force refresh for shows not fully watched |
| `-ExcludePattern` | File name patterns to exclude |
| `-CleanupFullyWatched` | Delete/move shows that are fully watched |
| `-CleanupWatchedSeasons` | Delete/move fully watched seasons from partial shows |
| `-MoveToPath` | Move items here instead of deleting |
| `-SkipRecycleBin` | Permanently delete instead of using Recycle Bin |
| `-Interactive` | Select shows for cleanup via GridView |
| `-CreateConfig` | Generate default config.json and exit |
| `-WhatIf` | Preview changes without making them |
| `-Verbose` | Show detailed processing information |

### Examples

**View all shows with watch status:**
```powershell
.\Watched-TVshow-Folder-Checker.ps1 -RootFolder "D:\TV Shows"
```

**Export to CSV for analysis:**
```powershell
.\Watched-TVshow-Folder-Checker.ps1 -OutputFormat CSV -OutputPath ".\tv-report.csv"
```

**Preview cleanup of fully watched shows:**
```powershell
.\Watched-TVshow-Folder-Checker.ps1 -CleanupFullyWatched -WhatIf
```

**Clean up both fully watched shows and watched seasons:**
```powershell
.\Watched-TVshow-Folder-Checker.ps1 -CleanupFullyWatched -CleanupWatchedSeasons
```

**Move watched content to archive instead of deleting:**
```powershell
.\Watched-TVshow-Folder-Checker.ps1 -CleanupFullyWatched -CleanupWatchedSeasons -MoveToPath "X:\Archive\TV"
```

**Interactive selection for cleanup:**
```powershell
.\Watched-TVshow-Folder-Checker.ps1 -Interactive
```

**Force fresh data from Trakt:**
```powershell
.\Watched-TVshow-Folder-Checker.ps1 -ForceRefresh
```

## Output

### Summary Statistics

```
======================================================================
SUMMARY
======================================================================
Shows:  150 total | 45 fully watched | 80 partial | 25 unwatched
Series: 60 ended | 90 returning
Size:   2.50 TB total | 1.20 TB watched | 1.30 TB unwatched
======================================================================
```

### Show Data Fields

| Field | Description |
|-------|-------------|
| Title | Folder name |
| Status | Watch status (Fully Watched, Watched till S02E05, Unwatched, etc.) |
| SeriesStatus | Returning, Ended, Canceled, In Production, Planned |
| Network | Broadcasting network |
| NextEpisode | Next episode air date (for returning shows) |
| LastWatched | Date of most recent watched episode |
| WatchedSizeGB | Disk space used by watched episodes |
| UnwatchedSizeGB | Disk space used by unwatched episodes |
| TotalSizeGB | Total disk space used |
| WatchedPct | Percentage of content watched |
| TraktUrl | Link to show on Trakt.tv |

## Caching Behavior

The script caches Trakt data to minimize API calls and speed up subsequent runs.

### Smart Cache Invalidation

The cache stores the total size (in bytes) of each show's video files. On each run, it compares the current disk size against the cached value. If they differ (new episodes downloaded or files deleted), the cache is automatically invalidated and fresh data is fetched from Trakt.

| Trigger | What Happens |
|---------|--------------|
| **Disk content changed** | New episodes downloaded or files deleted → automatic refresh |
| **TTL expired** | Default 30 days for watch progress, 7 days for metadata |
| **`-ForceRefresh`** | Bypasses all caching |
| **`-RefreshInProgress`** | Refreshes only partially watched shows |

This size-based invalidation means you can safely use a long TTL (30 days default). The script will automatically fetch fresh data when needed.

### Cache Files

| File | Contents |
|------|----------|
| `trakt-cache.json` | Watch progress, show metadata, folder paths, file sizes |
| `tokens.json` | OAuth access and refresh tokens (auto-refreshed on expiry) |

### Stale Entry Cleanup

The cache automatically removes entries for shows whose folders no longer exist on disk. This keeps the cache clean when you delete or move shows outside of the script.

### Verbose Output

Use `-Verbose` to see cache behavior and API calls:

```
VERBOSE: Processing: Breaking Bad (2008)
VERBOSE:   Using cached data

VERBOSE: Processing: Better Call Saul (2015)
VERBOSE:   Disk content changed (cached: 45678901234 bytes, current: 52345678901 bytes)
VERBOSE:   Searching Trakt for: Better Call Saul
VERBOSE:   Matched: Better Call Saul (2015)
VERBOSE:   Fetching watch progress...
VERBOSE:   Fetching show details (status, network)...
VERBOSE:   Fetching next episode...
```

## Cleanup Behavior

### `-CleanupFullyWatched`
Targets shows where **all aired episodes** have been watched. Deletes/moves the entire show folder.

### `-CleanupWatchedSeasons`
Targets shows that are **partially watched** but have one or more **fully completed seasons**. Deletes/moves only the watched season folders, preserving unwatched content.

### Combined Usage
When both flags are used together:
1. Fully watched shows are processed first
2. Then watched seasons from remaining partial shows are processed

This prevents attempting to clean seasons from shows that were already removed.

### Safety Features
- **Recycle Bin**: By default, deleted items go to the Recycle Bin
- **WhatIf**: Always preview with `-WhatIf` before actual cleanup
- **Confirmation**: High-impact operations require confirmation (use `-Confirm:$false` to skip)

## File Structure

```
Watched-TVshow-Folder-Checker/
├── Watched-TVshow-Folder-Checker.ps1  # Main script
├── config.json                         # Configuration (created with -CreateConfig)
├── tokens.json                         # OAuth tokens (auto-generated)
├── trakt-cache.json                    # Cached Trakt data (auto-generated)
└── README.md
```

## Folder Naming

The script expects TV show folders in standard naming format:

```
TV Shows/
├── Breaking Bad (2008)/
│   ├── Season 01/
│   ├── Season 02/
│   └── ...
├── The Office (2005)/
└── Show Name/              # Year is optional
```

Season folders can use various formats: `Season 1`, `Season 01`, `S01`, `Specials`

## Manual Mappings

If a show isn't matching correctly on Trakt, add a manual mapping in `config.json`:

1. Find the show on Trakt.tv
2. Note the URL: `https://trakt.tv/shows/the-show-name` → slug is `the-show-name`
3. Get the Trakt ID from the API or browser developer tools
4. Add to config:

```json
"manualMappings": {
  "My Problem Show (2020)": {
    "trakt_id": 12345,
    "trakt_slug": "the-correct-show"
  }
}
```

The key must match your folder name exactly (case-insensitive).

## Troubleshooting

**"No Trakt match found"**
- Check the folder name matches the show title on Trakt
- Add a manual mapping if the name differs significantly

**Token expired errors**
- Delete `tokens.json` and re-run to re-authenticate

**GridView not available (PowerShell 7)**
- Install: `Install-Module Microsoft.PowerShell.GraphicalTools`

**Shows not updating after watching more episodes**
- If you downloaded new content, refresh should happen automatically
- If you only watched on Trakt (no new downloads), use `-ForceRefresh` or wait for TTL expiry
- Use `-RefreshInProgress` to refresh only partial watches

**Upgrading from older versions**
- Delete `trakt-cache.json` to rebuild with new fields (total_bytes, folder_path)

## Acknowledgments

- [Trakt.tv](https://trakt.tv) for their excellent API
- The PowerShell community