# Watched TV Show Folder Checker (PowerShell)

Get a fast, sortable overview of the TV shows on your disk, cross-referenced with your **Trakt** watch history — so you can spot what’s **fully watched**, **partially watched**, or **unwatched**, and clean up space safely.

The script opens an **Out-GridView** table with status, last watched date, and watched/unwatched disk usage per show.
<img width="817" height="425" alt="image" src="https://github.com/user-attachments/assets/eb6830e9-01ab-49b9-a103-557b50807a6c" />

---

## ✨ Features

* **Trakt OAuth**: prompts once, then stores/refreshes tokens in `tokens.json`.
* **Title/Year matching**: resolves each folder to the correct Trakt show.
  (Prefers exact *Title + Year* → exact *Title* → first result.)
* **Accurate size accounting**:

  * `TotalSizeGB` — all video files in the folder
  * `WatchedSizeGB` — files containing watched episodes (handles multi-episode files like `S11E17E18` or `S11E17 - E18`)
  * `UnwatchedSizeGB` — `Total - Watched`, never negative
  * `WatchedPct` — percentage watched by size
* **Statuses**: `Fully Watched`, `Partially Watched`, `Unwatched`, or `Unknown`.
* **Graceful handling**: retries once on expired tokens; keeps working even if a show can’t be matched.

---

## 🧩 How it works

1. Reads your library root (e.g. `E:\Data\TVSeries\EN`), one subfolder per show.
2. Parses folder names like `Show Name (2021)` into `Title` and optional `Year`.
3. Looks up the show on Trakt and fetches watched progress.
4. Scans the show folder for video files and:

   * Totals all video sizes (`TotalSizeGB`).
   * Parses filenames for episode codes and counts the file once if **any** of the episodes it represents were watched (`WatchedSizeGB`).
5. Shows everything in a sortable Out-GridView.

---

## ✅ Requirements

* Windows PowerShell 5.1 (Out-GridView is built-in), **or**
* PowerShell 7 + module **Microsoft.PowerShell.GraphicalTools** (for `Out-GridView`)
* A Trakt account + an **API application** (Client ID & Client Secret)

> Save the script as **UTF-8 (no BOM)** to avoid stray character issues.

---

## 🔧 Installation

1. Clone/download this repo.
2. Put the script (e.g. `Watched-TVshow-Folder-Checker.ps1`) anywhere you like.
3. (PS7 only) Install Graphical Tools:

   ```powershell
   Install-Module Microsoft.PowerShell.GraphicalTools -Scope CurrentUser
   ```

---

## 🔑 Trakt API Setup

1. Go to **[https://trakt.tv/oauth/applications](https://trakt.tv/oauth/applications)** and create an application.
2. Set **Redirect URI** to `urn:ietf:wg:oauth:2.0:oob` (Out-of-band).
3. Copy your **Client ID** and **Client Secret**.

> The first run will ask for the **authorization code** from Trakt and then save `tokens.json` next to the script.

---

## ▶️ Usage

```powershell
# From a PowerShell prompt
.\Watched-TVshow-Folder-Checker.ps1 -rootFolder "E:\Data\TVSeries\EN" -clientId "<YOUR_CLIENT_ID>" -clientSecret "<YOUR_CLIENT_SECRET>"

# If tokens.json already exists, you can omit clientId/clientSecret:
.\Watched-TVshow-Folder-Checker.ps1 -rootFolder "E:\Data\TVSeries\EN"
```

The script displays an **Out-GridView** window titled:

```
Shows (Trakt + Disk Usage) - Watched / Unwatched
```

You can sort/filter by any column (e.g., sort by `UnwatchedSizeGB` to find the biggest cleanup candidates).

---

## 📊 Output Columns

* **Title** — folder name
* **Status** — `Fully Watched`, `Partially Watched`, `Unwatched`, or `Unknown`
* **LastWatched** — most recent watch timestamp (if available)
* **WatchedSizeGB** — size of files that contain watched episodes
* **UnwatchedSizeGB** — size of files with only unwatched episodes
* **TotalSizeGB** — total size of all video files in the folder
* **WatchedPct** — `WatchedSizeGB / TotalSizeGB * 100`

---

## 📁 Folder & File Naming Conventions

**Folders**
Best: `Show Name (2021)` — the year increases match accuracy on Trakt.

**Files**
The script recognizes many episode patterns:

* `S01E01`, `S01E01E02`, `S01E01-E02`, `S01E01 E02`, `S01E01 - E02`
* Multi-episode files are counted **once** even if they contain multiple episodes.

**Video extensions counted**
`.mkv`, `.mp4`, `.avi`, `.mov`, `.m4v`, `.wmv`
(Adjust in `$script:VideoExtensions` if needed.)

---

## 🧠 Notes on Accuracy

* `WatchedSizeGB` is based on **filename episode codes**. If files lack `SxxExx` in the name, they won’t be matched to Trakt episodes.
* For shows flagged **Fully Watched**, the script still computes watched size episode-by-episode; however it **clamps** `WatchedSizeGB` to never exceed `TotalSizeGB`.

---

## ⚡ Performance Tips

* Run from a fast disk (lots of recursive file I/O).
* Exclude junk (samples/trailers) at the source, or extend the script to skip them.
* If you have many shows, run during off hours (Trakt API limits apply).

---

## 🛠️ Troubleshooting

**401 Unauthorized**

* Your access token likely expired and refresh failed.
  Try deleting `tokens.json` and re-running to re-authorize.

**403 Forbidden**

* You reached an endpoint or scope your app isn’t allowed to use.
  This script only uses standard endpoints (`/search` and `/shows/{id}/progress`), which should be fine.

**“String is missing the terminator” or weird quotes/dashes**

* Ensure the script is saved as **UTF-8 (no BOM)**.
* Replace typographic quotes/dashes with plain ASCII.

**Show not matched / Wrong match**

* Include the year in folder names: `Show Name (2018)`.
* If a show is mis-matched, rename the folder (year helps a lot) and rerun.

---

## 🔒 Privacy

* `tokens.json` stores your Trakt access and refresh tokens plus the client ID/secret **locally** next to the script.
* No data is sent anywhere besides the Trakt API endpoints used by the script.

---

## 🙌 Acknowledgements

* [Trakt.tv](https://trakt.tv) for the API
* The PowerShell community for `Out-GridView` and tooling

---

### Quick Start (TL;DR)

```powershell
# 1) Create Trakt application and grab Client ID/Secret
# 2) Run the script once with your credentials:
.\Watched-TVshow-Folder-Checker.ps1 -rootFolder "E:\Data\TVSeries\EN" -clientId "xxx" -clientSecret "yyy"

# 3) Next runs only need rootFolder:
.\Watched-TVshow-Folder-Checker.ps1 -rootFolder "E:\Data\TVSeries\EN"
```

Happy tidying!
