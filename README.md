<div align="center">
<img src="icons/bookmark-96.png" alt="Bookmark Manager Zero Logo" width="128" height="128">

<h1 align="center">Bookmark Manager Zero</h1>

<p align="center">
  <strong>A modern, privacy-focused interface for managing your Firefox bookmarks.</strong>
</p>

<p align="center">
  <a href="https://gitlab.com/AbsoluteXYZero/BMZ-Firefox">
    <img src="https://img.shields.io/badge/version-3.7-blue" alt="Version">
  </a>
  <a href="LICENSE">
    <img src="https://img.shields.io/badge/license-MIT-green" alt="License">
  </a>
  <a href="https://addons.mozilla.org/firefox/">
    <img src="https://img.shields.io/badge/firefox-compatible-orange" alt="Firefox">
  </a>
</p>

<br>

<p align="center">
  <a href="https://addons.mozilla.org/en-US/firefox/addon/bookmark-manager-zero/">
    <img src="https://blog.mozilla.org/addons/files/2020/04/get-the-addon-fx-apr-2020.svg" alt="Get the Addon">
  </a>
</p>

</div>

## Overview

Bookmark Manager Zero is a Firefox extension that provides a beautiful, feature-rich sidebar interface for managing your **native Firefox bookmarks**. It works directly with the bookmarks already built into your browser, with optional cloud sync via GitLab Snippets for backup and cross-device synchronization.

Changes sync **bi-directionally and instantly**: any edits made in Bookmark Manager Zero immediately appear in Firefox's native bookmark system, and vice versa. Don't worry about accidental changes—the built-in undo feature and a changelog in the settings let you quickly restore recently deleted renamed, or moved bookmarks and folders

It enhances your bookmark management experience with modern UI, advanced search, safety checking, and intelligent organization tools while keeping your data exactly where it belongs: in Firefox.

### Why Bookmark Manager Zero?

**The only bookmark manager with integrated security scanning.**

Other bookmark tools make you choose between organization OR security. Bookmark Manager Zero combines both:

| Feature | Bookmark Manager Zero | [Bookmarks clean up](https://addons.mozilla.org/firefox/addon/bookmarks-clean-up/) | [Bookmarks Organizer](https://addons.mozilla.org/firefox/addon/bookmarks-organizer/) | [Malware & URL Scanner](https://chromewebstore.google.com/detail/pinkddkghldnoglcngpeolboghcbenfh) |
|---------|:--------------------:|:------------------:|:-------------------:|:---------------------:|
| Modern bookmark UI | ✅ | ❌ | ❌ | ❌ |
| Dead link detection | ✅ | ✅ | ✅ | ❌ |
| Parked domain detection | ✅ | ❌ | ❌ | ❌ |
| Multi-source malware scanning | ✅ | ❌ | ❌ | ✅ |
| Safety indicators on bookmarks | ✅ | ❌ | ❌ | ❌ |
| Suspicious pattern detection | ✅ | ❌ | ❌ | ❌ |
| No tracking/analytics | ✅ | ✅ | ✅ | ❌ |
| Website previews | ✅ | ❌ | ❌ | ❌ |
| Free (no premium upsell) | ✅ | ❌ | ✅ | ❌ |

Stop blindly clicking old bookmarks. Know which links are dead, parked, or potentially dangerous before you visit them.

## Screenshots

<div align="center">

### 📸 Gallery (Click to view full size)

<table>
  <tr>
    <td width="33%">
      <img src="screenshots/Screenshot 2025-11-19 204148.png" alt="Screenshot 1" width="100%">
    </td>
    <td width="33%">
      <img src="screenshots/Screenshot 2025-11-19 204209.png" alt="Screenshot 2" width="100%">
    </td>
    <td width="33%">
      <img src="screenshots/Screenshot 2025-11-19 204352.png" alt="Screenshot 3" width="100%">
    </td>
  </tr>
  <tr>
    <td width="33%">
      <img src="screenshots/Screenshot 2025-11-19 204236.png" alt="Screenshot 4" width="100%">
    </td>
    <td width="33%">
      <img src="screenshots/Screenshot 2025-11-19 204421.png" alt="Screenshot 5" width="100%">
    </td>
    <td width="33%">
      <img src="screenshots/Screenshot 2025-11-19 204437.png" alt="Screenshot 6" width="100%">
    </td>
  </tr>
  <tr>
    <td width="33%">
      <img src="screenshots/Screenshot 2025-11-19 215914.png" alt="Screenshot 7" width="100%">
    </td>
    <td width="33%">
      <img src="screenshots/Screenshot 2025-11-19 224518.png" alt="Screenshot 8" width="100%">
    </td>
    <td width="33%">
      <img src="screenshots/Screenshot 2025-12-05 133834.png" alt="Screenshot 9" width="100%">
    </td>
  </tr>
</table>

*Click any image to view full resolution. All screenshots show the extension running in Firefox.*

</div>

## Features

### Core Functionality
- ✅ **Native Bookmark Integration** - Works directly with Firefox's bookmark system
- ✅ **GitLab Snippet Sync (Optional)** - Cloud backup and cross-device synchronization
  - PAT authentication with AES-256-GCM encryption
  - Auto-sync every 5 minutes + event-driven sync on changes
  - Conflict detection for safe multi-device usage
  - Manual sync controls (pull/force push)
- ✅ **Modern Material Design UI** - Clean, intuitive interface with multiple themes
- ✅ **Sidebar Interface** - Quick access via toolbar icon or customizable keyboard shortcut
- ✅ **Real-time Sync** - Instantly reflects bookmark changes made in Firefox

### Organization & Search
- 🔍 **Advanced Search** - Real-time search across titles and URLs
- 📁 **Folder Management** - Create, edit, move, and organize folders
- 🏷️ **Smart Filters** - Filter by link status and safety with multi-select support
- 📊 **List & Grid Views** - Choose your preferred layout
- 🔄 **Drag & Drop** - Reorder bookmarks and folders

### Link & Safety Checking
- 🔗 **Link Status Checking** - Automatically detects broken/dead links
- 🛡️ **Security Scanning** - Checks URLs against malware databases
- 🔄 **Background Scanning** - Bookmark scanning continues in the background even when the sidebar is closed, with automatic progress synchronization when reopened
- 📂 **Folder Rescan** - Right-click any folder to recursively scan all bookmarks in that folder and subfolders with detailed statistics
- ⚠️ **Safety Indicators** - Visual warnings for suspicious links with detailed tooltips
- 👆 **Clickable Status Icons** - Click shield or chain icons for full status details popup
- 🔄 **HTTP Redirect Detection** - Detects when HTTP bookmarks redirect to HTTPS
- ✅ **Whitelist Support** - Mark trusted URLs to skip safety checks
- ⚪ **Trusted Filter** - Filter to view only whitelisted bookmarks (white shield)
- 📜 **Safety History** - Track status changes over time

### Privacy & Security
- 🔐 **Encrypted API Keys** - AES-256-GCM encryption for stored credentials
- 🔒 **Encrypted GitLab Tokens** - GitLab Personal Access Tokens encrypted with AES-256-GCM
- 🚫 **No Tracking** - Zero analytics, no data collection
- 🌐 **Offline Mode** - Works fully offline when external features disabled
- 🗑️ **Auto-Clear Cache** - Configurable automatic cache cleanup

### User Experience
- 🎨 **8 Themes** - Enhanced Blue (default), Enhanced Light, Enhanced Dark, Enhanced Gray, Blue, Light, Dark, Tinted
- ✨ **Enhanced Themes** - Modern rounded containers with enhanced 3D depth effects on search bar and toolbar buttons
- 🎨 **Tinted Theme Customization** - Adjust hue, saturation, and background colors for Tinted theme
- 🎨 **Custom Accent Colors** - Pick any color for theme customization
- 🎨 **Bookmark Background Opacity** - Adjust bookmark background transparency (0-100%) while keeping text at full opacity
- ✍️ **Custom Text Colors** - Visual color picker for bookmark and folder text with reset button
- 🖼️ **Custom Backgrounds** - Upload and position your own background images with drag-to-reposition
- 📱 **QR Code Generator Button** - Toolbar button for quick QR code generation of the current page URL
- ⌨️ **Keyboard Navigation** - Full keyboard support with arrow keys
- ♿ **Accessibility** - Comprehensive ARIA labels and keyboard traps
- 🔍 **Zoom Control** - 50% - 200% zoom levels for bookmark content
- 📏 **GUI Scaling** - 80% - 140% scaling for interface elements
- 📱 **Responsive Design** - Adapts to sidebar width with auto-wrapping filters and wider menus (280-450px)

### Advanced Features
- 🖼️ **Website Previews** - Screenshot thumbnails of bookmarks with hover preview popup
- 🔍 **High-Quality Preview Popups** - Hover over thumbnails to see 800x600 high-resolution preview
- 📌 **Smart Popup Positioning** - Preview popups appear above/below bookmarks to avoid covering content
- 💬 **URL Tooltips** - Hover over bookmark title/URL to see full URL in tooltip
- 📊 **Improved Status Bar** - Enhanced discoverability with visible "Scan All Bookmarks" label and centered status messages
- 📝 **Text-Only View** - View bookmark pages in text-only mode
- 🔄 **Bulk Operations** - Multi-select mode for batch editing/deletion
- 📋 **Duplicate Detection** - Find and manage duplicate bookmarks
- ⏮️ **Undo System** - Restore recently deleted bookmarks
- 📜 **Bookmark Changelog** - Track all bookmark and folder changes (creates, moves, deletes, renames) with persistent history
- 💾 **Pre-Sync Snapshot Protection** - Automatic snapshots before sync operations with one-click restore to undo mistaken syncs
- 🌍 **Favicon Display** - Show website icons

## Installation

### From Mozilla Add-ons (Recommended)
**Now officially available!** Install directly from the Mozilla Add-ons store for automatic updates and seamless integration.

**[Install from Mozilla Add-ons →](https://addons.mozilla.org/en-US/firefox/addon/bookmark-manager-zero/)**

This is the easiest and most secure installation method. Updates will be delivered automatically through Firefox.

### From Source Code (Development)
For development or testing purposes. **Note:** This method requires re-adding the extension every time Firefox closes.

1. Clone this repository:
   ```bash
   git clone https://gitlab.com/AbsoluteXYZero/BMZ-Firefox.git
   ```
2. Open Firefox and navigate to `about:debugging`
3. Click "This Firefox" → "Load Temporary Add-on"
4. Select `manifest.json` from the cloned directory

## Getting Started

Bookmark Manager Zero offers two ways to use the extension:

### Option 1: Native Bookmarks Mode (Default)
- **Works directly with Firefox's built-in bookmarks** - no setup required
- Changes sync **bidirectionally** between extension and native Firefox bookmarks
- No account or cloud sync needed
- Perfect for users who want enhanced bookmark management without GitLab

**Just install and start using!** All features work immediately with your existing Firefox bookmarks.

### Option 2: GitLab Sync Mode (Optional)
Add cloud backup and cross-device synchronization to your bookmarks:

1. **Create a free [GitLab account](https://gitlab.com)** and generate a Personal Access Token (PAT):
   - Navigate to GitLab → Settings → Access Tokens
   - Token name: "Bookmark Manager Zero" (or any name you prefer)
   - Scope required: **`api`** ✅
   - Expiration: Choose your preferred date
   - Click "Create personal access token"
   - **⚠️ CRITICAL**: PATs display only **ONCE** - copy immediately and save to a password manager
   - Track expiration date to avoid sync interruptions

2. **Configure Gitlab integration in the extension**:
   - Click the Gitlab icon in the GUI or open extension settings (gear icon)
   - Paste your token (must start with `glpat-` prefix)
   - Token will be encrypted with AES-256-GCM before storage
   - Choose to create new Snippet or connect to existing one

3. **Your bookmarks sync automatically**:
   - Changes sync across all your devices via private GitLab Snippets
   - Still works with native Firefox bookmarks (bidirectional sync maintained)
   - Auto-sync every 5 minutes when sidebar is open
   - Event-driven sync also triggers on bookmark/folder changes
   - **Important**: Sidebar must stay open for background sync to work

**Adding Sync to Existing Bookmarks**

Already using the extension? Add GitLab sync anytime:
1. Click the GitLab icon or settings (gear icon) → GitLab Snippet Sync
2. Enter your GitLab Personal Access Token
3. Choose your setup option:
   - **Create New Snippet** - Start fresh with a new snippet in GitLab
   - **Connect to Existing Snippet** - Link to a snippet you already created
4. **If you have local bookmarks**, you'll see a dialog with 3 options:
   - **Keep Local Bookmarks** - Cancel setup and keep your local bookmarks unchanged
   - **Merge Bookmarks** - Combine your local bookmarks with the snippet (recommended)
   - **Replace with Snippet** - Use only the snippet's bookmarks
     - Safety feature: Option to download backup before replacing
     - Choose "Download Backup & Replace" (recommended) or "Skip Backup & Replace"
5. After connecting, manual sync button options:
   - **Pull** - Download and merge remote bookmarks with local
   - **Push** (auto) - Upload local changes to remote
   - **Force Push** - Overwrite remote completely (Shift+Click sync button)

**Token Tips**
- Any PAT with `api` scope works as long as your GitLab account is in good standing
- The extension includes helpful error prompts to guide you if authentication issues occur
- Keep your token secure - it's encrypted before storage but treat it like a password

### Keyboard Shortcuts

#### Navigation (when item selected)
- `↑/↓` - Navigate bookmarks
- `←/→` - Collapse/expand folders or show/hide previews
- `Enter` - Open bookmark or toggle folder
- `Escape` - Clear selection

## Privacy

Bookmark Manager Zero respects your privacy:

- **All data stored locally** on your device
- **No tracking or analytics**
- **No advertisements**
- **Open source** - audit the code yourself

See [PRIVACY.md](PRIVACY.md) for complete privacy policy.

## External Services (Optional)

The extension can optionally use external services for enhanced features. **All can be disabled in settings:**

### Default Services (can be disabled)
- **WordPress mshots** - Website screenshot previews
- **8 Blocklist Sources** - Dual URLhaus coverage (Active + Historical), BlockList Project (Malware/Phishing/Scam), HaGeZi TIF, Phishing-Filter, OISD Big
- **URLVoid** - Multi-source reputation analysis from 30+ security engines
- **Google Favicons** - Website icons

### User-Configured Services (require API keys)
- **Google Safe Browsing** - Additional malware protection (10K requests/day)
- **Yandex Safe Browsing** - Geographic threat diversity (100K requests/day)
- **VirusTotal** - Comprehensive threat scanning from 70+ AV engines (500 requests/day)

All external service usage is disclosed in [PRIVACY.md](PRIVACY.md).

### Important Notice: GitLab API Usage

**How GitLab Snippets Are Used:**
- This extension uses GitLab Snippets as intended by GitLab: for storing structured data
- Your bookmarks are stored in a private Snippet in your own GitLab account
- Snippets are a legitimate GitLab feature designed for storing code, configuration, and structured data
- The extension uses standard GitLab Snippets API endpoints documented in the official GitLab API

**API Usage Considerations:**
- **Event-driven sync**: API calls are made when you add/edit/delete bookmarks or folders
- **Auto-sync polling**: When enabled, checks for remote changes every 5 minutes (when sidebar is open)
- **Manual sync**: Use the "Pull from Snippet" and "Push to Snippet" buttons for manual control
- **Sidebar requirement**: Sidebar must remain open for background sync to work
- **Rate limiting protection**: Built-in exponential backoff with jitter respects GitLab API limits
- **Rate limits**: GitLab has API rate limits; typical bookmark usage stays well within limits

**Best Practices:**
- Keep the sidebar open if you want automatic background sync
- Use manual "Snippet Sync button" in the GUI to check for changes from other devices when needed
- The extension automatically syncs when you make changes (add/edit/delete bookmarks)
- For very large collections (>5000 bookmarks), edits will naturally sync less frequently

## How Link & Safety Checking Works

This section provides technical details on how the extension determines link status and safety for anyone interested in the methodology.

### Link Status Checking

The extension checks if bookmark URLs are still accessible and categorizes them as **Live**, **Dead**, or **Parked**.

#### Detection Method

1. **Initial Domain Check**: The URL's domain is first checked against a list of 22+ known domain parking services:
   - **Registrars**: HugeDomains, GoDaddy, Namecheap, NameSilo, Porkbun, Dynadot, Epik
   - **Marketplaces**: Sedo, Dan.com, Afternic, DomainMarket, Squadhelp, BrandBucket, Undeveloped, Atom
   - **Parking Services**: Bodis, ParkingCrew, Above.com, SedoParking

2. **HTTP HEAD Request**: A lightweight HEAD request is sent with CORS mode to track redirects (10-second timeout)
   - No page content is downloaded
   - Credentials are omitted for privacy
   - Falls back to no-cors mode if CORS is blocked

3. **Redirect Detection**: If the URL redirects to a different domain, the final destination is checked against parking domain lists
   - Example: `example.com` → `hugedomains.com/domain/example.com` = **Parked**
   - Same-site redirects (www, HTTPS) are not flagged

4. **Response Interpretation**:
   - **Successful response** → Live
   - **Redirects to parking domain** → Parked
   - **Timeout/Network Error** → Dead

5. **Fallback Strategy**: If HEAD fails, a GET request is attempted with the same redirect detection logic

#### Performance & Rate Limiting

**Optimized Batch Processing:**
- Bookmarks are scanned in batches of 10 with a 100ms delay between batches
- Concurrency limiter enforces maximum 10 concurrent network requests
- Link and safety checks run in parallel for up to 2x faster scanning per bookmark

**Smart Timeout Strategy:**
- Link checks: 5s timeout (HEAD request), 5s timeout (GET fallback)
- URLVoid checks: 5s timeout (down from 15s)
- VirusTotal checks: 8s timeout (down from 15s)
- Timeout handling: Sites that timeout are marked as 'live' (slow server) instead of 'dead'
- No redundant GET fallback on timeout - saves up to 5s per slow site

**Network Protection:**
- Maximum 10 bookmarks actively scanning at any time (controlled by concurrency limiter)
- With parallel checks, actual concurrent requests can reach up to 20 (10 bookmarks × 2 checks each)
- 100ms delay between batches prevents DNS overload and router disruption

**Expected Performance:**
- Approximately 30-50 bookmarks per second throughput
- 1,000 bookmarks: ~30-60 seconds
- 5,000 bookmarks: ~2-5 minutes
- Performance varies based on network speed and server response times

**Why These Settings:**
- Batch size of 10: Sweet spot between speed and "waiting for stragglers" (Promise.all waits for slowest bookmark)
- 10 concurrent limit: Prevents overwhelming DNS resolver and WiFi router
- 100ms batch delay: Minimal pause that prevents request spikes
- 5s timeouts: Aggressive but appropriate since timeouts are marked as 'live' not 'dead'
- Parallel checks: Each bookmark queues both link and safety check simultaneously for maximum throughput

#### Caching
Results are cached locally for 7 days to minimize network requests.

#### Privileged URLs (Browser Internal Pages)

Certain URL schemes are recognized as browser internal pages and are automatically marked as trusted without scanning:

- `about:*` - Firefox internal pages (e.g., `about:debugging`, `about:config`)
- `chrome:*` - Browser internal pages
- `moz-extension:*` - Firefox extension pages
- `chrome-extension:*` - Extension pages
- `view-source:*` - View source pages
- `jar:*` - JAR resources
- `resource:*` - Browser resources

**Visual Indicators:**
- **Green chain-link icon** with tooltip: "Link Status: Browser internal page"
- **Green shield icon** with tooltip: "Not scanned (trusted browser page)"

These URLs are inherently safe and don't require HTTP status checks or security scanning.

---

### Safety Checking

The extension checks URLs against multiple threat databases to identify malicious, phishing, or scam websites.

#### Phase 1: Blocklist Lookup (Free, No API Key Required)

URLs are checked against eight community-maintained blocklists with dual URLhaus coverage:

| Source | Type | Description | Entries |
|--------|------|-------------|---------|
| **[URLhaus (Active)](https://urlhaus.abuse.ch/)** | Malware URLs | Official abuse.ch list - actively distributing malware (updated every 5 min) | ~107K |
| **[URLhaus (Historical)](https://urlhaus.abuse.ch/)** | Malware Domains | Historical threats via CDN mirror (updated every 12 hours) | ~37K |
| **[BlockList Project - Malware](https://github.com/blocklistproject/Lists)** | Malware Domains | Community-maintained malware domain list | ~300K |
| **[BlockList Project - Phishing](https://github.com/blocklistproject/Lists)** | Phishing Domains | Known phishing sites | ~214K |
| **[BlockList Project - Scam](https://github.com/blocklistproject/Lists)** | Scam Domains | Known scam websites | ~112K |
| **[HaGeZi TIF](https://github.com/hagezi/dns-blocklists)** | Threat Intel Feeds | Comprehensive malware, phishing, and scam domains | 608K |
| **[Phishing-Filter](https://gitlab.com/malware-filter/phishing-filter)** | Phishing URLs | Aggregated phishing database from OpenPhish & PhishTank | ~21K |
| **[OISD Big](https://oisd.nl/)** | Multi-source | Comprehensive blocklist aggregator covering malware, ads, trackers | ~215K |

**Total Coverage**: **~1.35M unique malicious domains** after deduplication (from 1.6M total entries)

**Implementation Details:**
- Blocklists are downloaded and cached locally in IndexedDB
- Updated every 24 hours automatically
- URLhaus Active uses CORS proxy to access official abuse.ch list with full URL context
- URLhaus Historical uses GitHub mirror for redundancy and historical coverage
- OISD Big uses GitHub mirror to avoid CORS restrictions
- Both full URLs and domain:port combinations are checked
- Dual URLhaus sources provide complementary coverage (active threats + historical data)
- Domain-level matching catches malicious IPs even if specific path differs
- **Any match → Unsafe** (tooltip shows all sources that flagged it)
- All scanning continues through every layer to aggregate findings
- Suspicious pattern detection provides additional coverage for IP-based threats

**Trusted Domain Exceptions:**
To prevent false positives, certain well-known trusted platforms are exempted from local blocklist checks (but still scanned by API-based services):
- `archive.org` - Internet Archive
- `*.github.io` - GitHub Pages (all subdomains)
- `*.githubusercontent.com` - GitHub raw content (all subdomains)
- `*.github.com` - GitHub domains (all subdomains)
- `*.gitlab.com` - GitLab domains (all subdomains)
- `*.gitlab.io` - GitLab Pages (all subdomains)
- `docs.google.com` - Google Docs
- `sites.google.com` - Google Sites
- `drive.google.com` - Google Drive

These domains bypass URLhaus and other local blocklists but are still checked by Google Safe Browsing, Yandex, and VirusTotal if API keys are configured.

#### Phase 2: Google Safe Browsing (Optional, Requires API Key)

If configured, URLs are checked against Google's threat database:

- **Threat Types Checked**: Malware, Social Engineering, Unwanted Software, Potentially Harmful Applications
- **Method**: POST request to Safe Browsing API v4
- **Rate Limit**: 10,000 requests/day (free tier)
- **Results aggregated** with other findings (doesn't stop scanning)

#### Phase 3: Yandex Safe Browsing (Optional, Requires API Key)

If configured, provides geographic threat diversity:

- **Coverage**: Russian and Eastern European threats
- **Method**: POST request to Yandex Safe Browsing API
- **Rate Limit**: 100,000 requests/day (free tier)
- **Results aggregated** with other findings

#### Phase 4: VirusTotal (Optional, Requires API Key)

If configured, URLs are submitted to VirusTotal's multi-engine scanner:

1. URL is submitted for analysis
2. Results are retrieved after 2 seconds
3. 70+ antivirus engines analyze the URL

**Threat Determination**:
- **2+ engines flag as malicious → Unsafe**
- **1 malicious OR 2+ suspicious → Warning**
- **0 detections → Safe**

**Rate Limit**: 500 requests/day, 4 requests/minute (free tier)

#### Phase 5: Suspicious Pattern Detection

The URL is analyzed for suspicious patterns (scanning continues regardless of previous results):

| Pattern | Detection | Result |
|---------|-----------|--------|
| **HTTP Only (Unencrypted)** | URL uses `http://` and doesn't redirect to HTTPS | Warning |
| **HTTP Only (redirects to HTTPS)** | URL uses `http://` but site redirects to HTTPS | Warning (informational) |
| **URL Shortener** | Domain is bit.ly, tinyurl.com, t.co, etc. (18+ services) | Warning |
| **Suspicious TLD** | Domain ends in .xyz, .top, .tk, .ml, .ga, .cf, .gq, .cc, etc. (30+ TLDs) | Warning |
| **IP Address** | URL uses IP address instead of domain name (IPv4 or IPv6) | Warning |

**Note:** Multiple patterns can be detected simultaneously (e.g., HTTP + Suspicious TLD).

#### Final Status Determination

**Scanning Methodology**: All layers are checked sequentially, and results are aggregated. The extension does NOT stop at the first flag—it continues through all enabled layers to provide comprehensive threat intelligence.

| Check Result | Final Status | Priority |
|--------------|--------------|----------|
| Blocklist match (any source) | **Unsafe** (red shield) | Highest |
| Google Safe Browsing match | **Unsafe** (red shield) | Highest |
| Yandex Safe Browsing match | **Unsafe** (red shield) | Highest |
| VirusTotal 2+ malicious | **Unsafe** (red shield) | Highest |
| VirusTotal 1 malicious or 2+ suspicious | **Warning** (yellow shield) | Medium |
| Suspicious patterns found | **Warning** (yellow shield) | Medium |
| All checks pass | **Safe** (green shield) | Normal |

**Multi-Source Attribution**: Tooltips display all sources that flagged a URL (e.g., "Detected by: URLhaus, Google Safe Browsing, Suspicious TLD"). This provides transparency and helps identify false positives.

#### Caching & Privacy

- All results are cached locally for 7 days
- Only URLs are sent to external services (no personal data)
- API keys are encrypted with AES-256-GCM before storage
- All features can be disabled in settings

---

### Whitelisting

Users can whitelist specific URLs to:
- Skip safety checks for trusted sites
- Override false positives
- Whitelisted bookmarks display a white shield indicator instead of green
- Add/remove from whitelist via bookmark context menu (right-click)
- Use the "Trusted" filter to view all whitelisted bookmarks
- Whitelist is stored locally and persists across sessions

## Permissions

### Required Permissions
- `bookmarks` - Read and manage your Firefox bookmarks
- `storage` - Save preferences and cache locally
- `tabs` - Open bookmarks in tabs
- `<all_urls>` - Check if bookmark links are still working and download malware blocklists
  - Sends HEAD requests to check bookmark URLs (no content accessed)
  - Downloads free public blocklists for malware protection
  - Can be fully disabled in settings

## Development

### Project Structure

### Key Technologies
- Vanilla JavaScript (no frameworks)
- Material Design 3 color system
- Firefox WebExtensions API
- AES-256-GCM encryption for API keys
- CSS Grid & Flexbox

## Security

### Security Features
- ✅ Strong Content Security Policy (CSP)
- ✅ AES-256-GCM encryption for stored API keys
- ✅ No eval() or inline scripts
- ✅ HTTPS-only external requests
- ✅ Input validation and sanitization
- ✅ XSS protection

### Reporting Security Issues
Please report security vulnerabilities via GitLab Issues (mark as security issue).

## Browser Compatibility

- **Firefox:** ✅ Fully supported (Manifest V3)
- **Chrome:** ❌ Use [Chrome version](https://gitlab.com/AbsoluteXYZero/BMZ-Chrome/)
- **Edge:** ❌ Use [Chrome version](https://gitlab.com/AbsoluteXYZero/BMZ-Chrome/) (Chromium-based)


## Changelog

### v3.7 (Current) - UI Improvements

**New Features:**
- 🎨 **Enhanced GitLab Login Button** - GitLab tanuki icon now displays "LOGIN" text overlay for clarity
  - Bold black text on white tanuki makes it immediately obvious this is a login button
  - Automatically switches to logout icon when authenticated
  - Improves user experience by making button purpose crystal clear

**Improvements:**
- 🔄 **Conditional Manual Sync Button** - Manual sync button now only appears when logged in
  - Hides when not authenticated to keep UI clean
  - Automatically shows/hides based on GitLab authentication state
  - Reduces UI clutter for users not using GitLab sync

---

### v3.6 - Pre-Sync Snapshot & Restore

**New Features:**
- 💾 **Pre-Sync Snapshot Protection** - Automatic safety net for sync operations
  - Creates complete bookmark snapshot before destructive sync operations (Pull Remote to Local, Bidirectional Merge)
  - Stores full bookmark tree state before replacing with remote data
  - Allows one-click restoration to pre-sync state if sync was done mistakenly
  - Accessible via changelog with prominent "Restore Pre-Sync Bookmarks" button
  - Clears old changelog entries (invalid IDs after sync) automatically
  - Prevents data loss from accidental sync operations

**How It Works:**
- When you perform "Pull Remote to Local" or "Bidirectional Merge", a snapshot is automatically created
- Changelog shows sync operation with orange sync icon and restore button
- Click "Restore Pre-Sync Bookmarks" to undo the sync and restore your previous bookmarks
- Confirms before restoration with clear warning about replacing current bookmarks
- Works across all sync operations that replace bookmark IDs

**User Experience:**
- Clear visual indicators in changelog (orange sync icon)
- Detailed confirmation dialogs prevent accidental restoration
- Full transparency about what will be replaced
- No manual backups needed - automatic protection for every sync

---

### v3.5 - Pretty-Printed Snippets

**Improvements:**
- 📄 **Pretty-Printed JSON Snippets** - GitLab snippets now use formatted JSON for better readability
  - Changed from single-line compact JSON to pretty-printed format with 2-space indentation
  - Makes snippet content much easier to read and debug when viewing in GitLab
  - All future snippet creations and updates will use formatted JSON

---

### v3.4 - GitLab Sync Bug Fixes

**Bug Fixes:**
- 🐛 **Fixed GitLab Snippet Merge Error** - Resolved "No Snippet ID provided" error when merging local bookmarks into snippet
  - Fixed parameter order mismatch in `updateBookmarksInSnippet()` function call at sidebar.js:11545
  - Fixed global `snippetId` variable being set after merge operation instead of before at sidebar.js:11724-11725
  - Merge operation now properly sets snippet ID before attempting to update
  - Ensures smooth GitLab sync setup when merging local bookmarks with existing snippets
- 🐛 **Fixed Missing calculateChecksum Function** - Resolved "calculateChecksum is not defined" error when creating new snippets
  - Added missing standalone `calculateChecksum()` function at sidebar.js:10737
  - Function was already present as a class method but missing as standalone utility
  - Fixes snippet creation and update operations
- 🐛 **Fixed Empty Snippet Creation** - Resolved issue where creating new snippet would create empty bookmark folders
  - Fixed Firefox bookmark tree root folder detection at sidebar.js:10777-10780
  - Changed from checking non-existent `rootFolder.root` property to checking `rootFolder.id`
  - Now correctly identifies Firefox root folders: toolbar_____, menu________, unfiled_____, mobile______
  - Snippets now properly include all bookmarks and folders when created
- 🐛 **Fixed GitLab Button Not Updating** - GitLab button now properly changes to logout icon when logged in
  - Updated `updateGitLabButtonIcon()` function at sidebar.js:10960-10978
  - Button now shows logout icon when connected and GitLab logo when disconnected
  - Matches Chrome version behavior for consistency

---

### v3.3 - Real-time Progress Updates (All Scan Types)

**Improvements:**
- 📊 **Universal Real-time Progress** - ALL scan types now update progress after every individual bookmark
  - Fixed folder expansion scanning (autoCheckBookmarkStatuses) to update per bookmark instead of per batch
  - Fixed rescan all bookmarks to update per bookmark
  - Fixed rescan folder to update per bookmark
  - Applies to all scan operations for consistent, responsive feedback

---

### v3.1 - Session Persistence & Progress Updates

**New Features:**
- 💾 **Session State Persistence** - Bookmark Manager Zero now remembers where you left off when you reopen it
  - Restores scroll position to exactly where you were
  - Remembers which folders were expanded/collapsed
  - Preserves your search query and active filters
  - Session clears when browser closes for privacy
- 📊 **Real-time Scan Progress** - Progress counter now updates after every bookmark scanned instead of every 10
  - More responsive and accurate progress feedback during scans
  - Consistent behavior across all scan operations

**Bug Fixes:**
- 🐛 **Fixed Stop Scan Button** - Stop scanning button now works correctly
  - Corrected message action name mismatch between sidebar and background script
  - Changed from 'stopBackgroundScan' to 'stopScan' to match background listener
- 🐛 **Fixed Rescan All Bookmarks** - Resolved "allBookmarks is not defined" error
  - Added proper bookmark retrieval before starting scan
  - Now correctly gets all bookmarks using getAllBookmarksFlat()

---

### v3.0 - Critical Fixes & Performance Optimizations

**Bug Fixes:**
- 🐛 **Fixed Duplicate clearCache() Function** - Removed duplicate function definition that was causing conflicts
  - Deleted second definition at sidebar.js:9720, keeping primary at sidebar.js:9164
  - Prevents function overwriting and ensures consistent cache behavior
- 🐛 **Fixed Duplicate updateBookmarkStatusInDOM()** - Resolved duplicate function definitions
  - Merged implementations from sidebar.js:7232 and sidebar.js:7261
  - Ensures consistent bookmark status updates in DOM
- 🐛 **Fixed Duplicate getAllFolders()** - Standardized function signature across codebase
  - Resolved conflicting signatures at sidebar.js:8164 and sidebar.js:9364
  - Consistent folder retrieval throughout extension
- 🐛 **Fixed Duplicate findFolderById()** - Merged duplicate implementations
  - Combined versions from sidebar.js:6741 and sidebar.js:8180
  - Unified folder lookup functionality
- 🐛 **Fixed Missing window.initSidebar** - Resolved undefined function reference
  - Added proper initialization function or removed orphaned reference at sidebar.js:2527
  - Prevents runtime errors during sidebar initialization
- 🔧 **Fixed Module Scope Issues** - Replaced this._syncInProgress with proper module-level variables
  - Corrected scope at sidebar.js:2502-2529
  - Ensures proper state management across sidebar lifecycle

**Code Quality Improvements:**
- ⚡ **Improved Cache Mutex** - Enhanced cache locking mechanism
  - Replaced busy-wait polling with efficient mutex implementation
  - Better performance and resource usage
- 🔒 **Enhanced Promise Handling** - Added proper rejection handling in retry flows
- ✅ **All HTML Element IDs Validated** - Fixed broken DOM references
- ✅ **Comprehensive Error Handling** - Robust error boundaries throughout
- ✅ **Proper Async/Await Usage** - Clean asynchronous code patterns
- ✅ **Effective Caching Strategies** - Optimized performance with smart caching
- ✅ **Rate Limiting added for APIs** - Prevents API throttling issues

**Performance Optimizations:**
- ⚡ **Concurrency Limiting** - Added ConcurrencyLimiter class to enforce maximum 10 concurrent network requests
- 🚀 **Parallel Scanning** - Link and safety checks now run in parallel for up to 2x faster scanning per bookmark
- ⏱️ **Reduced Timeouts** - Link checks reduced from 10s→5s, URLVoid from 15s→5s, VirusTotal from 15s→8s
- 📦 **Optimized Batch Processing** - Increased batch size from 5→10, reduced delay from 1000ms→100ms
- 🎯 **Smart Timeout Handling** - Timeout errors now mark sites as 'live' (slow server) instead of retrying with GET fallback
- 📈 **Improved Throughput** - ~30-50 bookmarks/second (1,000 bookmarks in ~30-60 seconds)
- 🌐 **Network Protection** - Prevents DNS overload and router disruption with controlled concurrency

---

### v2.7.2 - Whitelist Persistence Fix

**Bug Fixes:**
- 🐛 **Fixed whitelist persistence** - Whitelisted bookmarks now maintain their status after sidebar reload
  - Added whitelist check during cache restoration
  - Whitelist status takes priority over cached statuses
  - Fixes issue where whitelisted bookmarks showed gray shields after reopening sidebar

---

### v2.7.1 - Bug Fixes & Package Update

**Package Updates:**
- 📦 **Include qrcode-lib.js** - Ensures QR code generation library is included in extension package

**Bug Fixes:**
- 🐛 **Fixed cache race condition** - Resolved issue where parallel bookmark scans would overwrite each other's cache entries
  - Added mutex locks to prevent concurrent cache writes
  - Fixes gray indicators appearing after folder rescan and sidebar reload
  - Ensures privileged URLs (about:, moz-extension://) persist in cache correctly
- 🐛 **Fixed folder rescan progress** - Folder rescans now show real-time UI updates and status bar progress
  - Added `renderBookmarks()` call after each batch during folder rescan
  - Reduced batch delay from 1000ms to 300ms for 3x faster scanning
  - Status bar shows "Scanning folder: X/Y" during scan
- 🐛 **Fixed blocklist loading timing** - Scans now proactively load blocklist database before starting
  - Added `ensureBlocklistReady` message handler to trigger database update before scanning
  - Prevents "unknown" safety status results when database loads mid-scan
  - Applies to both folder rescans and background scans

---

### v2.7.0 - First-Time Setup & QR Code Generation

**New Features:**
- 🎆 **First-Time Setup Card** - Welcoming onboarding experience for new users
  - Appears only once on first installation (never on updates)
  - Explains auto-scan behavior and folder scanning
  - One-click option to scan all bookmarks immediately
  - Clear disclaimer about false positives/negatives
  - Persistent flag independent of cache clearing
- 📱 **QR Code Generator** - Generate QR codes for any bookmark
  - Right-click bookmark → "Generate QR Code"
  - Toolbar button for quick QR code generation of current page URL
  - 100% local generation (privacy-focused, no external requests)
  - Editable URL field with live QR code regeneration
  - Works completely offline
  - Perfect for quickly accessing bookmarks on mobile devices
- 🔄 **Background Scanning** - Bookmark scanning continues even when sidebar is closed
  - Scanning runs in background script for persistent operation
  - Progress automatically syncs when sidebar reopens
  - Scan results restore from cache upon reopening
  - Processes bookmarks in batches (10 items, 300ms delay)

**User Experience:**
- Setup card positioned as inline banner between header and bookmarks
- QR code popup with centered layout and Material Design styling
- QR code toolbar button with distinctive QR icon (left of themes button)
- Real-time QR code updates as you edit the URL
- Improved status bar with "Scan All Bookmarks" text label for better discoverability
- Centered status messages in status bar
- Matches enhanced-blue theme seamlessly

---

### v2.6.0 - Performance & Memory Optimization

**Performance Improvements:**
- ⚡ **10x Faster Scanning** - Fixed parallel processing bug that was checking bookmarks sequentially instead of in parallel
- 🚀 **2x Higher Throughput** - Increased batch size from 5 to 10 bookmarks per batch for ~33 bookmarks/second
- 📉 **67% Faster Large Scans** - 4000 bookmarks now scan in ~2 minutes instead of ~40 minutes
- 🔄 **Eliminated Redundant Downloads** - Fixed blocklist downloading multiple times during parallel scans

**Memory Optimizations:**
- 🧹 **Smart History Tracking** - Safety history only records actual status changes, not duplicate entries
- 💾 **Automatic Memory Cleanup** - Clears temporary bookmark tracking data after each scan
- 🗑️ **Orphaned Entry Removal** - Removes safety history for deleted bookmarks on sidebar reload
- 📊 **Reduced Memory Growth** - Prevents unbounded memory accumulation during multiple scans

**Bug Fixes:**
- Fixed sidebar lag after scanning 4000+ bookmarks (memory leak resolved)
- Fixed status bar not resetting to "Ready" after stopped scans
- Improved scan cancellation handling

**Technical Details:**
- Changed from sequential to parallel bookmark processing within batches
- Added `blocklistLoading` flag to prevent concurrent blocklist downloads
- Implemented `checkedBookmarks.clear()` after scan completion
- Added `cleanupSafetyHistory()` function for orphaned entry removal
- Only saves safety history on actual status changes instead of every scan

---

### v2.5.0 - Bookmark Changelog & History Tracking

**New Features:**
- 📜 **Bookmark Changelog** - Comprehensive history tracking for all bookmark and folder operations
  - Tracks creates, updates, moves, and deletes for both bookmarks and folders
  - Accessible via "View Bookmark Changelog" button in settings menu (just under Export Bookmarks)
  - Persistent storage survives browser restarts and sidebar closes
  - Maximum 1000 entries to prevent unlimited growth
- 🎨 **Modern SVG Icons** - Color-coded operation icons matching app aesthetic
  - Green: Create operations
  - Red: Delete operations
  - Blue: Move operations
  - Orange: Update/rename operations
- 📋 **Clickable URLs** - Click any bookmark URL in changelog to copy to clipboard with visual feedback
- 🕒 **Human-Readable Timestamps** - "5 minutes ago", "2 hours ago", etc.
- 📁 **Folder Path Tracking** - Shows full folder hierarchy for moved items
- 🔄 **Rename Tracking** - Displays old and new names for renamed items
- 🗑️ **Clear History** - Option to clear all changelog entries

**Implementation Details:**
- Uses browser.storage.local for persistent storage across sessions
- Automatic folder path reconstruction using recursive traversal
- Detailed move tracking shows "from → to" folder paths
- Modal interface with scrollable history and clear action buttons

---

### v2.4.0 - Interactive Preview & UI Enhancements

**Preview System Improvements:**
- 🖼️ **High-Quality Preview Popups** - Hover over bookmark thumbnails to see 800x600 high-resolution preview (2.5x larger than thumbnails)
- 📌 **Smart Positioning** - Preview popups intelligently position above/below bookmarks to avoid covering content
- 💬 **URL Tooltips** - Full bookmark URL displayed on hover over title/URL text
- ⚙️ **Preview Popup Toggle** - New setting to enable/disable preview popups in Display Options

**Theme Fixes:**
- 🎨 **Accent Color Fix** - Accent color picker now correctly applies to folder icons in Enhanced and Tinted themes
- 🌈 **Tinted Theme Improvements** - Context menus now use light backgrounds for better readability
- 🎨 **Vibrant Hue Slider** - Tinted theme hue slider now displays full-saturation rainbow gradient

**Technical Implementation:**
- Preview popups load dedicated 800x600 images from mshots service (not upscaled thumbnails)
- Smart positioning algorithm calculates available space and chooses optimal placement
- 10px gap between bookmark and popup for visual clarity
- Graceful fallback to low-res thumbnail if high-quality image fails to load
- Settings persisted to browser storage with checkbox state management

---

### v2.3.0 - Cache Persistence & Trusted Domains

**Cache Restoration:**
- 💾 **Persistent Scan Indicators** - Bookmark scan results now persist across sidebar reopens
- ⚡ **Instant Icon Display** - Shield and link status icons appear immediately from cache (7-day TTL)
- 🔄 **Smart Auto-Check** - Only scans bookmarks without cached results, reducing network requests
- 🎯 **Better UX** - No more "grey unknown" resets when closing/reopening sidebar

**Trusted Domain System:**
- ✅ **Platform Allow-List** - Prevent false positives for trusted hosting platforms and services
- 🌐 **9 Trusted Domains** - GitHub, GitLab, Archive.org, Google services bypass local blocklists
- 🔍 **API Scanning Still Active** - Trusted domains still checked by Google/Yandex/VirusTotal if configured
- 📋 **Documented Exemptions** - Clear documentation of which domains bypass blocklist checks

**Parking Detection Improvements:**
- 🏠 **Hosting Platform Exemptions** - GitHub Pages, GitLab Pages, Netlify, Vercel, Heroku no longer flagged as "parked"
- 🎯 **3-Layer Protection** - Exemptions apply to domain-based, redirect-based, AND content-based parking detection
- 🚫 **No More False Positives** - Legitimate static hosting platforms correctly show as "live"

**Rescan Improvements:**
- 🔄 **Cache Bypass on Rescan** - All manual rescan operations now force fresh checks
- 📊 **Applies to All Rescans** - Individual bookmark, folder, and "Rescan All" button all bypass cache
- ✅ **Guaranteed Fresh Results** - No more stale cached results on manual recheck

**Technical Implementation:**
- Cache restoration function (`restoreCachedBookmarkStatuses()`) runs after bookmark load
- `bypassCache` parameter propagates through entire message chain for rescans
- Trusted domains checked before blocklist lookups (security scanning still active)
- Parking exemptions skip all 3 detection layers (domain, redirect, content)

---

### v2.2.0 - Font Size Control

**New Feature:**
- 🔤 **Independent Font Size Slider** - Adjust text size (70-150%) without affecting container sizes
- 📐 **Content Zoom Renamed** - First slider clarified as "Content Zoom" for better understanding
- 🎯 **Precise Text Control** - Scale bookmark titles, URLs, and folder names independently from layout

**Implementation:**
- New Font Size slider in zoom menu (between Content Zoom and GUI Scale)
- Applies to all view modes (list and grid 2-6 columns)
- Persistent preference storage
- Works independently from content zoom

---

### v2.1.1 - Separator Fix

**Bug Fixes:**
- 🐛 **Fixed Separator Display** - Firefox bookmark toolbar separators no longer appear as "data:" entries in the extension
- ✅ **No More False Positives** - Separators are now properly filtered out and won't trigger malware warnings
- 📊 **Accurate Counts** - Bookmark counts now exclude separators for accurate totals

**Technical Details:**
- Added separator filtering in all bookmark traversal functions
- Separators (`type: 'separator'`) are now skipped in rendering, counting, and scanning operations

---

### v2.1.0 - Permission Cleanup & Documentation

**Permission Improvements:**
- 🔒 **Removed Unnecessary Permissions** - Eliminated unused `webRequest` permission for better privacy
- 📝 **Simplified Host Permissions** - Removed redundant URLhaus and OISD entries (covered by `<all_urls>`)
- 🛡️ **Updated Documentation** - Clarified `<all_urls>` permission usage for link checking and blocklist downloads

**What Changed:**
- More accurate permissions documentation in README
- Cleaner manifest with minimal required permissions
- No functional changes - everything works exactly the same

---

### v2.0.0 - Enhanced Themes & Expanded Security

**Security Enhancements:**
- 🔒 **5 Additional Blocklist Sources** - Expanded from 3 to 8 total sources for comprehensive malware protection
  - HaGeZi TIF (608K+ threat intel domains)
  - Phishing-Filter (21K+ phishing URLs from OpenPhish & PhishTank)
  - OISD Big (215K+ multi-source blocklist)
  - BlockList Project: Malware (435K+ domains), Phishing (190K+ domains), Scam (1.3K+ domains)
- 🌍 **Yandex Safe Browsing API** - Optional geographic threat diversity for Russian/Eastern European threats (100K requests/day free tier)
- 📊 **Total Coverage: ~1.35M unique malicious domains** (deduplicated from 1.6M entries)
- 🏷️ **Source Attribution** - Malware detection tooltips now show which blocklist(s) flagged the URL
- ⚠️ **Warning Status** - Suspicious URL patterns now display yellow warning shield
- 🔧 **Toggle Controls** - Added ability to disable link checking and safety checking independently

**New Themes:**
- 🎨 **5 New Enhanced Themes** - Enhanced Blue (default), Enhanced Light, Enhanced Dark, Enhanced Gray, plus Tinted
- 💧 **3D Depth Effects** - Enhanced visual depth with rounded containers, sophisticated shadows, and modern effects
- 🌈 **Tinted Theme Customization** - Full hue and saturation controls for Tinted theme
- ✨ **8 Total Themes** - Comprehensive theme collection for every preference

**UI/UX Improvements:**
- 🎯 **Fixed Display Menu Overlay** - Resolved invisible element blocking folder interactions
- 📏 **Adaptive Menu Width** - Auto-sizing menus (280-450px) that fit content while staying within viewport
- 📊 **Improved Opacity Control** - Restructured bookmark opacity slider for better visibility
- 🔲 **Enhanced Spacing** - 3px margins on header and status bar in enhanced themes
- 🎨 **Removed Invert Text Toggle** - Simplified theme menu (no longer needed)
- 🗂️ **Cleaner Folder Design** - Removed "▶" chevron symbols for streamlined appearance

**Menu System:**
- 🔄 **Auto-Wrapping Filters** - Better responsive layout for filter toggles
- 🖱️ **Context-Aware Interactions** - Proper pointer events to prevent UI conflicts
- 📐 **Wider Menu Items** - Improved readability with content-adaptive width

**Technical:**
- Parallel blocklist downloads with unified Set for O(1) lookups
- Multiple format parsing (plain text, hosts files, URLhaus format, wildcard domains)
- Updated all theme CSS classes from "liquid/glass" to "Enhanced" naming

### v1.7.0 - Enhanced Theming & Menu Improvements

**New Features:**
- 🎨 **Bookmark Opacity Slider** - Control bookmark background transparency (0-100%) directly from Theme menu
- ✍️ **Custom Text Color Picker** - Full color customization for bookmark and folder text with visual color picker and reset button
- 🎨 **Light Gray Default** - Text color defaults to light gray (#e8e8e8) which works reliably with Firefox's color picker
- ⚡ **Real-Time Color Preview** - Color pickers apply changes instantly as you adjust colors

**Improvements:**
- 📐 **Improved Menu Positioning** - All menus (Theme, View, Zoom, Settings) now respect 16px margins from viewport edges
- 🎯 **Enhanced Context Menu** - Bookmark context menus never extend behind toolbar, with better overflow handling
- 📱 **Better Responsive Menus** - Menus scale properly to viewport width with increased margins for cleaner layout
- 🎨 **Reorganized Theme Menu** - Bookmark Opacity, Accent Color, and Text Color logically grouped for easy access
- 🎯 **Reduced Font Sizes** - Accent Color and Text Color labels now use matching 11px font size for consistency

**Bug Fixes:**
- 🐛 **Firefox Color Picker Workaround** - Fixed Firefox bug where pure white (#ffffff) prevented custom color selection by using light gray default
- 🐛 Fixed context menus sometimes positioning behind header/toolbar
- 🐛 Fixed menu overflow on narrow viewports
- 🐛 Fixed opacity affecting text readability (now only affects background via CSS pseudo-element)
- 🐛 Fixed text color not affecting bookmark URLs (now applies to URLs in addition to titles and folder names)
- 🐛 Fixed menu positioning calculations for edge cases

**Technical Implementation:**
- **Bookmark Opacity**: Uses CSS `::before` pseudo-element to apply opacity only to the background layer, keeping text and icons at full opacity for better readability. The opacity value is controlled via CSS variable `--bookmark-container-opacity`.
- **Text Color**: Uses CSS `custom-text-color-style` that persists across dynamic DOM changes. Targets `.bookmark-title`, `.folder-title`, and `.bookmark-url` elements specifically for precise color control.
- **Firefox Color Picker**: Pure white (#ffffff) as default value prevents Firefox's native color picker from initializing the custom color gradient area. Using #e8e8e8 (light gray) works around this browser bug while remaining visually close to white. Users can still select pure white after initialization.

---

### v1.6.0 - UI Refinements & Custom Navigation

**New Features:**
- 📁 **Default Start Folder** - Choose which folder to auto-expand when opening the sidebar
- ⚪ **Trusted Filter** - New filter chip to view only whitelisted bookmarks (white shield icon at far right)
- 🎨 **Accent Color in Theme Menu** - Moved accent color picker from settings to theme menu for better organization
- 📏 **Compact Filter Chips** - Reduced size of safety filter chips so all 4 fit on one line

**Improvements:**
- 🔄 **Streamlined Whitelist Management** - Removed whitelist panel from settings menu; use Trusted filter instead
- 🎯 **Simplified Accent Color Picker** - Removed Done button as changes apply instantly
- 📐 **Compact Background Settings** - Reduced size of background image controls to save screen space
- 🎯 **Reorganized Settings** - Theme-related settings (theme, accent color, background, zoom, GUI scale) moved to theme menu

**Bug Fixes:**
- 🐛 Fixed accent color picker triggering theme switch when clicked
- 🐛 Fixed Safe filter excluding whitelisted bookmarks (now separate Trusted filter)

---

### v1.5.0 - Grid View & Link Detection Improvements

**New Features:**
- 📐 **Square Card Layout** - Bookmarks display as square cards in grid view with aspect-ratio
- 🖼️ **Preview Support** - Webpage previews visible in grid view cards
- 📁 **Compact Folders** - Reduced spacing between collapsed folders in grid view
- 🔧 **Fixed Column Layout** - Grid columns now properly sized with minmax(0, 1fr)
- 🔗 **Redirect-Based Parking Detection** - Detects when URLs redirect to known parking domains
- 🌐 **Expanded Parking Domains** - Now checks 22+ parking services (up from 10)
- ☠️ **Dead Link Detection** - Properly flags 404, 410, and 451 responses as dead

---

### v1.4.0 - UI Overhaul & Enhanced Status Display

**New Features:**
- 🎨 **Stacked Status Icons** - Shield and chain icons now stack vertically, reclaiming horizontal space
- 🔍 **Detailed Suspicious Pattern Tooltips** - Warning tooltips now show specific patterns detected (HTTP Only, URL Shortener, Suspicious TLD, IP Address)
- 🔄 **HTTP Redirect Detection** - Detects when HTTP bookmarks redirect to HTTPS
- 👆 **Clickable Status Icons** - Click on shield or chain to see full status details in a popup
- 📐 **Larger Favicons** - Increased favicon size from 16px to 20px for better visibility
- 🔧 **Context Menu Repositioning** - Menus automatically reposition to stay within viewport
- 💾 **Improved Caching** - Cache now stores sources with status for better tooltip support
- 📦 **Centralized Version** - Version now managed from manifest.json as single source of truth

**Bug Fixes:**
- 🐛 **Zoom Fix** - Fixed gap between content and status bar caused by CSS transform zoom
- Fixed security warnings not showing specific pattern details
- Improved cache to handle both old and new format for backwards compatibility

### v1.3.0 - Multiple Filters & Support

**New Features:**
- 🏷️ **Multiple Filter Selection** - Select multiple filters simultaneously for advanced filtering
  - OR logic within categories (e.g., Live + Dead shows both)
  - AND logic between categories (e.g., Live + Safe shows only live AND safe)
- ☕ **Buy Me a Coffee** - Added support link in settings menu

### v1.2.0 - Export Improvements & Code Cleanup

**New Features:**
- 📤 **HTML/JSON Export Choice** - Users can now choose between HTML (cross-browser compatible) or JSON (Firefox native) export formats
- 📋 **Netscape Bookmark Format** - HTML exports use standard format compatible with all major browsers

**Improvements:**
- 🧹 **Code Cleanup** - Removed legacy duplicate files (crypto-utils.js, url-validator.js)
- 📖 **Enhanced Documentation** - Added comprehensive acknowledgments for security services (URLhaus, BlockList Project, Google Safe Browsing, VirusTotal)
- 🔒 **Removed Private Tab Feature** - Eliminated confusing Firefox API limitation issues

**Bug Fixes:**
- Fixed incognito manifest setting for Firefox compatibility

### v1.1.0 - Bug Fixes & Improvements

**Critical Fixes:**
- 🔧 **Fixed link checking feature** - Content Security Policy updated to allow URL checking for all bookmark URLs (previously blocked by overly restrictive CSP)
- 🔧 **Fixed status indicators persisting** - Link and safety check results no longer reset to grey after bookmark operations (add/edit/delete)
- 🔧 **Fixed preview images not restoring** - Preview thumbnails now properly restore after status checks complete

**Improvements:**
- ✨ **Auto-add https:// protocol** - Bookmarks can now be saved without typing protocol (e.g., "google.com" → "https://google.com")
- 🎨 **Updated extension icons** - Removed black background square, cleaner transparent design with black-filled shield
- 📝 **Corrected documentation** - Fixed theme count (3 themes, not 8) in README and release notes

**Technical Details:**
- CSP `connect-src` changed from specific domains to `https: http:` to enable link checking
- Status data now preserved across `loadBookmarks()` calls using Map-based caching
- Preview tracking key changed from `bookmark.id` to `bookmark.url` for consistency
- Protocol detection regex: `^[a-zA-Z][a-zA-Z0-9+.-]*:` handles all valid URL schemes

### v1.0.0 - Stable Release
- **Private browsing support** with memory-only storage
- **Global error boundary** with comprehensive logging
- **Export bookmarks** as JSON backup
- **Cache management** with size display and auto-clear
- **Enhanced keyboard navigation** with arrow keys
- **Multi-select mode** with bulk operations
- **Accessibility improvements** (ARIA labels, focus traps, keyboard traps)
- **Security enhancements** (AES-256-GCM encryption, CSP, input validation)
- **Complete documentation** for Mozilla Add-ons submission
- **Bug fixes** including DoH toggle removal and export feature repair
- No longer in beta - production ready!

### Previous Versions
- **v0.7.0** - Development release with private browsing and error handling
- See commit history for detailed changes

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Support

- **Issues:** [GitLab Issues](https://gitlab.com/AbsoluteXYZero/BMZ-Firefox/-/issues)
- **Source Code:** [GitLab Repository](https://gitlab.com/AbsoluteXYZero/BMZ-Firefox)
- **Buy Me a Coffee:** [Support Development](https://buymeacoffee.com/absolutexyzero)

## Acknowledgments

### Design & Platform
- **Material Design 3** - Color system by Google
- **Firefox WebExtensions** - Mozilla Firefox team

### Security & Malware Detection
- **[URLhaus](https://urlhaus.abuse.ch/)** - Dual coverage: Active list (~107K entries, updated every 5 min) + Historical mirror (~37K entries)
- **[BlockList Project](https://github.com/blocklistproject/Lists)** - Community-maintained malware, phishing, and scam domain lists (626K+ entries)
- **[HaGeZi TIF](https://github.com/hagezi/dns-blocklists)** - Threat Intelligence Feeds blocklist (608K entries)
- **[Phishing-Filter](https://gitlab.com/malware-filter/phishing-filter)** - OpenPhish & PhishTank aggregated database (~21K entries)
- **[OISD Big](https://oisd.nl/)** - Comprehensive blocklist aggregator (~215K entries)
- **[corsproxy.io](https://corsproxy.io/)** - CORS proxy service enabling access to abuse.ch official list
- **[Google Safe Browsing API](https://developers.google.com/safe-browsing)** - Optional threat intelligence (requires API key)
- **[Yandex Safe Browsing](https://yandex.com/dev/safebrowsing/)** - Optional geographic threat diversity (requires API key)
- **[VirusTotal](https://www.virustotal.com/)** - Optional multi-engine malware scanning from 70+ AV engines (requires API key)

### Services
- **WordPress mShots** - Website screenshot preview service
- **Google Favicons** - Website icon service

Special thanks to the security research community for maintaining free, public malware databases that help keep users safe.

---

**Made with ❤️ for Firefox users who love organized bookmarks**


