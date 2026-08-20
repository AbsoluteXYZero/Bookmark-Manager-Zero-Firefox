<div align="center">
<img src="icons/bookmark-96.png" alt="Bookmark Manager Zero Logo" width="128" height="128">

<h1 align="center">Bookmark Manager Zero</h1>

<p align="center">
  <strong>A modern, privacy-focused interface for managing your Firefox bookmarks.</strong>
</p>

<p align="center">
  <a href="https://gitlab.com/AbsoluteXYZero/BMZ-Firefox">
    <!-- [ZeroLabs] 2026-08-19 7:12 PM - edited: version badge to 5.2 -->
    <img src="https://img.shields.io/badge/version-5.2-blue" alt="Version">
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

### Gallery (Click to view full size)

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

- **Native Bookmark Integration** - Works directly with Firefox's bookmark system
- **GitLab Snippet Sync (Optional)** - Cloud backup and cross-device synchronization

  - PAT authentication with AES-256-GCM encryption
  - Auto-sync every 5 minutes + event-driven sync on changes
  - Conflict detection for safe multi-device usage
  - Manual sync controls (pull/force push)
- **Modern Material Design UI** - Clean, intuitive interface with multiple themes
- **Sidebar Interface** - Quick access via toolbar icon or customizable keyboard shortcut
- **Real-time Sync** - Instantly reflects bookmark changes made in Firefox

### Organization & Search

- **Advanced Search** - Real-time search across titles and URLs
- **Folder Management** - Create, edit, move, and organize folders
-  **Smart Filters** - Filter by link status and safety with multi-select support
- **List & Grid Views** - Choose your preferred layout
- **Drag & Drop** - Reorder bookmarks and folders

### Link & Safety Checking

- **Link Status Checking** - Automatically detects broken/dead links
-  **Security Scanning** - Checks URLs against malware databases
- **Background Scanning** - Bookmark scanning continues in the background even when the sidebar is closed, with automatic progress synchronization when reopened
- **Folder Rescan** - Right-click any folder to recursively scan all bookmarks in that folder and subfolders with detailed statistics
- **Safety Indicators** - Visual warnings for suspicious links with detailed tooltips
- **Clickable Status Icons** - Click shield or chain icons for full status details popup
- **HTTP Redirect Detection** - Detects when HTTP bookmarks redirect to HTTPS
- **Whitelist Support** - Mark trusted URLs to skip safety checks
- **Trusted Filter** - Filter to view only whitelisted bookmarks (white shield)
- **Safety History** - Track status changes over time

### Privacy & Security

- **Encrypted API Keys** - AES-256-GCM encryption for stored credentials
- **Encrypted GitLab Tokens** - GitLab Personal Access Tokens encrypted with AES-256-GCM
- **No Tracking** - Zero analytics, no data collection
- **Offline Mode** - Works fully offline when external features disabled
- **Auto-Clear Cache** - Configurable automatic cache cleanup

### User Experience

- **8 Themes** - Enhanced Blue (default), Enhanced Light, Enhanced Dark, Enhanced Gray, Blue, Light, Dark, Tinted
- **Enhanced Themes** - Modern rounded containers with enhanced 3D depth effects on search bar and toolbar buttons
- **Tinted Theme Customization** - Adjust hue, saturation, and background colors for Tinted theme
- **Custom Accent Colors** - Pick any color for theme customization
- **Bookmark Background Opacity** - Adjust bookmark background transparency (0-100%) while keeping text at full opacity
- **Custom Text Colors** - Visual color picker for bookmark and folder text with reset button
- **Custom Backgrounds** - Upload and position your own background images with drag-to-reposition
- **QR Code Generator Button** - Toolbar button for quick QR code generation of the current page URL
- **Keyboard Navigation** - Full keyboard support with arrow keys
- **Accessibility** - Comprehensive ARIA labels and keyboard traps
- **Zoom Control** - 50% - 200% zoom levels for bookmark content
- **GUI Scaling** - 80% - 140% scaling for interface elements
- **Responsive Design** - Adapts to sidebar width with auto-wrapping filters and wider menus (280-450px)

### Advanced Features

- **Website Previews** - Screenshot thumbnails of bookmarks with hover preview popup
- **High-Quality Preview Popups** - Hover over thumbnails to see 800x600 high-resolution preview
- **Smart Popup Positioning** - Preview popups appear above/below bookmarks to avoid covering content
- **URL Tooltips** - Hover over bookmark title/URL to see full URL in tooltip
- **Improved Status Bar** - Enhanced discoverability with visible "Scan All Bookmarks" label and centered status messages
- **Text-Only View** - View bookmark pages in text-only mode
- **Bulk Operations** - Multi-select mode for batch editing/deletion
- **Duplicate Detection** - Find and manage duplicate bookmarks
- **Undo System** - Restore recently deleted bookmarks
- **Bookmark Changelog** - Track all bookmark and folder changes (creates, moves, deletes, renames) with persistent history
- **Pre-Sync Snapshot Protection** - Automatic snapshots before sync operations with one-click restore to undo mistaken syncs
- **Favicon Display** - Show website icons

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
- **10 Blocklist Sources** - Dual URLhaus coverage (Active + Historical), BlockList Project (Malware/Phishing/Scam), HaGeZi TIF, Phishing-Filter, OISD Big, FMHY Filterlist, Dandelion Sprout Anti-Malware

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

URLs are checked against ten community-maintained blocklists with dual URLhaus coverage:

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
| **[FMHY Filterlist](https://github.com/fmhy/FMHYFilterlist)** | Unsafe Sites | Fake activators, malware distributors, unsafe download sites | ~282 |
| **[Dandelion Sprout Anti-Malware](https://github.com/DandelionSprout/adfilt)** | Anti-Malware | Curated malware, scam, and phishing domains | ~5K |

**Total Coverage**: **~1.36M unique malicious domains** after deduplication

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
- Strong Content Security Policy (CSP)
- AES-256-GCM encryption for stored API keys
- No eval() or inline scripts
- HTTPS-only external requests
- Input validation and sanitization
- XSS protection

### Reporting Security Issues
Please report security vulnerabilities via GitLab Issues (mark as security issue).

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
- **[FMHY Filterlist](https://github.com/fmhy/FMHYFilterlist)** - Curated unsafe sites list (~282 entries)
- **[Dandelion Sprout Anti-Malware](https://github.com/DandelionSprout/adfilt)** - Curated anti-malware list (~5K entries)
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


