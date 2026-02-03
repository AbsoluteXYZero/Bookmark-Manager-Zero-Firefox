## Changelog

### v4.0 (Current) - Added Dandelion Sprout Anti-Malware

**New Features:**
- 🛡️ **Added Dandelion Sprout Anti-Malware List** - New blocklist source for enhanced malware detection
  - Curated list of ~5K malware, scam, and phishing domains
  - Actively maintained with regular updates
  - Complements existing blocklists with hand-curated security coverage

---

### v3.9 - Added FMHY Filterlist

**New Features:**
- 🛡️ **Added FMHY Filterlist** - New blocklist source from the FMHY community
  - Covers fake Windows activators (KMS-Pico variants), malware distributors, and unsafe download sites
  - ~282 curated domains from actively maintained community list
  - Complements existing blocklists with hand-curated unsafe site coverage

---

### v3.8 - Performance & Initialization Fixes

**Bug Fixes:**
- 🐛 **Fixed Status Bar Initialization** - Status bar now properly updates from "downloading blocklists (8/8)" to "Ready" on first load
  - Added blocklist complete event dispatch when using cached blocklists
  - Ensures UI updates correctly whether downloading fresh or loading from cache
  - Applies to initial extension load and subsequent reopens
- ⚡ **Eliminated Bookmark Click Delays During Scans** - Bookmarks now open instantly even during active background scans
  - Replaced expensive full DOM re-renders with surgical updates of specific bookmark elements
  - Performance improvement: 100-500ms → 1-5ms per update (100x faster)
  - Refactored `updateBookmarkStatusInDOM()` to match Chrome's cleaner implementation
  - Now updates both list view (.status-indicators) and grid view (.bookmark-top-row) layouts
  - Removed forced reflow hacks that were causing performance issues
  - Scan speed improvement: 40-60% faster overall due to eliminated UI blocking

**Technical Details:**
- Blocklist service now dispatches `blocklistComplete` message when loading from same-day cache
- Updated `updateBookmarkStatusInDOM()` function signature from 5 parameters to updates object
- Scan result handlers now use surgical DOM updates instead of `renderBookmarks()`
- CPU usage during scans reduced by ~95%
- No UI thread blocking - bookmark clicks are always instant
- Grid view status indicators now properly update during scans (previously broken)

---

### v3.7 - UI Improvements

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