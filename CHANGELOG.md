## Changelog

### v5.5 (Current)

**Bug Fixes:**
- **Bookmarks with a slash in their title no longer create phantom folders** - Setting up BMZ on a new device and pulling your bookmarks down could produce far more than you actually have. Folder locations were stored as text with "/" between each level, and a bookmark whose own title contained a slash - which is most GitHub links, "owner/repo: description" - was read as though the first half of its title were a folder. Each one invented a folder to sit in. A library of 2,911 bookmarks arrived as 4,476. Folder locations are now kept as a proper list rather than as text to be taken apart, so a title is treated as a title whatever characters are in it.

**Changes:**
- **Opening the sync dialog no longer starts a sync** - It used to begin the moment the dialog appeared, on the assumption that opening it meant you wanted to sync. That made the dialog impossible to reach for anything else: turning background auto-sync off, or changing which snippet you use, meant triggering the very sync you were trying to avoid. Syncing now happens when you press the sync button and not before.

---

### v5.4

**Bug Fixes:**
- **The scan counter no longer jumps around** - Expanding a second folder while a scan was already running started a separate count with its own total, and the two took turns writing to the same display, so the figure flipped between them - "40/125" then "12/137" then "41/125". Expanding now adds to the running total instead of starting a rival count, so the number only ever climbs and the total stays put.

---

### v5.3 - Sync That Runs On Its Own

**New Features:**
- **Bookmarks now sync without opening BMZ** - Saving a bookmark with the star button, Ctrl+D, or the Library window used to go unnoticed until the next time you opened the sidebar, because the only thing watching for changes lived in the sidebar itself. That watcher now runs in the extension's background, so a bookmark you save while browsing reaches your snippet shortly after with BMZ never opened. Bookmarks added on your other devices arrive here the same way, checked for every five minutes.
- **Deleting a bookmark asks before it travels** - Additions move on their own in both directions, but anything that would remove a bookmark stops and waits. The sync button turns amber, the extension icon carries a marker, and opening BMZ shows exactly which bookmarks are involved and which side they would disappear from, with the choice to approve it or leave it for later. This applies equally to a bookmark you deleted here that is still in the snippet, and to one deleted on another device that is still on this one.
- **Renaming or moving a bookmark elsewhere asks too** - A rename you make here syncs silently, since you clearly meant it. A rename arriving from another device would overwrite a name you may have chosen yourself, so it waits for you the same way a deletion does, showing both the current name and the incoming one. The same applies to bookmarks moved between folders, including everything inside a folder you renamed on another device.
- **Turn background syncing off** - A switch in Snippet Sync Options, on by default. With it off, nothing syncs on its own and the sync button still works normally.
- **A card explains a paused sync instead of a pop-up** - When a sync stops and waits for you, a card now appears at the top of your bookmark list, above Quick Access, showing the sync icon and a Review changes button. It replaces the dialog that used to open by itself every time you opened BMZ with something outstanding. Dismissing it with "Not now" leaves the amber sync arrows and the toolbar marker in place, so the signal is never fully silenced, and the card returns on the next new difference.
- **A paused sync now shows up while BMZ is already open** - Background syncing could stop and wait while you were looking at the panel, and the only sign was the marker on the toolbar icon, which the browser hides inside the extensions menu when BMZ is not pinned. The panel now notices the moment it happens.
- **A rename that arrives through sync is now recorded** - Approving a rename or move made on another device changed the bookmark and left no trace in the changelog, so there was nothing to review afterwards and no way to undo it. It now writes the same kind of entry that renaming a bookmark in BMZ's own edit dialog does, carrying the old and new names, and can be undone from there like any other change.
- **Deleting now asks straight away** - A deletion needs your approval before it travels to your snippet, and that request used to wait for the background sync and then sit as a marker until you next opened BMZ - so a bookmark deleted before bed simply had not gone anywhere by morning. BMZ now checks immediately after you delete, just after the undo window closes, so the choice is in front of you while you are still looking at what you removed. Deleting several in a row asks once, listing all of them.
- **A warning when an address does not look like a link** - Typing something into the address field that cannot work as a bookmark - most often by putting the title and the address in the wrong boxes - used to save without comment and then sync, after which stricter clients rejected it and complained on every sync afterwards. BMZ now says so, and offers to swap the two fields for you. It never refuses to save: if you want to keep it exactly as typed, you can. The same check runs when you edit an existing bookmark.
- **A "What's New" card** - A short summary of the latest changes now appears at the top of your bookmark list, with a Got it button that dismisses it for good. It returns only when there is genuinely something new to say.

**Improvements:**
- **One sync button instead of two** - "Sync from Cloud to Device" and "Sync from Device to Cloud" have been replaced by a single sync button that starts working the moment the dialog opens, so syncing is one click rather than two. Its ring spins while it works and settles green when finished, amber when something needs your decision. The old pair was misleading in both directions: one of them only opened a comparison and never synced anything, while the other overwrote your snippet immediately with no confirmation at all.
- **Merge now leaves both sides matching** - Choosing Merge when connecting to an existing snippet used to send your bookmarks up and leave this device still missing whatever the snippet had. It now brings the snippet's bookmarks down into their matching folders as well, so both ends genuinely hold everything.
- **Overwriting is always available** - "Overwrite Snippet with Local" and "Overwrite Local with Snippet" now live in Snippet Sync Options, reachable whenever you want them rather than only appearing when BMZ happened to detect a difference. The first tells you how many bookmarks in the snippet are not on this device before you commit.
- **Bookmarks that cannot be placed are named** - When a merge cannot work out where a bookmark belongs, BMZ now lists each one with the reason and offers a folder to put them in, instead of a passing message saying a number of items were skipped. Nothing is lost either way, since they stay in the snippet.
- **The review dialog says less and means more** - Each section now states plainly what syncing would do - "Remove 2 bookmarks from your snippet to match this device" - instead of a paragraph explaining that your consent is required, which the heading and the buttons already made obvious. Counts read as "1 bookmark" or "3 bookmarks" rather than "1 bookmark(s)", and renames show as "old name to new name" with an arrow.
- **Three buttons became two** - "Decline Sync - Keep Everything" and "Decide later" did almost the same thing, and once the notice card gained its own dismiss button the distinction stopped being worth making. There is now Approve and Cancel. Cancel changes nothing on either side and leaves the sync arrows amber, because the difference is genuinely still unresolved - nothing switches that warning off any more without actually settling it.
- **The Approve button is no longer red** - Red read as danger on a button whose entire job is to apply changes you have just reviewed and chosen. It now uses the same amber as the rest of the paused-sync flow, so the card, the sync arrows and the button are visibly one thing. The individual bookmarks listed above it keep their red and amber markers, which is where that warning belongs.
- **Sync dialogs match the rest of BMZ** - They were built in a way that never picked up the shadows every other panel in BMZ has, so they sat flat against the page while everything around them lifted off it. They now carry the same depth, and on the enhanced and tinted themes the same hairline border and lit top edge that the header and settings menu use. The plain themes stay flat, exactly as they do everywhere else.
- **The review dialog accounts for what synced silently** - Bookmarks that arrive from your snippet need no approval, so they are added without asking - but a dialog appearing while bookmarks quietly show up left that unexplained. It now says how many were added and how many of yours are about to go up, each expandable to name them.

**Bug Fixes:**
- **"Merge Bookmarks" never merged anything** - It reported success and uploaded the snippet back to itself unchanged. The conversion of your bookmarks was never waited for, so the merge received nothing to merge and quietly did nothing. This had never worked in any released version.
- **Syncing could quietly undo another device's work** - A push sent this device's entire bookmark list over the snippet with no check on what was already there, so a device that had not caught up could erase bookmarks added elsewhere and bring back ones you had deleted. Every sync now compares both sides first and refuses to remove anything without asking.
- **The version counter meant nothing** - Every upload stamped the same number regardless of what came before, so no client could tell whether a snippet had changed since it last looked. The number is now carried forward from the snippet itself.
- **Pinned bookmarks could silently fail to sync** - Quick Access pins were sent as part of a full bookmark upload, so anything that held that upload back took your pins with it. Pins are now written on their own and are unaffected by the state of your bookmarks.
- **The limit on how often BMZ contacts GitLab never worked** - It compared against a timestamp that was read but never written, so the check always passed. It now measures real time between syncs.
- **Bulk deletion can be undone** - Deleting several items at once, or clearing duplicates, recorded nothing and offered no undo - so the two most destructive actions in BMZ were the only ones with no way back, and the warning saying so was accurate. Both now log every item and show an undo button, exactly like deleting a single bookmark. Folders are captured with their entire contents.
- **Restoring a folder from the changelog brings its contents back** - It recreated an empty folder and told you the contents were lost, even though BMZ had stored them all along. Restoring now rebuilds the folder and everything inside it. If the original location no longer exists, the item is restored to a top-level folder and BMZ says where it went, instead of failing.
- **Selecting a folder and something inside it no longer breaks the delete** - Ticking both meant BMZ tried to delete the same bookmark twice, which failed and reported the whole operation as unsuccessful even though the items had gone. The contained selection is now recognised and skipped.
- **Link and safety checking switches had no effect on background scanning** - The two toggles in Settings were saved in a place the extension's background cannot read, and the background looked for them somewhere nothing had ever written. It therefore found no answer, assumed both were on, and carried on checking links and safety in the background no matter how the switches were set. They are now saved where the background can see them, so turning a check off actually stops it.
- **Blocklists no longer download when safety checking is off** - As a result of the fault above, the security database was fetched when Firefox started and again before every scan, for a feature that may well have been switched off - all ten lists, repeatedly, for data nothing would ever read. The download now checks the setting, and picks the lists back up as soon as you turn safety checking on again.
- **Safety checking no longer calls unknown sites "safe"** - One of the security sources returns a normal-looking page for any site it has never examined. BMZ counted the warnings on that page, found none, and recorded the site as safe - when what had actually happened was that nobody had ever looked at it. Those now read as no verdict from that source, and the result rests on the blocklist check alone rather than on a claim nothing supported.
- **Clearing the cache now actually rescans** - "Clear Cache" reset every status indicator but kept a private record of when each folder was last scanned, so expanding a folder afterwards found that record, decided it was recent, and scanned nothing - for up to a week. That record is now cleared along with everything else, and a folder whose statuses have gone is recognised as needing a scan regardless of what the record says.
- **A folder is no longer marked as checked when nothing was checked** - Expanding a folder recorded it as scanned straight away, without waiting to see whether the scan ran or even started. If checking was switched off at the time, or the scan was stopped part-way, the folder was still stamped as done for seven days - so turning checking back on left it showing no statuses, with no way to prompt it short of waiting the week out. The timestamp is now written only when the bookmarks were genuinely checked, or were already up to date.
- **The status bar could stay stuck reading "Downloading blocklists..."** - When the download finished, the check meant to stop it interrupting a scan already in progress was matching the download's own state instead, so it skipped clearing the message and left the bar frozen at "Downloading blocklists... (10/10)" with nothing ever coming back to reset it. It now returns to Ready, and a scan that really is running keeps the bar to itself rather than having its progress overwritten.
- **The status bar now tracks everything that is running** - Five separate parts of BMZ were each writing to it directly, so whichever finished last won regardless of what was still going: a blocklist download completing mid-scan wiped the scan's progress, a full rescan updated the bar without registering as activity at all, and a folder rescan that hit an error left its progress message on screen permanently with nothing to clear it. Every activity is now tracked in one place, so the bar always reflects what is genuinely still in progress and only settles to "Ready" when nothing is.

---

### v5.2 - Sync Clarity & Reliability

**New Features:**
- **Snippet Options are tucked away** - The GitLab Sync Settings dialog now opens to just the two sync buttons. The snippet ID, token storage, and the create, select, and disconnect actions live behind a "Snippet Options" section you expand when you need it, which are things you set once and rarely revisit. When no snippet is connected the section starts open, since setting one up is the only thing to do at that point.
- **Clear button in the search box** - A small X appears at the end of the search box once you have typed something, so clearing a long search takes one click instead of holding backspace. Clicking it also returns the cursor to the box so you can start typing again straight away.

**Improvements:**
- **Clearer sync button wording** - The two sync buttons now read "Sync from Cloud to Device" and "Sync from Device to Cloud", which say plainly which way your bookmarks are about to move. They previously referred to a "Snippet" and a "Browser", and neither made the direction obvious at a glance.
- **Identical sync wording everywhere** - The Firefox, Chrome, and web versions had drifted apart, naming the same things differently in each. Every label in the GitLab sync dialogs and the first-time setup screens is now the same across all three.
- **Token storage options explain themselves** - Local and Supabase each carry an information icon with a full explanation of what that choice means for your token when it renews.
- **Quick Access menu item no longer moves** - Add and Remove now occupy the same position in the right-click menu, just above Delete, so the item stays where you expect once a bookmark is pinned. Remove is shown in red and asks for confirmation first, with a reminder that it only unpins and never deletes the bookmark.
- **Clearer first-time setup** - When setup finds a snippet you already have, it now says so with a heading rather than showing an unexplained card, and the button beside it reads "Create New Snippet" instead of just "Create New".

**Bug Fixes:**
- **Sync no longer hangs indefinitely** - Requests to GitLab had no time limit, so a stalled connection could leave a sync waiting forever with nothing reported and no way to tell it had stopped. Requests now give up after 15 seconds and report the failure so it can be retried. Retrying is safe: bookmarks are written as a complete file, so a repeated attempt produces the same result whether or not the first one arrived.
- **Snippet names are no longer treated as formatting** - A snippet whose title contained characters that look like markup could render incorrectly in the setup and selection lists. Titles are now always shown as plain text.

---

### v5.1 - Quick Access & Recently Opened

**New Features:**
- **Quick Access** - Pin the bookmarks you use most to a section at the top of the sidebar. Right-click any bookmark and choose "Add to Quick Access", or drag one onto the section. Pinned entries are mirrors, not copies: the same bookmark, shown in a second place. Delete the bookmark from its real folder and the pin disappears with it, including when you delete it in Firefox's own bookmark manager. Removing a pin only unpins it and never touches the underlying bookmark, so there is no way to destroy a bookmark from the Quick Access section.
- **Drag to reorder Quick Access** - Arrange your pins in whatever order you like by dragging them within the section. Pins cannot be dragged out into your real folders, so reordering can never move or rearrange the actual bookmarks.
- **Recently Opened** - The last 5 bookmarks you opened from BMZ, so getting back to something takes one click. Opening the same bookmark twice in a row moves it to the top instead of adding a second row. This list stays on this device and is never synced.
- **Shared collapsible row** - Quick Access and Recently Opened share a single row split in two and behave as an accordion, so opening one closes the other and neither eats space when you are not using it. Your choice is remembered between sessions.
- **Display toggles** - Both sections can be shown or hidden independently from the Display Options button in the toolbar. Unlike the existing display toggles, these two persist across sidebar reopens. Hiding one gives the other the full width.
- **Quick Access syncs across devices** - Your pins travel with your GitLab snippet and arrive on every device using it. They are stored in a separate file inside the snippet, so versions of BMZ that do not yet support Quick Access cannot erase them, and pins made on two devices merge rather than overwrite. Unpinning on one device propagates instead of being resurrected by the other.

**Bug Fixes:**
- **Welcome and Cross-Device Sync cards no longer reappear in every private window** - Dismissing either card in a private window had no lasting effect, so both returned on every new private session. BMZ's private-mode storage wrapper keeps all data in memory only, which means the "don't show this again" flag could never survive the window closing. Both cards are now suppressed entirely in private windows rather than shown with a dismiss button that cannot persist.
- **HaGeZi TIF blocklist restored** - This source had stopped loading entirely, reporting HTTP 403. Two unrelated breakages happened at once: the jsDelivr CDN began refusing every file in the list's repository once the repository outgrew its 150 MB limit, and the project separately reorganised its folders so the old path no longer existed. Now loaded from GitHub directly using the current path. All ten blocklist sources were checked and the rest were unaffected.
- **Browser-internal bookmarks no longer show as phantom sync changes** - A bookmark such as `about:debugging` was reported as changed on every single pull, forever, even when nothing had changed. Chrome rewrites browser-internal addresses when it saves them, so the same bookmark ends up written slightly differently in each browser. BMZ was correctly noticing the difference and wrongly presenting the browser's own edit as yours. Sync now recognises these as the same bookmark. Each browser keeps the address its own engine requires, and nothing is rewritten or overwritten.
- **Merge dialog no longer appears when bookmarks already match** - Connecting to a snippet that was last written by a different browser always prompted you to choose a merge strategy, even with identical bookmarks. The check compared an exact fingerprint of the whole collection, and because Firefox names its toolbar folder "Bookmarks Toolbar" where Chrome names it "Bookmarks bar", that fingerprint could never match across browsers. BMZ now falls back to a real comparison and connects quietly when there is genuinely nothing to reconcile.
- **Scan results now update every copy of a bookmark** - With a bookmark visible in both the tree and Quick Access, only the first copy on the page received link and safety results. The other stayed on a stale icon until the next redraw.

---

### v4.9 - Header Layout Fix

**Bug Fixes:**
- **Header buttons no longer overlap the title/subtitle** - The GitLab, sync, logout, and settings buttons now sit in their own reserved space in the header instead of floating over it, and the title and subtitle automatically scale down to fit the remaining width on a single line. Fixes the buttons covering the title or subtitle at narrow sidebar widths and after signing in to GitLab (which adds buttons to the row).

---

### v4.8 - Sync Reliability

**New Features:**
- **Scan Intensity Slider** - New slider in Settings controls how many bookmarks are link/safety-checked at once (1-20, default 5). Each check is a live request that triggers a DNS lookup, so scanning a large library all at once could briefly overwhelm a local DNS resolver (AdGuard Home, Pi-hole) and knock out your internet. Lowering this keeps scans gentle on your network. Persists across sessions and applies live to an in-progress scan.
- **Request Jitter Slider** - New slider in Settings adds a small random delay (0-500ms) before each scan request, spreading DNS lookups across time instead of firing them as one burst. Raise it, alongside lowering Scan Intensity, if scans still disrupt your connection.

**Bug Fixes:**
- **Stop Scan Now Works Reliably** - The octagonal stop button now appears during every scan and actually cancels it. Previously it only stopped the manual background rescan and did nothing for the automatic scan that runs on load and when expanding folders, and its visibility could flicker off mid-scan. Button state is now driven by a single source of truth, and pressing Stop cancels both scan engines.
- **Scan Status Returns to "Ready"** - After stopping a scan, the status bar briefly shows "Scan stopped" and then settles back to "Ready" instead of sticking. Also fixed a leaked scan operation that could wedge the status bar on a stale message.
- **Settings Slider Handle** - Fixed the slider handle sitting too low and rendering clipped; it now sits centered on the track.

**Performance:**
- **DNS-Friendly Scanning** - All scan requests now share a single global concurrency limit. The automatic on-demand scan previously bypassed the limiter entirely, so a large library could fire a wall of simultaneous DNS lookups and stall your whole network; the default cap was also lowered.

**Changes:**
- **Removed per-sync "Merge" option** - The sync diff dialog no longer offers the bidirectional "Merge (Recommended)" button. A union merge can never propagate a deletion — a bookmark removed on one device is simply re-added from the other — so it caused bookmark counts to silently grow and deletions to never stick. Sync decisions are now explicit and deletion-honoring: Push Local to Remote or Pull Remote to Local. The one-time merge offered when first connecting a snippet is unchanged.

---

### v4.7 - Bug Fix

**Bug Fixes:**
- **Skip merge dialog when bookmarks already match** - When connecting to an existing GitLab snippet, BMZ now compares a checksum of the local bookmarks against the remote snippet before showing the replace/merge dialog. If they are identical, the snippet is connected silently with no dialog shown. The dialog still appears as normal when local and remote differ.

---

### v4.6 - Bug Fix

**Bug Fixes:**
- **Fixed "Set Up Sync" in announcement card** - Resolved `openSnippetSyncDialog is not defined` error when clicking "Set Up Sync" in the v4.5 announcement card. The function was scoped inside `setupEventListeners()` and not accessible from the card's click handler. Promoted to a module-level reference assigned at startup.

---

### v4.5 - GitLab OAuth & Supabase Sync

**New Features:**
- **GitLab OAuth Login for supabase** - Native GitLab OAuth via `browser.identity.launchWebAuthFlow`is. A popup window opens GitLab's own login/authorization page; no credentials are ever entered in the extension.
- **Supabase-Backed PAT Storage** - GitLab Personal Access Tokens can now be stored encrypted in Supabase (`gitlab_tokens` table) and automatically synced across devices. Token is encrypted with AES-GCM using the Supabase user UID as the key before upload.
- **Token Storage Mode** - New selector in sync setup lets users choose between Local (this device only) and Supabase (auto-sync across devices). Mode persists across sessions.
- **Disconnect: This Device vs All Devices** - When disconnecting in Supabase mode, users can choose to disconnect just the current device (leaves token in Supabase for other devices) or disconnect all devices (deletes token from Supabase).

**Improvements:**
- **401 Auto-Retry** - All Supabase API calls now use an `authFetch` wrapper that automatically refreshes the session token and retries once on 401 before failing.
- **OAuth Error Surfacing** - If GitLab or Supabase returns an error in the redirect URL (e.g. access denied, misconfigured provider), the human-readable error message is now shown to the user instead of a generic failure.
- **GitLab Button Logic** - GitLab toolbar button now shows the disconnect dialog when a snippet is connected, and opens sync setup otherwise. Manual sync button always opens the setup dialog rather than attempting a sync with no snippet connected.

---

### v4.4 - Bug Fixes

**Bug Fixes:**
- **Fixed GitLab Token Link** - "Create Token on GitLab" button now points to the correct URL after GitLab moved Personal Access Tokens from `/-/profile/` to `/-/user_settings/`.

---

### v4.3 - Multi-Select Bulk Open

**New Features:**
- **Long-Press to Multi-Select** - Click and hold any bookmark or folder for 750ms to enter multi-select mode. The held item is automatically added to the selection. Drag-and-drop is fully preserved — moving the mouse during the hold cancels the timer and initiates a drag as normal.
- **Open in New Tabs** - New bulk action button opens all selected bookmarks as background tabs in the current window. Also recurses into selected folders.
- **Open in New Windows** - New bulk action button opens each selected bookmark in its own separate window.

---

### v4.2 - Context Menu Redesign

**New Features:**
- **Replace Remote Snippet with Local** - New option in the sync setup dialog when connecting a GitLab snippet. Overwrites the remote snippet with your current local bookmarks, in addition to the existing Keep Local, Merge, and Replace Local with Remote Snippet options.

**Improvements:**
- **Drag-and-Drop Reliability** - Overhauled drop zone logic. Each item now acts as a single unified drop target (top half = insert before, bottom half = insert after) replacing the previous three competing zones per gap. Folder headers additionally support drop-into on the bottom half. Fixed an index offset bug that caused items to land one position too far down when reordering within the same folder.
- **Context Menu Redesign** - Right-click and hamburger menus now open as a slide-in panel from the right edge of the sidebar instead of a fragile absolute-positioned popup. Eliminates clipping, size inconsistencies, and overlap issues. Click outside or press Escape to dismiss.

---

### v4.1 - Move To, Keyboard Shortcuts & Drag Improvements

**New Features:**
- **Move to... Context Menu** - Right-click any bookmark or folder and select "Move to..." to relocate it via a modal folder picker
  - Folder dropdown with optional alphabetical sorting
  - Prevents moving folders into themselves or their descendants
  - Protects built-in Firefox root folders (Bookmarks Menu, Bookmarks Toolbar, Other Bookmarks, Mobile Bookmarks)
  - Full changelog integration with undo/restore support
- **Keyboard Shortcut: Ctrl+Click** - Open bookmarks in a new tab
- **Keyboard Shortcut: Shift+Click** - Open bookmarks in a new window
- **Multi-Select Click Anywhere** - In multi-select mode, clicking anywhere on a bookmark or folder toggles its selection (no longer requires clicking the small checkbox)

**Improvements:**
- **Drag-and-Drop Auto-Scroll** - Dragging a bookmark near the top or bottom edge of the list now auto-scrolls at a speed proportional to cursor proximity
- **Sync Success Visual Feedback** - Manual sync button now shows spinning arrows during sync and green arrows for 5 seconds on success, replacing success toasts. Error toasts are preserved.

**Bug Fixes:**
- **Fixed "allBookmarks is not defined"** - Resolved error in bulk recheck and bulk move functions by properly fetching the bookmark tree before use
- **Fixed Stop Scan Button Missing** - Stop button now consistently appears in the status bar during all scan types (folder expansion, multi-select recheck, and manual rescan)

---

### v4.0 - Added Dandelion Sprout Anti-Malware

**New Features:**
- **Added Dandelion Sprout Anti-Malware List** - New blocklist source for enhanced malware detection
- Curated list of ~5K malware, scam, and phishing domains
- Actively maintained with regular updates
- Complements existing blocklists with hand-curated security coverage
- Moved the syncChanges event emission to AFTER the data is saved in sync

---

### v3.9 - Added FMHY Filterlist

**New Features:**
- **Added FMHY Filterlist** - New blocklist source from the FMHY community
- Covers fake Windows activators (KMS-Pico variants), malware distributors, and unsafe download sites
- ~282 curated domains from actively maintained community list
- Complements existing blocklists with hand-curated unsafe site coverage

---

### v3.8 - Performance & Initialization Fixes

**Bug Fixes:**
- **Fixed Status Bar Initialization** - Status bar now properly updates from "downloading blocklists (8/8)" to "Ready" on first load
- Added blocklist complete event dispatch when using cached blocklists
- Ensures UI updates correctly whether downloading fresh or loading from cache
- Applies to initial extension load and subsequent reopens
- **Eliminated Bookmark Click Delays During Scans** - Bookmarks now open instantly even during active background scans
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
-  **Enhanced GitLab Login Button** - GitLab tanuki icon now displays "LOGIN" text overlay for clarity
- Bold black text on white tanuki makes it immediately obvious this is a login button
- Automatically switches to logout icon when authenticated
- Improves user experience by making button purpose crystal clear

**Improvements:**
- **Conditional Manual Sync Button** - Manual sync button now only appears when logged in
- Hides when not authenticated to keep UI clean
- Automatically shows/hides based on GitLab authentication state
- Reduces UI clutter for users not using GitLab sync

---

### v3.6 - Pre-Sync Snapshot & Restore

**New Features:**
-  **Pre-Sync Snapshot Protection** - Automatic safety net for sync operations
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
-  **Pretty-Printed JSON Snippets** - GitLab snippets now use formatted JSON for better readability
- Changed from single-line compact JSON to pretty-printed format with 2-space indentation
- Makes snippet content much easier to read and debug when viewing in GitLab
- All future snippet creations and updates will use formatted JSON

---

### v3.4 - GitLab Sync Bug Fixes

**Bug Fixes:**
-  **Fixed GitLab Snippet Merge Error** - Resolved "No Snippet ID provided" error when merging local bookmarks into snippet
- Fixed parameter order mismatch in `updateBookmarksInSnippet()` function call at sidebar.js:11545
- Fixed global `snippetId` variable being set after merge operation instead of before at sidebar.js:11724-11725
- Merge operation now properly sets snippet ID before attempting to update
- Ensures smooth GitLab sync setup when merging local bookmarks with existing snippets
-  **Fixed Missing calculateChecksum Function** - Resolved "calculateChecksum is not defined" error when creating new snippets
- Added missing standalone `calculateChecksum()` function at sidebar.js:10737
- Function was already present as a class method but missing as standalone utility
- Fixes snippet creation and update operations
-  **Fixed Empty Snippet Creation** - Resolved issue where creating new snippet would create empty bookmark folders
- Fixed Firefox bookmark tree root folder detection at sidebar.js:10777-10780
- Changed from checking non-existent `rootFolder.root` property to checking `rootFolder.id`
- Now correctly identifies Firefox root folders: toolbar_____, menu________, unfiled_____, mobile______
- Snippets now properly include all bookmarks and folders when created
-  **Fixed GitLab Button Not Updating** - GitLab button now properly changes to logout icon when logged in
- Updated `updateGitLabButtonIcon()` function at sidebar.js:10960-10978
- Button now shows logout icon when connected and GitLab logo when disconnected
- Matches Chrome version behavior for consistency

---

### v3.3 - Real-time Progress Updates (All Scan Types)

**Improvements:**
-  **Universal Real-time Progress** - ALL scan types now update progress after every individual bookmark
- Fixed folder expansion scanning (autoCheckBookmarkStatuses) to update per bookmark instead of per batch
- Fixed rescan all bookmarks to update per bookmark
- Fixed rescan folder to update per bookmark
- Applies to all scan operations for consistent, responsive feedback

---

### v3.1 - Session Persistence & Progress Updates

**New Features:**
-  **Session State Persistence** - Bookmark Manager Zero now remembers where you left off when you reopen it
- Restores scroll position to exactly where you were
- Remembers which folders were expanded/collapsed
- Preserves your search query and active filters
- Session clears when browser closes for privacy
-  **Real-time Scan Progress** - Progress counter now updates after every bookmark scanned instead of every 10
- More responsive and accurate progress feedback during scans
- Consistent behavior across all scan operations

**Bug Fixes:**
-  **Fixed Stop Scan Button** - Stop scanning button now works correctly
- Corrected message action name mismatch between sidebar and background script
- Changed from 'stopBackgroundScan' to 'stopScan' to match background listener
-  **Fixed Rescan All Bookmarks** - Resolved "allBookmarks is not defined" error
- Added proper bookmark retrieval before starting scan
- Now correctly gets all bookmarks using getAllBookmarksFlat()

---

### v3.0 - Critical Fixes & Performance Optimizations

**Bug Fixes:**
-  **Fixed Duplicate clearCache() Function** - Removed duplicate function definition that was causing conflicts
- Deleted second definition at sidebar.js:9720, keeping primary at sidebar.js:9164
- Prevents function overwriting and ensures consistent cache behavior
-  **Fixed Duplicate updateBookmarkStatusInDOM()** - Resolved duplicate function definitions
- Merged implementations from sidebar.js:7232 and sidebar.js:7261
- Ensures consistent bookmark status updates in DOM
-  **Fixed Duplicate getAllFolders()** - Standardized function signature across codebase
- Resolved conflicting signatures at sidebar.js:8164 and sidebar.js:9364
- Consistent folder retrieval throughout extension
-  **Fixed Duplicate findFolderById()** - Merged duplicate implementations
- Combined versions from sidebar.js:6741 and sidebar.js:8180
- Unified folder lookup functionality
-  **Fixed Missing window.initSidebar** - Resolved undefined function reference
- Added proper initialization function or removed orphaned reference at sidebar.js:2527
- Prevents runtime errors during sidebar initialization
-  **Fixed Module Scope Issues** - Replaced this._syncInProgress with proper module-level variables
- Corrected scope at sidebar.js:2502-2529
- Ensures proper state management across sidebar lifecycle

**Code Quality Improvements:**
-  **Improved Cache Mutex** - Enhanced cache locking mechanism
- Replaced busy-wait polling with efficient mutex implementation
- Better performance and resource usage
-  **Enhanced Promise Handling** - Added proper rejection handling in retry flows
-  **All HTML Element IDs Validated** - Fixed broken DOM references
-  **Comprehensive Error Handling** - Robust error boundaries throughout
-  **Proper Async/Await Usage** - Clean asynchronous code patterns
-  **Effective Caching Strategies** - Optimized performance with smart caching
-  **Rate Limiting added for APIs** - Prevents API throttling issues

**Performance Optimizations:**
-  **Concurrency Limiting** - Added ConcurrencyLimiter class to enforce maximum 10 concurrent network requests
-  **Parallel Scanning** - Link and safety checks now run in parallel for up to 2x faster scanning per bookmark
-  **Reduced Timeouts** - Link checks reduced from 10s→5s, URLVoid from 15s→5s, VirusTotal from 15s→8s
-  **Optimized Batch Processing** - Increased batch size from 5→10, reduced delay from 1000ms→100ms
-  **Smart Timeout Handling** - Timeout errors now mark sites as 'live' (slow server) instead of retrying with GET fallback
-  **Improved Throughput** - ~30-50 bookmarks/second (1,000 bookmarks in ~30-60 seconds)
-  **Network Protection** - Prevents DNS overload and router disruption with controlled concurrency

---

### v2.7.2 - Whitelist Persistence Fix

**Bug Fixes:**
-  **Fixed whitelist persistence** - Whitelisted bookmarks now maintain their status after sidebar reload
- Added whitelist check during cache restoration
- Whitelist status takes priority over cached statuses
- Fixes issue where whitelisted bookmarks showed gray shields after reopening sidebar

---

### v2.7.1 - Bug Fixes & Package Update

**Package Updates:**
-  **Include qrcode-lib.js** - Ensures QR code generation library is included in extension package

**Bug Fixes:**
-  **Fixed cache race condition** - Resolved issue where parallel bookmark scans would overwrite each other's cache entries
- Added mutex locks to prevent concurrent cache writes
- Fixes gray indicators appearing after folder rescan and sidebar reload
- Ensures privileged URLs (about:, moz-extension://) persist in cache correctly
-  **Fixed folder rescan progress** - Folder rescans now show real-time UI updates and status bar progress
- Added `renderBookmarks()` call after each batch during folder rescan
- Reduced batch delay from 1000ms to 300ms for 3x faster scanning
- Status bar shows "Scanning folder: X/Y" during scan
-  **Fixed blocklist loading timing** - Scans now proactively load blocklist database before starting
- Added `ensureBlocklistReady` message handler to trigger database update before scanning
- Prevents "unknown" safety status results when database loads mid-scan
- Applies to both folder rescans and background scans

---

### v2.7.0 - First-Time Setup & QR Code Generation

**New Features:**
-  **First-Time Setup Card** - Welcoming onboarding experience for new users
- Appears only once on first installation (never on updates)
- Explains auto-scan behavior and folder scanning
- One-click option to scan all bookmarks immediately
- Clear disclaimer about false positives/negatives
- Persistent flag independent of cache clearing
-  **QR Code Generator** - Generate QR codes for any bookmark
- Right-click bookmark → "Generate QR Code"
- Toolbar button for quick QR code generation of current page URL
- 100% local generation (privacy-focused, no external requests)
- Editable URL field with live QR code regeneration
- Works completely offline
- Perfect for quickly accessing bookmarks on mobile devices
-  **Background Scanning** - Bookmark scanning continues even when sidebar is closed
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
-  **10x Faster Scanning** - Fixed parallel processing bug that was checking bookmarks sequentially instead of in parallel
-  **2x Higher Throughput** - Increased batch size from 5 to 10 bookmarks per batch for ~33 bookmarks/second
-  **67% Faster Large Scans** - 4000 bookmarks now scan in ~2 minutes instead of ~40 minutes
-  **Eliminated Redundant Downloads** - Fixed blocklist downloading multiple times during parallel scans

**Memory Optimizations:**
-  **Smart History Tracking** - Safety history only records actual status changes, not duplicate entries
-  **Automatic Memory Cleanup** - Clears temporary bookmark tracking data after each scan
-  **Orphaned Entry Removal** - Removes safety history for deleted bookmarks on sidebar reload
-  **Reduced Memory Growth** - Prevents unbounded memory accumulation during multiple scans

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
-  **Bookmark Changelog** - Comprehensive history tracking for all bookmark and folder operations
- Tracks creates, updates, moves, and deletes for both bookmarks and folders
- Accessible via "View Bookmark Changelog" button in settings menu (just under Export Bookmarks)
- Persistent storage survives browser restarts and sidebar closes
- Maximum 1000 entries to prevent unlimited growth
-  **Modern SVG Icons** - Color-coded operation icons matching app aesthetic
- Green: Create operations
- Red: Delete operations
- Blue: Move operations
- Orange: Update/rename operations
-  **Clickable URLs** - Click any bookmark URL in changelog to copy to clipboard with visual feedback
-  **Human-Readable Timestamps** - "5 minutes ago", "2 hours ago", etc.
-  **Folder Path Tracking** - Shows full folder hierarchy for moved items
-  **Rename Tracking** - Displays old and new names for renamed items
-  **Clear History** - Option to clear all changelog entries

**Implementation Details:**
- Uses browser.storage.local for persistent storage across sessions
- Automatic folder path reconstruction using recursive traversal
- Detailed move tracking shows "from → to" folder paths
- Modal interface with scrollable history and clear action buttons

---

### v2.4.0 - Interactive Preview & UI Enhancements

**Preview System Improvements:**
-  **High-Quality Preview Popups** - Hover over bookmark thumbnails to see 800x600 high-resolution preview (2.5x larger than thumbnails)
-  **Smart Positioning** - Preview popups intelligently position above/below bookmarks to avoid covering content
-  **URL Tooltips** - Full bookmark URL displayed on hover over title/URL text
-  **Preview Popup Toggle** - New setting to enable/disable preview popups in Display Options

**Theme Fixes:**
-  **Accent Color Fix** - Accent color picker now correctly applies to folder icons in Enhanced and Tinted themes
-  **Tinted Theme Improvements** - Context menus now use light backgrounds for better readability
-  **Vibrant Hue Slider** - Tinted theme hue slider now displays full-saturation rainbow gradient

**Technical Implementation:**
- Preview popups load dedicated 800x600 images from mshots service (not upscaled thumbnails)
- Smart positioning algorithm calculates available space and chooses optimal placement
- 10px gap between bookmark and popup for visual clarity
- Graceful fallback to low-res thumbnail if high-quality image fails to load
- Settings persisted to browser storage with checkbox state management

---

### v2.3.0 - Cache Persistence & Trusted Domains

**Cache Restoration:**
-  **Persistent Scan Indicators** - Bookmark scan results now persist across sidebar reopens
-  **Instant Icon Display** - Shield and link status icons appear immediately from cache (7-day TTL)
-  **Smart Auto-Check** - Only scans bookmarks without cached results, reducing network requests
-  **Better UX** - No more "grey unknown" resets when closing/reopening sidebar

**Trusted Domain System:**
-  **Platform Allow-List** - Prevent false positives for trusted hosting platforms and services
-  **9 Trusted Domains** - GitHub, GitLab, Archive.org, Google services bypass local blocklists
-  **API Scanning Still Active** - Trusted domains still checked by Google/Yandex/VirusTotal if configured
-  **Documented Exemptions** - Clear documentation of which domains bypass blocklist checks

**Parking Detection Improvements:**
-  **Hosting Platform Exemptions** - GitHub Pages, GitLab Pages, Netlify, Vercel, Heroku no longer flagged as "parked"
-  **3-Layer Protection** - Exemptions apply to domain-based, redirect-based, AND content-based parking detection
-  **No More False Positives** - Legitimate static hosting platforms correctly show as "live"

**Rescan Improvements:**
-  **Cache Bypass on Rescan** - All manual rescan operations now force fresh checks
-  **Applies to All Rescans** - Individual bookmark, folder, and "Rescan All" button all bypass cache
-  **Guaranteed Fresh Results** - No more stale cached results on manual recheck

**Technical Implementation:**
- Cache restoration function (`restoreCachedBookmarkStatuses()`) runs after bookmark load
- `bypassCache` parameter propagates through entire message chain for rescans
- Trusted domains checked before blocklist lookups (security scanning still active)
- Parking exemptions skip all 3 detection layers (domain, redirect, content)

---

### v2.2.0 - Font Size Control

**New Feature:**
-  **Independent Font Size Slider** - Adjust text size (70-150%) without affecting container sizes
-  **Content Zoom Renamed** - First slider clarified as "Content Zoom" for better understanding
-  **Precise Text Control** - Scale bookmark titles, URLs, and folder names independently from layout

**Implementation:**
- New Font Size slider in zoom menu (between Content Zoom and GUI Scale)
- Applies to all view modes (list and grid 2-6 columns)
- Persistent preference storage
- Works independently from content zoom

---

### v2.1.1 - Separator Fix

**Bug Fixes:**
-  **Fixed Separator Display** - Firefox bookmark toolbar separators no longer appear as "data:" entries in the extension
-  **No More False Positives** - Separators are now properly filtered out and won't trigger malware warnings
-  **Accurate Counts** - Bookmark counts now exclude separators for accurate totals

**Technical Details:**
- Added separator filtering in all bookmark traversal functions
- Separators (`type: 'separator'`) are now skipped in rendering, counting, and scanning operations

---

### v2.1.0 - Permission Cleanup & Documentation

**Permission Improvements:**
-  **Removed Unnecessary Permissions** - Eliminated unused `webRequest` permission for better privacy
-  **Simplified Host Permissions** - Removed redundant URLhaus and OISD entries (covered by `<all_urls>`)
-  **Updated Documentation** - Clarified `<all_urls>` permission usage for link checking and blocklist downloads

**What Changed:**
- More accurate permissions documentation in README
- Cleaner manifest with minimal required permissions
- No functional changes - everything works exactly the same

---

### v2.0.0 - Enhanced Themes & Expanded Security

**Security Enhancements:**
-  **5 Additional Blocklist Sources** - Expanded from 3 to 8 total sources for comprehensive malware protection
- HaGeZi TIF (608K+ threat intel domains)
- Phishing-Filter (21K+ phishing URLs from OpenPhish & PhishTank)
- OISD Big (215K+ multi-source blocklist)
- BlockList Project: Malware (435K+ domains), Phishing (190K+ domains), Scam (1.3K+ domains)
-  **Yandex Safe Browsing API** - Optional geographic threat diversity for Russian/Eastern European threats (100K requests/day free tier)
-  **Total Coverage: ~1.35M unique malicious domains** (deduplicated from 1.6M entries)
-  **Source Attribution** - Malware detection tooltips now show which blocklist(s) flagged the URL
-  **Warning Status** - Suspicious URL patterns now display yellow warning shield
-  **Toggle Controls** - Added ability to disable link checking and safety checking independently

**New Themes:**
-  **5 New Enhanced Themes** - Enhanced Blue (default), Enhanced Light, Enhanced Dark, Enhanced Gray, plus Tinted
-  **3D Depth Effects** - Enhanced visual depth with rounded containers, sophisticated shadows, and modern effects
-  **Tinted Theme Customization** - Full hue and saturation controls for Tinted theme
-  **8 Total Themes** - Comprehensive theme collection for every preference

**UI/UX Improvements:**
-  **Fixed Display Menu Overlay** - Resolved invisible element blocking folder interactions
-  **Adaptive Menu Width** - Auto-sizing menus (280-450px) that fit content while staying within viewport
-  **Improved Opacity Control** - Restructured bookmark opacity slider for better visibility
-  **Enhanced Spacing** - 3px margins on header and status bar in enhanced themes
-  **Removed Invert Text Toggle** - Simplified theme menu (no longer needed)
-  **Cleaner Folder Design** - Removed "▶" chevron symbols for streamlined appearance

**Menu System:**
-  **Auto-Wrapping Filters** - Better responsive layout for filter toggles
-  **Context-Aware Interactions** - Proper pointer events to prevent UI conflicts
-  **Wider Menu Items** - Improved readability with content-adaptive width

**Technical:**
- Parallel blocklist downloads with unified Set for O(1) lookups
- Multiple format parsing (plain text, hosts files, URLhaus format, wildcard domains)
- Updated all theme CSS classes from "liquid/glass" to "Enhanced" naming

### v1.7.0 - Enhanced Theming & Menu Improvements

**New Features:**
-  **Bookmark Opacity Slider** - Control bookmark background transparency (0-100%) directly from Theme menu
-  **Custom Text Color Picker** - Full color customization for bookmark and folder text with visual color picker and reset button
-  **Light Gray Default** - Text color defaults to light gray (#e8e8e8) which works reliably with Firefox's color picker
-  **Real-Time Color Preview** - Color pickers apply changes instantly as you adjust colors

**Improvements:**
-  **Improved Menu Positioning** - All menus (Theme, View, Zoom, Settings) now respect 16px margins from viewport edges
-  **Enhanced Context Menu** - Bookmark context menus never extend behind toolbar, with better overflow handling
-  **Better Responsive Menus** - Menus scale properly to viewport width with increased margins for cleaner layout
-  **Reorganized Theme Menu** - Bookmark Opacity, Accent Color, and Text Color logically grouped for easy access
-  **Reduced Font Sizes** - Accent Color and Text Color labels now use matching 11px font size for consistency

**Bug Fixes:**
-  **Firefox Color Picker Workaround** - Fixed Firefox bug where pure white (#ffffff) prevented custom color selection by using light gray default
-  Fixed context menus sometimes positioning behind header/toolbar
-  Fixed menu overflow on narrow viewports
-  Fixed opacity affecting text readability (now only affects background via CSS pseudo-element)
-  Fixed text color not affecting bookmark URLs (now applies to URLs in addition to titles and folder names)
-  Fixed menu positioning calculations for edge cases

**Technical Implementation:**
- **Bookmark Opacity**: Uses CSS `::before` pseudo-element to apply opacity only to the background layer, keeping text and icons at full opacity for better readability. The opacity value is controlled via CSS variable `--bookmark-container-opacity`.
- **Text Color**: Uses CSS `custom-text-color-style` that persists across dynamic DOM changes. Targets `.bookmark-title`, `.folder-title`, and `.bookmark-url` elements specifically for precise color control.
- **Firefox Color Picker**: Pure white (#ffffff) as default value prevents Firefox's native color picker from initializing the custom color gradient area. Using #e8e8e8 (light gray) works around this browser bug while remaining visually close to white. Users can still select pure white after initialization.

---

### v1.6.0 - UI Refinements & Custom Navigation

**New Features:**
-  **Default Start Folder** - Choose which folder to auto-expand when opening the sidebar
-  **Trusted Filter** - New filter chip to view only whitelisted bookmarks (white shield icon at far right)
-  **Accent Color in Theme Menu** - Moved accent color picker from settings to theme menu for better organization
-  **Compact Filter Chips** - Reduced size of safety filter chips so all 4 fit on one line

**Improvements:**
-  **Streamlined Whitelist Management** - Removed whitelist panel from settings menu; use Trusted filter instead
-  **Simplified Accent Color Picker** - Removed Done button as changes apply instantly
-  **Compact Background Settings** - Reduced size of background image controls to save screen space
-  **Reorganized Settings** - Theme-related settings (theme, accent color, background, zoom, GUI scale) moved to theme menu

**Bug Fixes:**
-  Fixed accent color picker triggering theme switch when clicked
-  Fixed Safe filter excluding whitelisted bookmarks (now separate Trusted filter)

---

### v1.5.0 - Grid View & Link Detection Improvements

**New Features:**
-  **Square Card Layout** - Bookmarks display as square cards in grid view with aspect-ratio
-  **Preview Support** - Webpage previews visible in grid view cards
-  **Compact Folders** - Reduced spacing between collapsed folders in grid view
-  **Fixed Column Layout** - Grid columns now properly sized with minmax(0, 1fr)
-  **Redirect-Based Parking Detection** - Detects when URLs redirect to known parking domains
-  **Expanded Parking Domains** - Now checks 22+ parking services (up from 10)
-  **Dead Link Detection** - Properly flags 404, 410, and 451 responses as dead

---

### v1.4.0 - UI Overhaul & Enhanced Status Display

**New Features:**
-  **Stacked Status Icons** - Shield and chain icons now stack vertically, reclaiming horizontal space
-  **Detailed Suspicious Pattern Tooltips** - Warning tooltips now show specific patterns detected (HTTP Only, URL Shortener, Suspicious TLD, IP Address)
-  **HTTP Redirect Detection** - Detects when HTTP bookmarks redirect to HTTPS
-  **Clickable Status Icons** - Click on shield or chain to see full status details in a popup
-  **Larger Favicons** - Increased favicon size from 16px to 20px for better visibility
-  **Context Menu Repositioning** - Menus automatically reposition to stay within viewport
-  **Improved Caching** - Cache now stores sources with status for better tooltip support
-  **Centralized Version** - Version now managed from manifest.json as single source of truth

**Bug Fixes:**
-  **Zoom Fix** - Fixed gap between content and status bar caused by CSS transform zoom
- Fixed security warnings not showing specific pattern details
- Improved cache to handle both old and new format for backwards compatibility

### v1.3.0 - Multiple Filters & Support

**New Features:**
-  **Multiple Filter Selection** - Select multiple filters simultaneously for advanced filtering
- OR logic within categories (e.g., Live + Dead shows both)
- AND logic between categories (e.g., Live + Safe shows only live AND safe)
-  **Buy Me a Coffee** - Added support link in settings menu

### v1.2.0 - Export Improvements & Code Cleanup

**New Features:**
-  **HTML/JSON Export Choice** - Users can now choose between HTML (cross-browser compatible) or JSON (Firefox native) export formats
-  **Netscape Bookmark Format** - HTML exports use standard format compatible with all major browsers

**Improvements:**
-  **Code Cleanup** - Removed legacy duplicate files (crypto-utils.js, url-validator.js)
-  **Enhanced Documentation** - Added comprehensive acknowledgments for security services (URLhaus, BlockList Project, Google Safe Browsing, VirusTotal)
-  **Removed Private Tab Feature** - Eliminated confusing Firefox API limitation issues

**Bug Fixes:**
- Fixed incognito manifest setting for Firefox compatibility

### v1.1.0 - Bug Fixes & Improvements

**Critical Fixes:**
-  **Fixed link checking feature** - Content Security Policy updated to allow URL checking for all bookmark URLs (previously blocked by overly restrictive CSP)
-  **Fixed status indicators persisting** - Link and safety check results no longer reset to grey after bookmark operations (add/edit/delete)
-  **Fixed preview images not restoring** - Preview thumbnails now properly restore after status checks complete

**Improvements:**
-  **Auto-add https:// protocol** - Bookmarks can now be saved without typing protocol (e.g., "google.com"  "https://google.com")
-  **Updated extension icons** - Removed black background square, cleaner transparent design with black-filled shield
-  **Corrected documentation** - Fixed theme count (3 themes, not 8) in README and release notes

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