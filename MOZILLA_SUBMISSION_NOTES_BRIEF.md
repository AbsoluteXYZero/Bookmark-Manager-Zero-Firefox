BOOKMARK MANAGER ZERO - Submission Notes
Repository: - https://gitlab.com/AbsoluteXYZero/BMZ-Firefox

## PERMISSIONS

bookmarks - Core functionality: read/write Firefox bookmarks (getTree, create, update, remove, move)
storage - Store preferences locally (theme, view, zoom, cache, encrypted API keys) and optional cloud sync state
tabs - Open bookmarks in new tabs (tabs.create)
identity - GitLab OAuth login via browser.identity.launchWebAuthFlow (optional feature, user-initiated)
<all_urls> - Check bookmark availability via HEAD requests. Only status codes checked, no content. Disableable. Cached

## EXTERNAL APIS

Default (disableable):
• WordPress mshots - Screenshot previews
• URLhaus - Malware database
• BlockList Project - Malicious domains
• Google Favicons - Site icons

Opt-in (user API keys required):
• Google Safe Browsing - Threat intel
• VirusTotal - Manual scanning

Opt-in (user-initiated OAuth, optional feature):
• GitLab OAuth (gitlab.com) - Authenticate user for GitLab snippet sync
• Supabase (supabase.co) - Encrypted cloud storage for GitLab Personal Access Token, enabling cross-device sync. The Supabase anon key is intentionally public (per Supabase architecture); data is protected by Row-Level Security policies scoped to the authenticated user. No bookmark content is sent to Supabase — only the encrypted PAT.

Full disclosure in PRIVACY.md

## SECURITY

CSP: script-src 'self', no eval, no remote code
Encryption: AES-256-GCM for API keys and stored tokens (keyed on Supabase user UID)
Validation: URL sanitization, XSS protection
Private: Memory-only in incognito, no disk writes
OAuth: Uses browser.identity.launchWebAuthFlow — no credentials entered in the extension

## CODE

Pure vanilla JS - no obfuscation, minification, or bundlers
No remote code - all in package, no dynamic loading
Files: sidebar.js (13500+ lines), background.js, sidebar.html

## PRIVACY

✓ No analytics/tracking
✓ No third-party data collection
✓ Offline capable (GitLab/Supabase sync is fully opt-in)
✓ GDPR/CCPA compliant
✓ User control over external features
✓ Open source (MIT)

## ACCESSIBILITY

✓ ARIA labels
✓ Keyboard nav
✓ Screen reader compatible
✓ Focus management

## TESTING

Works with existing Firefox bookmarks - no accounts needed.
GitLab snippet sync and Supabase token storage are fully optional features.
Free API keys (optional):
- Safe Browsing: https://developers.google.com/safe-browsing/v4/get-started
- VirusTotal: https://www.virustotal.com/gui/my-apikey

## LIMITATIONS

Firefox only (Firefox bookmark API)
Sidebar only
No Firefox Sync (use native sync)

Contact: https://gitlab.com/AbsoluteXYZero/BMZ-Firefox/-/issues
