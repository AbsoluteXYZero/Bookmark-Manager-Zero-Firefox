// This script runs in the background and handles extension tasks.

// Version from manifest.json - single source of truth
const APP_VERSION = browser.runtime.getManifest().version;

// Encryption utilities inlined to avoid module loading issues
async function getDerivedKey() {
  // Use extension ID and browser info for key derivation (works in service workers)
  const extensionId = browser.runtime.id;
  const browserInfo = `${navigator.userAgent}-${navigator.language}-${extensionId}`;
  const encoder = new TextEncoder();
  const data = encoder.encode(browserInfo);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return await crypto.subtle.importKey(
    'raw',
    hashBuffer,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function decryptApiKey(encrypted) {
  if (!encrypted) return null;
  try {
    const key = await getDerivedKey();
    const combined = Uint8Array.from(atob(encrypted), c => c.charCodeAt(0));
    const iv = combined.slice(0, 12);
    const data = combined.slice(12);
    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      key,
      data
    );
    const decoder = new TextDecoder();
    return decoder.decode(decrypted);
  } catch (error) {
    // Handle decryption failures gracefully (e.g., different extension ID, corrupted data)
    // Don't log as error since this is expected when switching between extension versions
    console.debug('API key decryption failed (this is normal if switching extension versions):', error.message);
    return null;
  }
}

async function getDecryptedApiKey(keyName) {
  const result = await browser.storage.local.get(keyName);
  if (result[keyName]) {
    return await decryptApiKey(result[keyName]);
  }
  return null;
}

// Concurrency limiter to prevent overwhelming network with DNS lookups
class ConcurrencyLimiter {
  constructor(maxConcurrent = 10) {
    this.maxConcurrent = maxConcurrent;
    this.running = 0;
    this.queue = [];
    /* [ZeroLabs] 2026-06-20 10:50 AM - added: jitter to spread DNS lookups over time */
    this.jitterMs = 0; // Random 0..jitterMs delay before each request
  }

  async run(fn) {
    while (this.running >= this.maxConcurrent) {
      await new Promise(resolve => this.queue.push(resolve));
    }
    this.running++;
    try {
      // Stagger request starts so a batch of DNS lookups isn't fired as one wall
      if (this.jitterMs > 0) {
        await new Promise(resolve => setTimeout(resolve, Math.random() * this.jitterMs));
      }
      return await fn();
    } finally {
      this.running--;
      const next = this.queue.shift();
      if (next) next();
    }
  }

  /* [ZeroLabs] 2026-06-20 10:50 AM - added: live-adjustable cap for settings slider */
  setMax(n) {
    const next = Math.max(1, Math.min(20, Number(n) || this.maxConcurrent));
    const increased = next > this.maxConcurrent;
    this.maxConcurrent = next;
    if (increased) {
      let slots = this.maxConcurrent - this.running;
      while (slots-- > 0) {
        const resolve = this.queue.shift();
        if (!resolve) break;
        resolve();
      }
    }
  }

  /* [ZeroLabs] 2026-06-20 10:50 AM - added: live-adjustable jitter for settings slider */
  setJitter(ms) {
    this.jitterMs = Math.max(0, Math.min(1000, Number(ms) || 0));
  }
}

// Global concurrency limiter for all network requests
/* [ZeroLabs] 2026-06-20 10:35 AM - edited: lower cap to spare home DNS resolver */
// Each link check is a DNS lookup + connection to the bookmark's host. A high
// cap dumps a wall of simultaneous lookups on a local resolver (e.g. AdGuard
// Home) and briefly stalls the whole network. With link+safety each taking a
// slot, a cap of 5 means at most ~10 requests in flight -- gentle on DNS, and
// barely slower since per-request latency, not throughput, is the bottleneck.
const MAX_CONCURRENT_NETWORK = 5; // Default; user-tunable via Settings slider
const networkLimiter = new ConcurrencyLimiter(MAX_CONCURRENT_NETWORK);

/* [ZeroLabs] 2026-06-20 10:50 AM - added: apply saved scan concurrency + jitter on startup */
browser.storage.local.get(['scanConcurrency', 'scanJitter']).then(({ scanConcurrency, scanJitter }) => {
  if (scanConcurrency) networkLimiter.setMax(scanConcurrency);
  if (scanJitter !== undefined) networkLimiter.setJitter(scanJitter);
}).catch(() => {});

// URL validation utilities inlined to avoid module loading issues
const BLOCKED_SCHEMES = ['file', 'javascript', 'data', 'vbscript'];
const PRIVILEGED_SCHEMES = ['about', 'chrome', 'moz-extension', 'chrome-extension', 'view-source', 'jar', 'resource'];
const PRIVATE_IP_RANGES = [
  /^127\./, /^10\./, /^172\.(1[6-9]|2\d|3[01])\./, /^192\.168\./,
  /^169\.254\./, /^::1$/, /^fe80:/i, /^fc00:/i, /^fd00:/i, /^localhost$/i
];

function validateUrl(urlString) {
  if (!urlString || typeof urlString !== 'string') {
    return { valid: false, error: 'Invalid URL: empty or not a string' };
  }
  let url;
  try {
    url = new URL(urlString.trim());
  } catch (error) {
    return { valid: false, error: 'Invalid URL format' };
  }
  const scheme = url.protocol.replace(':', '').toLowerCase();

  // Allow privileged schemes (browser internal pages, extensions, etc.)
  if (PRIVILEGED_SCHEMES.includes(scheme)) {
    return { valid: true, url: url.href, privileged: true };
  }

  // Block dangerous schemes
  if (BLOCKED_SCHEMES.includes(scheme)) {
    return { valid: false, error: `Blocked URL scheme: ${scheme}` };
  }

  // Only allow HTTP/HTTPS for regular URLs
  if (scheme !== 'http' && scheme !== 'https') {
    return { valid: false, error: `Only HTTP and HTTPS URLs are allowed` };
  }

  const hostname = url.hostname.toLowerCase();
  for (const range of PRIVATE_IP_RANGES) {
    if (range.test(hostname)) {
      return { valid: false, error: 'Private/internal IP addresses are not allowed' };
    }
  }
  if (url.username || url.password) {
    return { valid: false, error: 'URLs with credentials are not allowed' };
  }
  return { valid: true, url: url.href };
}

function sanitizeUrl(urlString) {
  const validation = validateUrl(urlString);
  if (!validation.valid) {
    console.warn(`URL validation failed: ${validation.error}`);
    return null;
  }
  return validation.url;
}

const PARKING_DOMAINS = [
  // Major registrars with parking
  'hugedomains.com',
  'godaddy.com',
  'namecheap.com',
  'namesilo.com',
  'porkbun.com',
  'dynadot.com',
  'epik.com',
  // Domain marketplaces
  'sedo.com',
  'dan.com',
  'afternic.com',
  'domainmarket.com',
  'uniregistry.com',
  'squadhelp.com',
  'brandbucket.com',
  'undeveloped.com',
  'atom.com',
  // Parking services
  'bodis.com',
  'parkingcrew.net',
  'parkingcrew.com',
  'above.com',
  'sedoparking.com',
];

// Trusted domains that should never be flagged as unsafe by local blocklists
// These are well-known, trusted platforms that may have false positives in URLhaus/blocklists
// API-based scanners (Google, Yandex, VirusTotal) are NOT affected by this allow-list
const TRUSTED_DOMAINS = [
  'archive.org',
  'github.io',
  'githubusercontent.com',
  'github.com',
  'gitlab.com',
  'gitlab.io',
  'docs.google.com',
  'sites.google.com',
  'drive.google.com',
];

// Domains that should never be flagged as "parked" (for link status checking)
// These are legitimate hosting platforms, not parking services
const PARKING_EXEMPTIONS = [
  'github.io',
  'github.com',
  'githubusercontent.com',
  'gitlab.io',
  'gitlab.com',
  'pages.dev', // Cloudflare Pages
  'netlify.app',
  'vercel.app',
  'herokuapp.com',
];

// Helper function to check if a domain matches the trusted list (supports subdomains)
function isTrustedDomain(hostname) {
  if (!hostname) return false;

  const lowerHost = hostname.toLowerCase();

  for (const trustedDomain of TRUSTED_DOMAINS) {
    // Exact match
    if (lowerHost === trustedDomain) {
      return true;
    }
    // Subdomain match (e.g., "user.github.io" matches "github.io")
    if (lowerHost.endsWith('.' + trustedDomain)) {
      return true;
    }
  }

  return false;
}

// Helper function to check if a domain should be exempt from parking detection
function isParkingExempt(hostname) {
  if (!hostname) return false;

  const lowerHost = hostname.toLowerCase();

  for (const exemptDomain of PARKING_EXEMPTIONS) {
    // Exact match
    if (lowerHost === exemptDomain) {
      return true;
    }
    // Subdomain match (e.g., "user.github.io" matches "github.io")
    if (lowerHost.endsWith('.' + exemptDomain)) {
      return true;
    }
  }

  return false;
}

// Cache for link and safety checks (7 days TTL)
const CACHE_TTL = 7 * 24 * 60 * 60 * 1000; // 7 days in milliseconds

// Get cached result if valid
const getCachedResult = async (url, cacheKey) => {
  try {
    const cache = await browser.storage.local.get(cacheKey);
    if (cache[cacheKey]) {
      const cached = cache[cacheKey][url];
      if (cached && (Date.now() - cached.timestamp < CACHE_TTL)) {
        return cached.result;
      }
    }
  } catch (e) {
    console.warn('Cache read error:', e);
  }
  return null;
};

// Store result in cache (with mutex to prevent race conditions)
const cacheMutex = {};
const setCachedResult = async (url, result, cacheKey) => {
  // Wait for any pending write to the same cache to complete
  while (cacheMutex[cacheKey]) {
    await new Promise(resolve => setTimeout(resolve, 10));
  }

  cacheMutex[cacheKey] = true;

  try {
    const cache = await browser.storage.local.get(cacheKey);
    const cacheData = cache[cacheKey] || {};
    cacheData[url] = {
      result,
      timestamp: Date.now()
    };
    await browser.storage.local.set({ [cacheKey]: cacheData });
  } catch (e) {
    console.warn('Cache write error:', e);
  } finally {
    cacheMutex[cacheKey] = false;
  }
};

/**
 * Check if a URL is a browser privileged/internal URL that should not be scanned
 * @param {string} url The URL to check
 * @returns {object|null} Object with type and label if privileged, null otherwise
 */
function isPrivilegedUrl(url) {
  try {
    const urlObj = new URL(url);
    const scheme = urlObj.protocol.replace(':', '').toLowerCase();

    // Browser internal pages
    if (scheme === 'about') {
      return { type: 'browser-internal', label: 'Browser internal page' };
    }
    if (scheme === 'chrome') {
      return { type: 'browser-internal', label: 'Browser internal page' };
    }

    // Extension pages
    if (scheme === 'moz-extension') {
      return { type: 'extension', label: 'Extension page' };
    }
    if (scheme === 'chrome-extension') {
      return { type: 'extension', label: 'Extension page' };
    }

    // Developer/debugging schemes
    if (scheme === 'view-source') {
      return { type: 'developer', label: 'View source page' };
    }
    if (scheme === 'jar') {
      return { type: 'developer', label: 'JAR resource' };
    }
    if (scheme === 'resource') {
      return { type: 'developer', label: 'Browser resource' };
    }

    return null;
  } catch (e) {
    return null;
  }
}

/**
 * Checks if a URL is reachable and resolves to the expected domain.
 * This function runs in the background script, which has broader permissions
 * than content scripts, allowing it to bypass CORS restrictions.
 * @param {string} url The URL to check.
 * @returns {Promise<'live' | 'dead' | 'parked'>} The status of the link.
 */
const checkLinkStatus = async (url, bypassCache = false) => {
  // Check if this is a privileged URL that should not be scanned
  const privilegedInfo = isPrivilegedUrl(url);
  if (privilegedInfo) {
    console.log(`[Link Check] Privileged URL detected: ${privilegedInfo.label}`);
    // Cache the result so it persists after sidebar reload
    await setCachedResult(url, 'live', 'linkStatusCache');
    return 'live'; // Privileged URLs are always considered "live"
  }

  // Check cache first (unless bypassed for rescan)
  if (!bypassCache) {
    const cached = await getCachedResult(url, 'linkStatusCache');
    if (cached) {
      console.log(`[Link Check] Using cached result for ${url}: ${cached}`);
      return cached;
    }
  } else {
    console.log(`[Link Check] Bypassing cache for rescan of ${url}`);
  }

  let result;

  // Check if the URL itself is on a parking domain
  try {
    const urlHost = new URL(url).hostname.toLowerCase();
    // Skip parking check for exempt hosting platforms
    if (!isParkingExempt(urlHost) && PARKING_DOMAINS.some(domain => urlHost.includes(domain))) {
      result = 'parked';
      await setCachedResult(url, result, 'linkStatusCache');
      return result;
    }
  } catch (e) {
    // Invalid URL, continue with fetch attempt
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 5000); // 5-second timeout

  // Use a standard browser User-Agent to avoid being blocked
  const headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
  };

  try {
    // Try HEAD request first (lighter weight)
    // Note: Don't use mode: 'cors' - background scripts have broader permissions
    const response = await fetch(url, {
      method: 'HEAD',
      signal: controller.signal,
      credentials: 'omit',
      redirect: 'follow',
      headers: headers
    });
    clearTimeout(timeoutId);

    // Check if redirected to parking domain
    if (response.redirected || response.url !== url) {
      const finalHost = new URL(response.url).hostname.toLowerCase();
      // Skip parking check for exempt hosting platforms
      if (!isParkingExempt(finalHost) && PARKING_DOMAINS.some(domain => finalHost.includes(domain))) {
        result = 'parked';
        await setCachedResult(url, result, 'linkStatusCache');
        return result;
      }
    }

    // Check for successful status codes
    if (response.ok || (response.status >= 300 && response.status < 400)) {
      // Skip content-based parking detection for exempt hosting platforms
      const urlHost = new URL(url).hostname.toLowerCase();
      if (isParkingExempt(urlHost)) {
        result = 'live';
        await setCachedResult(url, result, 'linkStatusCache');
        return result;
      }

      // Try lightweight content check for parking indicators (with robust error handling)
      try {
        const contentController = new AbortController();
        const contentTimeout = setTimeout(() => contentController.abort(), 3000); // Short 3s timeout

        const contentResponse = await fetch(url, {
          method: 'GET',
          signal: contentController.signal,
          credentials: 'omit',
          redirect: 'follow',
          headers: headers
        });
        clearTimeout(contentTimeout);

        // Only check if we got a successful response
        if (contentResponse.ok) {
          const html = await contentResponse.text();
          const htmlLower = html.toLowerCase();

          // Real websites typically have substantial content
          // Parked pages are usually very simple (<30KB)
          const contentSize = html.length;
          const isSubstantialContent = contentSize > 30000;

          // Strong indicators - if any match, definitely parked
          const strongParkingIndicators = [
            'sedo domain parking',
            'this domain is parked',
            'domain is parked',
            'parked by',
            'parked domain',
            'parkingcrew',
            'bodis.com',
            'hugedomains.com/domain',
            'afternic.com/forsale',
            'this domain name is for sale',
            'the domain name is for sale',
            'buy this domain name',
            'domain has expired',
            'this domain has been registered'
          ];

          // If any strong indicator matches, it's parked
          if (strongParkingIndicators.some(indicator => htmlLower.includes(indicator))) {
            result = 'parked';
            await setCachedResult(url, result, 'linkStatusCache');
            return result;
          }

          // Skip weak indicator check for substantial content (real websites)
          if (isSubstantialContent) {
            result = 'live';
            await setCachedResult(url, result, 'linkStatusCache');
            return result;
          }

          // Weak indicators - need 3+ matches on small pages
          const weakParkingIndicators = [
            'domain for sale',
            'buy this domain',
            'domain is for sale',
            'this domain may be for sale',
            'make an offer',
            'make offer',
            'expired domain',
            'register this domain',
            'purchase this domain',
            'acquire this domain',
            'coming soon',
            'under construction',
            'inquire about this domain',
            'interested in this domain',
            'domain may be for sale'
          ];

          const matchCount = weakParkingIndicators.filter(indicator =>
            htmlLower.includes(indicator)
          ).length;

          // Require 3+ weak indicators on small pages
          if (matchCount >= 3) {
            result = 'parked';
            await setCachedResult(url, result, 'linkStatusCache');
            return result;
          }
        }
      } catch (contentError) {
        // Log CORS and other errors for debugging parking detection issues
        console.log(`[Parking Check] Content fetch failed for ${url}:`, contentError.message);
        // Silently continue - don't break link checking
      }

      // If content check didn't find parking indicators (or failed), return live
      result = 'live';
      await setCachedResult(url, result, 'linkStatusCache');
      return result;
    }

    // Check if it's a Cloudflare-protected site
    const serverHeader = response.headers.get('server');
    const cfRay = response.headers.get('cf-ray');

    if (serverHeader?.toLowerCase().includes('cloudflare') || cfRay) {
      // Cloudflare is fronting this domain - site is configured and live
      // Even with 4xx/5xx errors, the domain is valid and accessible
      // (403 often means the site blocks direct requests but works in browser)
      console.log(`[Link Check] Cloudflare detected for ${url} (status ${response.status}), marking as live`);
      result = 'live';
      await setCachedResult(url, result, 'linkStatusCache');
      return result;
    }

    // 4xx errors (except 404, 410, 451) often mean the site is blocking automated requests
    // but the site itself is live and accessible in a browser
    // 403 = Forbidden (often blocks bots), 401 = Unauthorized (needs login), 405 = Method Not Allowed
    const liveButBlocking = [401, 403, 405, 406, 429];
    if (liveButBlocking.includes(response.status)) {
      console.log(`[Link Check] ${url} returned ${response.status}, likely blocking automated requests - marking as live`);
      result = 'live';
      await setCachedResult(url, result, 'linkStatusCache');
      return result;
    }

    // 5xx errors could be temporary server issues - try GET fallback before marking dead
    if (response.status >= 500) {
      console.log(`[Link Check] ${url} returned ${response.status}, will try GET fallback`);
      // Fall through to catch block logic by throwing
      throw new Error(`Server error ${response.status}`);
    }

    // 404 from HEAD might be a site that doesn't support HEAD - try GET fallback
    if (response.status === 404) {
      console.log(`[Link Check] ${url} returned 404 on HEAD, trying GET fallback`);
      throw new Error(`HEAD returned 404`);
    }

    // 410 (Gone), 451 (Legal) - these indicate the content is truly gone
    console.log(`[Link Check] ${url} returned ${response.status}, marking as dead`);
    result = 'dead';
    await setCachedResult(url, result, 'linkStatusCache');
    return result;

  } catch (error) {
    clearTimeout(timeoutId);

    console.log(`[Link Check] HEAD failed for ${url}:`, error.name, error.message);

    // If HEAD timed out or was aborted, mark as live (slow server, not dead)
    if (error.name === 'AbortError' || error.message?.includes('abort')) {
      console.log(`[Link Check] HEAD request timed out for ${url}, marking as live (slow server)`);
      result = 'live';
      await setCachedResult(url, result, 'linkStatusCache');
      return result;
    }

    // If HEAD fails for other reasons, try GET as fallback
    try {
      const fallbackController = new AbortController();
      const fallbackTimeout = setTimeout(() => fallbackController.abort(), 5000);

      const fallbackResponse = await fetch(url, {
        method: 'GET',
        signal: fallbackController.signal,
        credentials: 'omit',
        redirect: 'follow',
        headers: headers
      });
      clearTimeout(fallbackTimeout);

      // Check for Cloudflare on fallback response too
      const fbServerHeader = fallbackResponse.headers.get('server');
      const fbCfRay = fallbackResponse.headers.get('cf-ray');

      if (fbServerHeader?.toLowerCase().includes('cloudflare') || fbCfRay) {
        console.log(`[Link Check] Cloudflare detected on fallback for ${url}, marking as live`);
        result = 'live';
        await setCachedResult(url, result, 'linkStatusCache');
        return result;
      }

      // Only mark as live if GET returned a successful response
      if (fallbackResponse.ok) {
        console.log(`[Link Check] GET fallback succeeded for ${url}, marking as live`);
        result = 'live';
        await setCachedResult(url, result, 'linkStatusCache');
        return result;
      }

      // GET also returned an error - site is dead
      console.log(`[Link Check] GET fallback returned ${fallbackResponse.status} for ${url}, marking as dead`);
      result = 'dead';
      await setCachedResult(url, result, 'linkStatusCache');
      return result;
    } catch (fallbackError) {
      // Check if it was a timeout (AbortError) - timeouts often mean slow server, not dead
      if (fallbackError.name === 'AbortError') {
        console.log(`[Link Check] Request timed out for ${url}, marking as live (slow server)`);
        result = 'live';
        await setCachedResult(url, result, 'linkStatusCache');
        return result;
      }

      // NetworkError usually means CORS blocked the request - site exists but blocks cross-origin
      // This is common for legitimate sites with strict security policies
      if (fallbackError.message?.includes('NetworkError') || fallbackError.name === 'TypeError') {
        console.log(`[Link Check] NetworkError for ${url}, likely CORS restriction - marking as live`);
        result = 'live';
        await setCachedResult(url, result, 'linkStatusCache');
        return result;
      }

      // Other errors (DNS errors, truly unreachable) mean the link is dead
      console.warn('Link check failed for:', url, fallbackError.message);
      result = 'dead';
      await setCachedResult(url, result, 'linkStatusCache');
      return result;
    }
  }
};

// Malicious URL/domain database (aggregated from multiple sources)
let maliciousUrlsSet = new Set();
let domainSourceMap = new Map(); // Track which source(s) flagged each domain
let domainOnlyMap = new Map(); // Map of domain:port -> sources (for entries with paths like "1.2.3.4:80/malware")
let blocklistLastUpdate = 0;
let blocklistLoading = false; // Flag to prevent duplicate loads

// Helper to check if two timestamps are on the same calendar day.
function isSameDay(timestamp1, timestamp2) {
    if (!timestamp1 || !timestamp2 || timestamp1 === 0 || timestamp2 === 0) return false;
    const d1 = new Date(timestamp1);
    const d2 = new Date(timestamp2);
    return d1.getFullYear() === d2.getFullYear() &&
           d1.getMonth() === d2.getMonth() &&
           d1.getDate() === d2.getDate();
}

// Blocklist sources - all free, no API keys required
const BLOCKLIST_SOURCES = [
  {
    name: 'URLhaus (Active)',
    // Fetched from dedicated GitHub repo (updated daily via GitHub Actions)
    url: 'https://raw.githubusercontent.com/AbsoluteXYZero/urlhaus-list/main/urlhaus-active.txt',
    format: 'urlhaus_text' // Full URLs with paths
  },
  {
    name: 'URLhaus (Historical)',
    // Using GitLab Pages CDN mirror with CORS support (updates every 12 hours from abuse.ch)
    url: 'https://curbengh.github.io/malware-filter/urlhaus-filter.txt',
    format: 'domains' // Domain list (one per line)
  },
  {
    name: 'BlockList Project (Malware)',
    url: 'https://blocklistproject.github.io/Lists/malware.txt',
    format: 'hosts' // Hosts file format (0.0.0.0 domain.com)
  },
  {
    name: 'BlockList Project (Phishing)',
    url: 'https://blocklistproject.github.io/Lists/phishing.txt',
    format: 'hosts'
  },
  {
    name: 'BlockList Project (Scam)',
    url: 'https://blocklistproject.github.io/Lists/scam.txt',
    format: 'hosts'
  },
  {
    /* [ZeroLabs] 2026-08-17 4:15 PM - edited: jsdelivr 403, repo restructured (see also: Bookmark-Manager-Zero-Chrome/background.js) */
    // Was cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/tif.txt.
    // Two independent breakages: jsDelivr now 403s every path in this repo
    // ("Package size exceeded the configured limit of 150 MB"), and the repo
    // dropped the domains/ directory in favour of wildcard/, with plain domain
    // lists renamed to *-onlydomains.txt. Switched to GitHub raw, which sends
    // Access-Control-Allow-Origin: * and is already used by OISD and FMHY below.
    // medium tier rather than full TIF: 7 MB vs 36.6 MB / 2.06M entries, and
    // every domain is held twice in memory here (maliciousUrlsSet + domainSourceMap).
    name: 'HaGeZi TIF',
    url: 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.medium-onlydomains.txt',
    format: 'domains' // Plain domain list (one per line)
  },
  {
    name: 'Phishing-Filter',
    url: 'https://malware-filter.gitlab.io/malware-filter/phishing-filter-hosts.txt',
    format: 'hosts'
  },
  {
    name: 'OISD Big',
    // Using GitHub mirror to avoid CORS issues with oisd.nl direct download
    url: 'https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/domainswild2_big.txt',
    format: 'domains' // Wildcard domains format
  },
  {
    name: 'FMHY Filterlist',
    // FMHY unsafe sites list - fake activators, malware distributors, unsafe piracy sites
    url: 'https://raw.githubusercontent.com/fmhy/FMHYFilterlist/main/filterlist-basic-domains.txt',
    format: 'domains' // Plain domain list (one per line)
  },
  {
    name: 'Dandelion Sprout Anti-Malware',
    // Curated anti-malware list - scams, phishing, malware domains
    url: 'https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareHosts.txt',
    format: 'hosts' // Hosts file format (127.0.0.1 domain.com)
  }
];

// Check URL using Google Safe Browsing API (fallback/redundancy check)
// Get a free API key at: https://developers.google.com/safe-browsing/v4/get-started
// Free tier: 10,000 requests per day
// API key is stored in browser.storage.local.googleSafeBrowsingApiKey
const checkGoogleSafeBrowsing = async (url) => {
  try {
    // Get encrypted API key from storage and decrypt it
    const apiKey = await getDecryptedApiKey('googleSafeBrowsingApiKey');

    if (!apiKey || apiKey.trim() === '') {
      console.log(`[Google SB] API key not configured, skipping`);
      return 'unknown';
    }

    console.log(`[Google SB] Starting check for ${url}`);

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000); // 5s timeout

    const response = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`,
      {
        method: 'POST',
        signal: controller.signal,
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          client: {
            clientId: 'bookmark-manager-zero',
            clientVersion: APP_VERSION
          },
          threatInfo: {
            threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
            platformTypes: ['ANY_PLATFORM'],
            threatEntryTypes: ['URL'],
            threatEntries: [{ url }]
          }
        })
      }
    );

    clearTimeout(timeout);

    if (!response.ok) {
        if (response.status === 429) {
            console.warn(`[Google SB] Rate limited (429). Check your quota.`);
        } else {
            console.error(`[Google SB] API error: ${response.status}`);
        }
        return 'unknown';
    }

    const data = await response.json();

    // If matches found, URL is unsafe
    if (data.matches && data.matches.length > 0) {
      console.log(`[Google SB] ⚠️ Threat detected:`, data.matches[0].threatType);
      return 'unsafe';
    }

    console.log(`[Google SB] Result: SAFE`);
    return 'safe';

  } catch (error) {
    console.error(`[Google SB] Error:`, error.message);
    return 'unknown';
  }
};

// ============================================================================
// VIRUSTOTAL SCANNING (WITH RATE LIMITING)
// ============================================================================

// Session-based rate limiting flag for VirusTotal API
// Reset at the start of each scan session
let virusTotalRateLimited = false;

// Check VirusTotal by scraping public web page (no API key needed)
// This always runs on every bookmark scan
// WARNING: For personal use only. May violate VirusTotal ToS if distributed.
const checkURLVoidScraping = async (url) => {
  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname.toLowerCase();

    console.log(`[URLVoid Scraping] Checking ${hostname}`);

    const urlvoidUrl = `https://www.urlvoid.com/scan/${encodeURIComponent(hostname)}/`;
    let html = null;

    // Try direct fetch first (extensions have elevated privileges)
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 10000);

      const response = await fetch(urlvoidUrl, {
        signal: controller.signal,
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0'
        }
      });

      clearTimeout(timeout);

      if (response.ok) {
        html = await response.text();
        console.log(`[URLVoid Scraping] Direct fetch succeeded for ${hostname}`);
      } else {
        console.log(`[URLVoid Scraping] Direct fetch failed: ${response.status}`);
      }
    } catch (directError) {
      console.log(`[URLVoid Scraping] Direct fetch error: ${directError.message}`);
    }

    // Fallback to CORS proxies if direct fetch failed
    if (!html) {
      console.log(`[URLVoid Scraping] Trying CORS proxy fallback for ${hostname}`);
      const corsProxies = [
        `https://corsproxy.io/?${encodeURIComponent(urlvoidUrl)}`,
        `https://api.allorigins.win/raw?url=${encodeURIComponent(urlvoidUrl)}`,
        `https://api.codetabs.com/v1/proxy?quest=${encodeURIComponent(urlvoidUrl)}`
      ];

      // Race all proxies in parallel
      const fetchPromises = corsProxies.map(async (proxiedUrl) => {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 15000);

        try {
          const response = await fetch(proxiedUrl, { signal: controller.signal });
          clearTimeout(timeout);

          if (!response.ok) throw new Error(`HTTP ${response.status}`);
          return await response.text();
        } catch (error) {
          clearTimeout(timeout);
          throw error;
        }
      });

      try {
        html = await Promise.any(fetchPromises);
        console.log(`[URLVoid Scraping] Proxy fallback succeeded for ${hostname}`);
      } catch (aggregateError) {
        console.log(`[URLVoid Scraping] All proxies failed for ${hostname}`);
        return 'unknown';
      }
    }

    /* [ZeroLabs] 2026-08-28 - fixed: "no report" was being counted as CLEAN */
    // URLVoid answers HTTP 200 with an ordinary-looking "Report Not Found" page
    // for any domain it has never examined. That page contains no "detected"
    // either, so the count below came out zero and the domain was recorded as
    // SAFE - when the truth was that nobody had ever looked at it. A false clean
    // is the one direction a safety check must never fail in.
    //
    // Detected by the page's own marker rather than by size: the same page
    // measures ~12.7KB but that varies, while a real result page is ~36KB.
    if (/Report Not Found/i.test(html)) {
      console.log(`[URLVoid Scraping] ${hostname}: no report - URLVoid has never scanned it`);
      return 'unknown'; // Abstain. 'safe' would be a claim nothing supports.
    }

    const detectedPattern = /detected/gi;
    const detectedMatches = html.match(detectedPattern) || [];
    const detectedCount = detectedMatches.length;

    console.log(`[URLVoid Scraping] ${hostname} - Detected: ${detectedCount}`);

    if (detectedCount >= 2) {
      return 'unsafe'; // 2 or more scanners detected malicious
    } else if (detectedCount === 1) {
      return 'warning'; // 1 scanner detected suspicious
    } else {
      return 'safe'; // No detections
    }

  } catch (error) {
    console.log(`[URLVoid Scraping] Error:`, error.message);
    return 'unknown';
  }
};

// Check VirusTotal using API v3 (requires API key)
// Get a free API key at: https://www.virustotal.com/
// Free tier: 500 requests/day, 4 requests/minute
// API key is stored in browser.storage.local.virusTotalApiKey
const checkVirusTotal = async (url) => {
  try {
    // Get encrypted API key from storage and decrypt it
    const apiKey = await getDecryptedApiKey('virusTotalApiKey');

    if (!apiKey || apiKey.trim() === '') {
      console.log(`[VirusTotal API] No API key configured, skipping`);
      return 'unknown';
    }

    // Check if we've hit rate limit this session
    if (virusTotalRateLimited) {
      console.log(`[VirusTotal API] Rate limited, skipping check for ${url}`);
      return 'unknown';
    }

    console.log(`[VirusTotal API] Starting check for ${url}`);

    // Generate URL ID for VirusTotal API (base64url of the URL)
    const urlId = btoa(url).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

    // Try to get existing report first (uses GET endpoint, counts against rate limit)
    const reportController = new AbortController();
    const reportTimeout = setTimeout(() => reportController.abort(), 8000);

    const reportResponse = await fetch(
      `https://www.virustotal.com/api/v3/urls/${urlId}`,
      {
        method: 'GET',
        signal: reportController.signal,
        headers: {
          'x-apikey': apiKey
        }
      }
    );

    clearTimeout(reportTimeout);

    // Check for rate limiting
    if (reportResponse.status === 429) {
      console.log(`[VirusTotal API] Rate limit hit (429), will skip remaining checks this session`);
      virusTotalRateLimited = true;
      return 'unknown';
    }

    if (!reportResponse.ok) {
      console.log(`[VirusTotal API] Failed to get report: ${reportResponse.status}`);
      return 'unknown';
    }

    const reportData = await reportResponse.json();

    // Extract analysis stats
    const stats = reportData.data?.attributes?.last_analysis_stats;

    if (!stats) {
      console.log(`[VirusTotal API] No analysis stats available`);
      return 'unknown';
    }

    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;

    console.log(`[VirusTotal API] Analysis stats - Malicious: ${malicious}, Suspicious: ${suspicious}`);

    // Determine threat level
    if (malicious >= 2) {
      return 'unsafe';
    }

    if (malicious >= 1 || suspicious >= 2) {
      return 'warning';
    }

    return 'safe';

  } catch (error) {
    if (error.name === 'AbortError') {
      console.log(`[VirusTotal API] Request timed out`);
    } else {
      console.error(`[VirusTotal API] Error:`, error.message);
    }
    return 'unknown';
  }
};


// Check URL using Yandex Safe Browsing API
// Register at: https://yandex.com/dev/
// Free tier: 100,000 requests per day
// API key is stored in browser.storage.local.yandexApiKey
const checkYandexSafeBrowsing = async (url) => {
  try {
    // Get encrypted API key from storage and decrypt it
    const apiKey = await getDecryptedApiKey('yandexApiKey');

    if (!apiKey || apiKey.trim() === '') {
      console.log(`[Yandex SB] API key not configured, skipping`);
      return 'unknown';
    }

    console.log(`[Yandex SB] Starting check for ${url}`);

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000); // 5s timeout

    const response = await fetch(
      `https://sba.yandex.net/v4/threatMatches:find?key=${apiKey}`,
      {
        method: 'POST',
        signal: controller.signal,
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          threatInfo: {
            threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'],
            platformTypes: ['ANY_PLATFORM'],
            threatEntryTypes: ['URL'],
            threatEntries: [{ url }]
          }
        })
      }
    );

    clearTimeout(timeout);

    if (!response.ok) {
        if (response.status === 429) {
            console.warn(`[Yandex SB] Rate limited (429). Check your quota.`);
        } else {
            console.error(`[Yandex SB] API error: ${response.status}`);
        }
        return 'unknown';
    }

    const data = await response.json();

    // If matches found, URL is unsafe
    if (data.matches && data.matches.length > 0) {
      console.log(`[Yandex SB] ⚠️ Threat detected:`, data.matches[0].threatType);
      return 'unsafe';
    }

    console.log(`[Yandex SB] Result: SAFE`);
    return 'safe';

  } catch (error) {
    console.error(`[Yandex SB] Error:`, error.message);
    return 'unknown';
  }
};

// Parse different blocklist formats
const parseBlocklistLine = (line, format) => {
  const trimmed = line.trim();

  // Skip empty lines and comments (# for most lists, ! for adblock-style lists)
  if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('!')) {
    return null;
  }

  let domain = null;

  if (format === 'hosts') {
    // Hosts file format: "0.0.0.0 domain.com" or "127.0.0.1 domain.com"
    const parts = trimmed.split(/\s+/);
    if (parts.length >= 2) {
      domain = parts[1]; // Second part is the domain
    }
  } else if (format === 'urlhaus_text') {
    // URLhaus text format: full URLs like "http://malicious.com/path/file.exe"
    if (trimmed.startsWith('http://') || trimmed.startsWith('https://')) {
      try {
        const urlObj = new URL(trimmed);
        domain = urlObj.hostname.toLowerCase();
      } catch {
        return null; // Invalid URL, skip
      }
    } else {
      return null; // Not a valid URL format
    }
  } else if (format === 'urlhaus') {
    // URLhaus format: plain URLs/domains
    domain = trimmed;
  } else if (format === 'domains') {
    // Plain domain list format
    domain = trimmed;
  } else {
    // Default: assume plain domain
    domain = trimmed;
  }

  if (!domain) {
    return null;
  }

  // Normalize: lowercase, remove protocol, remove trailing slash, remove wildcard prefix
  const normalized = domain.toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/\/$/, '')
    .replace(/^\*\./, ''); // Remove wildcard prefix for OISD format

  // Skip localhost and invalid entries
  if (normalized === 'localhost' || normalized.startsWith('127.') || normalized.startsWith('0.0.0.0')) {
    return null;
  }

  return normalized;
};

// Download from a single blocklist source
const downloadBlocklistSource = async (source) => {
  try {
    console.log(`[Blocklist] Downloading ${source.name}...`);

    // Use fetch API for better CORS handling in extensions
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 60000); // 60s timeout

    const response = await fetch(source.url, {
      method: 'GET',
      signal: controller.signal,
      mode: 'cors', // Use CORS mode but extensions can bypass via host_permissions
      cache: 'no-store',
      credentials: 'omit'
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      console.error(`[Blocklist] ${source.name} failed: HTTP ${response.status}`);
      return { domains: [], count: 0 };
    }

    let text = await response.text();
    console.log(`[Blocklist] ${source.name}: ${text.length} bytes downloaded`);

    // Check if response is JSON-wrapped (some proxies do this)
    try {
      const jsonData = JSON.parse(text);
      if (jsonData.contents) {
        text = jsonData.contents;
      } else if (jsonData.data) {
        text = jsonData.data;
      }
    } catch (e) {
      // Not JSON, use text as-is
    }

    const lines = text.split('\n');
    const domains = [];

    for (const line of lines) {
      const normalized = parseBlocklistLine(line, source.format);
      if (normalized) {
        domains.push(normalized);
      }
    }

    console.log(`[Blocklist] ${source.name}: ${domains.length} domains loaded`);
    return { domains, count: domains.length };

  } catch (error) {
    console.error(`[Blocklist] ${source.name} error:`, error.message);
    return { domains: [], count: 0 };
  }
};

/* [ZeroLabs] 2026-08-28 - added: the blocklists are safety checking's data */
// Absent means on, matching how the scan itself reads this setting, so a storage
// read that comes back empty never silently disables the feature. Only an
// explicit false counts as off.
const isSafetyCheckingEnabled = async () => {
  const { safetyCheckingEnabled } = await browser.storage.local.get('safetyCheckingEnabled');
  return safetyCheckingEnabled !== false;
};

/* [ZeroLabs] 2026-08-28 - added: the eager preload must not guess */
// The sidebar mirrors the real setting into extension storage when it opens, but
// the startup block runs BEFORE any sidebar exists - on a fresh profile, or on
// the first reload after this fix, the key is simply not there yet. Defaulting
// to "on" there means committing to a ~97 MB download for a feature that may
// well be switched off.
//
// So the eager preload requires an explicit yes and skips on unknown. Nothing is
// lost by skipping: the preload only warms the database, and every path that
// actually NEEDS it (ensureBlocklistReady, startScan) fetches it on demand and
// keeps defaulting to on, which is safe because by the time either runs the
// sidebar has mirrored the real value.
const isSafetyCheckingKnownOn = async () => {
  const { safetyCheckingEnabled } = await browser.storage.local.get('safetyCheckingEnabled');
  return safetyCheckingEnabled === true;
};

// Download and aggregate all blocklist sources
const updateBlocklistDatabase = async () => {
  // Prevent duplicate loads
  if (blocklistLoading) {
    console.log(`[Blocklist] Already loading, skipping duplicate request`);
    return true;
  }

  blocklistLoading = true;
  let success = false;
  const results = []; // Declare outside try block

  try {
    console.log(`[Blocklist] Starting update from ${BLOCKLIST_SOURCES.length} sources...`);

    // Notify UI that blocklist download is starting
    browser.runtime.sendMessage({
      type: 'blocklistProgress',
      current: 0,
      total: BLOCKLIST_SOURCES.length,
      status: 'starting'
    }).catch(() => {}); // Ignore if no listeners

    // Clear existing data
    maliciousUrlsSet.clear();
    domainSourceMap.clear();

    // Download sources sequentially to report progress
    for (let i = 0; i < BLOCKLIST_SOURCES.length; i++) {
      const source = BLOCKLIST_SOURCES[i];

      // Notify UI of current download
      browser.runtime.sendMessage({
        type: 'blocklistProgress',
        current: i + 1,
        total: BLOCKLIST_SOURCES.length,
        sourceName: source.name,
        status: 'downloading'
      }).catch(() => {});

      const result = await downloadBlocklistSource(source);
      results.push(result);
    }

    // Combine all domains into the Set and track sources
    let totalCount = 0;
    for (let i = 0; i < results.length; i++) {
      const result = results[i];
      const sourceName = BLOCKLIST_SOURCES[i].name;

      for (const domain of result.domains) {
        maliciousUrlsSet.add(domain);

        // Track which source(s) flagged this domain
        if (domainSourceMap.has(domain)) {
          // Use a Set to avoid duplicates when same domain appears multiple times in one blocklist
          const sources = domainSourceMap.get(domain);
          if (!sources.includes(sourceName)) {
            sources.push(sourceName);
          }
        } else {
          domainSourceMap.set(domain, [sourceName]);
        }

        // Build domain-only index for fast lookups (handles entries with paths like "1.2.3.4:80/malware")
        const domainPart = domain.split('/')[0]; // Extract domain:port before any path
        if (domainPart !== domain) { // Only index if there's a path component
          if (domainOnlyMap.has(domainPart)) {
            const sources = domainOnlyMap.get(domainPart);
            if (!sources.includes(sourceName)) {
              sources.push(sourceName);
            }
          } else {
            domainOnlyMap.set(domainPart, [sourceName]);
          }
        }
      }
      totalCount += result.count;
    }

    blocklistLastUpdate = Date.now();
    success = true;

    console.log(`[Blocklist] ✓ Database updated: ${maliciousUrlsSet.size} unique domains from ${totalCount} total entries`);
    const sourceNames = BLOCKLIST_SOURCES.map(s => s.name).join(', ');
    console.log(`[Blocklist] Sources: ${sourceNames}`);

    // Store update timestamp
    await browser.storage.local.set({
      blocklistLastUpdate: blocklistLastUpdate
    });

    return true;
  } catch (error) {
    console.error(`[Blocklist] Error updating database:`, error);
    return false;
  } finally {
    // ALWAYS send completion message to prevent UI from getting stuck
    // Even on partial failures, the UI should reset to "Ready"
    const finalDomains = maliciousUrlsSet.size;
    const finalSources = BLOCKLIST_SOURCES.length;

    console.log(`[Blocklist] Sending completion message (success: ${success}, domains: ${finalDomains})`);

    browser.runtime.sendMessage({
      type: 'blocklistComplete',
      domains: finalDomains,
      totalEntries: success ? results.reduce((sum, r) => sum + r.count, 0) : 0,
      sources: finalSources,
      success: success
    }).catch(() => {});

    blocklistLoading = false;
  }
};

// Check for suspicious URL patterns that aren't necessarily malicious but warrant caution
const checkSuspiciousPatterns = async (url, domain) => {
  const patterns = [];

  // 1. Check for HTTP-only (no encryption)
  if (url.toLowerCase().startsWith('http://')) {
    // Check if it redirects to HTTPS
    let redirectsToHttps = false;
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000);

      const response = await fetch(url, {
        method: 'HEAD',
        signal: controller.signal,
        credentials: 'omit',
        redirect: 'follow'
      });
      clearTimeout(timeoutId);

      // Check if final URL is HTTPS
      if (response.url && response.url.toLowerCase().startsWith('https://')) {
        redirectsToHttps = true;
      }
    } catch (e) {
      // Couldn't check redirect, assume no redirect
      console.log(`[Suspicious Patterns] Could not check redirect for ${url}:`, e.message);
    }

    if (redirectsToHttps) {
      patterns.push('HTTP Only (redirects to HTTPS)');
    } else {
      patterns.push('HTTP Only (Unencrypted)');
    }
  }

  // 2. Check for known URL shorteners
  const urlShorteners = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly',
    'adf.ly', 'bl.ink', 'lnkd.in', 'short.link', 'cutt.ly', 'rebrand.ly',
    'tiny.cc', 'rb.gy', 'clck.ru', 'shorturl.at', 'v.gd'
  ];

  const domainWithoutPort = domain.split(':')[0];
  if (urlShorteners.includes(domainWithoutPort)) {
    patterns.push('URL Shortener');
  }

  // 3. Check for suspicious TLDs (commonly abused)
  const suspiciousTlds = [
    '.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.cc', '.ws',
    '.info', '.biz', '.club', '.click', '.link', '.download', '.stream',
    '.loan', '.win', '.bid', '.trade', '.racing', '.party', '.review',
    '.science', '.work', '.date', '.faith', '.cricket', '.accountant'
  ];

  for (const tld of suspiciousTlds) {
    if (domainWithoutPort.endsWith(tld)) {
      patterns.push('Suspicious TLD');
      break;
    }
  }

  // 4. Check for IP addresses instead of domain names
  const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}(:\d+)?$/;
  const ipv6Pattern = /^\[?([0-9a-f:]+)\]?(:\d+)?$/i;

  if (ipv4Pattern.test(domainWithoutPort) || ipv6Pattern.test(domainWithoutPort)) {
    patterns.push('IP Address');
  }

  return patterns;
};

// Check URL safety using aggregated blocklist database
const checkURLSafety = async (url, bypassCache = false) => {
  // Check if this is a privileged URL that should not be scanned
  const privilegedInfo = isPrivilegedUrl(url);
  if (privilegedInfo) {
    console.log(`[Safety Check] Privileged URL detected: ${privilegedInfo.label}`);
    // Cache the result so it persists after sidebar reload
    const result = { status: 'safe', sources: [privilegedInfo.label + ' (not scanned)'] };
    await setCachedResult(url, result, 'safetyStatusCache');
    return result;
  }

  // Check cache first (unless bypassed for rescan)
  if (!bypassCache) {
    const cached = await getCachedResult(url, 'safetyStatusCache');
    if (cached) {
      console.log(`[Safety Check] Using cached result for ${url}:`, cached);
      // Handle both old format (string) and new format (object with sources)
      if (typeof cached === 'string') {
        return { status: cached, sources: [] };
      }
      return { status: cached.status, sources: cached.sources || [] };
    }
  } else {
    console.log(`[Safety Check] Bypassing cache for rescan of ${url}`);
  }

  console.log(`[Safety Check] Starting safety check for ${url}`);

  try {
    // If database is currently loading, wait for it to complete
    if (blocklistLoading) {
      console.log(`[Blocklist] Database still loading, waiting for completion...`);
      await new Promise(resolve => {
        const checkInterval = setInterval(() => {
          if (!blocklistLoading) {
            clearInterval(checkInterval);
            resolve();
          }
        }, 100);
      });
      console.log(`[Blocklist] Database loading complete, proceeding with scan`);
    }

    // Normalize URL for lookup (remove protocol, trailing slash, lowercase)
    const normalizedUrl = url.toLowerCase()
      .replace(/^https?:\/\//, '')
      .replace(/\/$/, '');

    // Extract domain (hostname with port, no path)
    const domain = normalizedUrl.split('/')[0];

    // Extract hostname without port for trusted domain check
    const hostname = domain.split(':')[0];

    // Check if domain is in trusted allow-list (bypass blocklist checks only)
    if (isTrustedDomain(hostname)) {
      console.log(`[Safety Check] Domain ${hostname} is in trusted allow-list, skipping local blocklist checks`);

      // Skip blocklist checks but continue with API-based scanners and suspicious pattern detection
      let finalStatus = 'safe';
      let allSources = [];

      const storage = await browser.storage.local.get(['googleSafeBrowsingApiKey', 'yandexApiKey', 'virusTotalApiKey']);
      const hasGoogleKey = !!storage.googleSafeBrowsingApiKey;
      const hasYandexKey = !!storage.yandexApiKey;
      const hasVTKey = !!storage.virusTotalApiKey;

      if (hasGoogleKey) {
        console.log(`[Safety Check] Checking Google Safe Browsing for trusted domain...`);
        const googleResult = await checkGoogleSafeBrowsing(url);
        if (googleResult === 'unsafe') {
          finalStatus = 'unsafe';
          allSources.push('Google Safe Browsing');
        }
      }

      if (hasYandexKey) {
        console.log(`[Safety Check] Checking Yandex Safe Browsing for trusted domain...`);
        const yandexResult = await checkYandexSafeBrowsing(url);
        if (yandexResult === 'unsafe' && finalStatus !== 'unsafe') {
          finalStatus = 'unsafe';
          allSources.push('Yandex Safe Browsing');
        }
      }

      // Check URLVoid Scraping (always runs, no API key needed)
      console.log(`[Safety Check] Checking URLVoid scraping for trusted domain...`);
      const vtScrapingResult = await checkURLVoidScraping(url);
      if (vtScrapingResult === 'unsafe') {
        finalStatus = 'unsafe';
        allSources.push('URLVoid');
      } else if (vtScrapingResult === 'warning' && finalStatus !== 'unsafe') {
        finalStatus = 'warning';
        allSources.push('URLVoid');
      }

      // Check VirusTotal API (optional, requires API key)
      const vtApiKey = await getDecryptedApiKey('virusTotalApiKey');
      if (vtApiKey) {
        console.log(`[Safety Check] Checking VirusTotal API for trusted domain...`);
        const vtApiResult = await checkVirusTotal(url);
        if (vtApiResult === 'unsafe') {
          finalStatus = 'unsafe';
          if (!allSources.includes('VirusTotal')) {
            allSources.push('VirusTotal');
          }
        } else if (vtApiResult === 'warning' && finalStatus !== 'unsafe') {
          finalStatus = 'warning';
          if (!allSources.includes('VirusTotal')) {
            allSources.push('VirusTotal');
          }
        }
      }

      const suspiciousPatterns = await checkSuspiciousPatterns(url, domain);
      if (suspiciousPatterns.length > 0 && finalStatus !== 'unsafe') {
        finalStatus = 'warning';
        allSources.push(...suspiciousPatterns);
      }

      const resultObj = { status: finalStatus, sources: allSources };
      console.log(`[Safety Check] Final result for trusted domain ${url}: ${resultObj.status}`);
      await setCachedResult(url, resultObj, 'safetyStatusCache');
      return resultObj;
    }

    console.log(`[Blocklist] Checking full URL: ${normalizedUrl}`);
    console.log(`[Blocklist] Checking domain: ${domain}`);

    if (maliciousUrlsSet.has(normalizedUrl)) {
      const sources = domainSourceMap.get(normalizedUrl) || [];
      console.log(`[Blocklist] ⚠️ Full URL found in malicious database!`);
      console.log(`[Blocklist] Detected by: ${sources.join(', ')}`);
      const resultObj = { status: 'unsafe', sources };
      await setCachedResult(url, resultObj, 'safetyStatusCache');
      return resultObj;
    }

    if (maliciousUrlsSet.has(domain)) {
      const sources = domainSourceMap.get(domain) || [];
      console.log(`[Blocklist] ⚠️ Domain found in malicious database!`);
      console.log(`[Blocklist] Detected by: ${sources.join(', ')}`);
      const resultObj = { status: 'unsafe', sources };
      await setCachedResult(url, resultObj, 'safetyStatusCache');
      return resultObj;
    }
    
    if (domainOnlyMap.has(domain)) {
        const sources = domainOnlyMap.get(domain);
        console.log(`[Blocklist] ⚠️ Domain:port found in malicious database (via path-based entry)!`);
        console.log(`[Blocklist] Detected by: ${sources.join(', ')}`);
        const resultObj = { status: 'unsafe', sources };
        await setCachedResult(url, resultObj, 'safetyStatusCache');
        return resultObj;
    }

    console.log(`[Blocklist] ✓ Neither full URL nor domain found in malicious database`);

    let finalStatus = 'safe';
    let allSources = [];

    const storage = await browser.storage.local.get(['googleSafeBrowsingApiKey', 'yandexApiKey', 'virusTotalApiKey']);
    const hasGoogleKey = !!storage.googleSafeBrowsingApiKey;
    const hasYandexKey = !!storage.yandexApiKey;
    const hasVTKey = !!storage.virusTotalApiKey;

    if (hasGoogleKey) {
      console.log(`[Safety Check] Blocklists say safe, checking Google Safe Browsing as redundancy...`);
      const googleResult = await checkGoogleSafeBrowsing(url);
      if (googleResult === 'unsafe') {
        finalStatus = 'unsafe';
        allSources.push('Google Safe Browsing');
      }
    }

    if (hasYandexKey) {
      console.log(`[Safety Check] Blocklists say safe, checking Yandex Safe Browsing as redundancy...`);
      const yandexResult = await checkYandexSafeBrowsing(url);
      if (yandexResult === 'unsafe') {
        finalStatus = 'unsafe';
        allSources.push('Yandex Safe Browsing');
      }
    }

    // Check URLVoid Scraping (always runs, no API key needed)
    console.log(`[Safety Check] Blocklists say safe, checking URLVoid scraping...`);
    const vtScrapingResult = await checkURLVoidScraping(url);
    if (vtScrapingResult === 'unsafe') {
      console.log(`[Safety Check] URLVoid scraping flagged URL as unsafe!`);
      finalStatus = 'unsafe';
      allSources.push('URLVoid');
    } else if (vtScrapingResult === 'warning' && finalStatus !== 'unsafe') {
      console.log(`[Safety Check] URLVoid scraping flagged URL as suspicious!`);
      finalStatus = 'warning';
      allSources.push('URLVoid');
    }

    // Check VirusTotal API (optional, requires API key)
    const vtApiKey = await getDecryptedApiKey('virusTotalApiKey');
    if (vtApiKey) {
      console.log(`[Safety Check] Checking VirusTotal API...`);
      const vtApiResult = await checkVirusTotal(url);
      if (vtApiResult === 'unsafe') {
        console.log(`[Safety Check] VirusTotal API flagged URL as unsafe!`);
        finalStatus = 'unsafe';
        if (!allSources.includes('VirusTotal')) {
          allSources.push('VirusTotal');
        }
      } else if (vtApiResult === 'warning') {
        console.log(`[Safety Check] VirusTotal API flagged URL as suspicious!`);
        if (finalStatus !== 'unsafe') {
          finalStatus = 'warning';
        }
        if (!allSources.includes('VirusTotal')) {
          allSources.push('VirusTotal');
        }
      }
    }

    const suspiciousPatterns = await checkSuspiciousPatterns(url, domain);
    if (suspiciousPatterns.length > 0) {
      if (finalStatus !== 'unsafe') {
        finalStatus = 'warning';
      }
      allSources.push(...suspiciousPatterns);
    }

    const resultObj = { status: finalStatus, sources: allSources };
    console.log(`[Safety Check] Final result for ${url}: ${resultObj.status} (sources: ${allSources.join(', ')})`);
    await setCachedResult(url, resultObj, 'safetyStatusCache');
    return resultObj;

  } catch (error) {
    console.error(`[Blocklist] Error checking URL safety:`, error);
    const resultObj = { status: 'unknown', sources: [] };
    await setCachedResult(url, resultObj, 'safetyStatusCache');
    return resultObj;
  }
};

// ============================================================================
// BACKGROUND SCANNING (REFACTORED)
// ============================================================================

let scanState = {
    isScanning: false,
    isCancelled: false,
    queue: [],
    total: 0,
    scanned: 0,
    bypassCache: false,
};

async function startScan(bookmarks, bypassCache = false) {
    if (scanState.isScanning) {
        console.warn('[Background Scan] Scan is already in progress.');
        return { success: false, message: 'Scan already in progress.' };
    }

    try {
        scanState = {
            isScanning: true,
            isCancelled: false,
            queue: [...bookmarks],
            total: bookmarks.length,
            scanned: 0,
            bypassCache,
        };

        // Reset rate limiting for new scan
        virusTotalRateLimited = false;
        console.log('[VirusTotal] Rate limit reset for new scan');
        
        /* [ZeroLabs] 2026-08-28 - added: a link-only scan needs no security database */
        // The per-bookmark checks below already honour safetyCheckingEnabled, but
        // the download in front of them did not, so a scan with safety checking
        // off still paid for all ten lists before checking a single link.
        const safetyOn = await isSafetyCheckingEnabled();

        if (safetyOn) {
            // Ensure blocklist is ready before starting
            console.log('[Background Scan] Ensuring blocklist database is up to date...');
            browser.runtime.sendMessage({ type: 'scanStatus', message: 'Loading security database...' }).catch(() => {});

            const now = Date.now();
            const lastUpdate = (await browser.storage.local.get('blocklistLastUpdate')).blocklistLastUpdate || 0;

            if (!isSameDay(now, lastUpdate) || maliciousUrlsSet.size === 0) {
                await updateBlocklistDatabase();
            }
        } else {
            console.log('[Background Scan] Safety checking is off. Skipping the security database.');
        }

        if (blocklistLoading) {
            await new Promise(resolve => {
                const interval = setInterval(() => {
                    if (!blocklistLoading) {
                        clearInterval(interval);
                        resolve();
                    }
                }, 100);
            });
        }
        
        console.log(`[Background Scan] Starting scan of ${scanState.total} bookmarks`);
        browser.runtime.sendMessage({ type: 'scanStarted', total: scanState.total }).catch(() => {});

        processScanQueue();

        return { success: true, total: scanState.total };
    } catch (error) {
        console.error('[Background Scan] Error starting scan:', error);
        scanState.isScanning = false;
        return { success: false, message: error.message };
    }
}

function stopScan() {
    if (!scanState.isScanning) {
        return { success: false, message: 'No scan in progress.' };
    }
    console.log('[Background Scan] Cancelling scan...');
    scanState.isCancelled = true;
    return { success: true };
}

function getScanStatus() {
    return {
        isScanning: scanState.isScanning,
        scanned: scanState.scanned,
        total: scanState.total,
    };
}

async function processScanQueue() {
    const BATCH_SIZE = 10;
    const BATCH_DELAY = 100;

    while (scanState.queue.length > 0 && !scanState.isCancelled) {
        const batch = scanState.queue.splice(0, BATCH_SIZE);
        const results = [];

        // Process batch in parallel with concurrency limiting
        const checkPromises = batch.map(async (bookmark) => {
            if (scanState.isCancelled) return null;

            try {
                const result = {
                    id: bookmark.id,
                    url: bookmark.url,
                    title: bookmark.title
                };

                const { linkCheckingEnabled, safetyCheckingEnabled } = await browser.storage.local.get(['linkCheckingEnabled', 'safetyCheckingEnabled']);

                // Check link status and safety status in parallel with concurrency limiting
                const checks = [];

                if (linkCheckingEnabled !== false) {
                    checks.push(
                        networkLimiter.run(async () => {
                            result.linkStatus = await checkLinkStatus(bookmark.url, scanState.bypassCache);
                        })
                    );
                }

                if (safetyCheckingEnabled !== false) {
                    checks.push(
                        networkLimiter.run(async () => {
                            const safetyResult = await checkURLSafety(bookmark.url, scanState.bypassCache);
                            result.safetyStatus = safetyResult.status;
                            result.safetySources = safetyResult.sources;
                        })
                    );
                }

                // Wait for both to complete
                await Promise.all(checks);

                scanState.scanned++;
                browser.runtime.sendMessage({ type: 'scanProgress', scanned: scanState.scanned, total: scanState.total }).catch(()=>{});

                return result;
            } catch (error) {
                console.error(`[Background Scan] Error checking bookmark ${bookmark.id}:`, error);
                scanState.scanned++; // Still count it as 'scanned' to not stall progress
                return null;
            }
        });

        const batchResults = await Promise.all(checkPromises);
        results.push(...batchResults.filter(r => r !== null));
        
        // Send batch results to UI
        if (results.length > 0) {
            browser.runtime.sendMessage({ type: 'scanBatchComplete', results }).catch(() => {});
        }

        if (scanState.queue.length > 0 && !scanState.isCancelled) {
            await new Promise(resolve => setTimeout(resolve, BATCH_DELAY));
        }
    }

    const wasCancelled = scanState.isCancelled;
    console.log(`[Background Scan] ${wasCancelled ? 'Cancelled' : 'Complete'} - Scanned ${scanState.scanned}/${scanState.total}`);
    browser.runtime.sendMessage({
        type: wasCancelled ? 'scanCancelled' : 'scanComplete',
        scanned: scanState.scanned,
        total: scanState.total
    }).catch(() => {});

    // Reset state
    scanState.isScanning = false;
    scanState.isCancelled = false;
    scanState.queue = [];
}


// Listen for messages from the frontend
browser.runtime.onMessage.addListener((request, sender, sendResponse) => {
  /* [ZeroLabs] 2026-06-20 10:50 AM - added: live update scan concurrency from slider */
  if (request.action === "setScanConcurrency") {
    networkLimiter.setMax(request.value);
    sendResponse({ success: true, value: networkLimiter.maxConcurrent });
    return true;
  }

  /* [ZeroLabs] 2026-06-20 10:50 AM - added: live update scan jitter from slider */
  if (request.action === "setScanJitter") {
    networkLimiter.setJitter(request.value);
    sendResponse({ success: true, value: networkLimiter.jitterMs });
    return true;
  }

  if (request.action === "checkLinkStatus") {
    const safeUrl = sanitizeUrl(request.url);
    if (!safeUrl) {
      sendResponse({ status: 'dead' });
      return true;
    }
    /* [ZeroLabs] 2026-06-20 10:35 AM - edited: route through global limiter (DNS) */
    // Front-end auto-check uses this handler; without the limiter it bypassed the
    // global cap and flooded DNS. Share the same limiter as the background scan.
    networkLimiter.run(() => checkLinkStatus(safeUrl, request.bypassCache || false)).then(status => sendResponse({ status }));
    return true;
  }

  if (request.action === "checkURLSafety") {
    const safeUrl = sanitizeUrl(request.url);
    if (!safeUrl) {
      sendResponse({ status: 'unsafe', sources: ['Invalid URL'] });
      return true;
    }
     /* [ZeroLabs] 2026-06-20 10:35 AM - edited: route through global limiter (DNS) */
     networkLimiter.run(() => checkURLSafety(safeUrl, request.bypassCache || false)).then(result => {
        if (typeof result === 'string') sendResponse({ status: result, sources: [] });
        else sendResponse({ status: result.status, sources: result.sources || [] });
    });
    return true;
  }

  // New generic scan commands
  if (request.action === "startScan") {
      startScan(request.bookmarks, request.bypassCache).then(result => sendResponse(result));
      return true;
  }
  if (request.action === "stopScan") {
      sendResponse(stopScan());
      return true;
  }
   if (request.action === "getScanStatus") {
      sendResponse(getScanStatus());
      return true;
  }

  if (request.action === "isBlocklistLoading") {
    sendResponse({ isLoading: blocklistLoading });
    return true;
  }

  if (request.action === "ensureBlocklistReady") {
    (async () => {
      /* [ZeroLabs] 2026-08-28 - added: nothing to make ready when safety is off */
      // Answered rather than ignored: callers await this, and a silent skip would
      // leave them waiting. The UI is told the download is over as well, so no
      // listener is left holding a progress message that never resolves.
      if (!(await isSafetyCheckingEnabled())) {
        browser.runtime.sendMessage({
          type: 'blocklistComplete',
          domains: maliciousUrlsSet.size,
          totalEntries: maliciousUrlsSet.size,
          sources: 0,
          success: true
        }).catch(() => {});
        sendResponse({ ready: true, size: maliciousUrlsSet.size, skipped: true });
        return;
      }

      const now = Date.now();
      const lastUpdate = (await browser.storage.local.get('blocklistLastUpdate')).blocklistLastUpdate || 0;
      if (!isSameDay(now, lastUpdate) || maliciousUrlsSet.size === 0) {
        console.log('[Blocklist] Ensuring database is up to date...');
        await updateBlocklistDatabase();
      } else {
        console.log('[Blocklist] Using cached data from today');
        // Send complete message so UI updates properly even when using cache
        browser.runtime.sendMessage({
          type: 'blocklistComplete',
          domains: maliciousUrlsSet.size,
          totalEntries: maliciousUrlsSet.size,
          sources: BLOCKLIST_SOURCES.length,
          success: true
        }).catch(() => {}); // Ignore if no listeners
      }
      if (blocklistLoading) {
        await new Promise(resolve => {
          const interval = setInterval(() => {
            if (!blocklistLoading) {
              clearInterval(interval);
              resolve();
            }
          }, 100);
        });
      }
      sendResponse({ ready: true, size: maliciousUrlsSet.size });
    })();
    return true;
  }
    
    return false; // For synchronous messages
});


// Handles the browser action (clicking the toolbar icon)
// When clicked, toggle the sidebar
try {
  browser.action.onClicked.addListener(() => {
    browser.sidebarAction.toggle();
  });
} catch (error) {
  console.error("Error setting up browser action listener:", error);
}

/* [ZeroLabs] 2026-08-26 11:43 PM - added: background snippet push (see also: Bookmark-Manager-Zero-Firefox/sidebar.js, Bookmark-Manager-Zero-Chrome/background.js) */
// ============================================================================
// BACKGROUND SNIPPET PUSH
// ============================================================================
// A bookmark added from the browser itself -- the star button, Ctrl+D, the
// Library window -- fires while the sidebar is closed, so the sidebar's listener
// never saw it and the change sat unsynced until the next time the sidebar
// happened to be opened. These listeners live in the background page, which the
// bookmarks events restart on their own, so the push no longer depends on the
// sidebar being on screen.
//
// Two deliberate limits, both because nobody is watching this one:
//
// 1. Only bookmarks.json is written. bmz-meta.json (Quick Access pins) is left
//    alone. GitLab rewrites only the files named in the request, and the
//    background has never loaded the pins, so naming that file would blank them.
// 2. The staleness guard here is version equality alone. The sidebar can fall
//    back to a content diff when the versions disagree; the background
//    deliberately does not and defers to the sidebar instead. Skipping a push
//    costs a delay, pushing a stale tree costs somebody else's bookmarks.
//
// setTimeout cannot carry the debounce: DOM timers do not survive an idled event
// page. browser.alarms does, and creating an alarm under an existing name
// replaces it, which is exactly the debounce reset.

const SNIPPET_PUSH_ALARM = 'bmz-snippet-push';
const SNIPPET_PUSH_DELAY_MIN = 0.5;
/* [ZeroLabs] 2026-08-27 11:36 AM - added: poll for changes made elsewhere */
// The push is event-driven and needs no interval, but nothing tells us when
// ANOTHER device writes the snippet, so that half has to be asked for. Five
// minutes matches the sidebar's existing cycle. GitLab's authenticated limit is
// 600 requests a minute, so roughly 24 an hour is not close to anything; the
// reasons not to go faster are abuse detection and waking the background page
// for a question that is almost always answered "nothing changed".
const SNIPPET_POLL_ALARM = 'bmz-snippet-poll';
const SNIPPET_POLL_PERIOD_MIN = 5;
const SNIPPET_MIN_SYNC_INTERVAL_MS = 60000;
const SNIPPET_GITLAB_TIMEOUT_MS = 15000;
const SNIPPET_MAX_PUSH_ATTEMPTS = 3;

async function snippetFetchGitLab(url, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), SNIPPET_GITLAB_TIMEOUT_MS);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } catch (error) {
    if (error.name === 'AbortError') {
      throw new Error(`GitLab did not respond within ${Math.round(SNIPPET_GITLAB_TIMEOUT_MS / 1000)} seconds.`);
    }
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

// Mirrors calculateChecksum in sidebar.js. The excluded fields are the ones that
// change on every write, so the hash covers the bookmarks alone.
async function snippetCalculateChecksum(data) {
  const { checksum, lastModified, version, editLock, ...dataToHash } = data;
  const str = JSON.stringify(dataToHash, Object.keys(dataToHash).sort());
  const buffer = new TextEncoder().encode(str);
  const hash = await crypto.subtle.digest('SHA-256', buffer);
  return Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

// Mirrors firefoxBookmarksToSnippetFormat in sidebar.js, including the empty
// root folders it guarantees so every client reads the same shape.
async function snippetTreeToSnippetFormat(firefoxTree) {
  const convertNode = (node) => {
    if (node.url) {
      return {
        id: node.id,
        title: node.title,
        url: node.url,
        type: 'bookmark',
        dateAdded: node.dateAdded || Date.now()
      };
    }
    const folder = {
      id: node.id,
      title: node.title || node.name || 'Unnamed Folder',
      name: node.title || node.name || 'Unnamed Folder',
      type: 'folder',
      dateAdded: node.dateAdded || Date.now(),
      children: []
    };
    if (node.children) {
      folder.children = node.children.map(child => convertNode(child));
    }
    return folder;
  };

  const roots = {};
  if (firefoxTree && firefoxTree[0] && firefoxTree[0].children) {
    for (const rootFolder of firefoxTree[0].children) {
      const key = rootFolder.id === 'toolbar_____' ? 'bookmark_bar' :
                  rootFolder.id === 'unfiled_____' ? 'other' :
                  rootFolder.id === 'mobile______' ? 'mobile' :
                  rootFolder.id === 'menu________' ? 'menu' : null;
      if (key) {
        roots[key] = convertNode(rootFolder);
      }
    }
  }

  if (!roots.bookmark_bar) {
    roots.bookmark_bar = {
      id: 'root________',
      title: 'Bookmarks Toolbar',
      name: 'Bookmarks Toolbar',
      type: 'folder',
      dateAdded: Date.now(),
      children: []
    };
  }
  if (!roots.menu) {
    roots.menu = {
      id: 'menu________',
      title: 'Bookmarks Menu',
      name: 'Bookmarks Menu',
      type: 'folder',
      dateAdded: Date.now(),
      children: []
    };
  }
  if (!roots.other) {
    roots.other = {
      id: 'unfiled_____',
      title: 'Other Bookmarks',
      name: 'Other Bookmarks',
      type: 'folder',
      dateAdded: Date.now(),
      children: []
    };
  }

  const snippetData = {
    version: 1,
    checksum: '',
    lastModified: Date.now(),
    roots: roots
  };

  snippetData.checksum = await snippetCalculateChecksum(snippetData);
  return snippetData;
}

// Everything the push needs, or null when this device is not set up to sync.
// Reads browser.storage.local directly rather than the sidebar's safeStorage
// wrapper: in a private window that wrapper keeps everything in memory, and a
// private session has nothing here to push with anyway.
async function loadSnippetPushConfig() {
  const stored = await browser.storage.local.get([
    'bmz_snippet_id',
    'gitlab_token',
    'snippet_local_version',
    'snippet_last_sync'
  ]);

  /* [ZeroLabs] 2026-08-27 12:14 AM - added: say which piece is missing */
  // This returning null used to be indistinguishable from "nothing to do", which
  // made an unattended failure impossible to diagnose from the log alone.
  if (!stored.bmz_snippet_id) {
    console.log('[SnippetPush] No snippet connected on this device');
    return null;
  }
  if (!stored.gitlab_token) {
    console.log('[SnippetPush] No stored GitLab token');
    return null;
  }

  const token = await decryptApiKey(stored.gitlab_token);
  if (!token) {
    console.warn('[SnippetPush] Stored token could not be decrypted in the background');
    return null;
  }

  return {
    snippetId: stored.bmz_snippet_id,
    token,
    localVersion: Number(stored.snippet_local_version) || 0,
    lastSync: Number(stored.snippet_last_sync) || 0
  };
}

// The sidebar owns the same flag and reads it on open, so a push skipped while
// the sidebar was closed still shows up as an amber sync button once it opens.
async function setSnippetReconcileBadge(needs) {
  try {
    await browser.storage.local.set({ snippet_needs_reconcile: !!needs });
  } catch (error) {
    console.error('[SnippetPush] Failed to store reconcile flag:', error);
  }

  try {
    await browser.action.setBadgeText({ text: needs ? '!' : '' });
    if (needs) {
      await browser.action.setBadgeBackgroundColor({ color: '#f59e0b' });
    }
  } catch (error) {
    // Badge unavailable; the stored flag still reaches the sidebar
  }
}

// Same two-step read the sidebar does: the snippet API may or may not inline
// file contents, so fall back to the raw endpoint when it does not.
async function readRemoteSnippetBookmarks(config) {
  const headers = {
    'Authorization': `Bearer ${config.token}`,
    'Content-Type': 'application/json'
  };

  const response = await snippetFetchGitLab(
    `https://gitlab.com/api/v4/snippets/${config.snippetId}`,
    { headers }
  );
  if (!response.ok) {
    throw new Error(`Failed to read Snippet: ${response.status}`);
  }

  const snippet = await response.json();
  const bookmarkFile = snippet.files?.find(f =>
    f.path === 'bookmarks.json' || f.file_name === 'bookmarks.json'
  );
  if (!bookmarkFile) {
    throw new Error('Snippet does not contain bookmarks.json');
  }

  let content = bookmarkFile.content;
  if (!content) {
    const fileResponse = await snippetFetchGitLab(
      `https://gitlab.com/api/v4/snippets/${config.snippetId}/files/main/bookmarks.json/raw`,
      { headers }
    );
    if (!fileResponse.ok) {
      throw new Error(`Failed to fetch file content: ${fileResponse.status}`);
    }
    content = await fileResponse.text();
  }

  if (!content || content.trim() === '') return null;
  return JSON.parse(content);
}

/* [ZeroLabs] 2026-08-29 - added: a URL is an address, not an identity */
// These maps were keyed on the URL alone, so two bookmarks pointing at the same
// place overwrote each other and the second copy stopped existing as far as sync
// was concerned. A library holding 2911 bookmarks with one duplicate reported
// 2910, and a device rebuilding from the snippet created only one of the pair.
// Nothing ever healed it either: the copy was never seen as missing, so every
// later sync agreed the two sides matched. Deleting one of two copies was
// invisible for the same reason - the URL was still there.
//
// The Nth copy of a URL is now keyed "<url>\u0000#N". The FIRST copy keeps the bare
// URL, so every bookmark that appears once has exactly the key it always had -
// which is what keeps this from re-syncing an entire library on upgrade.
//
// Copies are numbered by sorted location rather than by tree order, so two
// browsers walking their trees in different orders still agree on which copy is
// which, and neither reads the other's copy 1 as a move of its own copy 2.
//
// A NUL cannot appear in a URL, so no real bookmark can collide with a copy key.
// These keys never leave memory: what is stored or pushed is always entry.url.
const SNIPPET_COPY_SEP = '\u0000#';

function snippetKeyUrl(key) {
  const at = key.indexOf(SNIPPET_COPY_SEP);
  return at === -1 ? key : key.slice(0, at);
}

function snippetCopyLocation(entry) {
  return [entry.rootKey].concat(entry.segments || []).join('/') + '/' + (entry.title || '');
}

function keyByUrlCopy(list) {
  const byUrl = new Map();
  list.forEach(entry => {
    if (!byUrl.has(entry.url)) byUrl.set(entry.url, []);
    byUrl.get(entry.url).push(entry);
  });

  const keyed = new Map();
  byUrl.forEach((group, url) => {
    if (group.length === 1) {
      keyed.set(url, group[0]);
      return;
    }
    group.sort((a, b) => snippetCopyLocation(a).localeCompare(snippetCopyLocation(b)));
    group.forEach((entry, i) => {
      keyed.set(i === 0 ? url : `${url}${SNIPPET_COPY_SEP}${i + 1}`, entry);
    });
  });
  return keyed;
}

/* [ZeroLabs] 2026-08-27 2:26 AM - added: what a push would take out of the snippet */
// Additions are safe to send unattended; removals are not. Comparing by URL
// rather than by path means a moved or renamed bookmark still counts as present,
// so only a genuine disappearance holds the push.
/* [ZeroLabs] 2026-08-29 - edited: built from collectSnippetEntries */
// It used to do its own walk, which meant two walks that had to agree about
// which bookmarks exist. Now that a key encodes which copy it is, any drift
// between the two would compare copy 1 here against copy 2 there. Deriving one
// from the other makes disagreement impossible rather than unlikely.
function collectSnippetItems(snippetData) {
  const items = new Map();
  collectSnippetEntries(snippetData).forEach((entry, key) => {
    items.set(key, entry.title);
  });
  return items;
}

/* [ZeroLabs] 2026-08-27 11:36 AM - added: snippet items with the folders they live in */
// collectSnippetItems answers "is this URL present". Creating one locally needs
// to know where it belongs, so this carries the root it sits under and the
// folder names below that root. Roots are handled by KEY rather than by title:
// the snippet names its toolbar root differently depending on which browser
// last wrote it, and the key is the one thing that survives that.
function collectSnippetEntries(snippetData) {
  /* [ZeroLabs] 2026-08-29 - edited: collect first, key afterwards */
  // Keying during the walk is exactly what lost duplicates - the second set()
  // on a URL replaced the first. Collecting into a list keeps every copy, and
  // keying the finished list is what allows copies to be numbered by location
  // instead of by the order the walk happened to reach them.
  const list = [];
  if (!snippetData || !snippetData.roots) return new Map();

  const walk = (node, rootKey, segments) => {
    if (!node) return;
    if (node.url) {
      list.push({ url: node.url, title: node.title || node.url, rootKey, segments });
      return;
    }
    if (Array.isArray(node.children)) {
      node.children.forEach(child => walk(
        child,
        rootKey,
        child.url ? segments : segments.concat(child.title || child.name || 'Unnamed Folder')
      ));
    }
  };

  Object.keys(snippetData.roots).forEach(rootKey => {
    const root = snippetData.roots[rootKey];
    if (!root) return;
    if (Array.isArray(root.children)) {
      root.children.forEach(child => walk(
        child,
        rootKey,
        child.url ? [] : [child.title || child.name || 'Unnamed Folder']
      ));
    }
  });

  return keyByUrlCopy(list);
}

/* [ZeroLabs] 2026-08-27 11:36 AM - added: let the background place bookmarks itself */
// Until now only the sidebar could create bookmarks, which is why additions made
// on another device never arrived unless you opened BMZ. Firefox has a real menu
// root, so unlike Chrome nothing has to be folded into Other Bookmarks.
function firefoxRootForSnippetKey(rootKey) {
  switch (rootKey) {
    case 'bookmark_bar': return 'toolbar_____';
    case 'menu': return 'menu________';
    case 'other': return 'unfiled_____';
    case 'mobile': return 'mobile______';
    default: return null;
  }
}

async function resolveOrCreateFolderUnder(parentId, segments) {
  let currentId = parentId;
  for (const segment of segments) {
    const children = await browser.bookmarks.getChildren(currentId);
    let match = children.find(child => !child.url && child.title === segment);
    if (!match) {
      match = await browser.bookmarks.create({ parentId: currentId, title: segment });
    }
    currentId = match.id;
  }
  return currentId;
}

async function createSnippetItemsLocally(entries) {
  let created = 0;

  // Shallower folders first, so a parent exists before anything inside it
  const ordered = [...entries].sort((a, b) => a.segments.length - b.segments.length);

  for (const entry of ordered) {
    try {
      const rootId = firefoxRootForSnippetKey(entry.rootKey);
      if (!rootId) continue;

      const parentId = await resolveOrCreateFolderUnder(rootId, entry.segments);
      await browser.bookmarks.create({ parentId, title: entry.title, url: entry.url });
      created++;
    } catch (error) {
      // A URL the browser refuses must not take the rest of the sync with it
      console.warn('[SnippetPush] Could not create locally:', entry.url, error.message);
    }
  }

  return created;
}

/* [ZeroLabs] 2026-08-27 11:36 AM - added: remember what this device did (see also: Bookmark-Manager-Zero-Chrome/background.js) */
// A bookmark present here but not in the snippet is either something you just
// added or something another device deleted, and those want opposite answers.
// The bookmarks events say which, and until now the listeners discarded the
// payload. Recording it is what lets an addition sync silently while a deletion
// defers for consent, with no guessing about intent.
async function recordLocalBookmarkEvent(kind, node) {
  if (!node) return;

  // Deleting a folder fires one event for the folder, never one per bookmark
  // inside it, so the whole subtree has to be walked or those URLs go unrecorded
  // and their deletion looks like it happened somewhere else.
  const urls = [];
  const walk = (n) => {
    if (!n) return;
    if (n.url) urls.push(n.url);
    if (Array.isArray(n.children)) n.children.forEach(walk);
  };
  walk(node);
  if (urls.length === 0) return;

  const key = kind === 'created' ? 'snippet_local_created' : 'snippet_local_deleted';
  const opposite = kind === 'created' ? 'snippet_local_deleted' : 'snippet_local_created';

  try {
    const stored = await browser.storage.local.get([key, opposite]);
    const list = new Set(stored[key] || []);
    const otherList = new Set(stored[opposite] || []);

    urls.forEach(url => {
      list.add(url);
      // Re-adding something you deleted cancels the deletion, and vice versa, so
      // the two lists can never disagree about the same URL.
      otherList.delete(url);
    });

    await browser.storage.local.set({
      [key]: Array.from(list).slice(-2000),
      [opposite]: Array.from(otherList)
    });
  } catch (error) {
    console.error('[SnippetPush] Could not record local bookmark event:', error);
  }
}

/* [ZeroLabs] 2026-08-27 1:47 PM - added: record edits, not just creates and deletes */
// A renamed or moved bookmark keeps its URL, so it is invisible to the
// created/deleted lists, and comparing titles alone cannot say WHOSE rename it
// is. Without this, two browsers holding different titles for the same URL each
// see a difference, each push their own, and they revert each other forever.
async function recordLocalBookmarkEdit(id, explicitUrl) {
  try {
    let url = explicitUrl;
    if (!url) {
      // onMoved carries only parent ids, and onChanged only carries the fields
      // that changed, so the URL usually has to be looked up.
      const nodes = await browser.bookmarks.get(id);
      url = nodes && nodes[0] && nodes[0].url;
    }
    if (!url) return; // Folders are represented by the bookmarks inside them

    const stored = await browser.storage.local.get('snippet_local_edited');
    const list = new Set(stored.snippet_local_edited || []);
    list.add(url);
    await browser.storage.local.set({ snippet_local_edited: Array.from(list).slice(-2000) });
  } catch (error) {
    console.error('[SnippetPush] Could not record local edit:', error);
  }
}

async function clearLocalBookmarkEvents() {
  await browser.storage.local.set({
    snippet_local_created: [],
    snippet_local_deleted: [],
    snippet_local_edited: []
  });
}

/* [ZeroLabs] 2026-08-27 2:02 PM - removed: applyRemoteEditsLocally (moved to: sidebar.js) */
// Applying someone else's rename overwrites data on this device, so it now
// waits for consent and the sidebar carries it out, next to the removals it
// already applies on approval.

/* [ZeroLabs] 2026-08-27 11:36 AM - added: the user can switch this off */
// Default on, and only absent-means-on: an explicit false is the only way off,
// so a storage read that comes back empty never silently disables syncing.
async function isBackgroundSyncEnabled() {
  const stored = await browser.storage.local.get('bmz_auto_sync_enabled');
  return stored.bmz_auto_sync_enabled !== false;
}

function scheduleSnippetPush(reason) {
  browser.storage.local.set({ snippet_push_pending: true }).catch(() => {});
  // Same name replaces the pending alarm, so a burst of edits collapses into one
  // push 30 seconds after the last of them.
  browser.alarms.create(SNIPPET_PUSH_ALARM, { delayInMinutes: SNIPPET_PUSH_DELAY_MIN });
  console.log(`[SnippetPush] Push scheduled (${reason})`);
}

async function runSnippetPush() {
  /* [ZeroLabs] 2026-08-27 12:14 AM - edited: log every exit path */
  // Nobody is watching this run, so every way out of it has to leave a trace.
  console.log('[SnippetPush] Running');

  if (!(await isBackgroundSyncEnabled())) {
    console.log('[SnippetPush] Background sync is switched off');
    await browser.storage.local.set({ snippet_push_pending: false });
    return;
  }

  const config = await loadSnippetPushConfig();
  if (!config) {
    await browser.storage.local.set({ snippet_push_pending: false, snippet_push_attempts: 0 });
    return;
  }

  if (!navigator.onLine) {
    console.log('[SnippetPush] Offline, retrying after the next alarm');
    browser.alarms.create(SNIPPET_PUSH_ALARM, { delayInMinutes: SNIPPET_PUSH_DELAY_MIN });
    return;
  }

  // Shared 60 second floor with the sidebar, both reading the same stored stamp
  const sinceLastSync = Date.now() - config.lastSync;
  if (config.lastSync && sinceLastSync < SNIPPET_MIN_SYNC_INTERVAL_MS) {
    console.log(`[SnippetPush] Last push was ${Math.round(sinceLastSync / 1000)}s ago, deferring`);
    browser.alarms.create(SNIPPET_PUSH_ALARM, { delayInMinutes: SNIPPET_PUSH_DELAY_MIN });
    return;
  }

  try {
    const remote = await readRemoteSnippetBookmarks(config);
    const remoteVersion = Number(remote?.version) || 0;

    let tree = await browser.bookmarks.getTree();
    let snippetData = await snippetTreeToSnippetFormat(tree);

    /* [ZeroLabs] 2026-08-27 11:36 AM - edited: four outcomes, not two */
    // Every sync starts as a merge check. What separates a silent sync from a
    // deferral is not the version number but what this device saw you do: a
    // bookmark here that this device watched you create is your addition, one it
    // never saw created came from elsewhere. The version is no longer a gate,
    // which is what stops a stale version number from dead-ending the sync.
    const localItems = collectSnippetItems(snippetData);
    const remoteEntries = collectSnippetEntries(remote);

    const events = await browser.storage.local.get([
      'snippet_local_created',
      'snippet_local_deleted',
      'snippet_local_edited'
    ]);
    const createdHere = new Set(events.snippet_local_created || []);
    const deletedHere = new Set(events.snippet_local_deleted || []);

    const toAddLocally = [];   // in the snippet, not here, and not deleted here
    const removesFromSnippet = []; // in the snippet, not here, because you deleted it here
    /* [ZeroLabs] 2026-08-29 - edited: the map key is a copy, the URL is not */
    // Attribution stays keyed by URL, because a URL is what survives the round
    // trip through the snippet. That is still the right question to ask of it:
    // "did you delete this link here". Which copy went is answered by the counts
    // on either side, not by the event lists.
    remoteEntries.forEach((entry, key) => {
      if (localItems.has(key)) return;
      if (deletedHere.has(entry.url)) {
        removesFromSnippet.push({ url: entry.url, title: entry.title });
      } else {
        toAddLocally.push(entry);
      }
    });

    const removesFromDevice = []; // here, not in the snippet, and not added here
    let hasLocalAdditions = false;
    localItems.forEach((title, key) => {
      if (remoteEntries.has(key)) return;
      const url = snippetKeyUrl(key);
      if (createdHere.has(url)) {
        hasLocalAdditions = true;
      } else {
        removesFromDevice.push({ url, title });
      }
    });

    /* [ZeroLabs] 2026-08-27 2:02 PM - added: renames and moves, judged before the deferral */
    // A rename or move keeps the URL, so it is invisible to the two loops above
    // and has to be compared separately. Attribution decides what happens, and
    // the two directions are deliberately not symmetric:
    //
    //   edited here     -> you made the change and want it to travel. Push it.
    //   edited          -> the snippet wants to overwrite a name or location on
    //     elsewhere         this device. That is a change to data you may have
    //                       chosen, and nothing here can tell which is wanted,
    //                       so it waits for you exactly as a deletion does.
    //
    // A folder rename or move arrives here as every bookmark inside it changing
    // path, so folders are covered by the same rule without a separate case.
    //
    // Compared by title and location rather than by checksum on purpose: a
    // Firefox checksum can never equal a Chrome one, because the two name their
    // root folders differently, so a checksum test would report a difference
    // forever and the browsers would push at each other in a loop. Root KEYS
    // (bookmark_bar, menu, other, mobile) and user folder names match on both
    // sides, so this comparison is safe across browsers.
    const editedHere = new Set(events.snippet_local_edited || []);
    const localEntries = collectSnippetEntries(snippetData);
    let hasLocalEdits = false;
    const overwritesOnDevice = [];

    localEntries.forEach((localEntry, key) => {
      const remoteEntry = remoteEntries.get(key);
      if (!remoteEntry) return; // Additions are handled by the loops above

      const movedOrRenamed =
        localEntry.title !== remoteEntry.title ||
        localEntry.rootKey !== remoteEntry.rootKey ||
        localEntry.segments.join('/') !== remoteEntry.segments.join('/');
      if (!movedOrRenamed) return;

      if (editedHere.has(localEntry.url)) {
        // You made this change here, so the intent is known and it propagates.
        hasLocalEdits = true;
      } else {
        // rootKey and segments travel with it so the sidebar can place the
        // bookmark if you approve, without re-deriving the path from a title.
        overwritesOnDevice.push({
          url: localEntry.url,
          title: localEntry.title,
          remoteTitle: remoteEntry.title,
          localPath: [localEntry.rootKey].concat(localEntry.segments).join('/'),
          remotePath: [remoteEntry.rootKey].concat(remoteEntry.segments).join('/'),
          remoteRootKey: remoteEntry.rootKey,
          remoteSegments: remoteEntry.segments
        });
      }
    });

    /* [ZeroLabs] 2026-08-27 - edited: additions land BEFORE any deferral */
    // This used to sit after the deferral check, which meant a pending deletion
    // suppressed a perfectly safe addition - and worse, approving that deletion
    // then pushed a local tree that had never received it, deleting it from the
    // snippet. Local ABCDF against snippet ABCDE, approving the removal of F,
    // pushed ABCD and destroyed E.
    //
    // Adding is never destructive, so it is never a reason to wait.
    let addedLocally = 0;
    if (toAddLocally.length > 0) {
      addedLocally = await createSnippetItemsLocally(toAddLocally);
      console.log(`[SnippetPush] Added ${addedLocally} item(s) from the snippet to this device`);
      tree = await browser.bookmarks.getTree();
      snippetData = await snippetTreeToSnippetFormat(tree);
    }

    /* [ZeroLabs] 2026-08-27 - added: the safe additions, for the dialog to list */
    // Additions never need consent and are already applied by this point, but a
    // dialog appearing while bookmarks quietly arrive should account for them.
    // Approve also pushes, so this device's own additions travel with it.
    const entryPath = (e) => [e.rootKey].concat(e.segments).join('/');
    const addedHereItems = toAddLocally.slice(0, 200).map(e => ({
      url: e.url, title: e.title, path: entryPath(e)
    }));
    const pendingPushItems = [];
    localEntries.forEach((entry, key) => {
      if (!remoteEntries.has(key) && createdHere.has(entry.url)) {
        pendingPushItems.push({ url: entry.url, title: entry.title, path: entryPath(entry) });
      }
    });

    // Outcome 4: anything that removes or overwrites on either side waits.
    if (removesFromSnippet.length > 0 || removesFromDevice.length > 0 || overwritesOnDevice.length > 0) {
      await browser.storage.local.set({
        snippet_push_held: true,
        snippet_push_held_items: removesFromSnippet.slice(0, 200),
        snippet_pull_held_items: removesFromDevice.slice(0, 200),
        snippet_overwrite_held_items: overwritesOnDevice.slice(0, 200),
        snippet_added_here_items: addedHereItems,
        snippet_pending_push_items: pendingPushItems.slice(0, 200),
        snippet_push_pending: false,
        snippet_push_attempts: 0
      });
      await setSnippetReconcileBadge(true);
      console.warn('[SnippetPush] Deferred for consent', {
        wouldRemoveFromSnippet: removesFromSnippet.length,
        wouldRemoveFromDevice: removesFromDevice.length,
        wouldOverwriteOnDevice: overwritesOnDevice.length
      });
      return;
    }

    // Outcome 2 and 3: push when this device has something the snippet lacks.
    // Adopting an edit brings this side to the snippet, so it needs no push
    // either; only changes made here do.
    if (!hasLocalAdditions && addedLocally === 0 && !hasLocalEdits) {
      await browser.storage.local.set({
        snippet_local_version: remoteVersion,
        snippet_last_sync: Date.now(),
        snippet_push_pending: false,
        snippet_push_attempts: 0,
        snippet_push_held: false,
        snippet_push_held_items: [],
        snippet_pull_held_items: [],
        snippet_overwrite_held_items: []
      });
      await clearLocalBookmarkEvents();
      await setSnippetReconcileBadge(false);
      console.log('[SnippetPush] Already in sync, version recorded as', remoteVersion);
      return;
    }

    const payload = {
      ...snippetData,
      version: remoteVersion + 1,
      checksum: await snippetCalculateChecksum(snippetData),
      lastModified: Date.now()
    };

    const response = await snippetFetchGitLab(
      `https://gitlab.com/api/v4/snippets/${config.snippetId}`,
      {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${config.token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          files: [{
            action: 'update',
            file_path: 'bookmarks.json',
            content: JSON.stringify(payload, null, 2)
          }]
        })
      }
    );

    if (!response.ok) {
      throw new Error(`Failed to update Snippet: ${response.status}`);
    }

    await browser.storage.local.set({
      snippet_local_version: remoteVersion + 1,
      snippet_last_sync: Date.now(),
      snippet_push_pending: false,
      snippet_push_attempts: 0,
      /* [ZeroLabs] 2026-08-27 2:26 AM - added: a clean push clears any hold */
      snippet_push_held: false,
      snippet_push_held_items: [],
      snippet_pull_held_items: [],
        snippet_overwrite_held_items: []
    });
    /* [ZeroLabs] 2026-08-27 11:36 AM - added: both sides agree, the records are spent */
    await clearLocalBookmarkEvents();
    await setSnippetReconcileBadge(false);
    console.log('[SnippetPush] Pushed bookmarks.json at version', remoteVersion + 1);
  } catch (error) {
    // A dead token or a missing snippet fails identically every time, so retries
    // are capped rather than left to hammer GitLab until the browser closes.
    const { snippet_push_attempts = 0 } = await browser.storage.local.get('snippet_push_attempts');
    const attempts = snippet_push_attempts + 1;
    await browser.storage.local.set({ snippet_push_attempts: attempts });

    console.error(`[SnippetPush] Attempt ${attempts} failed:`, error);

    if (attempts < SNIPPET_MAX_PUSH_ATTEMPTS) {
      browser.alarms.create(SNIPPET_PUSH_ALARM, { delayInMinutes: SNIPPET_PUSH_DELAY_MIN });
    } else {
      // Give up until the next bookmark change, and say so where it can be seen
      await setSnippetReconcileBadge(true);
      await browser.storage.local.set({ snippet_push_pending: false, snippet_push_attempts: 0 });
    }
  }
}

browser.alarms.onAlarm.addListener((alarm) => {
  /* [ZeroLabs] 2026-08-27 11:36 AM - edited: the poll runs the same reconcile */
  // Both alarms end in the same place. The push alarm is your own change asking
  // to go up; the poll is this device asking whether anything came in.
  if (alarm.name === SNIPPET_PUSH_ALARM || alarm.name === SNIPPET_POLL_ALARM) {
    runSnippetPush();
  }
});

/* [ZeroLabs] 2026-08-27 11:36 AM - added: keep the poll alarm alive */
// Alarms survive an idled event page but not an update or reinstall, so this is
// re-asserted on both startup events. Creating it under the same name replaces
// it rather than stacking a second one.
function ensureSnippetPollAlarm() {
  browser.alarms.create(SNIPPET_POLL_ALARM, {
    periodInMinutes: SNIPPET_POLL_PERIOD_MIN,
    delayInMinutes: SNIPPET_POLL_PERIOD_MIN
  });
}

browser.runtime.onInstalled.addListener(ensureSnippetPollAlarm);
browser.runtime.onStartup.addListener(ensureSnippetPollAlarm);

/* [ZeroLabs] 2026-08-27 11:36 AM - edited: keep the payload instead of discarding it */
// Registered at the top level so an idled event page is restarted by the event.
// onCreated hands over the new node; onRemoved hands over removeInfo.node, which
// is the only moment the deleted bookmark's URL is still knowable.
browser.bookmarks.onCreated.addListener((id, bookmark) => {
  recordLocalBookmarkEvent('created', bookmark);
  scheduleSnippetPush('onCreated');
});

browser.bookmarks.onRemoved.addListener((id, removeInfo) => {
  recordLocalBookmarkEvent('deleted', removeInfo && removeInfo.node);
  scheduleSnippetPush('onRemoved');
});

/* [ZeroLabs] 2026-08-27 1:47 PM - edited: an edit is attributable too */
browser.bookmarks.onChanged.addListener((id, changeInfo) => {
  recordLocalBookmarkEdit(id, changeInfo && changeInfo.url);
  scheduleSnippetPush('onChanged');
});

browser.bookmarks.onMoved.addListener((id) => {
  recordLocalBookmarkEdit(id);
  scheduleSnippetPush('onMoved');
});

// A push left pending when the page was idled or the browser closed still has to
// happen, and its alarm may have been consumed already.
browser.runtime.onStartup.addListener(async () => {
  const { snippet_push_pending } = await browser.storage.local.get('snippet_push_pending');
  if (snippet_push_pending) {
    browser.alarms.create(SNIPPET_PUSH_ALARM, { delayInMinutes: SNIPPET_PUSH_DELAY_MIN });
  }
});

// Preload blocklist database on extension startup
// This ensures the database is ready when the sidebar opens
(async () => {
    try {
        const result = await browser.storage.local.get('blocklistLastUpdate');
        blocklistLastUpdate = result.blocklistLastUpdate || 0;

        const now = Date.now();
        /* [ZeroLabs] 2026-08-28 - added: do not preload what this device will never use */
        // This preload only ever checked staleness, so a device with safety
        // checking switched OFF still downloaded all ten blocklists on every
        // startup - bandwidth spent on data nothing would read, and the download
        // it kicked off is what left the status bar sitting at "Downloading
        // blocklists... (10/10)" on a device that does no safety checking at all.
        if (!(await isSafetyCheckingKnownOn())) {
            console.log('[Startup] Safety checking is not known to be on. Skipping blocklist preload; it loads on demand if a scan needs it.');
        } else if (!isSameDay(now, blocklistLastUpdate)) {
            console.log('[Startup] Blocklist is stale on startup. Pre-loading in background...');
            updateBlocklistDatabase(); // Run in background
        } else {
            console.log('[Startup] Blocklist database is up to date. Loading from memory/cache...');
            // In a real scenario, you'd load the cached blocklist here.
            // For simplicity in this model, we just rely on the periodic update.
            // If the service worker was terminated, the blocklist will be empty and
            // the check in startScan() will trigger a download.
        }
    } catch (error) {
        console.error('[Startup] Failed to initialize blocklist database:', error);
    }
})();
