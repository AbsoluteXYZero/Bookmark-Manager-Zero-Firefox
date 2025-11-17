// This script runs in the background and handles extension tasks.

const PARKING_DOMAINS = [
  'hugedomains.com',
  'godaddy.com',
  'namecheap.com',
  'sedo.com',
  'dan.com',
  'squadhelp.com',
  'afternic.com',
  'domainmarket.com',
  'uniregistry.com',
  'namesilo.com',
];

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

// Store result in cache
const setCachedResult = async (url, result, cacheKey) => {
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
  }
};

/**
 * Checks if a URL is reachable and resolves to the expected domain.
 * This function runs in the background script, which has broader permissions
 * than content scripts, allowing it to bypass CORS restrictions.
 * @param {string} url The URL to check.
 * @returns {Promise<'live' | 'dead' | 'parked'>} The status of the link.
 */
const checkLinkStatus = async (url) => {
  // Check cache first
  const cached = await getCachedResult(url, 'linkStatusCache');
  if (cached) {
    console.log(`[Link Check] Using cached result for ${url}: ${cached}`);
    return cached;
  }

  let result;

  // Check if the URL itself is on a parking domain
  try {
    const urlHost = new URL(url).hostname.toLowerCase();
    if (PARKING_DOMAINS.some(domain => urlHost.includes(domain))) {
      result = 'parked';
      await setCachedResult(url, result, 'linkStatusCache');
      return result;
    }
  } catch (e) {
    // Invalid URL, continue with fetch attempt
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 10000); // 10-second timeout

  try {
    // Try HEAD request first (lighter weight)
    const response = await fetch(url, {
      method: 'HEAD',
      signal: controller.signal,
      mode: 'cors',
      credentials: 'omit',
      redirect: 'follow'
    });
    clearTimeout(timeoutId);

    // Check if redirected to parking domain
    if (response.redirected || response.url !== url) {
      const finalHost = new URL(response.url).hostname.toLowerCase();
      if (PARKING_DOMAINS.some(domain => finalHost.includes(domain))) {
        result = 'parked';
        await setCachedResult(url, result, 'linkStatusCache');
        return result;
      }
    }

    // Check for successful status codes
    if (response.ok || (response.status >= 300 && response.status < 400)) {
      // Try lightweight content check for parking indicators (with robust error handling)
      try {
        const contentController = new AbortController();
        const contentTimeout = setTimeout(() => contentController.abort(), 3000); // Short 3s timeout

        const contentResponse = await fetch(url, {
          method: 'GET',
          signal: contentController.signal,
          mode: 'cors',
          credentials: 'omit',
          redirect: 'follow'
        });
        clearTimeout(contentTimeout);

        // Only check if we got a successful response
        if (contentResponse.ok) {
          const html = await contentResponse.text();
          const htmlLower = html.toLowerCase();

          // Check for parking page indicators
          const parkingIndicators = [
            'domain for sale',
            'buy this domain',
            'domain is for sale',
            'this domain may be for sale',
            'this domain is for sale',
            'premium domain',
            'parked free',
            'domain parking',
            'parked domain',
            'buy now',
            'make an offer',
            'make offer',
            'expired domain',
            'domain expired',
            'register this domain',
            'purchase this domain',
            'acquire this domain',
            'get this domain',
            'domain is parked',
            'parking page',
            'coming soon',
            'under construction',
            'sedo domain parking',
            'sedo.com',
            'afternic.com/forsale',
            'afternic.com',
            'hugedomains.com',
            'bodis.com',
            'parkingcrew',
            'domain name is for sale',
            'inquire about this domain',
            'interested in this domain',
            'domain may be for sale',
            'brandable domain',
            'premium domains',
            'domain broker'
          ];

          if (parkingIndicators.some(indicator => htmlLower.includes(indicator))) {
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

    // 4xx or 5xx error means the link is dead
    result = 'dead';
    await setCachedResult(url, result, 'linkStatusCache');
    return result;

  } catch (error) {
    clearTimeout(timeoutId);

    // If HEAD fails, try GET with no-cors as fallback
    try {
      const fallbackController = new AbortController();
      const fallbackTimeout = setTimeout(() => fallbackController.abort(), 8000);

      const fallbackResponse = await fetch(url, {
        method: 'GET',
        signal: fallbackController.signal,
        mode: 'no-cors',
        credentials: 'omit',
        redirect: 'follow'
      });
      clearTimeout(fallbackTimeout);

      // no-cors mode returns opaque response, but if fetch succeeds, link is likely live
      result = 'live';
      await setCachedResult(url, result, 'linkStatusCache');
      return result;
    } catch (fallbackError) {
      // Both HEAD and GET failed - link is likely dead
      console.warn('Link check failed for:', url, fallbackError.message);
      result = 'dead';
      await setCachedResult(url, result, 'linkStatusCache');
      return result;
    }
  }
};

// Check URL safety by scraping VirusTotal
// WARNING: For personal use only. May violate VirusTotal ToS if distributed.
const checkURLSafety = async (url) => {
  // Check cache first
  const cached = await getCachedResult(url, 'safetyStatusCache');
  if (cached) {
    console.log(`[Safety Check] Using cached result for ${url}: ${cached}`);
    return cached;
  }

  console.log(`[Safety Check] Starting safety check for ${url}`);

  let result;

  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname.toLowerCase();

    console.log(`[Safety Check] Checking ${hostname} via VirusTotal (no whitelisting)`);

    // Try calling VirusTotal's internal API directly
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 10000); // 10s timeout

      // Try multiple API endpoint patterns
      const apiEndpoints = [
        `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(hostname)}`,
        `https://www.virustotal.com/vtapi/v2/domain/report?domain=${encodeURIComponent(hostname)}`,
        `https://www.virustotal.com/ui/domains/${encodeURIComponent(hostname)}`,
        `https://www.virustotal.com/api-proxy/domains/${encodeURIComponent(hostname)}`
      ];

      console.log(`[VT API] Trying ${apiEndpoints.length} API endpoints for ${hostname}`);

      for (const apiUrl of apiEndpoints) {
        try {
          console.log(`[VT API] Attempting: ${apiUrl}`);

          const response = await fetch(apiUrl, {
            signal: controller.signal,
            credentials: 'include', // Include cookies for auth
            headers: {
              'Accept': 'application/json',
              'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0'
            }
          });

          console.log(`[VT API] Response status: ${response.status} for ${apiUrl}`);

          if (response.ok || response.status === 200) {
            const contentType = response.headers.get('content-type');
            console.log(`[VT API] Content-Type: ${contentType}`);

            if (contentType && contentType.includes('application/json')) {
              const data = await response.json();
              console.log(`[VT API] SUCCESS! Got JSON data for ${hostname}:`, data);

              // Parse the response based on structure
              let malicious = 0;
              let suspicious = 0;

              // Try different JSON structures
              if (data.data && data.data.attributes) {
                const attrs = data.data.attributes;

                // v3 API structure
                if (attrs.last_analysis_stats) {
                  malicious = attrs.last_analysis_stats.malicious || 0;
                  suspicious = attrs.last_analysis_stats.suspicious || 0;
                  console.log(`[VT API] Parsed v3 stats - Malicious: ${malicious}, Suspicious: ${suspicious}`);
                }

                // Also check reputation score
                if (attrs.reputation !== undefined) {
                  console.log(`[VT API] Reputation score: ${attrs.reputation}`);
                  if (attrs.reputation < -50) malicious = Math.max(malicious, 5);
                  else if (attrs.reputation < 0) suspicious = Math.max(suspicious, 3);
                }
              }

              // v2 API structure
              if (data.detected_urls) {
                const detectedCount = data.detected_urls.filter(u => u.positives > 0).length;
                malicious = Math.min(detectedCount, 10);
                console.log(`[VT API] Parsed v2 detected_urls - Count: ${detectedCount}`);
              }

              // Determine safety based on detections
              if (malicious > 3) {
                result = 'unsafe';
              } else if (malicious > 0 || suspicious > 5) {
                result = 'warning';
              } else {
                result = 'safe';
              }

              console.log(`[VT API] Final result for ${hostname}: ${result}`);
              clearTimeout(timeout);
              await setCachedResult(url, result, 'safetyStatusCache');
              return result;
            }
          }
        } catch (endpointError) {
          console.log(`[VT API] Endpoint ${apiUrl} failed:`, endpointError.message);
          // Continue to next endpoint
        }
      }

      clearTimeout(timeout);

      // If all API endpoints failed, fall back to unknown
      console.warn(`[VT API] All API endpoints failed for ${hostname}`);
      result = 'unknown';
      await setCachedResult(url, result, 'safetyStatusCache');
      return result;

    } catch (vtError) {
      console.error(`[VT Check] Error scraping VT for ${hostname}:`, vtError.message);
      // Fall back to unknown on error - something is broken
      result = 'unknown';
      await setCachedResult(url, result, 'safetyStatusCache');
      return result;
    }

  } catch (error) {
    console.error('Error in checkURLSafety:', error);
    result = 'unknown';
    await setCachedResult(url, result, 'safetyStatusCache');
    return result;
  }
};

// Listen for messages from the frontend
browser.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "checkLinkStatus") {
    checkLinkStatus(request.url).then(status => {
      sendResponse({ status });
    });
    return true; // Required to indicate an asynchronous response.
  }

  if (request.action === "checkURLSafety") {
    checkURLSafety(request.url).then(status => {
      sendResponse({ status });
    });
    return true; // Required to indicate an asynchronous response.
  }

  if (request.action === "testVirusTotal") {
    // Manual VT test for debugging
    (async () => {
      try {
        // Add protocol if missing
        let testUrl = request.url;
        if (!testUrl.startsWith('http://') && !testUrl.startsWith('https://')) {
          testUrl = 'https://' + testUrl;
        }

        const urlObj = new URL(testUrl);
        const hostname = urlObj.hostname.toLowerCase();

        console.log(`[VT TEST] Manual test for ${hostname}`);
        console.log(`[VT TEST] Calling checkURLSafety...`);

        // Call the actual safety check function
        const result = await checkURLSafety(testUrl);

        console.log(`[VT TEST] Final result: ${result}`);

        sendResponse({ success: true, result, hostname });
      } catch (error) {
        console.error(`[VT TEST] Error:`, error);
        sendResponse({ success: false, error: error.message });
      }
    })();
    return true;
  }

  if (request.action === "getPageContent") {
    fetch(request.url)
      .then(response => {
        if (!response.ok) {
          throw new Error(`HTTP error! Status: ${response.status}`);
        }
        return response.text();
      })
      .then(text => sendResponse({ content: text }))
      .catch(error => sendResponse({ error: error.message }));
    return true; // Required for async response
  }

  if (request.action === "openReaderView") {
    const readerUrl = browser.runtime.getURL(`reader.html?url=${encodeURIComponent(request.url)}`);
    browser.tabs.create({ url: readerUrl });
    // This message doesn't need a response.
  }

  if (request.action === "openPrintView") {
    const printUrl = browser.runtime.getURL(`print.html?url=${encodeURIComponent(request.url)}`);
    browser.tabs.create({ url: printUrl });
    // This message doesn't need a response.
  }
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