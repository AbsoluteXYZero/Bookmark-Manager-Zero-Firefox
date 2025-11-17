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

/**
 * Checks if a URL is reachable and resolves to the expected domain.
 * This function runs in the background script, which has broader permissions
 * than content scripts, allowing it to bypass CORS restrictions.
 * @param {string} url The URL to check.
 * @returns {Promise<'live' | 'dead' | 'parked'>} The status of the link.
 */
const checkLinkStatus = async (url) => {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 10000); // 10-second timeout

  try {
    const response = await fetch(url, { method: 'GET', signal: controller.signal });
    clearTimeout(timeoutId);

    if (response.redirected) {
      const finalHost = new URL(response.url).hostname.toLowerCase();
      // Check if the final destination is a known domain parking service
      if (PARKING_DOMAINS.some(domain => finalHost.includes(domain))) {
        return 'parked';
      }
    }
    
    // Check for successful status codes (2xx)
    if (response.ok) {
      return 'live';
    }

    // If we get here, it's a 4xx or 5xx error, which means the link is dead.
    return 'dead';

  } catch (error) {
    // This catches network errors, DNS errors, timeouts, etc.
    clearTimeout(timeoutId);
    return 'dead';
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