// Bookmark Manager Zero - Sidebar Script
// Connects to Firefox native bookmarks API

// ============================================================================
// VERSION - Single source of truth from manifest.json
// ============================================================================
const APP_VERSION = browser.runtime.getManifest().version;

/* [ZeroLabs] 2026-08-19 7:12 PM - added: timeout for GitLab requests (see also: Bookmark-Manager-Zero-Website/js/storage/snippet-adapter.js) */
// ============================================================================
// NETWORK TIMEOUT
// ============================================================================
// GitLab calls had no time limit, so a stalled connection left the promise
// pending forever: no error, no catch, no completion. Used only for GitLab
// requests; the scanning code in background.js has its own timeouts already.
//
// 15s rather than 30s because several of these sit inside retryWithBackoff,
// and three 30s attempts would take a minute and a half to surface anything.
//
// Safe to retry after an abort: the snippet write is a whole-file PUT, so
// repeating it lands the same result whether or not the first attempt arrived.
const GITLAB_TIMEOUT_MS = 15000;

async function fetchGitLab(url, options = {}, timeoutMs = GITLAB_TIMEOUT_MS) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } catch (error) {
    if (error.name === 'AbortError') {
      throw new Error(`GitLab did not respond within ${Math.round(timeoutMs / 1000)} seconds.`);
    }
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

// ============================================================================
// AUTHENTICATION MANAGER - Adapted from website version
// ============================================================================

class AuthManager {
  constructor() {
    this.token = null;
    this.user = null;
    this.encryptionKey = null;
  }

  /**
   * Derive encryption key from browser fingerprint
   * Uses same method as browser extensions for consistency
   */
  async getDerivedKey(userPassword = null) {
    // Browser fingerprint for key derivation (using origin instead of screen dimensions)
    const appId = browser.runtime.id;
    const browserInfo = `${navigator.userAgent}-${navigator.language}-${appId}`;

    // Optionally add user password for additional security
    const material = userPassword ? `${browserInfo}-${userPassword}` : browserInfo;

    const encoder = new TextEncoder();
    const data = encoder.encode(material);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    return await crypto.subtle.importKey(
      'raw',
      hashBuffer,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  /**
   * Encrypt a token using AES-256-GCM
   */
  async encryptToken(token, userPassword = null) {
    const key = await this.getDerivedKey(userPassword);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoder = new TextEncoder();

    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      encoder.encode(token)
    );

    // Combine IV and encrypted data
    const combined = new Uint8Array(iv.length + encrypted.byteLength);
    combined.set(iv);
    combined.set(new Uint8Array(encrypted), iv.length);

    // Return as base64
    return btoa(Array.from(combined, b => String.fromCharCode(b)).join(''));
  }

  /**
   * Decrypt a token using AES-256-GCM
   */
  async decryptToken(encryptedBase64, userPassword = null) {
    if (!encryptedBase64) return null;

    try {
      const key = await this.getDerivedKey(userPassword);
      const combined = Uint8Array.from(atob(encryptedBase64), c => c.charCodeAt(0));
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
      console.error('Token decryption failed:', error);
      return null;
    }
  }

  /**
   * Store encrypted token in browser storage
   */
  async storeToken(token, userPassword = null, provider = 'gitlab') {
    const encrypted = await this.encryptToken(token, userPassword);
    const key = `${provider}_token`;
    await safeStorage.set({ [key]: encrypted });

    this.token = token;
    console.log(`${provider} token stored securely`);
  }

  /**
   * Retrieve and decrypt token from browser storage
   */
  async loadToken(userPassword = null, provider = 'gitlab') {
    const key = `${provider}_token`;
    const result = await safeStorage.get(key);

    if (result[key]) {
      const token = await this.decryptToken(result[key], userPassword);
      this.token = token;
      return token;
    }
    return null;
  }

  /**
   * Remove token from storage
   */
  async clearToken(provider = 'gitlab') {
    const key = `${provider}_token`;
    await safeStorage.remove(key);

    // Clear in-memory state
    this.token = null;
    this.user = null;

    console.log(`${provider} token cleared`);
  }

  /**
   * Get current token (from memory or storage)
   */
  async getToken(provider = 'gitlab') {
    if (this.token) {
      return this.token;
    }
    return await this.loadToken(null, provider);
  }

  /**
   * Check if user is authenticated
   */
  async isAuthenticated() {
    const token = await this.getToken();
    return !!token;
  }

  /**
   * Fetch user information from GitLab
   */
  async fetchUserInfo() {
    const token = await this.getToken();
    if (!token) throw new Error('No authentication token');

    try {
      const response = await fetchGitLab('https://gitlab.com/api/v4/user', {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      if (!response.ok) {
        throw new Error(`GitLab API error: ${response.status}`);
      }

      this.user = await response.json();
      return this.user;
    } catch (error) {
      console.error('Failed to fetch user info:', error);
      throw error;
    }
  }

  /**
   * Get cached user info or fetch from GitLab
   */
  async getUserInfo() {
    if (this.user) return this.user;
    return await this.fetchUserInfo();
  }

  /**
   * Validate token with GitLab API
   */
  async validateToken() {
    try {
      await this.fetchUserInfo();
      return true;
    } catch (error) {
      console.error('Token validation failed:', error);
      return false;
    }
  }

  /**
   * Encrypt and store API key (for scanning services)
   */
  async storeApiKey(keyName, apiKey, userPassword = null) {
    const encrypted = await this.encryptToken(apiKey, userPassword);
    await safeStorage.set({ [keyName]: encrypted });
    console.log(`API key ${keyName} stored securely`);
  }

  /**
   * Retrieve and decrypt API key
   */
  async getApiKey(keyName, userPassword = null) {
    const result = await safeStorage.get(keyName);
    if (result[keyName]) {
      return await this.decryptToken(result[keyName], userPassword);
    }
    return null;
  }

  /**
   * Remove API key from storage
   */
  async removeApiKey(keyName) {
    await safeStorage.remove(keyName);
    console.log(`API key ${keyName} removed`);
  }

  /**
   * Store user preferences
   */
  async storePreference(key, value) {
    await safeStorage.set({ [key]: value });
  }

  /**
   * Get user preference
   */
  async getPreference(key, defaultValue = null) {
    const result = await safeStorage.get(key);
    return result[key] !== undefined ? result[key] : defaultValue;
  }

  /**
   * Generate a unique device ID for sync locking
   */
  getDeviceId() {
    let deviceId = localStorage.getItem('bmz_device_id');
    if (!deviceId) {
      deviceId = `device_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
      localStorage.setItem('bmz_device_id', deviceId);
    }
    return deviceId;
  }

  /**
   * Get authentication status for UI
   */
  async getAuthStatus() {
    const isAuth = await this.isAuthenticated();
    if (!isAuth) {
      return {
        authenticated: false,
        user: null,
        deviceId: this.getDeviceId()
      };
    }

    try {
      const user = await this.getUserInfo();
      return {
        authenticated: true,
        user: {
          login: user.username || user.login,
          name: user.name,
          avatar: user.avatar_url,
          email: user.email
        },
        deviceId: this.getDeviceId()
      };
    } catch (error) {
      // Token invalid, clear it
      await this.clearToken();
      return {
        authenticated: false,
        user: null,
        deviceId: this.getDeviceId()
      };
    }
  }
}

// Create singleton instance
const authManager = new AuthManager();

// ============================================================================
// OAUTH PAT - Personal Access Token Authentication
// ============================================================================

class OAuthPAT {
  constructor() {
    this.token = null;
    this.user = null;
    this.provider = 'gitlab'; // Always GitLab
  }

  /**
   * Authenticate with Personal Access Token
   * @param {string} token - GitLab Personal Access Token
   * @param {Function} retryCallback - Callback to trigger retry with new token
   * @returns {Promise<Object|null>} User info and token, or null if authentication error popup was shown
   */
  async authenticate(token, retryCallback = null) {
    if (!token || token.trim().length === 0) {
      throw new Error('Token is required');
    }

    const trimmedToken = token.trim();

    // Validate token format (GitLab tokens start with glpat-)
    if (!trimmedToken.startsWith('glpat-')) {
      throw new Error('Invalid GitLab token format. Token should start with glpat-');
    }

    console.log('Authenticating with GitLab PAT');

    try {
      const result = await this.authenticateGitLab(trimmedToken, retryCallback);
      if (result === null) {
        // Authentication error popup was shown, allow retry without throwing
        return null;
      }
      return result;
    } catch (error) {
      // Clear stored token on error
      this.token = null;
      this.user = null;
      throw error;
    }
  }

  /**
   * Authenticate with GitLab PAT
   */
  async authenticateGitLab(token, retryCallback = null) {
    // Test token by fetching user info
    const response = await fetchGitLab('https://gitlab.com/api/v4/user', {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });

    if (!response.ok) {
      if (response.status === 401) {
        // Show informational popup and allow retry
        this.showAuthErrorPopup(retryCallback, false);
        // Return null to indicate authentication failed but allow retry
        return null;
      } else if (response.status === 403) {
        // Show permission error popup and allow retry
        this.showAuthErrorPopup(retryCallback, true);
        // Return null to indicate permission failed but allow retry
        return null;
      } else if (response.status === 429) {
        // Show rate limit popup and allow retry
        this.showRateLimitPopup(retryCallback);
        // Return null to indicate rate limited but allow retry
        return null;
      } else if (response.status >= 500 && response.status < 600) {
        // Show service error popup and allow retry
        this.showServiceErrorPopup(retryCallback);
        // Return null to indicate service error but allow retry
        return null;
      } else {
        throw new Error('GitLab authentication failed: ' + response.statusText);
      }
    }

    const user = await response.json();

    // Verify token has api scope by trying to list snippets
    const snippetResponse = await fetchGitLab('https://gitlab.com/api/v4/snippets', {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });

    if (!snippetResponse.ok) {
      if (snippetResponse.status === 401) {
        // Show informational popup for scope issue
        this.showAuthErrorPopup(retryCallback, false);
        return null;
      } else if (snippetResponse.status === 403) {
        // Show permission error popup for scope issue
        this.showAuthErrorPopup(retryCallback, true);
        return null;
      } else if (snippetResponse.status === 429) {
        // Show rate limit popup for scope check
        this.showRateLimitPopup(retryCallback);
        return null;
      } else if (snippetResponse.status >= 500 && snippetResponse.status < 600) {
        // Show service error popup for scope check
        this.showServiceErrorPopup(retryCallback);
        return null;
      } else {
        throw new Error('GitLab token does not have "api" scope. Please create a new token with "api" permission.');
      }
    }

    // Store token and user info
    this.token = token;
    this.user = user;

    return {
      access_token: token,
      token_type: 'bearer',
      scope: 'api',
      user: user,
      provider: 'gitlab'
    };
  }

  /**
   * Show authentication error popup
   */
  showAuthErrorPopup(retryCallback, isPermissionError = false) {
    const title = isPermissionError ? 'Permission Error' : 'Authentication Failed';
    const message = isPermissionError
      ? 'Your GitLab token lacks the required permissions. Please create a new Personal Access Token with "api" scope.'
      : 'Your GitLab token is invalid or expired. Please check your token and try again.';

    const details = isPermissionError
      ? 'Go to GitLab → User Settings → Access Tokens → Create a new token with "api" scope selected.'
      : 'Make sure you copied the complete token starting with "glpat-".';

    this.showErrorPopup(title, message, details, retryCallback);
  }

  /**
   * Show rate limit error popup
   */
  showRateLimitPopup(retryCallback) {
    const title = 'Rate Limit Exceeded';
    const message = 'GitLab API rate limit reached. Please wait a few minutes before trying again.';
    const details = 'GitLab allows 2000 requests per hour for authenticated users. The limit resets every hour.';

    this.showErrorPopup(title, message, details, retryCallback);
  }

  /**
   * Show service error popup
   */
  showServiceErrorPopup(retryCallback) {
    const title = 'GitLab Service Error';
    const message = 'GitLab is currently experiencing issues. Please try again later.';
    const details = 'This is usually temporary. Check GitLab status at https://status.gitlab.com/';

    this.showErrorPopup(title, message, details, retryCallback);
  }

  /**
   * Show error popup with retry option
   */
  showErrorPopup(title, message, details, retryCallback) {
    // Create modal overlay
    const modal = document.createElement('div');
    modal.className = 'modal-overlay';
    modal.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: rgba(0, 0, 0, 0.6);
      backdrop-filter: blur(4px);
      z-index: 10001;
      display: flex;
      align-items: center;
      justify-content: center;
    `;

    modal.innerHTML = `
      <div style="
        background: var(--md-sys-color-surface);
        border-radius: 16px;
        padding: 24px;
        max-width: 400px;
        width: 90%;
        box-shadow: 0 8px 32px rgba(0,0,0,0.3);
        border: 1px solid var(--md-sys-color-outline);
      ">
        <h3 style="
          margin: 0 0 16px 0;
          color: var(--md-sys-color-error);
          font-size: 18px;
          font-weight: 600;
        ">${title}</h3>
        <p style="margin-bottom: 12px; color: var(--md-sys-color-on-surface); line-height: 1.5;">
          ${message}
        </p>
        <div style="
          background: var(--md-sys-color-surface-variant);
          padding: 12px;
          border-radius: 8px;
          margin-bottom: 20px;
          font-size: 13px;
          color: var(--md-sys-color-on-surface-variant);
          line-height: 1.4;
        ">
          ${details}
        </div>
        <div style="display: flex; gap: 12px; justify-content: flex-end;">
          <button id="cancelRetry" style="
            background: var(--md-sys-color-surface-variant);
            color: var(--md-sys-color-on-surface-variant);
            border: none;
            padding: 10px 16px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 14px;
          ">Cancel</button>
          <button id="retryAuth" style="
            background: var(--md-sys-color-primary);
            color: var(--md-sys-color-on-primary);
            border: none;
            padding: 10px 16px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 500;
          ">Try Again</button>
        </div>
      </div>
    `;

    document.body.appendChild(modal);

    // Handle button clicks
    modal.querySelector('#cancelRetry').onclick = () => {
      modal.remove();
    };

    modal.querySelector('#retryAuth').onclick = () => {
      modal.remove();
      if (retryCallback) retryCallback();
    };

    // Close on background click
    modal.onclick = (e) => {
      if (e.target === modal) {
        modal.remove();
      }
    };

    // Close on Escape key
    document.addEventListener('keydown', function escHandler(e) {
      if (e.key === 'Escape') {
        modal.remove();
        document.removeEventListener('keydown', escHandler);
      }
    });
  }

  /**
   * Get current token
   * @returns {string|null} Current token
   */
  getToken() {
    return this.token;
  }

  /**
   * Get current user
   * @returns {Object|null} Current user info
   */
  getUser() {
    return this.user;
  }

  /**
   * Get current provider
   * @returns {string} Always 'gitlab'
   */
  getProvider() {
    return this.provider;
  }

  /**
   * Clear authentication
   */
  clear() {
    this.token = null;
    this.user = null;
  }

  /**
   * Check if authenticated
   * @returns {boolean} True if authenticated
   */
  isAuthenticated() {
    return this.token !== null;
  }
}

// Create singleton instance
const oauthPAT = new OAuthPAT();

// ============================================================================
// SNIPPET ADAPTER - GitLab Snippet Operations
// ============================================================================

class SnippetAdapter {
  constructor() {
    this.apiBase = 'https://gitlab.com/api/v4';
    this.snippetId = null;
    this.rateLimit = {
      remaining: null,
      limit: null,
      reset: null
    };
    this.userCache = null;
    this.userCacheExpiry = 0;
  }

  /**
   * Get authorization headers for GitLab API
   */
  async getHeaders() {
    const token = await authManager.getToken('gitlab');
    if (!token) {
      throw new Error('No GitLab authentication token available');
    }

    return {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
      'User-Agent': 'Bookmark-Manager-Zero/1.0 (https://github.com/AbsoluteXYZero/bookmark-manager-zero)'
    };
  }

  /**
   * Update rate limit info from response headers
   */
  updateRateLimitFromResponse(response) {
    const remaining = response.headers.get('RateLimit-Remaining');
    const limit = response.headers.get('RateLimit-Limit');
    const reset = response.headers.get('RateLimit-Reset');

    if (remaining !== null) this.rateLimit.remaining = parseInt(remaining, 10);
    if (limit !== null) this.rateLimit.limit = parseInt(limit, 10);
    if (reset !== null) this.rateLimit.reset = parseInt(reset, 10);

    // Log warning if rate limit is getting low
    if (this.rateLimit.remaining !== null && this.rateLimit.remaining < 100) {
      const resetDate = new Date(this.rateLimit.reset * 1000);
      console.warn(`[RateLimit] GitLab API rate limit low: ${this.rateLimit.remaining}/${this.rateLimit.limit} remaining (resets at ${resetDate.toLocaleTimeString()})`);
    }
  }

  /**
   * Check if we should proceed with API call based on rate limits
   */
  checkRateLimit() {
    if (this.rateLimit.remaining !== null && this.rateLimit.remaining < 10) {
      const resetDate = new Date(this.rateLimit.reset * 1000);
      const now = Date.now();
      const msUntilReset = (this.rateLimit.reset * 1000) - now;

      if (msUntilReset > 0) {
        throw new Error(`GitLab API rate limit nearly exhausted (${this.rateLimit.remaining} remaining). Sync will retry after ${resetDate.toLocaleTimeString()}`);
      }
    }
  }

  /**
   * Get rate limit status
   */
  getRateLimitStatus() {
    return { ...this.rateLimit };
  }

  /**
   * Exponential backoff with jitter for retry logic
   */
  async retryWithBackoff(fn, maxRetries = 3, baseDelay = 1000) {
    let lastError;

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        return await fn();
      } catch (error) {
        lastError = error;

        // Don't retry on certain errors
        if (error.message.includes('404') ||
            error.message.includes('401') ||
            error.message.includes('403')) {
          throw error;
        }

        // If this was the last attempt, throw the error
        if (attempt === maxRetries) {
          throw error;
        }

        // Calculate delay with exponential backoff and jitter
        const exponentialDelay = baseDelay * Math.pow(2, attempt);
        const jitter = Math.random() * exponentialDelay * 0.3; // 30% jitter
        const delay = exponentialDelay + jitter;

        console.log(`[RetryBackoff] Attempt ${attempt + 1}/${maxRetries + 1} failed. Retrying in ${Math.round(delay)}ms...`);
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }

    throw lastError;
  }

  /**
   * Get all user's snippets
   */
  async getAllSnippets() {
    try {
      // Check rate limits before making API calls
      this.checkRateLimit();

      const headers = await this.getHeaders();

      // Use cached user info if available (expires after 5 minutes)
      const now = Date.now();
      if (!this.userCache || now > this.userCacheExpiry) {
        console.log('[GetAllSnippets] Fetching user info (cache expired or empty)...');
        const userResponse = await fetch(`${this.apiBase}/user`, { headers });
        this.updateRateLimitFromResponse(userResponse);

        if (userResponse.ok) {
          this.userCache = await userResponse.json();
          this.userCacheExpiry = now + (5 * 60 * 1000); // Cache for 5 minutes
          console.log('[GetAllSnippets] Authenticated as:', this.userCache.username, '(User ID:', this.userCache.id + ')');
        } else {
          console.error('[GetAllSnippets] Failed to verify user:', userResponse.status);
        }
      } else {
        console.log('[GetAllSnippets] Using cached user info:', this.userCache.username);
      }

      // Fetch all snippets for the authenticated user
      console.log('[GetAllSnippets] Fetching from:', `${this.apiBase}/snippets?per_page=100`);
      const response = await fetch(`${this.apiBase}/snippets?per_page=100`, { headers });

      // Update rate limit tracking
      this.updateRateLimitFromResponse(response);

      console.log('[GetAllSnippets] Response status:', response.status, response.statusText);

      // Check pagination headers
      const linkHeader = response.headers.get('Link');
      const totalCount = response.headers.get('X-Total-Count');
      if (linkHeader) {
        console.log('[GetAllSnippets] Pagination Link header:', linkHeader);
      }
      if (totalCount) {
        console.log('[GetAllSnippets] Total count:', totalCount);
      }

      if (!response.ok) {
        if (response.status === 401) {
          // Show authentication error popup and allow retry
          return new Promise((resolve, reject) => {
            oauthPAT.showAuthErrorPopup(() => {
              // Retry the entire operation
              this.getAllSnippets().then(resolve).catch(reject);
            }, false);
          });
        } else if (response.status === 403) {
          // Show permission error popup and allow retry
          return new Promise((resolve, reject) => {
            oauthPAT.showAuthErrorPopup(() => {
              // Retry the entire operation
              this.getAllSnippets().then(resolve).catch(reject);
            }, true);
          });
        } else if (response.status === 429) {
          // Show rate limit popup and allow retry
          return new Promise((resolve, reject) => {
            oauthPAT.showRateLimitPopup(() => {
              // Retry the entire operation
              this.getAllSnippets().then(resolve).catch(reject);
            });
          });
        } else if (response.status >= 500 && response.status < 600) {
          // Show service error popup and allow retry
          return new Promise((resolve, reject) => {
            oauthPAT.showServiceErrorPopup(() => {
              // Retry the entire operation
              this.getAllSnippets().then(resolve).catch(reject);
            });
          });
        }
        const errorText = await response.text();
        console.error('[GetAllSnippets] Error response:', errorText);
        throw new Error(`Failed to fetch snippets: ${response.status}`);
      }

      const snippets = await response.json();
      console.log('[GetAllSnippets] Retrieved', snippets.length, 'snippets')

      // Log details about each snippet
      if (snippets.length > 0) {
        console.log('[GetAllSnippets] Snippet details:');
        snippets.forEach((s, idx) => {
          const fileName = s.file_name || 'unknown';
          const visibility = s.visibility || 'unknown';
          console.log(`  ${idx + 1}. ${s.id} - ${visibility} - File: ${fileName} - Title: "${s.title || 'none'}"`);
        });
      } else {
        console.warn('[GetAllSnippets] No snippets found. Possible reasons:');
        console.warn('  1. This GitLab account has no Snippets');
        console.warn('  2. Token permissions issue (needs "api" scope)');
      }

      return snippets;
    } catch (error) {
      console.error('Failed to fetch snippets:', error);
      throw error;
    }
  }

  /**
   * Find user's bookmark Snippet
   */
  async findBookmarkSnippet() {
    try {
      const snippets = await this.getAllSnippets();

      // Look for Snippet with BMZ in title or bookmarks.json file
      const bookmarkSnippet = snippets.find(s =>
        s.title?.includes('BMZ') ||
        s.title?.includes('Bookmark Manager Zero') ||
        s.file_name === 'bookmarks.json'
      );

      if (bookmarkSnippet) {
        // Validate that we can actually read from this snippet
        try {
          await this.readBookmarks(bookmarkSnippet.id);
          this.snippetId = bookmarkSnippet.id;
          console.log('Found and validated bookmark Snippet:', this.snippetId);
          return bookmarkSnippet.id;
        } catch (error) {
          console.warn('Found bookmark snippet but cannot read from it:', bookmarkSnippet.id, error);
          return null;
        }
      }

      return null;
    } catch (error) {
      console.error('Failed to find bookmark Snippet:', error);
      throw error;
    }
  }

  /**
   * Set snippet ID to use
   */
  setSnippetId(snippetId) {
    this.snippetId = snippetId;
    // Store in localStorage so we remember it
    localStorage.setItem('bmz_snippet_id', snippetId);
    console.log('Set bookmark Snippet ID:', snippetId);
  }

  /**
   * Load saved snippet ID from storage
   */
  loadSavedSnippetId() {
    const savedId = localStorage.getItem('bmz_snippet_id');
    if (savedId) {
      // Validate that it's a string and not an object
      if (typeof savedId === 'string' && !savedId.startsWith('{') && !savedId.startsWith('[')) {
        this.snippetId = savedId;
        console.log('Loaded saved Snippet ID:', savedId);
        return savedId;
      } else {
        console.warn('Invalid snippet ID in localStorage:', savedId);
        localStorage.removeItem('bmz_snippet_id');
      }
    }
    return null;
  }

  /**
   * Create a new Snippet for bookmarks
   */
  async createBookmarkSnippet(bookmarkTree = null) {
    try {
      const headers = await this.getHeaders();

      // Default bookmark structure with standard root folders
      const defaultTree = {
        version: 1,
        checksum: '',
        lastModified: Date.now(),
        roots: {
          bookmark_bar: {
            id: '1',
            title: 'Bookmarks Toolbar',
            name: 'Bookmarks Toolbar',
            type: 'folder',
            dateAdded: Date.now(),
            children: []
          },
          menu: {
            id: '2',
            title: 'Bookmarks Menu',
            name: 'Bookmarks Menu',
            type: 'folder',
            dateAdded: Date.now(),
            children: []
          },
          other: {
            id: '3',
            title: 'Other Bookmarks',
            name: 'Other Bookmarks',
            type: 'folder',
            dateAdded: Date.now(),
            children: []
          },
          mobile: {
            id: '4',
            title: 'Mobile Bookmarks',
            name: 'Mobile Bookmarks',
            type: 'folder',
            dateAdded: Date.now(),
            children: []
          }
        }
      };

      const tree = bookmarkTree || defaultTree;
      tree.checksum = await this.calculateChecksum(tree);

      // Check rate limits before creating
      this.checkRateLimit();

      console.log('[CreateSnippet] Sending request to GitLab API...');
      const response = await fetch(`${this.apiBase}/snippets`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          title: 'BMZ Bookmarks - Managed by Bookmark Manager Zero',
          visibility: 'private',
          files: [
            {
              file_path: 'bookmarks.json',
              content: JSON.stringify(tree)
            }
          ]
        })
      });

      // Update rate limit tracking
      this.updateRateLimitFromResponse(response);

      console.log('[CreateSnippet] Response status:', response.status, response.statusText);

      if (!response.ok) {
        if (response.status === 401) {
          // Show authentication error popup and allow retry
          return new Promise((resolve, reject) => {
            oauthPAT.showAuthErrorPopup(() => {
              // Retry the entire operation
              this.createBookmarkSnippet(bookmarkTree).then(resolve).catch(reject);
            }, false);
          });
        } else if (response.status === 403) {
          // Show permission error popup and allow retry
          return new Promise((resolve, reject) => {
            oauthPAT.showAuthErrorPopup(() => {
              // Retry the entire operation
              this.createBookmarkSnippet(bookmarkTree).then(resolve).catch(reject);
            }, true);
          });
        } else if (response.status === 429) {
          // Show rate limit popup and allow retry
          return new Promise((resolve, reject) => {
            oauthPAT.showRateLimitPopup(() => {
              // Retry the entire operation
              this.createBookmarkSnippet(bookmarkTree).then(resolve).catch(reject);
            });
          });
        } else if (response.status >= 500 && response.status < 600) {
          // Show service error popup and allow retry
          return new Promise((resolve, reject) => {
            oauthPAT.showServiceErrorPopup(() => {
              // Retry the entire operation
              this.createBookmarkSnippet(bookmarkTree).then(resolve).catch(reject);
            });
          });
        }
        const errorBody = await response.text();
        console.error('[CreateSnippet] Error response:', errorBody);
        throw new Error(`Failed to create Snippet: ${response.status} - ${errorBody}`);
      }

      const snippet = await response.json();
      console.log('[CreateSnippet] Snippet created successfully:', {
        id: snippet.id,
        url: snippet.web_url,
        title: snippet.title
      });

      this.snippetId = snippet.id;
      // Save to localStorage
      this.setSnippetId(snippet.id);

      console.log('Created bookmark Snippet:', this.snippetId);

      return snippet.id;
    } catch (error) {
      console.error('Failed to create bookmark Snippet:', error);
      throw error;
    }
  }

  /**
   * Read bookmark data from Snippet
   */
  async readBookmarks(snippetId = null) {
    const id = snippetId || this.snippetId;
    console.log('[ReadSnippet] Attempting to read Snippet:', {
      providedId: snippetId,
      storedId: this.snippetId,
      usingId: id
    });

    if (!id) {
      throw new Error('No Snippet ID provided');
    }

    try {
      // Check rate limits before reading
      this.checkRateLimit();

      const headers = await this.getHeaders();
      console.log('[ReadSnippet] Fetching from:', `${this.apiBase}/snippets/${id}`);
      const response = await fetch(`${this.apiBase}/snippets/${id}`, { headers });

      // Update rate limit tracking
      this.updateRateLimitFromResponse(response);

      console.log('[ReadSnippet] Response status:', response.status, response.statusText);

      if (!response.ok) {
        if (response.status === 404) {
          const errorText = await response.text();
          console.error('[ReadSnippet] 404 Error - Snippet not found. Response:', errorText);

          // Clear the invalid Snippet ID immediately
          console.warn('[ReadSnippet] Clearing invalid Snippet ID:', id);
          this.snippetId = null;
          localStorage.removeItem('bmz_snippet_id');

          throw new Error('Bookmark Snippet not found');
        } else if (response.status >= 500 && response.status < 600) {
          // Show service error popup and allow retry
          return new Promise((resolve, reject) => {
            oauthPAT.showServiceErrorPopup(() => {
              // Retry the entire operation
              this.readBookmarks(snippetId).then(resolve).catch(reject);
            });
          });
        }
        const errorText = await response.text();
        console.error('[ReadSnippet] Error response:', errorText);
        throw new Error(`Failed to read Snippet: ${response.status}`);
      }

      const snippet = await response.json();
      console.log('[ReadSnippet] Snippet fetched successfully:', {
        id: snippet.id,
        title: snippet.title,
        filesCount: snippet.files?.length || 0
      });

      // GitLab snippets have a 'files' array
      const bookmarkFile = snippet.files?.find(f => f.path === 'bookmarks.json' || f.file_name === 'bookmarks.json');
      if (!bookmarkFile) {
        throw new Error('Snippet does not contain bookmarks.json');
      }

      console.log('[ReadSnippet] Found bookmarks.json file:', {
        path: bookmarkFile.path,
        file_name: bookmarkFile.file_name
      });

      // GitLab API v4 doesn't include content directly, need to fetch it via API
      let content = bookmarkFile.content;

      // If content is not in the response, fetch it using the API with authentication
      if (!content) {
        console.log('[ReadSnippet] Content not in response, fetching via API...');
        // Use the authenticated API endpoint instead of raw_url to avoid CORS
        const fileResponse = await fetch(`${this.apiBase}/snippets/${id}/files/main/bookmarks.json/raw`, { headers });
        if (!fileResponse.ok) {
          if (fileResponse.status === 429) {
            // Show rate limit popup and allow retry
            return new Promise((resolve, reject) => {
              oauthPAT.showRateLimitPopup(() => {
                // Retry the entire operation
                this.readBookmarks(snippetId).then(resolve).catch(reject);
              });
            });
          } else if (fileResponse.status >= 500 && fileResponse.status < 600) {
            // Show service error popup and allow retry
            return new Promise((resolve, reject) => {
              oauthPAT.showServiceErrorPopup(() => {
                // Retry the entire operation
                this.readBookmarks(snippetId).then(resolve).catch(reject);
              });
            });
          }
          console.warn('[ReadSnippet] API raw endpoint failed with status:', fileResponse.status);
          throw new Error(`Failed to fetch file content: ${fileResponse.status}`);
        }
        content = await fileResponse.text();
        console.log('[ReadSnippet] Fetched content length:', content?.length);
      }

      // If content is empty or just whitespace, return empty bookmark structure
      if (!content || content.trim() === '') {
        console.log('[ReadSnippet] Snippet file is empty, returning empty bookmark structure');
        return this.getEmptyBookmarkTree();
      }

      const bookmarkData = JSON.parse(content);

      console.log('[ReadSnippet] Bookmarks parsed successfully. Version:', bookmarkData.version);
      return bookmarkData;
    } catch (error) {
      console.error('Failed to read bookmarks from Snippet:', error);
      throw error;
    }
  }

  /**
   * Update Snippet with new bookmark data
   */
  async updateBookmarks(snippetId = null, bookmarkTree, version = null) {
    const id = snippetId || this.snippetId;
    console.log('[UpdateSnippet] Attempting to update Snippet:', {
      providedId: snippetId,
      storedId: this.snippetId,
      usingId: id
    });

    if (!id) {
      throw new Error('No Snippet ID provided');
    }

    try {
      // Add version and metadata
      const dataWithMeta = {
        ...bookmarkTree,
        version: version !== null ? version : (bookmarkTree.version || 1) + 1,
        checksum: await this.calculateChecksum(bookmarkTree),
        lastModified: Date.now()
      };

      console.log('[UpdateSnippet] Updating with version:', dataWithMeta.version);

      // Check rate limits before updating
      this.checkRateLimit();

      const headers = await this.getHeaders();
      const response = await fetch(`${this.apiBase}/snippets/${id}`, {
        method: 'PUT',
        headers,
        body: JSON.stringify({
          files: [
            {
              action: 'update',
              file_path: 'bookmarks.json',
              content: JSON.stringify(dataWithMeta)
            }
          ]
        })
      });

      // Update rate limit tracking
      this.updateRateLimitFromResponse(response);

      console.log('[UpdateSnippet] Response status:', response.status, response.statusText);

      if (!response.ok) {
        if (response.status === 401) {
          // Show authentication error popup and allow retry
          return new Promise((resolve, reject) => {
            oauthPAT.showAuthErrorPopup(() => {
              // Retry the entire operation
              this.updateBookmarks(snippetId, bookmarkTree, version).then(resolve).catch(reject);
            }, false);
          });
        } else if (response.status === 403) {
          // Show permission error popup and allow retry
          return new Promise((resolve, reject) => {
            oauthPAT.showAuthErrorPopup(() => {
              // Retry the entire operation
              this.updateBookmarks(snippetId, bookmarkTree, version).then(resolve).catch(reject);
            }, true);
          });
        } else if (response.status === 429) {
          // Show rate limit popup and allow retry
          return new Promise((resolve, reject) => {
            oauthPAT.showRateLimitPopup(() => {
              // Retry the entire operation
              this.updateBookmarks(snippetId, bookmarkTree, version).then(resolve).catch(reject);
            });
          });
        } else if (response.status >= 500 && response.status < 600) {
          // Show service error popup and allow retry
          return new Promise((resolve, reject) => {
            oauthPAT.showServiceErrorPopup(() => {
              // Retry the entire operation
              this.updateBookmarks(snippetId, bookmarkTree, version).then(resolve).catch(reject);
            });
          });
        }
        const errorText = await response.text();
        console.error('[UpdateSnippet] Error response:', errorText);
        throw new Error(`Failed to update Snippet: ${response.status} - ${errorText}`);
      }

      const snippet = await response.json();
      console.log('[UpdateSnippet] Updated bookmarks in Snippet:', id, '- New version:', dataWithMeta.version);
      return snippet;
    } catch (error) {
      console.error('Failed to update bookmarks in Snippet:', error);
      throw error;
    }
  }

  /**
   * Calculate SHA-256 checksum for conflict detection
   */
  async calculateChecksum(data) {
    // Remove fields that change on every update
    const { checksum, lastModified, version, editLock, ...dataToHash } = data;

    const str = JSON.stringify(dataToHash, Object.keys(dataToHash).sort());
    const buffer = new TextEncoder().encode(str);
    const hash = await crypto.subtle.digest('SHA-256', buffer);

    return Array.from(new Uint8Array(hash))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  /**
   * Get current Snippet ID
   */
  getSnippetId() {
    return this.snippetId;
  }

  /**
   * Get empty bookmark tree structure
   */
  getEmptyBookmarkTree() {
    return {
      version: 1,
      checksum: '',
      lastModified: Date.now(),
      roots: {
        bookmark_bar: {
          id: '1',
          title: 'Bookmarks Toolbar',
          name: 'Bookmarks Toolbar',
          type: 'folder',
          dateAdded: Date.now(),
          children: []
        },
        menu: {
          id: '2',
          title: 'Bookmarks Menu',
          name: 'Bookmarks Menu',
          type: 'folder',
          dateAdded: Date.now(),
          children: []
        },
        other: {
          id: '3',
          title: 'Other Bookmarks',
          name: 'Other Bookmarks',
          type: 'folder',
          dateAdded: Date.now(),
          children: []
        },
        mobile: {
          id: '4',
          title: 'Mobile Bookmarks',
          name: 'Mobile Bookmarks',
          type: 'folder',
          dateAdded: Date.now(),
          children: []
        }
      }
    };
  }
}

// Create singleton instance
const snippetAdapter = new SnippetAdapter();

// ============================================================================
// SYNC MANAGER - Handles bidirectional sync with GitLab
// ============================================================================

class SyncManager {
  constructor() {
    this.snippetId = null;
    this.provider = 'gitlab';
    this.deviceId = authManager.getDeviceId();
    this.syncInterval = null;
    this.syncIntervalId = null; // Timer ID for auto-sync
    this.isSyncing = false;
    this.hasUnsyncedChanges = false;
    this.lastSyncTime = null;
    this.autoSyncEnabled = true;
    this.minSyncInterval = 60000; // Minimum 60 seconds between syncs
  }

  /**
   * Initialize the sync manager
   */
  async init() {
    // Prevent duplicate initialization
    if (this._initialized) {
      return;
    }
    this._initialized = true;

    this.provider = await authManager.getPreference('syncProvider') || 'gitlab';

    // Load snippet ID from storage
    const savedId = snippetAdapter.loadSavedSnippetId();
    if (savedId) {
      this.snippetId = savedId;

      // Start auto-sync timer when GitLab account is connected
      this.startAutoSync();
    }
  }

  /**
   * Set Snippet ID
   */
  async setSnippetId(snippetId) {
    this.snippetId = snippetId;
    snippetAdapter.setSnippetId(snippetId);
    await safeStorage.set({ snippetId });
    await this.setProvider('gitlab');
    console.log('Snippet ID saved:', snippetId);

    // Start auto-sync when GitLab account is connected
    this.startAutoSync();
  }

  /**
   * Set the current provider
   */
  async setProvider(provider) {
    this.provider = 'gitlab';
    await safeStorage.set({ syncProvider: 'gitlab' });
    console.log('Sync provider set to: gitlab');
  }

  /**
   * Start auto-sync timer (5-minute interval)
   */
  async startAutoSync() {
    // Clear any existing timer
    this.stopAutoSync();

    if (!this.snippetId) {
      console.log('[AutoSync] No GitLab account connected - auto-sync disabled');
      return;
    }

    const syncInterval = 5 * 60 * 1000; // 5 minutes

    // Perform initial sync immediately
    if (navigator.onLine && !this.isSyncing) {
      console.log('[AutoSync] Running initial sync...');
      try {
        await this.syncFromRemote();
      } catch (error) {
        console.error('[AutoSync] Initial sync failed:', error);
      }
    }

    // Then start the interval for subsequent syncs
    this.syncIntervalId = setInterval(async () => {
      if (!navigator.onLine) {
        console.log('[AutoSync] Offline - skipping scheduled sync');
        return;
      }

      if (this.isSyncing) {
        console.log('[AutoSync] Sync already in progress - skipping scheduled sync');
        return;
      }

      console.log('[AutoSync] Starting scheduled sync (5-minute interval)...');
      try {
        await this.syncFromRemote();
      } catch (error) {
        console.error('[AutoSync] Scheduled sync failed:', error);
      }
    }, syncInterval);

    console.log('[AutoSync] Started with immediate + 5-minute interval');
  }

  /**
   * Stop auto-sync timer
   */
  stopAutoSync() {
    if (this.syncIntervalId) {
      clearInterval(this.syncIntervalId);
      this.syncIntervalId = null;
      console.log('[AutoSync] Stopped');
    }
  }

  /**
   * Mark that local changes need to be synced
   */
  async markChanged() {
    console.log('[MarkChanged] Setting hasUnsyncedChanges = true');
    this.hasUnsyncedChanges = true;

    // Trigger sync if online
    if (navigator.onLine) {
      // Debounce sync to avoid too many requests
      if (this.syncDebounceTimer) {
        clearTimeout(this.syncDebounceTimer);
      }
      this.syncDebounceTimer = setTimeout(async () => {
        // Check if we still have a valid remote ID before syncing
        if (!this.getRemoteId()) {
          console.log('[MarkChanged] No remote ID, skipping sync');
          return;
        }

        try {
          await this.syncToRemote();
          this.emitEvent('syncSuccess', 'Changes synced to remote');
        } catch (error) {
          console.error('Sync failed:', error);
          this.emitEvent('syncError', error.message || 'Failed to sync changes');
          // Retry after 5 seconds
          setTimeout(() => {
            if (this.hasUnsyncedChanges && navigator.onLine && this.getRemoteId()) {
              this.syncToRemote().catch(err => {
                console.error('Retry sync failed:', err);
                this.emitEvent('syncError', 'Sync retry failed. Changes will sync when connection improves.');
              });
            }
          }, 5000);
        }
      }, 30000); // Wait 30 seconds after last change to batch multiple edits
    }
  }

  /**
   * Sync local changes to remote (push)
   */
  async syncToRemote() {
    console.log('[SyncToRemote] Called, checking conditions...');

    if (this.isSyncing) {
      console.log('[SyncToRemote] Sync already in progress, skipping...');
      return;
    }

    if (!navigator.onLine) {
      console.log('[SyncToRemote] Offline, cannot sync to remote');
      return;
    }

    const remoteId = this.getRemoteId();
    if (!remoteId) {
      console.log('[SyncToRemote] No remote ID, cannot sync');
      return;
    }

    // Rate limiting: prevent syncing more frequently than minSyncInterval
    const timeSinceLastSync = Date.now() - (this.lastSyncTime || 0);
    if (this.lastSyncTime && timeSinceLastSync < this.minSyncInterval) {
      const waitTime = Math.ceil((this.minSyncInterval - timeSinceLastSync) / 1000);
      console.log(`[SyncToRemote] Rate limit: Last sync was ${Math.ceil(timeSinceLastSync / 1000)}s ago. Please wait ${waitTime}s before syncing again.`);
      this.emitEvent('syncError', `Please wait ${waitTime} seconds before syncing again to avoid rate limits`);
      return;
    }

    console.log(`[SyncToRemote] All conditions passed. Provider: ${this.provider}, Remote ID: ${remoteId}`);
    this.isSyncing = true;

    // Cancel any pending debounced sync since we're doing an explicit sync now
    if (this.syncDebounceTimer) {
      clearTimeout(this.syncDebounceTimer);
      this.syncDebounceTimer = null;
      console.log('[SyncToRemote] Cancelled pending debounced sync');
    }

    try {
      console.log(`[SyncToRemote] Starting sync of local changes to ${this.provider}...`);

      // Check rate limits before syncing
      const rateLimitStatus = snippetAdapter.getRateLimitStatus();
      if (rateLimitStatus.remaining !== null && rateLimitStatus.remaining < 10) {
        const resetDate = new Date(rateLimitStatus.reset * 1000);
        throw new Error(`API rate limit nearly exhausted (${rateLimitStatus.remaining} remaining). Sync will retry after ${resetDate.toLocaleTimeString()}`);
      }

      // Load local bookmark tree
      const localBookmarks = await this.loadLocalBookmarks();
      const bookmarkCount = this.countBookmarksInTree(localBookmarks);
      console.log(`[SyncToRemote] Loaded local bookmarks: ${bookmarkCount} total bookmarks`);

      // Get remote version (single read, no locking to reduce API calls)
      const remoteData = await snippetAdapter.readBookmarks(remoteId);
      const localVersion = await this.getLocalVersion();

      console.log(`[SyncToRemote] Version check - Local: ${localVersion}, Remote: ${remoteData.version}`);

      // Check for conflicts
      if (remoteData.version > localVersion) {
        console.warn('[SyncToRemote] Remote has newer changes! Conflict detected.');
        throw new Error('Sync conflict: Remote has newer changes. Please reload and try again.');
      }

      // Push local changes
      const newVersion = remoteData.version + 1;
      console.log(`[SyncToRemote] Pushing ${bookmarkCount} bookmarks to remote with version ${newVersion}...`);
      await snippetAdapter.updateBookmarks(remoteId, localBookmarks, newVersion);

      // Update local metadata
      await this.setLocalVersion(newVersion);
      console.log('[SyncToRemote] Setting hasUnsyncedChanges = false');
      this.hasUnsyncedChanges = false;
      this.lastSyncTime = Date.now();
      await safeStorage.set({ lastSync: this.lastSyncTime });

      console.log(`[SyncToRemote] Sync complete! Version ${newVersion} with ${bookmarkCount} bookmarks pushed to remote`);
    } catch (error) {
      console.error('Sync to remote failed:', error);

      // If the error is a 404 (Snippet not found), stop syncing
      if (error.message && error.message.includes('not found')) {
        console.warn('[SyncToRemote] Remote not found (404), aborting sync and clearing stored ID');
        this.hasUnsyncedChanges = false; // Clear the flag to prevent retry loops

        // Clear the stored snippet ID
        localStorage.removeItem('bmz_snippet_id');
        await safeStorage.remove('snippetId');
        this.snippetId = null;
        snippetAdapter.snippetId = null;

        // Emit event to notify UI that setup is needed
        this.emitEvent('syncError', {
          error: 'Remote storage not found. Please set up sync again.',
          requiresSetup: true
        });
      }

      throw error;
    } finally {
      this.isSyncing = false;
    }
  }

  /**
   * Sync remote changes to local (pull)
   */
  async syncFromRemote() {
    if (this.isSyncing) {
      console.log('[SyncFromRemote] Already syncing, skipping...');
      return;
    }

    if (!navigator.onLine) {
      console.log('[SyncFromRemote] Offline, skipping...');
      return;
    }

    const remoteId = this.getRemoteId();
    if (!remoteId) {
      console.log('[SyncFromRemote] No remote ID, skipping...');
      return;
    }

    this.isSyncing = true;

    try {
      console.log(`[SyncFromRemote] Starting sync for ${this.provider}:`, remoteId);

      // Check rate limits before syncing
      const rateLimitStatus = snippetAdapter.getRateLimitStatus();
      if (rateLimitStatus.remaining !== null && rateLimitStatus.remaining < 10) {
        const resetDate = new Date(rateLimitStatus.reset * 1000);
        throw new Error(`API rate limit nearly exhausted (${rateLimitStatus.remaining} remaining). Sync will retry after ${resetDate.toLocaleTimeString()}`);
      }

      const remoteData = await snippetAdapter.readBookmarks(remoteId);
      const remoteBookmarkCount = this.countBookmarksInTree(remoteData);
      console.log('[SyncFromRemote] Remote data fetched:', {
        hasRoots: !!remoteData?.roots,
        rootKeys: remoteData?.roots ? Object.keys(remoteData.roots) : [],
        version: remoteData?.version,
        bookmarkCount: remoteBookmarkCount
      });

      const localData = await this.loadLocalBookmarks();
      const localBookmarkCount = this.countBookmarksInTree(localData);
      const localVersion = await this.getLocalVersion();
      console.log('[SyncFromRemote] Local version:', localVersion, 'Local bookmarks:', localBookmarkCount);

      // Sync if remote is newer OR if local is empty (version 0)
      if (remoteData.version > localVersion || localVersion === 0) {
        console.log(`[SyncFromRemote] Remote version (${remoteData.version}) >= Local version (${localVersion}), pulling changes...`);

        // Get current local data for diff
        const localData = await this.getLocalBookmarks();

        // Calculate diff
        const diff = this.calculateBookmarkDiff(localData, remoteData);
        console.log('[SyncFromRemote] Changes detected:', {
          added: diff.added.length,
          removed: diff.removed.length,
          moved: diff.moved.length,
          modified: diff.modified.length
        });

        // Check if there are deletions - require user confirmation
        if (diff.removed.length > 0) {
          // Emit event with diff data for UI to handle
          this.emitEvent('syncConflict', {
            diff,
            remoteData,
            requiresConfirmation: true,
            message: `Remote has ${diff.removed.length} deletion(s). Review changes before syncing.`
          });

          this.isSyncing = false;
          return false; // Don't auto-sync, wait for user confirmation
        }

        // Save remote data to local BEFORE emitting event
        await this.saveLocalBookmarks(remoteData);
        console.log('[SyncFromRemote] Saved remote data to local storage');

        await this.setLocalVersion(remoteData.version);
        console.log('[SyncFromRemote] Updated local version to:', remoteData.version);

        this.lastSyncTime = Date.now();
        await safeStorage.set({ lastSync: this.lastSyncTime });

        // No deletions - notify UI after data is saved
        if (diff.added.length > 0 || diff.moved.length > 0 || diff.modified.length > 0) {
          // Emit event with diff data (after save so UI can reload)
          this.emitEvent('syncChanges', {
            diff,
            remoteData,
            requiresConfirmation: false,
            message: `Remote has ${diff.added.length} addition(s), ${diff.moved.length} move(s), ${diff.modified.length} modification(s).`
          });
        }

        console.log('[SyncFromRemote] Sync complete, version:', remoteData.version);
        return true; // Indicate that data was updated
      } else {
        console.log('[SyncFromRemote] Local is up to date (local:', localVersion, ', remote:', remoteData.version, ')');
        return false;
      }
    } catch (error) {
      console.error('[SyncFromRemote] Sync failed:', error);

      // If the error is a 404 (Snippet not found), clear the stored ID
      if (error.message && error.message.includes('not found')) {
        console.warn('[SyncFromRemote] Remote not found (404), clearing stored ID');

        localStorage.removeItem('bmz_snippet_id');
        await safeStorage.remove('snippetId');
        this.snippetId = null;
        snippetAdapter.snippetId = null;

        // Emit event to notify UI that setup is needed
        this.emitEvent('syncError', {
          error: 'Remote storage not found. Please set up sync again.',
          requiresSetup: true
        });
      }

      return false;
    } finally {
      this.isSyncing = false;
    }
  }

  /**
   * Apply remote sync manually (after user confirmation)
   */
  async applyRemoteSync(remoteData) {
    try {
      // Save remote data to local
      await this.saveLocalBookmarks(remoteData);
      console.log('[ApplyRemoteSync] Saved remote data to local storage');

      await this.setLocalVersion(remoteData.version);
      console.log('[ApplyRemoteSync] Updated local version to:', remoteData.version);

      this.lastSyncTime = Date.now();
      await safeStorage.set({ lastSync: this.lastSyncTime });

      console.log('[ApplyRemoteSync] Manual sync applied successfully');
      this.emitEvent('syncSuccess', 'Bookmarks updated from remote');

      return true;
    } catch (error) {
      console.error('[ApplyRemoteSync] Failed to apply sync:', error);
      this.emitEvent('syncError', error.message);
      return false;
    }
  }

  /**
   * Calculate diff between local and remote bookmark trees
   */
  calculateBookmarkDiff(localTree, remoteTree) {
    const diff = {
      added: [],
      removed: [],
      moved: [],
      modified: []
    };

    // Create ID maps for quick lookup
    const localMap = new Map();
    const remoteMap = new Map();

    // Recursively map all items by ID
    const mapItems = (node, map, parentPath = '') => {
      if (!node) return;

      const path = parentPath ? `${parentPath}/${node.title || node.id}` : (node.title || node.id);
      map.set(node.id, { node, path, parentId: node.parentId });

      if (node.children) {
        node.children.forEach(child => mapItems(child, map, path));
      }
    };

    // Map local tree
    if (localTree?.roots) {
      Object.values(localTree.roots).forEach(root => mapItems(root, localMap));
    }

    // Map remote tree
    if (remoteTree?.roots) {
      Object.values(remoteTree.roots).forEach(root => mapItems(root, remoteMap));
    }

    // Find added items (in remote, not in local)
    remoteMap.forEach((value, id) => {
      if (!localMap.has(id)) {
        diff.added.push({
          id,
          title: value.node.title || 'Untitled',
          url: value.node.url || null,
          path: value.path,
          type: value.node.url ? 'bookmark' : 'folder'
        });
      }
    });

    // Find removed items (in local, not in remote)
    localMap.forEach((value, id) => {
      if (!remoteMap.has(id)) {
        diff.removed.push({
          id,
          title: value.node.title || 'Untitled',
          url: value.node.url || null,
          path: value.path,
          type: value.node.url ? 'bookmark' : 'folder'
        });
      }
    });

    // Find moved/modified items
    localMap.forEach((localValue, id) => {
      const remoteValue = remoteMap.get(id);
      if (remoteValue) {
        // Check if moved (parent changed)
        if (localValue.parentId !== remoteValue.parentId) {
          diff.moved.push({
            id,
            title: remoteValue.node.title || 'Untitled',
            url: remoteValue.node.url || null,
            oldPath: localValue.path,
            newPath: remoteValue.path,
            type: remoteValue.node.url ? 'bookmark' : 'folder'
          });
        }
        // Check if modified (title or url changed), ignoring case-only title differences
        const titleDiffers = (localValue.node.title || '').toLowerCase() !== (remoteValue.node.title || '').toLowerCase();
        const urlDiffers = localValue.node.url !== remoteValue.node.url;
        if (titleDiffers || urlDiffers) {
          diff.modified.push({
            id,
            oldTitle: localValue.node.title || 'Untitled',
            newTitle: remoteValue.node.title || 'Untitled',
            oldUrl: localValue.node.url || null,
            newUrl: remoteValue.node.url || null,
            path: remoteValue.path,
            type: remoteValue.node.url ? 'bookmark' : 'folder'
          });
        }
      }
    });

    return diff;
  }

  /**
   * Get local bookmarks
   */
  async getLocalBookmarks() {
    return await this.loadLocalBookmarks();
  }

  /**
   * Load bookmarks from local storage
   */
  async loadLocalBookmarks() {
    const bookmarksRecord = await safeStorage.get('bookmarkTree');
    const result = bookmarksRecord.bookmarkTree ? bookmarksRecord.bookmarkTree : this.getEmptyBookmarkTree();
    return result;
  }

  /**
   * Save bookmarks to local storage
   */
  async saveLocalBookmarks(bookmarkTree) {
    try {
      await safeStorage.set({ bookmarkTree });
    } catch (error) {
      console.error('[SyncManager.saveLocalBookmarks] Failed to save:', error);
      throw error;
    }
  }

  /**
   * Get local version number
   */
  async getLocalVersion() {
    const versionRecord = await safeStorage.get('localVersion');
    return versionRecord.localVersion || 0;
  }

  /**
   * Set local version number
   */
  async setLocalVersion(version) {
    await safeStorage.set({ localVersion: version });
  }

  /**
   * Get remote ID
   */
  getRemoteId() {
    return this.snippetId;
  }

  /**
   * Count total bookmarks in a tree
   */
  countBookmarksInTree(tree) {
    if (!tree || !tree.roots) return 0;

    let count = 0;
    const countInNode = (node) => {
      if (node.type === 'bookmark' || node.url) {
        count++;
      }
      if (node.children) {
        node.children.forEach(child => countInNode(child));
      }
    };

    Object.values(tree.roots).forEach(root => countInNode(root));
    return count;
  }

  /**
   * Get empty bookmark tree structure
   */
  getEmptyBookmarkTree() {
    return {
      version: 1,
      checksum: '',
      lastModified: Date.now(),
      roots: {
        bookmark_bar: {
          id: '1',
          title: 'Bookmarks Toolbar',
          name: 'Bookmarks Toolbar',
          type: 'folder',
          dateAdded: Date.now(),
          children: []
        },
        menu: {
          id: '2',
          title: 'Bookmarks Menu',
          name: 'Bookmarks Menu',
          type: 'folder',
          dateAdded: Date.now(),
          children: []
        },
        other: {
          id: '3',
          title: 'Other Bookmarks',
          name: 'Other Bookmarks',
          type: 'folder',
          dateAdded: Date.now(),
          children: []
        },
        mobile: {
          id: '4',
          title: 'Mobile Bookmarks',
          name: 'Mobile Bookmarks',
          type: 'folder',
          dateAdded: Date.now(),
          children: []
        }
      }
    };
  }

  /**
   * Manual sync trigger - bidirectional
   */
  async manualSync(forcePush = false) {
    if (this.isSyncing) {
      console.log('[ManualSync] Sync already in progress');
      return;
    }

    if (!navigator.onLine) {
      this.emitEvent('syncError', 'Cannot sync while offline');
      return;
    }

    const remoteId = this.getRemoteId();
    if (!remoteId) {
      this.emitEvent('syncError', 'No remote storage configured');
      return;
    }

    try {
      console.log(`[ManualSync] Starting (forcePush: ${forcePush}, hasUnsyncedChanges: ${this.hasUnsyncedChanges})`);

      // Push local changes first
      if (this.hasUnsyncedChanges || forcePush) {
        console.log('[ManualSync] Pushing local changes to remote...');
        await this.syncToRemote();
      }
      // Then pull remote changes
      const updated = await this.syncFromRemote();

      if (updated || this.hasUnsyncedChanges) {
        this.emitEvent('syncSuccess', 'Manual sync complete');
      } else {
        this.emitEvent('syncSuccess', 'Already up to date');
      }
    } catch (error) {
      console.error('Manual sync failed:', error);
      this.emitEvent('syncError', 'Manual sync failed: ' + error.message);
    }
  }

  /**
   * Emit custom events for UI updates
   */
  emitEvent(eventName, data = null) {
    const event = new CustomEvent(`sync:${eventName}`, { detail: data });
    window.dispatchEvent(event);
  }

  /**
   * Get sync status for UI
   */
  getSyncStatus() {
    return {
      isOnline: navigator.onLine,
      isSyncing: this.isSyncing,
      hasUnsyncedChanges: this.hasUnsyncedChanges,
      lastSyncTime: this.lastSyncTime,
      provider: this.provider,
      snippetId: this.snippetId,
      remoteId: this.getRemoteId(),
      deviceId: this.deviceId
    };
  }
}

// Create singleton instance
const syncManager = new SyncManager();

// ============================================================================
// POST-AUTHENTICATION FLOW - Adapted from website
// ============================================================================

/**
 * Initialize the Firefox extension with native bookmarks
 */
async function initFirefoxExtension() {
  console.log('[Firefox Extension] Initializing with native bookmarks...');

  // Load native Firefox bookmarks and show main UI immediately
  await loadBookmarksAndInit();
}

/**
 * Check if we have a snippet set up
 */
async function checkSnippetSetup() {
  // Check for saved snippet ID in localStorage
  const savedId = localStorage.getItem('bmz_snippet_id');
  if (savedId) {
    console.log('Found saved snippet ID:', savedId);
    // Try to use the saved ID directly
    try {
      await snippetAdapter.readBookmarks(savedId);
      snippetAdapter.snippetId = savedId;
      syncManager.setSnippetId(savedId);
      return true;
    } catch (err) {
      console.warn('Saved snippet ID is invalid, clearing:', err);
      localStorage.removeItem('bmz_snippet_id');
    }
  }

  // No valid saved ID found
  return false;
}

/**
 * Show authentication setup UI
 */
function showAuthSetup() {
  // Hide main content and show auth setup
  const mainContent = document.getElementById('mainContent');
  if (mainContent) {
    mainContent.style.display = 'none';
  }

  // Create auth setup modal
  const modal = document.createElement('div');
  modal.id = 'authSetupModal';
  modal.className = 'modal-overlay';
  modal.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: rgba(0, 0, 0, 0.6);
    backdrop-filter: blur(4px);
    z-index: 10001;
    display: flex;
    align-items: center;
    justify-content: center;
  `;

  modal.innerHTML = `
    <div style="
      background: var(--md-sys-color-surface);
      border-radius: 16px;
      padding: 24px;
      max-width: 400px;
      width: 90%;
      box-shadow: 0 8px 32px rgba(0,0,0,0.3);
      border: 1px solid var(--md-sys-color-outline);
    ">
      <h2 style="
        margin: 0 0 16px 0;
        color: var(--md-sys-color-primary);
        font-size: 20px;
        font-weight: 600;
        text-align: center;
      ">Connect to GitLab</h2>
      <p style="margin-bottom: 20px; color: var(--md-sys-color-on-surface); line-height: 1.5;">
        To sync your bookmarks across devices, connect your GitLab account. Your bookmarks will be stored securely in a private GitLab Snippet.
      </p>

      <div style="margin-bottom: 20px;">
        <label style="display: block; font-size: 14px; font-weight: 500; color: var(--md-sys-color-on-surface); margin-bottom: 8px;">
          GitLab Personal Access Token
        </label>
        <input type="password" id="gitlabTokenInput" placeholder="glpat-..." style="
          width: 100%;
          padding: 12px;
          border: 1px solid var(--md-sys-color-outline-variant);
          border-radius: 8px;
          background: var(--md-sys-color-surface-container);
          color: var(--md-sys-color-on-surface);
          font-size: 14px;
          box-sizing: border-box;
        ">
        <div style="margin-top: 8px; font-size: 12px; color: var(--md-sys-color-on-surface-variant); line-height: 1.4;">
          Create a token at <a href="https://gitlab.com/-/user_settings/personal_access_tokens" target="_blank" style="color: var(--md-sys-color-primary);">GitLab → User Settings → Access Tokens</a> with "api" scope.
        </div>
      </div>

      <div id="authError" style="display: none; margin-bottom: 16px; padding: 12px; background: var(--md-sys-color-error-container); color: var(--md-sys-color-on-error-container); border-radius: 8px; font-size: 14px;"></div>

      <div style="display: flex; gap: 12px;">
        <button id="connectGitlabBtn" style="
          flex: 1;
          background: var(--md-sys-color-primary);
          color: var(--md-sys-color-on-primary);
          border: none;
          padding: 12px 16px;
          border-radius: 8px;
          font-size: 14px;
          font-weight: 500;
          cursor: pointer;
          transition: background 0.2s;
        ">Connect GitLab</button>
        <button id="skipAuthBtn" style="
          background: var(--md-sys-color-surface-variant);
          color: var(--md-sys-color-on-surface-variant);
          border: none;
          padding: 12px 16px;
          border-radius: 8px;
          font-size: 14px;
          cursor: pointer;
          transition: background 0.2s;
        ">Use Local Only</button>
      </div>
    </div>
  `;

  document.body.appendChild(modal);

  // Set up event handlers
  const connectBtn = modal.querySelector('#connectGitlabBtn');
  const skipBtn = modal.querySelector('#skipAuthBtn');
  const tokenInput = modal.querySelector('#gitlabTokenInput');
  const errorDiv = modal.querySelector('#authError');

  // Handle Enter key in token input
  tokenInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
      connectBtn.click();
    }
  });

  // Connect button
  connectBtn.addEventListener('click', async () => {
    const token = tokenInput.value.trim();

    if (!token) {
      errorDiv.textContent = 'Please enter your Personal Access Token';
      errorDiv.style.display = 'block';
      return;
    }

    // Show loading state
    connectBtn.disabled = true;
    connectBtn.textContent = 'Connecting...';
    errorDiv.style.display = 'none';

    try {
      // Authenticate with token
      const authResult = await oauthPAT.authenticate(token);

      if (authResult === null) {
        // Authentication failed but user can retry
        connectBtn.disabled = false;
        connectBtn.textContent = 'Connect GitLab';
        return;
      }

      console.log(`Authenticated with GitLab:`, authResult.user.username);

      // Store token securely
      await authManager.storeToken(authResult.access_token, null, 'gitlab');

      // Store provider preference
      await authManager.storePreference('syncProvider', 'gitlab');

      // Close modal and initialize sync
      modal.remove();

      // Initialize sync manager and show snippet setup
      await syncManager.init();
      await showSnippetSetup();

    } catch (error) {
      console.error('Login failed:', error);
      errorDiv.textContent = error.message || 'Authentication failed. Please check your token and try again.';
      errorDiv.style.display = 'block';

      // Reset button
      connectBtn.disabled = false;
      connectBtn.textContent = 'Connect GitLab';
    }
  });

  // Skip button - use local only
  skipBtn.addEventListener('click', async () => {
    modal.remove();

    // Set local mode flag
    localStorage.setItem('bmz_local_mode', 'true');

    // Load bookmarks and initialize UI
    await loadBookmarksAndInit();
  });
}

/**
 * Show snippet setup modal
 */
async function showSnippetSetup() {
  const modal = document.createElement('div');
  modal.id = 'snippetSetupModal';
  modal.className = 'modal-overlay';
  modal.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: rgba(0, 0, 0, 0.6);
    backdrop-filter: blur(4px);
    z-index: 10001;
    display: flex;
    align-items: center;
    justify-content: center;
  `;

  modal.innerHTML = `
    <div style="
      background: var(--md-sys-color-surface);
      border-radius: 16px;
      padding: 24px;
      max-width: 500px;
      width: 90%;
      max-height: 80vh;
      overflow-y: auto;
      box-shadow: 0 8px 32px rgba(0,0,0,0.3);
      border: 1px solid var(--md-sys-color-outline);
    ">
      <h2 style="
        margin: 0 0 16px 0;
        color: var(--md-sys-color-primary);
        font-size: 20px;
        font-weight: 600;
        text-align: center;
      ">Set Up Bookmark Sync</h2>
      <p style="margin-bottom: 20px; color: var(--md-sys-color-on-surface); line-height: 1.5;">
        Your bookmarks will be stored in a private GitLab Snippet for syncing across devices.
      </p>

      <div id="snippetSetupContent">
        <div style="text-align: center; padding: 40px 20px;">
          <div style="font-size: 48px; margin-bottom: 12px; opacity: 0.5;">🔄</div>
          <div style="font-size: 14px; color: var(--md-sys-color-on-surface-variant);">Loading snippets...</div>
        </div>
      </div>

      <div id="snippetSetupError" style="display: none; margin-top: 16px; padding: 12px; background: var(--md-sys-color-error-container); color: var(--md-sys-color-on-error-container); border-radius: 8px; font-size: 14px;"></div>
    </div>
  `;

  document.body.appendChild(modal);

  try {
    // Get all user's snippets
    const snippets = await snippetAdapter.getAllSnippets();

    // Filter for bookmark-like items
    const bookmarkSnippets = snippets.filter(snippet =>
      snippet.title?.includes('BMZ') ||
      snippet.title?.includes('Bookmark Manager Zero') ||
      snippet.file_name === 'bookmarks.json'
    );

    const content = modal.querySelector('#snippetSetupContent');

    if (bookmarkSnippets.length === 0) {
      // No bookmark snippets found - show create option
      content.innerHTML = `
        <div style="text-align: center; padding: 20px 0;">
          <div style="font-size: 36px; margin-bottom: 12px;">📝</div>
          <p style="margin-bottom: 20px; color: var(--md-sys-color-on-surface-variant);">
            No bookmark snippets found. Create a new one to start syncing.
          </p>
          <button id="createSnippetBtn" style="
            background: var(--md-sys-color-primary);
            color: var(--md-sys-color-on-primary);
            border: none;
            padding: 12px 24px;
            border-radius: 8px;
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
            transition: background 0.2s;
          ">Create New Snippet</button>
        </div>
      `;

      modal.querySelector('#createSnippetBtn').addEventListener('click', async () => {
        try {
          const snippetId = await snippetAdapter.createBookmarkSnippet();
          await syncManager.setSnippetId(snippetId);
          modal.remove();
          await loadBookmarksAndInit();
        } catch (error) {
          console.error('Failed to create snippet:', error);
          const errorDiv = modal.querySelector('#snippetSetupError');
          errorDiv.textContent = 'Failed to create snippet: ' + error.message;
          errorDiv.style.display = 'block';
        }
      });

    } else if (bookmarkSnippets.length === 1) {
      // One bookmark snippet found - show use option
      const snippet = bookmarkSnippets[0];
      const fileCount = snippet.files?.length || 1;
      const lastUpdated = new Date(snippet.updated_at).toLocaleDateString();

      /* [ZeroLabs] 2026-08-19 7:12 PM - edited: heading and clearer alternative label */
      // The card previously appeared with no explanation of why. "Create New"
      // also failed to say new what, sitting beside "Use This Snippet".
      content.innerHTML = `
        <div style="padding: 20px 0;">
          <h3 style="margin: 0 0 12px 0; font-size: 15px; font-weight: 600; color: var(--md-sys-color-on-surface);">Found Existing Bookmark Snippet</h3>
          <div style="background: var(--md-sys-color-surface-variant); padding: 16px; border-radius: 8px; margin-bottom: 20px;">
            <div style="font-weight: 500; margin-bottom: 4px;">${escapeHtml(snippet.title || 'Untitled Snippet')}</div>
            <div style="font-size: 12px; color: var(--md-sys-color-on-surface-variant);">${fileCount} files • Updated ${lastUpdated}</div>
          </div>
          <div style="display: flex; gap: 12px;">
            <button id="useSnippetBtn" style="
              flex: 1;
              background: var(--md-sys-color-primary);
              color: var(--md-sys-color-on-primary);
              border: none;
              padding: 12px 16px;
              border-radius: 8px;
              font-size: 14px;
              font-weight: 500;
              cursor: pointer;
              transition: background 0.2s;
            ">Use This Snippet</button>
            <button id="createNewSnippetBtn" style="
              background: var(--md-sys-color-surface-variant);
              color: var(--md-sys-color-on-surface-variant);
              border: none;
              padding: 12px 16px;
              border-radius: 8px;
              font-size: 14px;
              cursor: pointer;
              transition: background 0.2s;
            ">Create New Snippet</button>
          </div>
        </div>
      `;

      modal.querySelector('#useSnippetBtn').addEventListener('click', async () => {
        try {
          await syncManager.setSnippetId(snippet.id);
          modal.remove();
          await loadBookmarksAndInit();
        } catch (error) {
          console.error('Failed to use snippet:', error);
          const errorDiv = modal.querySelector('#snippetSetupError');
          errorDiv.textContent = 'Failed to use snippet: ' + error.message;
          errorDiv.style.display = 'block';
        }
      });

      modal.querySelector('#createNewSnippetBtn').addEventListener('click', async () => {
        try {
          const snippetId = await snippetAdapter.createBookmarkSnippet();
          await syncManager.setSnippetId(snippetId);
          modal.remove();
          await loadBookmarksAndInit();
        } catch (error) {
          console.error('Failed to create snippet:', error);
          const errorDiv = modal.querySelector('#snippetSetupError');
          errorDiv.textContent = 'Failed to create snippet: ' + error.message;
          errorDiv.style.display = 'block';
        }
      });

    } else {
      // Multiple bookmark snippets - show selection
      let html = '<div style="padding: 20px 0;"><p style="margin-bottom: 16px; color: var(--md-sys-color-on-surface-variant);">Select a snippet to use:</p>';

      bookmarkSnippets.forEach(snippet => {
        const fileCount = snippet.files?.length || 1;
        const lastUpdated = new Date(snippet.updated_at).toLocaleDateString();

        html += `
          <div style="background: var(--md-sys-color-surface-variant); padding: 12px; border-radius: 8px; margin-bottom: 8px; cursor: pointer; border: 2px solid transparent; transition: border-color 0.2s;" data-snippet-id="${snippet.id}">
            <!-- [ZeroLabs] 2026-08-19 7:12 PM - edited: escape the snippet title -->
            <div style="font-weight: 500; margin-bottom: 4px;">${escapeHtml(snippet.title || 'Untitled Snippet')}</div>
            <div style="font-size: 12px; color: var(--md-sys-color-on-surface-variant);">${fileCount} files • Updated ${lastUpdated}</div>
          </div>
        `;
      });

      html += `
        <div style="margin-top: 20px; text-align: center;">
          <button id="createNewSnippetBtn" style="
            background: var(--md-sys-color-surface-variant);
            color: var(--md-sys-color-on-surface-variant);
            border: none;
            padding: 10px 16px;
            border-radius: 8px;
            font-size: 14px;
            cursor: pointer;
            transition: background 0.2s;
          ">Create New Snippet</button>
        </div>
      </div>`;

      content.innerHTML = html;

      // Add click handlers for snippet selection
      content.querySelectorAll('[data-snippet-id]').forEach(el => {
        el.addEventListener('click', async () => {
          const snippetId = el.getAttribute('data-snippet-id');
          try {
            await syncManager.setSnippetId(snippetId);
            modal.remove();
            await loadBookmarksAndInit();
          } catch (error) {
            console.error('Failed to use snippet:', error);
            const errorDiv = modal.querySelector('#snippetSetupError');
            errorDiv.textContent = 'Failed to use snippet: ' + error.message;
            errorDiv.style.display = 'block';
          }
        });
      });

      modal.querySelector('#createNewSnippetBtn').addEventListener('click', async () => {
        try {
          const snippetId = await snippetAdapter.createBookmarkSnippet();
          await syncManager.setSnippetId(snippetId);
          modal.remove();
          await loadBookmarksAndInit();
        } catch (error) {
          console.error('Failed to create snippet:', error);
          const errorDiv = modal.querySelector('#snippetSetupError');
          errorDiv.textContent = 'Failed to create snippet: ' + error.message;
          errorDiv.style.display = 'block';
        }
      });
    }

  } catch (error) {
    console.error('Failed to load snippets:', error);
    const content = modal.querySelector('#snippetSetupContent');
    content.innerHTML = `
      <div style="text-align: center; padding: 20px 0;">
        <div style="font-size: 36px; margin-bottom: 12px;">⚠️</div>
        <p style="margin-bottom: 20px; color: var(--md-sys-color-error);">
          Failed to load snippets: ${error.message}
        </p>
        <button id="retrySnippetSetup" style="
          background: var(--md-sys-color-primary);
          color: var(--md-sys-color-on-primary);
          border: none;
          padding: 10px 16px;
          border-radius: 8px;
          font-size: 14px;
          cursor: pointer;
        ">Retry</button>
      </div>
    `;

    modal.querySelector('#retrySnippetSetup').addEventListener('click', () => {
      modal.remove();
      showSnippetSetup();
    });
  }
}

/**
 * Show main application after authentication (adapted from website)
 */
async function showMainApp() {
  // Hide login screen
  const authSetupModal = document.getElementById('authSetupModal');
  if (authSetupModal) {
    authSetupModal.remove();
  }

  // Show main content
  const mainContent = document.getElementById('mainContent');
  if (mainContent) {
    mainContent.style.display = 'block';
  }

  // Initialize sync manager
  await syncManager.init();

  // Skip snippet setup and remote sync if in local mode
  const isLocalMode = localStorage.getItem('bmz_local_mode') === 'true';
  if (isLocalMode) {

    // Hide logout button in local mode
    const logoutBtn = document.getElementById('logoutBtn');
    if (logoutBtn) {
      logoutBtn.style.display = 'none';
    }

    // Show Connect GitLab button in header for local mode users
    const headerConnectGitlabBtn = document.getElementById('headerConnectGitlabBtn');
    if (headerConnectGitlabBtn) {
      headerConnectGitlabBtn.style.display = 'flex';
      headerConnectGitlabBtn.addEventListener('click', () => {
        showConnectGitlabModal();
      });
    }

    // Load bookmarks and initialize UI
    await loadBookmarksAndInit();
    return;
  }

  // Check if we have a snippet set up
  const hasSnippet = await checkSnippetSetup();

  if (!hasSnippet) {
    // Show snippet setup modal
    await showSnippetSetup();
    return;
  }

  // Sync from remote to ensure we have latest data
  // Prevent duplicate sync operations
  if (!syncInProgress) {
    syncInProgress = true;
    try {
      // Check if we already have the latest data from checkSnippetSetup()
      // We can check if local bookmarks are already loaded and match the remote
      const localBookmarks = await syncManager.loadLocalBookmarks();
      const hasLocalBookmarks = localBookmarks && localBookmarks.roots && Object.keys(localBookmarks.roots).length > 0;

      if (!hasLocalBookmarks) {
        await syncManager.syncFromRemote();
      }
    } catch (error) {
      console.warn('[App] Sync from remote failed, will use cached data:', error);
    } finally {
      syncInProgress = false;
    }
  }

  // Load bookmarks and initialize UI
  await loadBookmarksAndInit();
}

/**
 * Load bookmarks and initialize the main UI
 */
async function loadBookmarksAndInit() {
  try {
    // Load bookmarks from local storage or remote
    await loadBookmarks();

    // Initialize the main UI
    initMainUI();

    console.log('[App] Main app initialized successfully');
  } catch (error) {
    console.error('[App] Failed to load bookmarks:', error);
    showError('Failed to load bookmarks', error);
  }
}

// ============================================================================
// FIRST-TIME SETUP CARD
// ============================================================================
let hasSeenSetupCard = true; // Default to true, will be loaded from storage

// Load setup card flag from storage
async function loadSetupCardFlag() {
  /* [ZeroLabs] 2026-08-17 3:28 PM - added: suppress setup card in private mode */
  // safeStorage is memory-only in private windows, so a dismissal can never
  // persist there. Treat the card as already seen instead of re-showing it.
  if (isPrivateMode) {
    hasSeenSetupCard = true;
    return;
  }
  try {
    const result = await safeStorage.get('hasSeenSetupCard');
    hasSeenSetupCard = result.hasSeenSetupCard || false;
  } catch (error) {
    console.error('Error loading setup card flag:', error);
    hasSeenSetupCard = false;
  }
}

// Mark setup card as seen
async function dismissSetupCard() {
  hasSeenSetupCard = true;
  try {
    await safeStorage.set({ hasSeenSetupCard: true });
    renderBookmarks(); // Re-render to remove the card
  } catch (error) {
    console.error('Error saving setup card flag:', error);
  }
}

// ============================================================================
// V4.5 ANNOUNCEMENT CARD
// ============================================================================
/* [ZeroLabs] 2026-08-27 - edited: repurposed from the v4.5 card */
// One reusable "what's new" card rather than a new one per release. The storage
// key carries the DATE, so writing the next announcement means changing the key
// with it and the card reappears for everyone - including people who dismissed
// the last one. A fixed key would have to be renamed by hand, and forgetting
// would leave the new copy invisible to exactly the users who read the old one.
// A date also avoids a version number, which differs between the extensions and
// the website anyway.
const LATEST_CARD_KEY = 'bmz_latest_card_20260827';
let hasSeenLatestCard = true; // Default to true, will be loaded from storage

async function loadLatestCardFlag() {
  /* [ZeroLabs] 2026-08-17 3:28 PM - added: suppress announcement in private mode */
  // Same reason as the setup card: nothing persists in a private window.
  if (isPrivateMode) {
    hasSeenLatestCard = true;
    return;
  }
  try {
    const result = await safeStorage.get(LATEST_CARD_KEY);
    hasSeenLatestCard = result[LATEST_CARD_KEY] || false;
  } catch (error) {
    hasSeenLatestCard = false;
  }
}

async function dismissLatestCard() {
  hasSeenLatestCard = true;
  try {
    await safeStorage.set({ [LATEST_CARD_KEY]: true });
    renderBookmarks();
  } catch (error) {
    console.error('Error saving latest card flag:', error);
  }
}

// ============================================================================
// GLOBAL ERROR BOUNDARY
// ============================================================================

// Toast DOM elements
let successToast;
let successToastMessage;
let successDismiss;
let errorToast;
let errorTitle;
let errorMessage;
let errorReload;
let errorDismiss;

// Error log storage (keep last 50 errors)
const MAX_ERROR_LOGS = 50;

// Initialize toast elements after DOM loads
function initErrorToast() {
   // Success toast
   successToast = document.getElementById('successToast');
   successToastMessage = document.getElementById('successMessage');
   successDismiss = document.getElementById('successDismiss');

   if (successDismiss) {
      successDismiss.addEventListener('click', () => {
         hideSuccessToast();
      });
   }

   // Error toast
   errorToast = document.getElementById('errorToast');
   errorTitle = document.getElementById('errorTitle');
   errorMessage = document.getElementById('errorMessage');
   errorReload = document.getElementById('errorReload');
   errorDismiss = document.getElementById('errorDismiss');

   if (errorReload) {
      errorReload.addEventListener('click', () => {
         location.reload();
      });
   }

   if (errorDismiss) {
      errorDismiss.addEventListener('click', () => {
         hideErrorToast();
      });
   }
}

// Show error toast notification
function showErrorToast(title, message) {
  const fullMessage = title && message ? `${title}: ${message}` : (message || title);
  showToast(fullMessage, 'error', 10000);
}

// Hide error toast
function hideErrorToast() {
  // No-op for compatibility
}

// Show success toast notification
// New toast system - stacks from bottom
let toastContainer;
let toastIdCounter = 0;

function initToastSystem() {
  toastContainer = document.getElementById('toastContainer');
}

function showToast(message, type = 'success', duration = 5000) {
  if (!toastContainer) {
    initToastSystem();
  }

  const toastId = `toast-${toastIdCounter++}`;

  // Create toast element
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.id = toastId;

  // Icon based on type
  let icon = '';
  if (type === 'success') {
    icon = '<svg width="20" height="20" fill="currentColor" viewBox="0 0 24 24" style="flex-shrink: 0; color: var(--md-sys-color-success);"><path d="M12,2A10,10 0 0,1 22,12A10,10 0 0,1 12,22A10,10 0 0,1 2,12A10,10 0 0,1 12,2M12,4A8,8 0 0,0 4,12A8,8 0 0,0 12,20A8,8 0 0,0 20,12A8,8 0 0,0 12,4M11,16.5L6.5,12L7.91,10.59L11,13.67L16.59,8.09L18,9.5L11,16.5Z"/></svg>';
  } else if (type === 'error') {
    icon = '<svg width="20" height="20" fill="currentColor" viewBox="0 0 24 24" style="flex-shrink: 0; color: var(--md-sys-color-error);"><path d="M12,2L1,21H23M12,6L19.53,19H4.47M11,10V14H13V10M11,16V18H13V16"/></svg>';
  } else {
    icon = '<svg width="20" height="20" fill="currentColor" viewBox="0 0 24 24" style="flex-shrink: 0; color: var(--md-sys-color-primary);"><path d="M13,9H11V7H13M13,17H11V11H13M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2Z"/></svg>';
  }

  toast.innerHTML = `
    <div class="toast-content">
      ${icon}
      <div style="flex: 1;">
        <div style="font-weight: 600;">${message}</div>
      </div>
      <div class="toast-actions">
        <button class="toast-dismiss">×</button>
      </div>
    </div>
  `;

  // Add to container (inserts at bottom, pushes others up)
  toastContainer.appendChild(toast);

  // Add click listener to dismiss button
  const dismissBtn = toast.querySelector('.toast-dismiss');
  if (dismissBtn) {
    dismissBtn.addEventListener('click', () => removeToast(toastId));
  }

  // Auto-remove after duration
  if (duration > 0) {
    setTimeout(() => removeToast(toastId), duration);
  }

  return toastId;
}

function removeToast(toastId) {
  const toast = document.getElementById(toastId);
  if (!toast) return;

  toast.classList.add('removing');
  setTimeout(() => {
    if (toast.parentNode) {
      toast.parentNode.removeChild(toast);
    }
  }, 300); // Match animation duration
}

function showSuccessToast(message) {
  showToast(message, 'success');
}

function hideSuccessToast() {
  // No-op for compatibility
}

// Log error to browser storage
async function logError(error, context = '') {
  try {
    const errorLog = {
      timestamp: Date.now(),
      message: error.message || String(error),
      stack: error.stack || '',
      context: context,
      userAgent: navigator.userAgent,
      url: window.location.href
    };

    // Get existing error logs
    const result = await browser.storage.local.get('errorLogs');
    let errorLogs = result.errorLogs || [];

    // Add new error
    errorLogs.unshift(errorLog);

    // Keep only last 50 errors
    if (errorLogs.length > MAX_ERROR_LOGS) {
      errorLogs = errorLogs.slice(0, MAX_ERROR_LOGS);
    }

    // Save to storage
    await browser.storage.local.set({ errorLogs });
    console.error(`[Error Logged] ${context}:`, error);
  } catch (storageError) {
    console.error('Failed to log error to storage:', storageError);
  }
}

// Global error handler for synchronous errors
window.addEventListener('error', async (event) => {
  const error = event.error || new Error(event.message);

  console.error('Global error caught:', error);

  // Log error to storage
  await logError(error, 'Global Error');

  // Show user-friendly error message
  showErrorToast(
    'Unexpected Error',
    error.message || 'An unexpected error occurred. The extension will continue to work, but some features may not function correctly.'
  );

  // Prevent default browser error handling
  event.preventDefault();
});

// Global handler for unhandled promise rejections
window.addEventListener('unhandledrejection', async (event) => {
  const error = event.reason instanceof Error ? event.reason : new Error(String(event.reason));

  console.error('Unhandled promise rejection:', error);

  // Log error to storage
  await logError(error, 'Unhandled Promise Rejection');

  // Show user-friendly error message
  showErrorToast(
    'Promise Error',
    error.message || 'An operation failed unexpectedly. Please try again.'
  );

  // Prevent default browser error handling
  event.preventDefault();
});

// Initialize error toast when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initErrorToast);
} else {
  initErrorToast();
}

// ============================================================================
// PRIVATE BROWSING MODE DETECTION & HANDLING
// ============================================================================

// Detect if we're in private/incognito mode
const isPrivateMode = browser.extension.inIncognitoContext;

// Session-only storage for private mode (cleared when window closes)
const privateSessionStorage = new Map();

// Privacy-respecting storage wrapper
const safeStorage = {
  async get(keys) {
    if (isPrivateMode) {
      // In private mode, use session storage only
      if (typeof keys === 'string') {
        return { [keys]: privateSessionStorage.get(keys) };
      } else if (Array.isArray(keys)) {
        const result = {};
        keys.forEach(key => {
          result[key] = privateSessionStorage.get(key);
        });
        return result;
      }
      return {};
    }
    // Normal mode: use browser.storage.local
    return await browser.storage.local.get(keys);
  },

  async set(items) {
    if (isPrivateMode) {
      // In private mode, store in session storage only (memory)
      Object.entries(items).forEach(([key, value]) => {
        privateSessionStorage.set(key, value);
      });
      console.log('[Private Mode] Data stored in session memory only (will not persist)');
      return;
    }
    // Normal mode: use browser.storage.local
    return await browser.storage.local.set(items);
  },

  async remove(keys) {
    if (isPrivateMode) {
      const keysArray = Array.isArray(keys) ? keys : [keys];
      keysArray.forEach(key => privateSessionStorage.delete(key));
      return;
    }
    return await browser.storage.local.remove(keys);
  }
};

// Show private mode indicator in UI
function showPrivateModeIndicator() {
  if (!isPrivateMode) return;

  const header = document.querySelector('.header');
  if (!header) return;

  const indicator = document.createElement('div');
  indicator.className = 'private-mode-indicator';
  indicator.innerHTML = `
    <svg width="14" height="14" fill="currentColor" viewBox="0 0 24 24" style="vertical-align: middle; margin-right: 4px;">
      <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z"/>
    </svg>
    <span style="font-size: 11px; font-weight: 500;">Private Mode</span>
  `;
  indicator.style.cssText = `
    display: flex;
    align-items: center;
    padding: 4px 12px;
    background: var(--md-sys-color-secondary-container, rgba(208, 188, 255, 0.2));
    color: var(--md-sys-color-on-secondary-container, #d0bcff);
    border-radius: 12px;
    font-size: 11px;
    margin-left: 8px;
  `;
  indicator.title = 'Private browsing mode: No data will be saved to disk';

  // Insert after logo
  const logo = header.querySelector('.logo');
  if (logo && logo.parentElement) {
    logo.parentElement.insertBefore(indicator, logo.nextSibling);
  }
}

// ============================================================================
// ENCRYPTION UTILITIES
// ============================================================================

// Encryption utilities inlined to avoid module loading issues
async function getDerivedKey() {
  // Use extension ID and browser info for key derivation (consistent with background.js)
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

async function encryptApiKey(plaintext) {
  if (!plaintext) return null;
  try {
    const key = await getDerivedKey();
    const encoder = new TextEncoder();
    const data = encoder.encode(plaintext);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      data
    );
    const combined = new Uint8Array(iv.length + encrypted.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(encrypted), iv.length);
    return btoa(Array.from(combined, b => String.fromCharCode(b)).join(''));
  } catch (error) {
    console.error('Encryption failed:', error);
    return null;
  }
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

async function storeEncryptedApiKey(keyName, apiKey) {
  const encrypted = await encryptApiKey(apiKey);
  if (encrypted) {
    await safeStorage.set({ [keyName]: encrypted });
    return true;
  }
  return false;
}

async function getDecryptedApiKey(keyName) {
  const result = await safeStorage.get(keyName);
  if (result[keyName]) {
    return await decryptApiKey(result[keyName]);
  }
  return null;
}

// ============================================================================
// CHANGELOG UTILITIES
// ============================================================================

// Maximum number of changelog entries to keep
const MAX_CHANGELOG_ENTRIES = 1000;

// Add an entry to the changelog
async function addChangelogEntry(type, itemType, title, url = null, details = {}) {
  try {
    const result = await safeStorage.get('changelogEntries');
    let changelogEntries = result.changelogEntries || [];

    const entry = {
      id: Date.now(),
      type, // 'create', 'update', 'move', 'delete'
      itemType, // 'bookmark', 'folder'
      timestamp: Date.now(),
      title,
      url,
      details
    };

    // Add new entry at the beginning (most recent first)
    changelogEntries.unshift(entry);

    // Keep only the latest entries
    if (changelogEntries.length > MAX_CHANGELOG_ENTRIES) {
      changelogEntries = changelogEntries.slice(0, MAX_CHANGELOG_ENTRIES);
    }

    await safeStorage.set({ changelogEntries });
    console.log('[Changelog] Added entry:', entry);
  } catch (error) {
    console.error('[Changelog] Failed to add entry:', error);
  }
}

// Get all changelog entries
async function getChangelogEntries() {
  try {
    const result = await safeStorage.get('changelogEntries');
    return result.changelogEntries || [];
  } catch (error) {
    console.error('[Changelog] Failed to get entries:', error);
    return [];
  }
}

// Clear all changelog entries
async function clearChangelog() {
  try {
    await safeStorage.set({ changelogEntries: [] });
    console.log('[Changelog] Cleared all entries');
  } catch (error) {
    console.error('[Changelog] Failed to clear entries:', error);
  }
}

// Get folder path for a bookmark/folder
async function getFolderPath(itemId) {
  try {
    if (!itemId) return 'Root';
    
    const path = [];
    let currentId = itemId;

    while (currentId) {
      const items = await browser.bookmarks.get(currentId);
      if (!items || items.length === 0) break;

      const item = items[0];
      if (item.title) {
        path.unshift(item.title);
      }
      
      if (!item.parentId) break;
      currentId = item.parentId;
    }

    return path.length > 0 ? path.join(' > ') : 'Root';
  } catch (error) {
    return 'Unknown';
  }
}

async function getFolderName(folderId) {
  try {
    if (!folderId) return 'Root';
    
    const items = await browser.bookmarks.get(folderId);
    if (!items || items.length === 0) return 'Unknown';
    
    const folder = items[0];
    return folder.title || 'Unnamed Folder';
  } catch (error) {
    return 'Unknown';
  }
}

// Focus trap utility for modal accessibility
let previouslyFocusedElement = null;
let focusTrapListener = null;

function trapFocus(modal) {
  // Store the element that had focus before modal opened
  previouslyFocusedElement = document.activeElement;

  // Get all focusable elements in modal
  const getFocusableElements = () => {
    return Array.from(modal.querySelectorAll(
      'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"]):not([disabled])'
    ));
  };

  // Focus first element
  const focusableElements = getFocusableElements();
  if (focusableElements.length > 0) {
    focusableElements[0].focus();
  }

  // Remove previous listener if exists
  if (focusTrapListener) {
    document.removeEventListener('keydown', focusTrapListener);
  }

  // Add focus trap listener
  focusTrapListener = (e) => {
    if (e.key !== 'Tab') return;

    const focusableElements = getFocusableElements();
    if (focusableElements.length === 0) return;

    const firstElement = focusableElements[0];
    const lastElement = focusableElements[focusableElements.length - 1];

    if (e.shiftKey) {
      // Shift + Tab: moving backwards
      if (document.activeElement === firstElement) {
        e.preventDefault();
        lastElement.focus();
      }
    } else {
      // Tab: moving forwards
      if (document.activeElement === lastElement) {
        e.preventDefault();
        firstElement.focus();
      }
    }
  };

  document.addEventListener('keydown', focusTrapListener);
}

function releaseFocusTrap() {
  // Remove focus trap listener
  if (focusTrapListener) {
    document.removeEventListener('keydown', focusTrapListener);
    focusTrapListener = null;
  }

  // Restore focus to previously focused element
  if (previouslyFocusedElement && previouslyFocusedElement.focus) {
    previouslyFocusedElement.focus();
    previouslyFocusedElement = null;
  }
}

// State
let bookmarkTree = [];
let searchTerm = '';
let activeFilters = [];
let expandedFolders = new Set();
let folderScanTimestamps = {}; // Track when each folder was last scanned
const FOLDER_SCAN_CACHE_DURATION = 7 * 24 * 60 * 60 * 1000; // 7 days in milliseconds
let syncInProgress = false; // Track sync operations to prevent duplicates
let theme = 'enhanced-blue';
let viewMode = 'list';
/* [ZeroLabs] 2026-08-17 4:15 PM - edited: added quickAccess/recent display flags */
let displayOptions = {
  title: true,
  url: true,
  liveStatus: true,
  safetyStatus: true,
  preview: true,
  favicon: true,
  quickAccess: true,
  recent: true
};

/* [ZeroLabs] 2026-08-17 4:15 PM - added: quick access and recently opened state */
// ============================================================================
// QUICK ACCESS & RECENTLY OPENED
// ============================================================================
// A pin is a URL, never a bookmark id. Firefox ids are profile-local GUIDs and
// a pull-from-snippet deletes and recreates every bookmark, so ids change. URLs
// survive, and resolving them against the live tree at render time is what makes
// "delete the bookmark, the pin disappears" work with no extra bookkeeping.

const QUICK_ACCESS_KEY = 'bmz_quick_access';
const RECENT_OPENS_KEY = 'bmz_recent_opens';
const SECTION_STATE_KEY = 'bmz_section_state';
const DISPLAY_SECTIONS_KEY = 'bmz_display_sections';
const RECENT_OPENS_LIMIT = 5;

let quickAccessPins = [];        // [{ url, title, pinnedAt }] - display order
let quickAccessTombstones = [];  // [{ url, removedAt }] - so unpins survive a merge
let quickAccessSnippetTag = null; // Which snippet these pins belong to (null = local only)
let quickAccessMetaLoaded = false; // True once bmz-meta.json has been read for the current snippet
let recentOpens = [];            // [{ url, openedAt }] - device local, never synced
// The two sections share one row and behave as an accordion: at most one open.
let activeSection = 'quickAccess'; // 'quickAccess' | 'recent' | null (both closed)

// Normalize a URL for identity comparison. Scheme and host are case-insensitive,
// a lone trailing slash is noise, everything else is significant.
function normalizeUrlKey(url) {
  if (!url) return '';
  try {
    const u = new URL(url);
    const base = `${u.protocol}//${u.host.toLowerCase()}${u.pathname}${u.search}${u.hash}`;
    return base.replace(/\/$/, '');
  } catch (error) {
    return String(url).trim();
  }
}

// Map every bookmark in the live tree by normalized URL. First match wins, so a
// URL bookmarked in two folders resolves to one Quick Access row.
function buildUrlIndex() {
  const index = new Map();
  const walk = (nodes) => {
    if (!Array.isArray(nodes)) return;
    for (const node of nodes) {
      if (node.url) {
        const key = normalizeUrlKey(node.url);
        if (key && !index.has(key)) index.set(key, node);
      } else if (node.children) {
        walk(node.children);
      }
    }
  };
  walk(bookmarkTree);
  return index;
}

async function loadQuickAccess() {
  try {
    const result = await safeStorage.get(QUICK_ACCESS_KEY);
    const stored = result[QUICK_ACCESS_KEY];
    if (stored && typeof stored === 'object') {
      quickAccessPins = Array.isArray(stored.pins) ? stored.pins : [];
      quickAccessTombstones = Array.isArray(stored.tombstones) ? stored.tombstones : [];
      quickAccessSnippetTag = stored.snippetId || null;
    } else {
      quickAccessPins = [];
      quickAccessTombstones = [];
      quickAccessSnippetTag = null;
    }
  } catch (error) {
    console.error('Error loading quick access:', error);
    quickAccessPins = [];
    quickAccessTombstones = [];
    quickAccessSnippetTag = null;
  }
}

async function saveQuickAccess() {
  try {
    await safeStorage.set({
      [QUICK_ACCESS_KEY]: {
        snippetId: quickAccessSnippetTag,
        pins: quickAccessPins,
        tombstones: quickAccessTombstones
      }
    });
  } catch (error) {
    console.error('Error saving quick access:', error);
  }
}

async function loadRecentOpens() {
  try {
    const result = await safeStorage.get(RECENT_OPENS_KEY);
    recentOpens = Array.isArray(result[RECENT_OPENS_KEY]) ? result[RECENT_OPENS_KEY] : [];
  } catch (error) {
    console.error('Error loading recent opens:', error);
    recentOpens = [];
  }
}

async function saveRecentOpens() {
  try {
    await safeStorage.set({ [RECENT_OPENS_KEY]: recentOpens });
  } catch (error) {
    console.error('Error saving recent opens:', error);
  }
}

async function loadSectionState() {
  try {
    const result = await safeStorage.get(SECTION_STATE_KEY);
    const stored = result[SECTION_STATE_KEY];
    if (stored && typeof stored === 'object' && 'active' in stored) {
      const valid = ['quickAccess', 'recent', null];
      activeSection = valid.includes(stored.active) ? stored.active : 'quickAccess';
    }
  } catch (error) {
    console.error('Error loading section state:', error);
  }
}

async function saveSectionState() {
  try {
    await safeStorage.set({ [SECTION_STATE_KEY]: { active: activeSection } });
  } catch (error) {
    console.error('Error saving section state:', error);
  }
}

// The six pre-existing display options have never been persisted and still are
// not; only the two new section toggles are, so they survive a sidebar reopen.
async function loadDisplaySections() {
  try {
    const result = await safeStorage.get(DISPLAY_SECTIONS_KEY);
    const stored = result[DISPLAY_SECTIONS_KEY];
    if (stored && typeof stored === 'object') {
      displayOptions.quickAccess = stored.quickAccess !== false;
      displayOptions.recent = stored.recent !== false;
    }
  } catch (error) {
    console.error('Error loading display sections:', error);
  }
}

async function saveDisplaySections() {
  try {
    await safeStorage.set({
      [DISPLAY_SECTIONS_KEY]: {
        quickAccess: displayOptions.quickAccess,
        recent: displayOptions.recent
      }
    });
  } catch (error) {
    console.error('Error saving display sections:', error);
  }
}

function isPinned(url) {
  const key = normalizeUrlKey(url);
  if (!key) return false;
  return quickAccessPins.some(pin => normalizeUrlKey(pin.url) === key);
}

async function pinBookmark(bookmark) {
  if (!bookmark || !bookmark.url) return;
  const key = normalizeUrlKey(bookmark.url);
  if (!key || isPinned(bookmark.url)) return;

  quickAccessPins.push({
    url: bookmark.url,
    title: bookmark.title || bookmark.url,
    pinnedAt: Date.now()
  });
  // Re-pinning clears any tombstone, otherwise a merge would delete it again.
  quickAccessTombstones = quickAccessTombstones.filter(t => normalizeUrlKey(t.url) !== key);

  await saveQuickAccess();
  markQuickAccessChanged();
  renderBookmarks();
}

// Unpin only. This never touches the underlying bookmark.
async function unpinUrl(url) {
  const key = normalizeUrlKey(url);
  if (!key) return;
  const before = quickAccessPins.length;
  quickAccessPins = quickAccessPins.filter(pin => normalizeUrlKey(pin.url) !== key);
  if (quickAccessPins.length === before) return;

  quickAccessTombstones = quickAccessTombstones.filter(t => normalizeUrlKey(t.url) !== key);
  quickAccessTombstones.push({ url, removedAt: Date.now() });

  await saveQuickAccess();
  markQuickAccessChanged();
  renderBookmarks();
}

async function reorderQuickAccess(fromKey, toKey, dropBefore) {
  const fromIndex = quickAccessPins.findIndex(p => normalizeUrlKey(p.url) === fromKey);
  const toIndex = quickAccessPins.findIndex(p => normalizeUrlKey(p.url) === toKey);
  if (fromIndex === -1 || toIndex === -1 || fromIndex === toIndex) return;

  const [moved] = quickAccessPins.splice(fromIndex, 1);
  // Removing the source first shifts every later index down by one.
  let insertAt = quickAccessPins.findIndex(p => normalizeUrlKey(p.url) === toKey);
  if (!dropBefore) insertAt += 1;
  quickAccessPins.splice(insertAt, 0, moved);

  await saveQuickAccess();
  markQuickAccessChanged();
  renderBookmarks();
}

async function recordRecentOpen(url) {
  if (!url) return;
  const key = normalizeUrlKey(url);
  if (!key) return;

  // Opening the same bookmark twice in a row must not produce two rows.
  recentOpens = recentOpens.filter(entry => normalizeUrlKey(entry.url) !== key);
  recentOpens.unshift({ url, openedAt: Date.now() });
  if (recentOpens.length > RECENT_OPENS_LIMIT) {
    recentOpens = recentOpens.slice(0, RECENT_OPENS_LIMIT);
  }

  await saveRecentOpens();
  if (displayOptions.recent) renderBookmarks();
}

// Resolve pins against the live tree, dropping any whose bookmark is gone. This
// is what removes a pin when the bookmark is deleted, including deletions made
// in Firefox's own bookmark manager rather than in BMZ.
/* [ZeroLabs] 2026-08-17 4:15 PM - edited: resolve never deletes stored pins */
// Deliberately does NOT prune. A pin whose bookmark is missing is simply not
// rendered, which is what makes it vanish when you delete the bookmark. Deleting
// the stored entry here was destroying pins during a sync: a pull resolves pins
// against the OLD tree, before the incoming bookmarks have been written, so
// every pin looked dead for that window and got erased permanently.
function resolveQuickAccess() {
  const index = buildUrlIndex();
  const resolved = [];

  for (const pin of quickAccessPins) {
    const node = index.get(normalizeUrlKey(pin.url));
    if (node) resolved.push(node);
  }

  return resolved;
}

/* [ZeroLabs] 2026-08-17 4:15 PM - added: quick access merge for sync */
const TOMBSTONE_MAX_AGE = 90 * 24 * 60 * 60 * 1000; // 90 days

// Merge a remote pin list into the local one. Tombstones are what make an unpin
// stick: without them the other device's copy of the pin simply reappears on the
// next pull. A tombstone wins only if it is newer than the pin it shadows.
function mergeQuickAccess(remotePins, remoteTombstones) {
  const tombstones = new Map();
  const addTombstone = (entry) => {
    if (!entry || !entry.url) return;
    const key = normalizeUrlKey(entry.url);
    const existing = tombstones.get(key);
    if (!existing || (entry.removedAt || 0) > (existing.removedAt || 0)) {
      tombstones.set(key, { url: entry.url, removedAt: entry.removedAt || 0 });
    }
  };
  quickAccessTombstones.forEach(addTombstone);
  (remoteTombstones || []).forEach(addTombstone);

  const pins = new Map();
  const addPin = (pin) => {
    if (!pin || !pin.url) return;
    const key = normalizeUrlKey(pin.url);
    const existing = pins.get(key);
    // Earliest pin time wins so the entry keeps its original position intent.
    if (!existing || (pin.pinnedAt || 0) < (existing.pinnedAt || 0)) {
      pins.set(key, { url: pin.url, title: pin.title || pin.url, pinnedAt: pin.pinnedAt || Date.now() });
    }
  };
  // Local order first so this device's arrangement survives the merge.
  quickAccessPins.forEach(addPin);
  (remotePins || []).forEach(addPin);

  const merged = [];
  for (const [key, pin] of pins) {
    const tomb = tombstones.get(key);
    if (tomb && (tomb.removedAt || 0) > (pin.pinnedAt || 0)) continue; // Unpinned later than pinned
    merged.push(pin);
    tombstones.delete(key); // Pin outlived the tombstone, drop the tombstone
  }

  const cutoff = Date.now() - TOMBSTONE_MAX_AGE;
  quickAccessPins = merged;
  quickAccessTombstones = Array.from(tombstones.values()).filter(t => (t.removedAt || 0) > cutoff);
}

// Same rule as the pins: skip what cannot be resolved, never delete it.
function resolveRecentOpens() {
  const index = buildUrlIndex();
  const resolved = [];

  for (const entry of recentOpens) {
    const node = index.get(normalizeUrlKey(entry.url));
    if (node) resolved.push(node);
  }

  return resolved;
}
let currentEditItem = null;
let zoomLevel = 80;
let fontSize = 100; // Font size for bookmark/folder text (70-150%)
let guiScale = 100; // GUI scale for header, toolbar, and filter elements
let customBackgroundImage = null; // Custom background image data
let backgroundPosition = { x: 50, y: 50 }; // Background image position (%)
let backgroundScale = 100; // Background image scale (%)
let checkedBookmarks = new Set(); // Track which bookmarks have been checked to prevent infinite loops
let scanCancelled = false; // Flag to cancel ongoing scans
/* [ZeroLabs] 2026-06-20 12:21 AM - added: single-source scan control state */
let autoScanDepth = 0; // Re-entrancy count for front-end autoCheck loops
/* [ZeroLabs] 2026-08-28 - added: one counter across overlapping auto-checks */
// autoCheckBookmarkStatuses runs once per folder expansion and can overlap
// itself - that is what autoScanDepth tracks. Each invocation used to keep its
// OWN scannedCount and totalToScan while writing to the single 'auto-check'
// status, so the bar flipped between two unrelated tallies ("3/10", "1/4",
// "4/10") and looked like it was jumping around rather than counting up.
// Shared here so overlapping scans report as one coherent total, and reset when
// the last of them finishes.
let autoScanTotal = 0;
let autoScanDone = 0;
let backgroundScanActive = false; // Whether the worker scan is running
// One owner for the Stop/Rescan buttons: Stop visible iff any scan is active
function updateScanControls() {
  const stopBtn = document.getElementById('stopScanBtn');
  const rescanBtn = document.getElementById('rescanAllBtn');
  const active = autoScanDepth > 0 || backgroundScanActive;
  if (stopBtn) stopBtn.style.display = active ? 'flex' : 'none';
  if (rescanBtn) rescanBtn.style.display = active ? 'none' : 'flex';
}
// Cancel every scan engine: front-end loops (via flag) and the worker (via message)
async function cancelAllScans() {
  scanCancelled = true;
  try {
    await browser.runtime.sendMessage({ action: 'stopScan' });
  } catch (error) {
    console.error('Error stopping background scan:', error);
  }
}
let linkCheckingEnabled = true; // Toggle for link checking
let safetyCheckingEnabled = true; // Toggle for safety checking
let whitelistedUrls = new Set(); // URLs whitelisted by user
let safetyHistory = {}; // Track safety status changes over time {url: [{timestamp, status, sources}]}
let selectedBookmarkIndex = -1; // Currently selected bookmark for keyboard navigation
let visibleBookmarks = []; // Flat list of visible bookmarks for keyboard navigation
let multiSelectMode = false; // Toggle for multi-select mode
let selectedItems = new Set(); // IDs of selected bookmarks/folders
let startFolderId = null; // Default folder to open when sidebar loads (null = root)

// Track open menus to preserve state across re-renders
let openMenuBookmarkId = null;

// Track which bookmarks have loaded previews (persists across re-renders)
let loadedPreviews = new Set();

// Undo system state
let undoData = null;
let undoTimer = null;
let undoCountdown = null;

// DOM Elements
const bookmarkList = document.getElementById('bookmarkList');
const searchInput = document.getElementById('searchInput');
const filterToggle = document.getElementById('filterToggle');
const filterBar = document.getElementById('filterBar');
const displayToggle = document.getElementById('displayToggle');
const displayBar = document.getElementById('displayBar');
const qrCodeBtn = document.getElementById('qrCodeBtn');
const themeBtn = document.getElementById('themeBtn');
const headerCollapseBtn = document.getElementById('headerCollapseBtn');
const collapsibleHeader = document.getElementById('collapsibleHeader');
const themeMenu = document.getElementById('themeMenu');
const viewBtn = document.getElementById('viewBtn');
const viewMenu = document.getElementById('viewMenu');
const zoomBtn = document.getElementById('zoomBtn');
const zoomMenu = document.getElementById('zoomMenu');
const zoomSlider = document.getElementById('zoomSlider');
const zoomValue = document.getElementById('zoomValue');
const fontSizeSlider = document.getElementById('fontSizeSlider');
const fontSizeValue = document.getElementById('fontSizeValue');
const settingsBtn = document.getElementById('settingsBtn');
const settingsMenu = document.getElementById('settingsMenu');
const openInTabBtn = document.getElementById('openInTabBtn');
const exportBookmarksBtn = document.getElementById('exportBookmarksBtn');
const closeExtensionBtn = document.getElementById('closeExtensionBtn');
const clearCacheBtn = document.getElementById('clearCacheBtn');
const autoClearCacheSelect = document.getElementById('autoClearCache');
const setApiKeyBtn = document.getElementById('setApiKeyBtn');
const accentColorPicker = document.getElementById('accentColorPicker');
const resetAccentColorBtn = document.getElementById('resetAccentColor');
const backgroundImagePicker = document.getElementById('backgroundImagePicker');
const chooseBackgroundImageBtn = document.getElementById('chooseBackgroundImage');
const removeBackgroundImageBtn = document.getElementById('removeBackgroundImage');
const backgroundOpacitySlider = document.getElementById('backgroundOpacity');
const backgroundBlurSlider = document.getElementById('backgroundBlur');
const backgroundSizeSelect = document.getElementById('backgroundSize');
const repositionBackgroundBtn = document.getElementById('repositionBackground');
const backgroundScaleSlider = document.getElementById('backgroundScale');
const dragModeOverlay = document.getElementById('dragModeOverlay');
const closeDragModeBtn = document.getElementById('closeDragModeBtn');
const opacityValue = document.getElementById('opacityValue');
const blurValue = document.getElementById('blurValue');
const scaleValue = document.getElementById('scaleValue');
const containerOpacitySlider = document.getElementById('containerOpacity');
const containerOpacityValue = document.getElementById('containerOpacityValue');
const textColorPicker = document.getElementById('textColorPicker');
const resetTextColorBtn = document.getElementById('resetTextColor');
const guiScaleSelect = document.getElementById('guiScaleSelect');
const startFolderSelect = document.getElementById('startFolderSelect');

// Undo toast DOM elements
const undoToast = document.getElementById('undoToast');
const undoMessage = document.getElementById('undoMessage');
const undoButton = document.getElementById('undoButton');
const undoCountdownEl = document.getElementById('undoCountdown');
const undoDismiss = document.getElementById('undoDismiss');

// Scan status bar DOM elements
const rescanAllBtn = document.getElementById('rescanAllBtn');
const scanStatusBar = document.getElementById('scanStatusBar');
const scanProgress = document.getElementById('scanProgress');
const totalCount = document.getElementById('totalCount');

// ============================================================================
// CENTRALIZED STATUS MANAGEMENT
// ============================================================================
/* [ZeroLabs] 2026-08-28 - added: one owner for the scan status bar */
// Ported from sidepanel.js, where it is proven. Five separate functions here
// wrote scanProgress.textContent and toggled .scanning by hand, so whichever
// finished last won regardless of what was still running: a blocklist download
// completing mid-scan blanked the scan's progress, and the blocklistComplete
// handler ended up testing for the .scanning class IT had set itself, matched,
// skipped its own reset, and left the bar frozen on "Downloading blocklists...
// (10/10)" with nothing left to clear it.
//
// Every operation now registers by id and the bar is derived from what is still
// active, so no function can decide on its own that the bar should read Ready.
//
// TOP LEVEL on purpose: rescanFolder and the message handlers live inside
// setupEventListeners, and inner scope can reach out to here but never the
// reverse - the same trap that broke showHeldPushDialog and recordLocalDeletion.
let activeOperations = new Set(); // Set of active operation IDs
let operationDetails = new Map(); // Map of operation ID to its current message

// Named so an id cannot drift between its set and clear calls
const RESCAN_ALL_OP = 'rescan-all';
const RESCAN_FOLDER_OP = 'rescan-folder';

function setScanningStatus(operationId, message) {
  activeOperations.add(operationId);
  operationDetails.set(operationId, message);

  /* [ZeroLabs] 2026-08-28 - fixed: two operations fought over the bar */
  // This wrote `message` straight to the bar, so whichever operation called most
  // recently won. With two running at once - an auto-check alongside a
  // background scan, or a full rescan - the display alternated between their two
  // counters and appeared to jump around instead of counting up.
  //
  // The operation's message is recorded above; updateStatusBar picks which one is
  // shown, and it picks the same one every time (the most recently STARTED, by
  // Set insertion order, which re-adding an existing id does not disturb).
  updateStatusBar();
}

function clearScanningStatus(operationId) {
  if (activeOperations.has(operationId)) {
    activeOperations.delete(operationId);
    operationDetails.delete(operationId);
    updateStatusBar();
  }
}

// The single place that decides what the bar says
function updateStatusBar() {
  if (activeOperations.size === 0) {
    if (scanStatusBar) scanStatusBar.classList.remove('scanning');
    if (scanProgress) scanProgress.textContent = 'Ready';
    return;
  }

  // Show the most recently started operation
  if (scanStatusBar) scanStatusBar.classList.add('scanning');
  const remaining = Array.from(activeOperations);
  const current = operationDetails.get(remaining[remaining.length - 1]);
  if (scanProgress && current) scanProgress.textContent = current;
}

// Load folder scan timestamps from storage
async function loadFolderScanTimestamps() {
  try{
    const result = await browser.storage.local.get('folderScanTimestamps');
    if (result.folderScanTimestamps) {
      folderScanTimestamps = result.folderScanTimestamps;
    }
  } catch (error) {
    console.error('[Folder Scan Cache] Error loading timestamps:', error);
  }
}

// Save folder scan timestamp for a folder
async function saveFolderScanTimestamp(folderId) {
  try {
    folderScanTimestamps[folderId] = Date.now();
    await browser.storage.local.set({ folderScanTimestamps });
  } catch (error) {
    console.error('[Folder Scan Cache] Error saving timestamp:', error);
  }
}

/* [ZeroLabs] 2026-08-28 - added: a timestamp is not proof that results exist */
// The tree is the right place to look. restoreCachedBookmarkStatuses() hydrates
// every node from linkStatusCache/safetyStatusCache at load, so by the time a
// folder is expanded any surviving cached status is already sitting on its
// nodes. If not one bookmark in the folder carries a status, there is genuinely
// nothing cached and nothing to show.
//
// A folder holding no bookmarks at all returns true: there is nothing to scan
// either way, and answering false would rescan empty folders on every expansion.
function folderHasCachedStatuses(folderId) {
  const folder = findFolderById(bookmarkTree, folderId);
  if (!folder) return false;

  let sawBookmark = false;
  let sawStatus = false;

  const walk = (nodes) => {
    if (!Array.isArray(nodes) || sawStatus) return;
    for (const node of nodes) {
      if (node.url) {
        sawBookmark = true;
        // 'unknown' is what a failed or unavailable check writes, so it is not a result
        /* [ZeroLabs] 2026-08-28 - fixed: 'unknown' safetyStatus counted as a result */
        // linkStatus excluded 'unknown' but safetyStatus was only tested for
        // truthiness. clearCache() sets BOTH to the string 'unknown', which is
        // truthy - so a cleared folder still looked cached, shouldScanFolder
        // skipped it, and re-expanding after Clear Cache scanned nothing.
        if ((node.linkStatus && node.linkStatus !== 'unknown') ||
            (node.safetyStatus && node.safetyStatus !== 'unknown')) {
          sawStatus = true;
          return;
        }
      }
      if (node.children) {
        walk(node.children);
        if (sawStatus) return;
      }
    }
  };
  walk(folder.children);

  return !sawBookmark || sawStatus;
}

// Check if folder needs scanning (never scanned OR >7 days old OR nothing cached)
function shouldScanFolder(folderId) {
  const lastScan = folderScanTimestamps[folderId];
  if (!lastScan) return true; // Never scanned

  /* [ZeroLabs] 2026-08-28 - added: skip only when results are actually there */
  // This used to trust the timestamp alone, so a folder whose statuses had gone -
  // cache cleared, entries expired, or a timestamp recorded by a scan that never
  // produced anything - was skipped regardless and stayed blank until the seven
  // days ran out, with no way to prompt it short of waiting the week out.
  if (!folderHasCachedStatuses(folderId)) return true;

  const now = Date.now();
  const elapsed = now - lastScan;
  return elapsed > FOLDER_SCAN_CACHE_DURATION; // >7 days
}

// Sync UI with ongoing background scan status
async function syncBackgroundScanStatus() {
  try {
    const status = await browser.runtime.sendMessage({ action: 'getScanStatus' });

    if (status && status.isScanning) {
      console.log(`[Background Scan] Syncing UI - ${status.scanned}/${status.total}`);

      /* [ZeroLabs] 2026-08-28 - edited: register it instead of writing the bar */
      // Adopting an already-running background scan wrote straight to the bar,
      // so it showed on screen but was absent from activeOperations - the next
      // clear from anything else reset the bar while the scan carried on.
      setScanningStatus('background-scan', `Scanning: ${status.scanned}/${status.total}`);

      /* [ZeroLabs] 2026-06-20 12:21 AM - edited: route button via updateScanControls */
      backgroundScanActive = true;
      updateScanControls();
    }
  } catch (error) {
    console.error('Error syncing background scan status:', error);
  }
}

// Setup listener for blocklist download progress messages from background script
function setupBlocklistProgressListener() {
  browser.runtime.onMessage.addListener((message) => {
    if (message.type === 'blocklistProgress') {
      // Update status bar with download progress
      if (message.status === 'starting') {
        setScanningStatus('blocklist-download', 'Downloading blocklists...');
      } else if (message.status === 'downloading') {
        setScanningStatus('blocklist-download', `Downloading blocklists... (${message.current}/${message.total})`);
      }
      console.log(`[Blocklist Progress] ${message.current}/${message.total}${message.sourceName ? ` - ${message.sourceName}` : ''}`);
    } else if (message.type === 'blocklistComplete') {
      /* [ZeroLabs] 2026-08-28 - edited: the outcome IS the operation, briefly */
      // This used to guard on the .scanning class, which the download branch
      // above had set itself - so it matched its own state, skipped its reset,
      // and froze the bar on "Downloading blocklists... (10/10)". The backgroundScanActive
      // guard that replaced it worked but still wrote the bar from outside.
      //
      // Holding the completion message as this operation's own message for three
      // seconds means a bookmark scan running alongside keeps its progress
      // visible, and the bar settles to Ready only when updateStatusBar finds
      // nothing else active.
      setScanningStatus('blocklist-download', `Blocklists loaded: ${message.domains.toLocaleString()} domains`);
      setTimeout(() => clearScanningStatus('blocklist-download'), 3000);
      console.log(`[Blocklist Complete] ${message.domains.toLocaleString()} unique domains from ${message.totalEntries.toLocaleString()} entries (${message.sources} sources)`);
    }
    // Background scan messages
    else if (message.type === 'scanStarted') {
      console.log(`[Background Scan] Started - ${message.total} bookmarks`);
      setScanningStatus('background-scan', `Scanning: 0/${message.total}`);

      /* [ZeroLabs] 2026-06-20 12:21 AM - edited: route button via updateScanControls */
      backgroundScanActive = true;
      updateScanControls();
    } else if (message.type === 'scanProgress') {
      // Update progress in status bar
      setScanningStatus('background-scan', `Scanning: ${message.scanned}/${message.total}`);

      // Update the bookmark in the tree with scan results
      if (message.result) {
        const updates = {};
        if (message.result.linkStatus) {
          updates.linkStatus = message.result.linkStatus;
        }
        if (message.result.safetyStatus) {
          updates.safetyStatus = message.result.safetyStatus;
          updates.safetySources = message.result.safetySources || [];
        }

        updateBookmarkInTree(message.result.id, updates);

        // Update only the specific bookmark element (fast, non-blocking)
        updateBookmarkStatusInDOM(message.result.id, updates);
      }
    } else if (message.type === 'scanComplete') {
      console.log(`[Background Scan] Complete - ${message.scanned}/${message.total} bookmarks scanned`);
      clearScanningStatus('background-scan');

      /* [ZeroLabs] 2026-06-20 12:21 AM - edited: route button via updateScanControls */
      backgroundScanActive = false;
      updateScanControls();
    } else if (message.type === 'scanCancelled') {
      console.log(`[Background Scan] Cancelled - ${message.scanned}/${message.total} bookmarks scanned`);
      clearScanningStatus('background-scan');

      /* [ZeroLabs] 2026-06-20 12:21 AM - edited: route button via updateScanControls */
      backgroundScanActive = false;
      updateScanControls();
    }
  });
}

// Initialize the main UI (called after authentication is complete)
async function initMainUI() {
  // Force update logo title to bypass cache
  const logoTitle = document.querySelector('.logo-title');
  const logoSubtitle = document.querySelector('.logo-subtitle');
  if (logoTitle) logoTitle.innerHTML = `Bookmark Manager Zero • <span style="color: var(--md-sys-color-primary); font-weight: 500; font-size: 11px;">v${APP_VERSION}</span>`;
  if (logoSubtitle) logoSubtitle.textContent = 'A modern interface for your native bookmarks';

  // Force update filter button icon
  const filterToggle = document.getElementById('filterToggle');
  if (filterToggle) {
    filterToggle.innerHTML = `
      <svg width="16" height="16" fill="currentColor" viewBox="0 0 24 24">
        <path d="M4.25,5.61C6.27,8.2,10,13,10,13v6c0,0.55,0.45,1,1,1h2c0.55,0,1-0.45,1-1v-6c0,0,3.72-4.8,5.74-7.39 C20.25,4.95,19.78,4,18.95,4H5.04C4.21,4,3.74,4.95,4.25,5.61z"/>
      </svg>
    `;
    filterToggle.title = 'Filters';
  }

  // Show private mode indicator if in incognito/private browsing
  showPrivateModeIndicator();

  loadTheme();
  loadView();
  loadZoom();
  loadFontSize();
  loadGuiScale();
  loadBackgroundImage();
  loadContainerOpacity();
  // loadCustomTextColor(); // Moved to after event listener setup (line ~5388)
  loadCheckingSettings();
  loadScanConcurrency();
  await loadSetupCardFlag();
  await loadLatestCardFlag();
  /* [ZeroLabs] 2026-08-17 4:15 PM - added: load quick access and recent state */
  await loadQuickAccess();
  await loadRecentOpens();
  await loadSectionState();
  await loadDisplaySections();
  await loadWhitelist();
  await loadSafetyHistory();
  await loadFolderScanTimestamps();
  await loadAutoClearSetting();
  await loadStartFolder();
  cleanupSafetyHistory(); // Clean up stale entries on sidebar load
  await restoreCachedBookmarkStatuses();
  await restoreSessionState(); // Restore previous session (scroll, expanded folders, search)
  await expandToStartFolder();
  setupEventListeners();
  setupBlocklistProgressListener();
  renderBookmarks();

  // Check if background scan is in progress and sync UI
  await syncBackgroundScanStatus();

  // Automatically check bookmark statuses after initial render
  autoCheckBookmarkStatuses();
}

// Initialize (entry point - now handles authentication flow)
async function init() {
  // Start the authentication and initialization flow
  await checkAuthAndInit();
}

// Load and apply auto-clear cache setting
async function loadAutoClearSetting() {
  try {
    const result = await safeStorage.get('autoClearCacheDays');
    const autoClearDays = result.autoClearCacheDays || '7';

    // Set the select value
    if (autoClearCacheSelect) {
      autoClearCacheSelect.value = autoClearDays;
    }

    // Check if we need to run auto-clear
    if (autoClearDays !== 'never') {
      const lastClearResult = await safeStorage.get('lastCacheClear');
      const lastClear = lastClearResult.lastCacheClear || 0;
      const timeSinceLastClear = Date.now() - lastClear;
      const clearInterval = 24 * 60 * 60 * 1000; // Check once per day

      // Run auto-clear if it's been more than a day since last check
      if (timeSinceLastClear > clearInterval) {
        await clearOldCacheEntries(autoClearDays);
      }
    }
  } catch (error) {
    console.error('Error loading auto-clear setting:', error);
  }
}

// ============================================================================
// SESSION STATE PERSISTENCE
// ============================================================================

// Save current session state (scroll position, expanded folders, search, filters)
async function saveSessionState() {
  try {
    const sessionState = {
      scrollPosition: bookmarkList?.scrollTop || 0,
      expandedFolders: Array.from(expandedFolders),
      searchTerm: searchTerm,
      activeFilters: activeFilters,
      timestamp: Date.now()
    };
    // Use browser.storage.session so it clears when browser closes
    await browser.storage.session.set({ sessionState });
  } catch (error) {
    console.error('Error saving session state:', error);
  }
}

// Restore previous session state
async function restoreSessionState() {
  try {
    const result = await browser.storage.session.get('sessionState');
    if (result.sessionState) {
      const state = result.sessionState;

      // Session persists until browser is closed (no expiration)
      // The session will be cleared when the browser closes

      // Restore expanded folders
      if (state.expandedFolders && Array.isArray(state.expandedFolders)) {
        expandedFolders = new Set(state.expandedFolders);
      }

      // Restore search term
      if (state.searchTerm) {
        searchTerm = state.searchTerm;
        if (searchInput) {
          searchInput.value = state.searchTerm;
          /* [ZeroLabs] 2026-08-19 7:12 PM - added: reveal clear button on a restored search */
          // This runs after the listeners are wired, so the button's initial
          // state was decided against an empty box.
          const restoredClear = document.getElementById('searchClear');
          if (restoredClear) restoredClear.classList.remove('hidden');
        }
      }

      // Restore active filters
      if (state.activeFilters && Array.isArray(state.activeFilters)) {
        activeFilters = state.activeFilters;
      }

      // Restore scroll position after rendering
      if (state.scrollPosition && bookmarkList) {
        // Use setTimeout to ensure rendering is complete
        setTimeout(() => {
          bookmarkList.scrollTop = state.scrollPosition;
        }, 100);
      }

      console.log('Session state restored');
    }
  } catch (error) {
    console.error('Error restoring session state:', error);
  }
}

// Debounced save to avoid excessive storage writes
let saveStateTimeout;
function saveSessionStateDebounced() {
  clearTimeout(saveStateTimeout);
  saveStateTimeout = setTimeout(saveSessionState, 500);
}

// Load theme preference
function loadTheme() {
  safeStorage.get('theme').then(result => {
    theme = result.theme || 'enhanced-blue';
    applyTheme();

    // Update dropdown to match loaded theme
    const themeSelect = document.getElementById('themeSelect');
    if (themeSelect) {
      themeSelect.value = theme;
    }
  });
}

// Store current custom accent color globally
let currentCustomAccentColor = null;

// Apply custom accent color (global function so it can be called from applyTheme)
function applyCustomAccentColor(color) {
  currentCustomAccentColor = color;
  // Convert hex to RGB for variations
  const r = parseInt(color.slice(1, 3), 16);
  const g = parseInt(color.slice(3, 5), 16);
  const b = parseInt(color.slice(5, 7), 16);

  // Create lighter container color (add 80 to each channel, cap at 255)
  const containerR = Math.min(255, r + 80);
  const containerG = Math.min(255, g + 80);
  const containerB = Math.min(255, b + 80);
  const containerColor = `#${containerR.toString(16).padStart(2, '0')}${containerG.toString(16).padStart(2, '0')}${containerB.toString(16).padStart(2, '0')}`;

  // Remove existing custom accent style if it exists
  let styleTag = document.getElementById('custom-accent-style');
  if (styleTag) {
    styleTag.remove();
  }

  // Inject a style tag with higher specificity selectors
  styleTag = document.createElement('style');
  styleTag.id = 'custom-accent-style';
  styleTag.textContent = `
    /* Use @layer to ensure these rules take priority */
    @layer custom-accent {
      html:root {
        --md-sys-color-primary: ${color} !important;
        --md-sys-color-primary-container: ${containerColor} !important;
        --md-sys-color-secondary: ${color} !important;
      }
      html body.light,
      html body.blue-dark,
      html body.dark,
      html body.enhanced-blue,
      html body.enhanced-light,
      html body.enhanced-dark,
      html body.enhanced-gray,
      html body.tinted {
        --md-sys-color-primary: ${color} !important;
        --md-sys-color-primary-container: ${containerColor} !important;
        --md-sys-color-secondary: ${color} !important;
      }
      /* Directly override border-left on folder-children */
      .folder-children {
        border-left: 2px solid ${color} !important;
      }
    }
  `;
  // Append to body instead of head for later cascade position
  if (document.body) {
    document.body.appendChild(styleTag);
  } else {
    document.head.appendChild(styleTag);
  }

  // Directly update all existing .folder-children elements
  // This bypasses CSS variable resolution issues
  document.querySelectorAll('.folder-children').forEach(element => {
    element.style.setProperty('border-left-color', color, 'important');
  });
}

// Set up MutationObserver to apply custom color to new folder-children elements
function setupFolderChildrenObserver() {
  if (typeof window.folderChildrenObserver === 'undefined' && document.body) {
    window.folderChildrenObserver = new MutationObserver((mutations) => {
      if (!currentCustomAccentColor) return;

      mutations.forEach((mutation) => {
        mutation.addedNodes.forEach((node) => {
          if (node.nodeType === 1) { // Element node
            // Check if the node itself is folder-children
            if (node.classList && node.classList.contains('folder-children')) {
              node.style.setProperty('border-left-color', currentCustomAccentColor, 'important');
            }
            // Check descendants
            if (node.querySelectorAll) {
              node.querySelectorAll('.folder-children').forEach(element => {
                element.style.setProperty('border-left-color', currentCustomAccentColor, 'important');
              });
            }
          }
        });

        // Also check for class changes (when .show is added)
        if (mutation.type === 'attributes' && mutation.attributeName === 'class') {
          const target = mutation.target;
          if (target.classList && target.classList.contains('folder-children')) {
            target.style.setProperty('border-left-color', currentCustomAccentColor, 'important');
          }
        }
      });
    });

    // Start observing
    window.folderChildrenObserver.observe(document.body, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ['class']
    });
  }
}

// Call setup when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', setupFolderChildrenObserver);
} else {
  setupFolderChildrenObserver();
}

// Apply theme
function applyTheme() {
  // Remove all theme classes
  document.body.classList.remove('dark', 'light', 'blue-dark',
    'enhanced-blue', 'enhanced-light', 'enhanced-dark', 'enhanced-gray',
    'tinted');

  // CRITICAL FIX: Clear tint-related inline styles when switching away from tinted theme
  if (theme !== 'tinted') {
    // Remove inline style modifications from tinted theme
    document.body.style.removeProperty('--md-sys-color-surface');
    document.documentElement.style.removeProperty('--tint-hue');
    document.documentElement.style.removeProperty('--tint-saturation');
    document.documentElement.style.removeProperty('--header-background');
    document.documentElement.style.removeProperty('--footer-background');
  }

  // Add current theme class
  document.body.classList.add(theme);

  // Update tint controls visibility
  updateTintControlsVisibility();

  // Load tint settings if tinted theme
  if (theme === 'tinted') {
    loadTintSettings();
  }

  // Reapply custom accent color if one is saved
  const savedColor = localStorage.getItem('customAccentColor');
  if (savedColor) {
    applyCustomAccentColor(savedColor);
  }
}

// Update tint controls visibility
function updateTintControlsVisibility() {
  const tintControls = document.getElementById('tintControls');
  if (tintControls) {
    if (theme === 'tinted') {
      tintControls.style.display = 'block';
    } else {
      tintControls.style.display = 'none';
    }
  }
}

// Apply tint settings
function applyTintSettings(hue, saturation) {
  if (theme !== 'tinted') return;

  document.documentElement.style.setProperty('--tint-hue', hue);
  document.documentElement.style.setProperty('--tint-saturation', `${saturation}%`);

  // Calculate luminance-balanced background
  const lightness = saturation > 50 ? 65 : 70;
  const bgColor = `hsla(${hue}, ${saturation}%, ${lightness}%, 0.72)`;
  document.body.style.setProperty('--md-sys-color-surface', bgColor);

  // Update header and footer backgrounds
  const headerFooterLightness = saturation > 50 ? 70 : 75;
  const headerFooterColor = `hsla(${hue}, ${saturation}%, ${headerFooterLightness}%, 0.85)`;
  document.documentElement.style.setProperty('--header-background', headerFooterColor);
  document.documentElement.style.setProperty('--footer-background', headerFooterColor);

  // Save to storage
  safeStorage.set({
    tintHue: hue,
    tintSaturation: saturation
  });
}

// Load tint settings
function loadTintSettings() {
  safeStorage.get(['tintHue', 'tintSaturation']).then(result => {
    const hue = result.tintHue || 220;
    const saturation = result.tintSaturation || 30;

    const hueInput = document.getElementById('tintHue');
    const saturationInput = document.getElementById('tintSaturation');
    const hueValue = document.getElementById('hueValue');
    const saturationValue = document.getElementById('saturationValue');

    if (hueInput) hueInput.value = hue;
    if (saturationInput) saturationInput.value = saturation;
    if (hueValue) hueValue.textContent = `${hue}°`;
    if (saturationValue) saturationValue.textContent = `${saturation}%`;

    applyTintSettings(hue, saturation);
  });
}

// Set theme
function setTheme(newTheme) {
  theme = newTheme;
  applyTheme();
  safeStorage.set({ theme });
}

// Load view preference
function loadView() {
  safeStorage.get('viewMode').then(result => {
    viewMode = result.viewMode || 'list';
    applyView();
  });
}

// Apply view
function applyView() {
  // Remove all view classes
  bookmarkList.classList.remove('grid-view', 'grid-2', 'grid-3', 'grid-4', 'grid-5', 'grid-6');

  // Add current view classes
  if (viewMode !== 'list') {
    bookmarkList.classList.add('grid-view', viewMode);
  }
}

// Set view
function setView(newView) {
  viewMode = newView;
  applyView();
  safeStorage.set({ viewMode });
}

// Load zoom preference
function loadZoom() {
  safeStorage.get('zoomLevel').then(result => {
    zoomLevel = result.zoomLevel || 80;
    applyZoom();
    updateZoomDisplay();
  });
}

// Load font size preference
function loadFontSize() {

  safeStorage.get('fontSize').then(result => {
    fontSize = result.fontSize || 100;
    applyFontSize();
    updateFontSizeDisplay();
  });
}

// Load and apply GUI scale
function loadGuiScale() {
  const savedScale = localStorage.getItem('guiScale');
  guiScale = savedScale ? parseInt(savedScale) : 100;
  applyGuiScale();
  if (guiScaleSelect) {
    guiScaleSelect.value = guiScale;
  }
}

// Apply GUI scale to header, toolbar, and filter elements
function applyGuiScale() {
  const scaleFactor = guiScale / 100;
  const elements = [
    document.querySelector('.header'),
    document.getElementById('collapsibleHeader'),
    document.getElementById('filterBar'),
    document.getElementById('displayBar'),
    document.getElementById('scanStatusBar')
  ];

  elements.forEach(element => {
    if (element) {
      element.style.zoom = scaleFactor;
    }
  });
}

// Load start folder preference
async function loadStartFolder() {
  try {
    const result = await safeStorage.get('startFolderId');
    startFolderId = result.startFolderId || null;
  } catch (error) {
    console.error('Error loading start folder preference:', error);
    startFolderId = null;
  }
}

// Populate start folder dropdown with all available folders
function populateStartFolderDropdown() {
  if (!startFolderSelect) return;

  // Get all folders from bookmark tree
  const folders = getAllFolders(bookmarkTree);

  // Clear existing options except the first one (Root)
  startFolderSelect.innerHTML = '<option value="">All Bookmarks (Root)</option>';

  // Add folder options
  folders.forEach(folder => {
    const option = document.createElement('option');
    option.value = folder.id;
    option.textContent = folder.title;
    startFolderSelect.appendChild(option);
  });

  // Set selected value
  if (startFolderId) {
    startFolderSelect.value = startFolderId;
  }
}

// Expand to start folder on load
async function expandToStartFolder() {
  if (!startFolderId) return;

  // Find the path to this folder (all parent folders)
  const pathToFolder = [];
  function findPath(nodes, targetId, path = []) {
    for (const node of nodes) {
      if (node.id === targetId) {
        return [...path, node.id];
      }
      if (node.children) {
        const found = findPath(node.children, targetId, [...path, node.id]);
        if (found) return found;
      }
    }
    return null;
  }

  const path = findPath(bookmarkTree, startFolderId);
  if (path) {
    // Expand all folders in the path
    path.forEach(folderId => {
      expandedFolders.add(folderId);
    });
  }
}

// Load and apply custom background image
// Apply background image with all settings
function applyBackgroundImage(imageData, opacity, blur, size, positionX, positionY, scale) {
  if (imageData) {
    // Create or update background overlay
    let bgOverlay = document.getElementById('background-overlay');
    if (!bgOverlay) {
      bgOverlay = document.createElement('div');
      bgOverlay.id = 'background-overlay';
      bgOverlay.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        z-index: 0;
        pointer-events: none;
        background-repeat: no-repeat;
      `;
      document.body.insertBefore(bgOverlay, document.body.firstChild);

      // Make sure container has higher z-index
      const content = document.querySelector('.content');
      if (content && !content.style.position) {
        content.style.position = 'relative';
        content.style.zIndex = '1';
      }

      // Make sure status bar has higher z-index
      const statusBar = document.getElementById('scanStatusBar');
      if (statusBar) {
        statusBar.style.position = 'relative';
        statusBar.style.zIndex = '2';
      }
    }

    bgOverlay.style.backgroundImage = `url(${imageData})`;
    bgOverlay.style.opacity = opacity / 100;
    bgOverlay.style.filter = `blur(${blur}px)`;
    bgOverlay.style.backgroundSize = size || 'cover';
    bgOverlay.style.backgroundPosition = `${positionX || 50}% ${positionY || 50}%`;

    // Apply scale by using transform
    if (scale && scale != 100) {
      const scalePercent = scale / 100;
      bgOverlay.style.transform = `scale(${scalePercent})`;
      bgOverlay.style.transformOrigin = 'center center';
    } else {
      bgOverlay.style.transform = 'none';
      bgOverlay.style.transformOrigin = 'center center';
    }
  } else {
    // Remove background overlay
    const bgOverlay = document.getElementById('background-overlay');
    if (bgOverlay) {
      bgOverlay.remove();
    }
  }
}

function loadSavedBackgroundImage() {
  const savedImage = localStorage.getItem('backgroundImage');
  const savedOpacity = localStorage.getItem('backgroundOpacity');
  const savedBlur = localStorage.getItem('backgroundBlur');
  const savedSize = localStorage.getItem('backgroundSize');
  const savedPositionX = localStorage.getItem('backgroundPositionX');
  const savedPositionY = localStorage.getItem('backgroundPositionY');
  const savedScale = localStorage.getItem('backgroundScale');

  if (savedOpacity) {
    backgroundOpacitySlider.value = savedOpacity;
    opacityValue.textContent = `${savedOpacity}%`;
  }
  if (savedBlur) {
    backgroundBlurSlider.value = savedBlur;
    blurValue.textContent = `${savedBlur}px`;
  }
  if (savedSize) {
    backgroundSizeSelect.value = savedSize;
  }
  if (savedScale) {
    backgroundScaleSlider.value = savedScale;
    scaleValue.textContent = `${savedScale}%`;
  }

  if (savedImage) {
    applyBackgroundImage(
      savedImage,
      savedOpacity || 100,
      savedBlur || 0,
      savedSize || 'contain',
      savedPositionX || 50,
      savedPositionY || 50,
      savedScale || 200
    );
  }
}

function loadBackgroundImage() {
  loadSavedBackgroundImage();
}

// Apply container opacity to bookmark items
function applyContainerOpacity(opacity) {
  const opacityValue = opacity / 100;
  document.documentElement.style.setProperty('--bookmark-container-opacity', opacityValue);
}

// Load saved container opacity
function loadContainerOpacity() {
  if (!containerOpacitySlider) return;
  const savedOpacity = localStorage.getItem('containerOpacity');
  if (savedOpacity) {
    containerOpacitySlider.value = savedOpacity;
    containerOpacityValue.textContent = `${savedOpacity}%`;
    applyContainerOpacity(savedOpacity);
  } else {
    applyContainerOpacity(100);
  }
}

// Apply dark text mode
// Dark text mode functions removed - no longer needed

// Apply custom text color
function applyCustomTextColor(color) {
  // Remove existing custom text color style if it exists
  let styleTag = document.getElementById('custom-text-color-style');
  if (styleTag) {
    styleTag.remove();
  }

  // Inject a style tag with the custom text color
  // Use high specificity selectors to override dark-text-mode styles
  styleTag = document.createElement('style');
  styleTag.id = 'custom-text-color-style';
  styleTag.textContent = `
    body .bookmark-title,
    body .folder-title,
    body.dark-text-mode .bookmark-title,
    body.dark-text-mode .folder-title,
    body.blue-dark.dark-text-mode .bookmark-title,
    body.blue-dark.dark-text-mode .folder-title,
    body.dark.dark-text-mode .bookmark-title,
    body.dark.dark-text-mode .folder-title,
    body.light.dark-text-mode .bookmark-title,
    body.light.dark-text-mode .folder-title {
      color: ${color} !important;
    }

    body .bookmark-url,
    body.dark-text-mode .bookmark-url {
      color: ${color} !important;
      opacity: 0.7;
    }
  `;
  document.head.appendChild(styleTag);
}

// Load saved custom text color
function loadCustomTextColor() {
  if (!textColorPicker) return;
  const savedColor = localStorage.getItem('customTextColor');
  if (savedColor) {
    textColorPicker.value = savedColor;
    applyCustomTextColor(savedColor);
  } else {
    textColorPicker.value = '#e8e8e8'; // Light gray default - works with Firefox color picker
  }
}

// Reset custom text color
function resetCustomTextColor() {
  // Remove the custom style
  const styleTag = document.getElementById('custom-text-color-style');
  if (styleTag) {
    styleTag.remove();
  }
  localStorage.removeItem('customTextColor');
}

// Remove URL from whitelist
async function removeFromWhitelist(url) {
  whitelistedUrls.delete(url);
  await saveWhitelist();

  // Recheck affected bookmarks
  const affectedBookmarks = bookmarkTree.filter(item =>
    !item.children && item.url && new URL(item.url).hostname === new URL(url).hostname
  );

  if (affectedBookmarks.length > 0) {
    console.log(`Rechecking ${affectedBookmarks.length} bookmarks after removing ${url} from whitelist`);
    for (const bookmark of affectedBookmarks) {
      // Clear cached safety status
      const cached = await safeStorage.get(bookmark.url);
      if (cached[bookmark.url]) {
        delete cached[bookmark.url].safety;
        await safeStorage.set({ [bookmark.url]: cached[bookmark.url] });
      }
      // Recheck
      if (safetyCheckingEnabled) {
        await checkUrlSafety(bookmark);
      }
    }
    renderBookmarks();
  }
}

// Load checking settings from localStorage
/* [ZeroLabs] 2026-08-28 - added: the background cannot see localStorage */
// These toggles live in localStorage because the sidebar reads them
// synchronously all over the place. The background reads browser.storage.local -
// a completely different store, where nothing had ever written these two keys.
// Every read there came back undefined and defaulted to on, so the background
// scan ran link AND safety checks regardless of these switches, and the
// blocklist download gate could never see that safety checking was off.
//
// localStorage stays the sidebar's source of truth; this mirrors it so the
// background sees the same answer. Called on load as well as on change, so an
// existing install carries its current setting over without the user touching
// anything.
function mirrorCheckingSettingsToExtensionStorage() {
  try {
    browser.storage.local.set({ linkCheckingEnabled, safetyCheckingEnabled });
  } catch (error) {
    console.warn('[Settings] Could not mirror checking settings to the background:', error);
  }
}

function loadCheckingSettings() {
  const savedLinkChecking = localStorage.getItem('linkCheckingEnabled');
  const savedSafetyChecking = localStorage.getItem('safetyCheckingEnabled');

  // Default to true if not set
  linkCheckingEnabled = savedLinkChecking !== null ? savedLinkChecking === 'true' : true;
  safetyCheckingEnabled = savedSafetyChecking !== null ? savedSafetyChecking === 'true' : true;

  // Update checkbox states
  const linkCheckbox = document.getElementById('enableLinkChecking');
  const safetyCheckbox = document.getElementById('enableSafetyChecking');
  if (linkCheckbox) linkCheckbox.checked = linkCheckingEnabled;
  if (safetyCheckbox) safetyCheckbox.checked = safetyCheckingEnabled;

  mirrorCheckingSettingsToExtensionStorage();
}

/* [ZeroLabs] 2026-06-20 10:50 AM - added: load + sync scan concurrency + jitter sliders */
async function loadScanConcurrency() {
  let concurrency = 5; // Default cap (matches background.js MAX_CONCURRENT_NETWORK)
  let jitter = 0;      // Default: no jitter
  try {
    const result = await browser.storage.local.get(['scanConcurrency', 'scanJitter']);
    if (result.scanConcurrency) concurrency = result.scanConcurrency;
    if (result.scanJitter !== undefined) jitter = result.scanJitter;
  } catch (e) {}

  const cSlider = document.getElementById('scanConcurrencySlider');
  const cLabel = document.getElementById('scanConcurrencyValue');
  if (cSlider) cSlider.value = concurrency;
  if (cLabel) cLabel.textContent = concurrency;

  const jSlider = document.getElementById('scanJitterSlider');
  const jLabel = document.getElementById('scanJitterValue');
  if (jSlider) jSlider.value = jitter;
  if (jLabel) jLabel.textContent = jitter + 'ms';

  // Push saved values to the background limiter
  browser.runtime.sendMessage({ action: 'setScanConcurrency', value: concurrency }).catch(() => {});
  browser.runtime.sendMessage({ action: 'setScanJitter', value: jitter }).catch(() => {});
}

// Apply zoom
function applyZoom() {
  const zoomFactor = zoomLevel / 100;
  // Use CSS zoom instead of transform scale - it actually changes layout size
  // This prevents the gap issue that transform: scale() causes
  bookmarkList.style.zoom = zoomFactor;
  // Reset any previous transform-based zoom
  bookmarkList.style.transform = '';
  bookmarkList.style.width = '';
}

// Set zoom
function setZoom(newZoom) {
  zoomLevel = newZoom;
  applyZoom();
  updateZoomDisplay();
  safeStorage.set({ zoomLevel });
}

// Update zoom display
function updateZoomDisplay() {
  if (zoomSlider) zoomSlider.value = zoomLevel;
  if (zoomValue) zoomValue.textContent = `${zoomLevel}%`;
}

// Apply font size
function applyFontSize() {
  const fontSizeFactor = fontSize / 100;
  document.documentElement.style.setProperty('--font-size-scale', fontSizeFactor);
}

// Set font size
function setFontSize(newSize) {
  fontSize = newSize;
  applyFontSize();
  updateFontSizeDisplay();
  safeStorage.set({ fontSize });
}

// Update font size display
function updateFontSizeDisplay() {
  if (fontSizeSlider) fontSizeSlider.value = fontSize;
  if (fontSizeValue) fontSizeValue.textContent = `${fontSize}%`;
}

// Load bookmarks from sync manager (local storage or remote)
async function loadBookmarks() {
  try {
    console.log('[loadBookmarks] Loading native Firefox bookmarks...');

    // Load native Firefox bookmarks using the bookmarks API
    const firefoxTree = await browser.bookmarks.getTree();

    // Firefox bookmark tree structure: [root] where root.children contains the bookmark folders
    if (firefoxTree && firefoxTree[0] && firefoxTree[0].children) {
      bookmarkTree = firefoxTree[0].children;
      console.log('[loadBookmarks] Loaded native Firefox bookmarks:', bookmarkTree.length, 'root folders');
    } else {
      // Fallback to empty tree
      bookmarkTree = [];
      console.log('[loadBookmarks] No bookmarks found, using empty tree');
    }

    // Clear checked bookmarks when loading fresh data
    checkedBookmarks.clear();
    // Update start folder dropdown with current folders
    populateStartFolderDropdown();

    console.log('[loadBookmarks] Bookmarks loaded successfully');
  } catch (error) {
    console.error('[loadBookmarks] Error loading bookmarks:', error);
    showError('Failed to load bookmarks');
  }
}

// Helper function to validate cache entries
function isValidCache(cached) {
  const CACHE_TTL = 7 * 24 * 60 * 60 * 1000; // 7 days
  return cached && (Date.now() - cached.timestamp < CACHE_TTL);
}

// Restore cached bookmark statuses from persistent storage
async function restoreCachedBookmarkStatuses() {
  try {
    // Load both caches from storage
    const result = await safeStorage.get(['linkStatusCache', 'safetyStatusCache']);
    const linkCache = result.linkStatusCache || {};
    const safetyCache = result.safetyStatusCache || {};

    let restored = 0;

    // Recursively traverse bookmark tree
    function restoreStatuses(nodes) {
      nodes.forEach(node => {
        if (node.url) {
          // Check if URL is whitelisted (takes priority over cache)
          try {
            const hostname = new URL(node.url).hostname;
            if (whitelistedUrls.has(hostname)) {
              node.safetyStatus = 'safe';
              node.safetySources = ['Whitelisted by user'];
              node.linkStatus = node.linkStatus || 'unknown'; // Keep existing link status if present
              restored++;
            }
          } catch (e) {
            // Invalid URL, skip whitelist check
          }

          // Check link status cache (only if not already set by whitelist)
          if (!node.linkStatus) {
            const linkCached = linkCache[node.url];
            if (linkCached && isValidCache(linkCached)) {
              node.linkStatus = linkCached.result;
              restored++;
            }
          }

          // Check safety status cache (only if not whitelisted)
          if (!node.safetyStatus) {
            const safetyCached = safetyCache[node.url];
            if (safetyCached && isValidCache(safetyCached)) {
              node.safetyStatus = safetyCached.result?.status || safetyCached.result;
              node.safetySources = safetyCached.result?.sources || [];
              restored++;
            }
          }
        }

        if (node.children) {
          restoreStatuses(node.children);
        }
      });
    }

    restoreStatuses(bookmarkTree);
    console.log(`[Cache Restore] Restored ${restored} cached status indicators`);
  } catch (error) {
    console.error('[Cache Restore] Error restoring cached statuses:', error);
  }
}

// Scan ALL bookmarks regardless of folder expansion (used by rescan button)
async function rescanAllBookmarks() {
  // Skip if both checking types are disabled
  if (!linkCheckingEnabled && !safetyCheckingEnabled) {
    console.log('Link and safety checking are both disabled, skipping...');
    return;
  }

  const bookmarksToCheck = [];

  // Traverse tree to find ALL bookmarks regardless of folder state or check status
  function traverseAll(nodes) {
    nodes.forEach(node => {
      // Skip separators
      if (node.type === 'separator') return;

      // Check all bookmarks regardless of folder expansion or previous check status
      if (node.url && !checkedBookmarks.has(node.id)) {
        bookmarksToCheck.push(node);
      }
      // Always traverse children
      if (node.type === 'folder' && node.children) {
        traverseAll(node.children);
      }
    });
  }

  traverseAll(bookmarkTree);

  if (bookmarksToCheck.length === 0) {
    /* [ZeroLabs] 2026-08-28 - edited: recompute rather than forcing Ready */
    // No operation was ever registered here, so forcing 'Ready' wiped whatever
    // else was running. updateStatusBar settles to Ready only if nothing is.
    updateStatusBar();
    return;
  }

  console.log(`Rescanning ALL ${bookmarksToCheck.length} bookmarks in batches...`);

  // Mark these bookmarks as being checked
  bookmarksToCheck.forEach(item => checkedBookmarks.add(item.id));

  // Show stop button, hide rescan button
  const stopBtn = document.getElementById('stopScanBtn');
  if (stopBtn) stopBtn.style.display = 'flex';
  if (rescanAllBtn) rescanAllBtn.style.display = 'none';

  // Process bookmarks in batches
  const BATCH_SIZE = 10;
  const BATCH_DELAY = 100;

  // Update status bar
  const totalToScan = bookmarksToCheck.length;
  let scannedCount = 0;
  scanCancelled = false; // Reset the cancel flag
  /* [ZeroLabs] 2026-08-28 - edited: register as an operation */
  // The .scanning class is owned by setScanningStatus now, so it is no longer
  // toggled by hand here - that is what let one function strip the styling off
  // another function's live scan.
  setScanningStatus(RESCAN_ALL_OP, `Scanning: 0/${totalToScan}`);

  for (let i = 0; i < bookmarksToCheck.length; i += BATCH_SIZE) {
    // Check if scan was cancelled
    if (scanCancelled) {
      console.log('Scan cancelled by user');
      break;
    }

    const batch = bookmarksToCheck.slice(i, i + BATCH_SIZE);

    // Check each bookmark in the batch in parallel
    const batchPromises = batch.map(async (node) => {
      const results = {};

      if (linkCheckingEnabled) {
        results.linkStatus = await checkLinkStatus(node.url, true); // Bypass cache for rescan
      }
      if (safetyCheckingEnabled) {
        const safetyStatusResult = await checkSafetyStatus(node.url, true); // Bypass cache for rescan
        results.safetyStatus = safetyStatusResult.status;
        results.safetySources = safetyStatusResult.sources || [];
      }

      // Update the node in the tree
      updateBookmarkInTree(node.id, results);

      // Update progress immediately after each bookmark completes
      scannedCount++;
      setScanningStatus(RESCAN_ALL_OP, `Scanning: ${scannedCount}/${totalToScan}`);

      return results;
    });

    // Wait for all checks in the batch to complete
    await Promise.all(batchPromises);

    if (i + BATCH_SIZE < bookmarksToCheck.length) {
      await new Promise(resolve => setTimeout(resolve, BATCH_DELAY));
    }
  }

  renderBookmarks();

  // Hide stop button, show rescan button
  if (stopBtn) stopBtn.style.display = 'none';
  if (rescanAllBtn) rescanAllBtn.style.display = 'flex';

  // Clear checkedBookmarks to free memory after scan completes
  checkedBookmarks.clear();

  /* [ZeroLabs] 2026-08-28 - edited: the outcome stays this operation's message */
  // Writing the outcome over the bar and then forcing 'Ready' two seconds later
  // stomped anything else still running, twice. Clearing the operation instead
  // lets updateStatusBar decide what follows.
  setScanningStatus(RESCAN_ALL_OP, scanCancelled ? 'Scan stopped' : 'Scan complete');
  setTimeout(() => clearScanningStatus(RESCAN_ALL_OP), 2000);

  console.log(`Finished rescanning ${bookmarksToCheck.length} bookmarks`);
}

// Automatically check bookmark statuses for unchecked bookmarks
// Uses rate limiting to prevent browser overload
/* [ZeroLabs] 2026-08-28 - edited: report whether a scan actually happened */
// Callers recorded a "folder scanned" timestamp as soon as this returned, but an
// early return was indistinguishable from a completed scan. Expanding a folder
// with checking switched off therefore marked it scanned for seven days, so
// turning checking back on left that folder stuck with no statuses and no way to
// prompt a rescan short of waiting the cache out. Returns true only when the
// bookmarks were actually scanned or found already current.
async function autoCheckBookmarkStatuses() {
  // Skip if both checking types are disabled
  if (!linkCheckingEnabled && !safetyCheckingEnabled) {
    console.log('Link and safety checking are both disabled, skipping...');
    return false;
  }

  const bookmarksToCheck = [];

  // Traverse tree to find unchecked bookmarks (only in root or expanded folders)
  function traverse(nodes, parentExpanded = true) {
    nodes.forEach(node => {
      // Skip separators
      if (node.type === 'separator') return;

      // Only check bookmarks if parent is expanded (or at root level)
      if (parentExpanded && node.url && (!node.linkStatus || node.linkStatus === 'unknown') && !checkedBookmarks.has(node.id)) {
        bookmarksToCheck.push(node);
      }
      // For folders, only traverse children if folder is expanded
      if (node.type === 'folder' && node.children) {
        const isFolderExpanded = expandedFolders.has(node.id);
        traverse(node.children, isFolderExpanded);
      }
    });
  }

  traverse(bookmarkTree, true);

  if (bookmarksToCheck.length === 0) {
    /* [ZeroLabs] 2026-08-28 - edited: recompute rather than forcing Ready */
    // Forcing 'Ready' here wiped the progress of anything else running.
    updateStatusBar();
    // Nothing needed checking, so the folder genuinely is up to date
    return true;
  }

  console.log(`Auto-checking ${bookmarksToCheck.length} bookmarks in batches...`);

  // Mark these bookmarks as being checked to prevent re-checking
  bookmarksToCheck.forEach(item => checkedBookmarks.add(item.id));

  // Process bookmarks in batches to prevent browser/network overload
  const BATCH_SIZE = 10; // Check 10 bookmarks at a time
  const BATCH_DELAY = 100; // 100ms delay between batches

  // Update status bar to show scanning state
  const totalToScan = bookmarksToCheck.length;
  let scannedCount = 0;
  autoScanTotal += totalToScan;
  setScanningStatus('auto-check', `Scanning: ${autoScanDone}/${autoScanTotal}`);

  /* [ZeroLabs] 2026-06-20 12:21 AM - edited: re-entrant scan + central button owner */
  // Only the outermost scan clears the cancel flag, so a Stop pressed during
  // overlapping auto-checks (one per folder expansion) cancels them all instead
  // of a later invocation silently un-cancelling the earlier ones.
  if (autoScanDepth === 0) scanCancelled = false;
  autoScanDepth++;
  updateScanControls();

  try {
  for (let i = 0; i < bookmarksToCheck.length; i += BATCH_SIZE) {
    // Check if scan was cancelled
    if (scanCancelled) {
      console.log('Scan cancelled, stopping...');
      break;
    }

    const batch = bookmarksToCheck.slice(i, i + BATCH_SIZE);

    // Set batch to checking status (update data only, don't render yet)
    batch.forEach(item => {
      const updates = {};
      if (linkCheckingEnabled) updates.linkStatus = 'checking';
      if (safetyCheckingEnabled) updates.safetyStatus = 'checking';
      updateBookmarkInTree(item.id, updates);
    });

    // Check this batch - conditionally check link status and/or safety based on settings
    const checkPromises = batch.map(async (item) => {
      try {
        const result = { id: item.id };

        if (linkCheckingEnabled) {
          result.linkStatus = await checkLinkStatus(item.url);
        }

        if (safetyCheckingEnabled) {
          const safetyResult = await checkSafetyStatus(item.url);
          result.safetyStatus = safetyResult.status;
          result.safetySources = safetyResult.sources;
        }

        // Update progress immediately after each bookmark completes
        scannedCount++;
        autoScanDone++;
        setScanningStatus('auto-check', `Scanning: ${autoScanDone}/${autoScanTotal}`);

        return result;
      } catch (error) {
        console.error(`Error checking bookmark ${item.id} (${item.url}):`, error);
        const errorResult = { id: item.id };
        if (linkCheckingEnabled) errorResult.linkStatus = 'dead';
        if (safetyCheckingEnabled) {
          errorResult.safetyStatus = 'unknown';
          errorResult.safetySources = [];
        }

        // Update progress even on error
        scannedCount++;
        autoScanDone++;
        setScanningStatus('auto-check', `Scanning: ${autoScanDone}/${autoScanTotal}`);

        return errorResult;
      }
    });

    const results = await Promise.all(checkPromises);

    // Update results for this batch (update data and DOM immediately)
    results.forEach(result => {
      // Find the original bookmark to get the URL
      // Update the data structure
      const updates = {
        linkStatus: result.linkStatus,
        safetyStatus: result.safetyStatus,
        safetySources: result.safetySources
      };
      updateBookmarkInTree(result.id, updates);

      // Update the DOM immediately for this bookmark
      updateBookmarkStatusInDOM(result.id, updates);
    });

    console.log(`Checked batch ${Math.floor(i / BATCH_SIZE) + 1}/${Math.ceil(bookmarksToCheck.length / BATCH_SIZE)} (${results.length} bookmarks)`);

    // Wait before processing next batch (except for the last batch)
    if (i + BATCH_SIZE < bookmarksToCheck.length) {
      await new Promise(resolve => setTimeout(resolve, BATCH_DELAY));
    }
  }

  } finally {
    /* [ZeroLabs] 2026-06-20 10:35 AM - edited: only outermost scan settles status */
    // Render once at the end (or on cancel) of all batches
    renderBookmarks();

    autoScanDepth = Math.max(0, autoScanDepth - 1);
    updateScanControls();

    // Only the last overlapping scan finalizes the status bar
    if (autoScanDepth === 0) {
      // Last overlapping scan out resets the shared tally
      autoScanTotal = 0;
      autoScanDone = 0;
      checkedBookmarks.clear();
      /* [ZeroLabs] 2026-08-28 - edited: the outcome stays this operation's message */
      // The depth check still guards against a newer overlapping scan finishing
      // first; the difference is that clearing the operation lets updateStatusBar
      // decide what follows, instead of forcing 'Ready' over anything else.
      setScanningStatus('auto-check', scanCancelled ? 'Scan stopped' : 'Scan complete');
      setTimeout(() => {
        if (autoScanDepth === 0) clearScanningStatus('auto-check');
      }, 2000);
    }
  }

  /* [ZeroLabs] 2026-08-28 - edited: the message claimed the opposite of what ran */
  // It ended "(safety checks disabled - use Test VT button)", hardcoded and
  // unconditional, left from when safety was a separate manual step - while the
  // log above it filled up with completed safety checks. "link status" was wrong
  // for the same reason, so the line now states only what it can vouch for.
  console.log(`Finished checking ${bookmarksToCheck.length} bookmarks`);

  // Cancelled part-way through is not a completed scan, so it must not count
  return !scanCancelled;
}

// Update total bookmark count in status bar
function updateTotalBookmarkCount() {
  if (!totalCount) return;

  let count = 0;
  function countBookmarksRecursive(nodes) {
    nodes.forEach(node => {
      if (node.type === 'bookmark' && node.url && node.type !== 'separator') {
        count++;
      } else if (node.type === 'folder' && node.children) {
        countBookmarksRecursive(node.children);
      }
    });
  }

  countBookmarksRecursive(bookmarkTree);
  totalCount.textContent = `${count} bookmark${count !== 1 ? 's' : ''}`;
}

/**
 * Open a URL using the most appropriate method based on the URL scheme.
 * For privileged schemes (about:, moz-extension:, etc.), use anchor click.
 * For regular HTTP(S) URLs, use browser tab APIs for better control.
 */
async function openBookmarkUrl(url, openInNewTab = false) {
  try {
    const urlObj = new URL(url);
    const scheme = urlObj.protocol.replace(':', '').toLowerCase();

    // List of privileged schemes that Firefox blocks from extensions
    const blockedSchemes = ['about'];

    if (blockedSchemes.includes(scheme)) {
      // Firefox security blocks extensions from opening about: URLs
      // Copy to clipboard and notify user
      try {
        await navigator.clipboard.writeText(url);
        alert(`Firefox security prevents extensions from opening ${scheme}: URLs.\n\nThe URL has been copied to your clipboard:\n${url}\n\nPlease paste it into the address bar manually.`);
      } catch (clipboardError) {
        alert(`Firefox security prevents extensions from opening ${scheme}: URLs.\n\nPlease copy and paste this URL manually:\n${url}`);
      }
      return;
    }

    /* [ZeroLabs] 2026-08-17 4:15 PM - added: track recent opens */
    // Recorded past the blocked-scheme return, so a URL Firefox refused to open
    // never counts as opened.
    recordRecentOpen(url);

    // List of other privileged schemes that may work with window.open
    const privilegedSchemes = ['moz-extension', 'chrome', 'view-source', 'jar', 'resource'];

    if (privilegedSchemes.includes(scheme)) {
      // Try window.open for other privileged URLs
      window.open(url, '_blank');
    } else {
      // Use browser APIs for regular URLs (better control)
      if (openInNewTab) {
        browser.tabs.create({ url: url });
      } else {
        const tabs = await browser.tabs.query({ active: true, currentWindow: true });
        if (tabs[0]) {
          browser.tabs.update(tabs[0].id, { url: url });
        } else {
          browser.tabs.create({ url: url });
        }
      }
    }
  } catch (error) {
    console.error('Failed to open URL:', url, error);
    // Fallback: try window.open anyway
    try {
      window.open(url, '_blank');
    } catch (fallbackError) {
      console.error('Fallback also failed:', fallbackError);
      alert(`Unable to open URL: ${url}\n\nPlease copy and paste it into the address bar manually.`);
    }
  }
}

// Render bookmarks
function renderBookmarks() {
  const filtered = filterAndSearchBookmarks(bookmarkTree);

  if (filtered.length === 0) {
    bookmarkList.innerHTML = `
      <div style="text-align: center; padding: 40px 20px; color: var(--md-sys-color-on-surface-variant);">
        <div style="font-size: 48px; margin-bottom: 12px; opacity: 0.5;">🔍</div>
        <div style="font-size: 14px;">No bookmarks found</div>
      </div>
    `;
    return;
  }

  bookmarkList.innerHTML = '';

  // Show first-time setup card if user hasn't seen it
  if (!hasSeenSetupCard) {
    const setupCard = document.createElement('div');
    setupCard.className = 'setup-card';
    setupCard.innerHTML = `
      <div class="setup-card-header">🎆 Welcome to Bookmark Manager Zero! 🎆</div>
      <div class="setup-card-subheader">Your bookmarks are already here!</div>
      <button class="setup-card-scan-btn" id="setupScanBtn">🔍 Scan All Bookmarks Now</button>
      <div class="setup-card-info">
        Bookmarks auto-scan when you expand folders (every 7 days). Progress appears in the status bar below.
        You'll be alerted if safe bookmarks turn malicious.
      </div>
      <div class="setup-card-disclaimer">
        <strong>Note:</strong> Scanning relies on community-submitted threat lists and automated link validation.
        This may produce false positive/negative results. Use Bookmark Manager Zero as a helpful safety tool,
        not a security guarantee.
      </div>
      <button class="setup-card-dismiss-btn" id="setupDismissBtn">Got it, don't show this again</button>
    `;
    bookmarkList.appendChild(setupCard);

    // Add event listeners
    setTimeout(() => {
      const scanBtn = document.getElementById('setupScanBtn');
      const dismissBtn = document.getElementById('setupDismissBtn');

      if (scanBtn) {
        scanBtn.addEventListener('click', async () => {
          await dismissSetupCard();
          // Trigger full scan directly
          await rescanAllBookmarks();
        });
      }

      if (dismissBtn) {
        dismissBtn.addEventListener('click', dismissSetupCard);
      }
    }, 0);
  }

  /* [ZeroLabs] 2026-08-27 - edited: one reusable what's-new card */
  if (!hasSeenLatestCard) {
    const announcementCard = document.createElement('div');
    announcementCard.className = 'announcement-card';
    announcementCard.innerHTML = `
      <div class="announcement-card-title">What's New as of Aug 27, 2026</div>
      <div class="announcement-card-body">
        Sync now runs robustly in the background, even with BMZ closed.
        <br><br>
        Every sync is now a proper merge. BMZ compares your local bookmarks against your
        Snippet, quietly adds whatever is missing from either, and stops the moment something
        would be removed, renamed or otherwise overwritten to ask your permission before any
        action takes place. A card appears at the top of your bookmark list and the sync button
        turns amber. Nothing is lost or changed while it waits.
        <br><br>
        Sync settings have been rebuilt and streamlined around a single button that shows you
        what it's doing, and a switch to turn automatic syncing off (on is the default).
        <br><br>
        Deletion is now undoable everywhere — including bulk deletions and whole folders.
        Restoring a folder from the changelog brings its contents back too.
        <br><br>
        BMZ now warns you before saving a bookmark that isn't a valid link.
      </div>
      <div class="announcement-card-actions">
        <button class="announcement-card-dismiss-btn" id="latestCardDismissBtn">Got it</button>
      </div>
    `;
    bookmarkList.appendChild(announcementCard);

    // Dismiss only. The v4.5 card's "Set Up Sync" button broke in v4.6 because its
    // handler was scoped inside setupEventListeners; with no action button there
    // is nothing left to scope wrongly.
    setTimeout(() => {
      const dismissBtn = document.getElementById('latestCardDismissBtn');
      if (dismissBtn) dismissBtn.addEventListener('click', dismissLatestCard);
    }, 0);
  }

  /* [ZeroLabs] 2026-08-17 4:15 PM - added: quick access and recent sections */
  // Hidden while searching or filtering: the tree is already showing matches
  // from everywhere, so mirrored rows would just duplicate the results.
  /* [ZeroLabs] 2026-08-27 - added: deferred sync notice, above everything else */
  // Ahead of Quick Access, and outside the isNarrowing guard: it is a standing
  // alert rather than a mirrored list, so it should not vanish when you search.
  renderSyncNoticeCard(bookmarkList);

  const isNarrowing = searchTerm.length > 0 || activeFilters.length > 0;
  if (!isNarrowing) {
    renderSections(bookmarkList);
  }

  renderNodes(filtered, bookmarkList);

  // Add a drop zone at the end of the root to allow dropping items there
  const dropZone = document.createElement('div');
  dropZone.className = 'root-drop-zone';
  dropZone.dataset.id = 'root-end';
  dropZone.style.minHeight = '10px';
  dropZone.style.marginTop = '4px';

  dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
    dropZone.classList.add('drop-active');
  });

  dropZone.addEventListener('dragleave', () => {
    dropZone.classList.remove('drop-active');
  });

  dropZone.addEventListener('drop', async (e) => {
    e.preventDefault();
    e.stopPropagation();
    dropZone.classList.remove('drop-active');

    const draggedId = e.dataTransfer.getData('text/plain');
    await handleDropToRoot(draggedId);
  });

  bookmarkList.appendChild(dropZone);

  // Update total bookmark count in status bar
  updateTotalBookmarkCount();
}

/* [ZeroLabs] 2026-08-17 4:15 PM - added: quick access / recent section rendering */
// ============================================================================
// SECTION RENDERING (QUICK ACCESS + RECENTLY OPENED)
// ============================================================================

// Which list a drag started from. dataTransfer payloads are unreadable during
// dragover in Firefox, so the drop targets need this to decide whether to accept.
let dragContext = null; // null | 'tree' | 'tree-folder' | 'quick-access'

// Which list the open context menu belongs to, so a menu opened from Quick
// Access can offer Remove from Quick Access instead of Delete.
let contextMenuOrigin = 'tree'; // 'tree' | 'quick-access' | 'recent'

/* [ZeroLabs] 2026-08-17 4:15 PM - edited: shared split header row */
// Both sections sit on one row, each taking half the width, and behave as an
// accordion: opening one closes the other. Clicking the open one closes both.
function buildSectionHeader(config, count, isActive) {
  const header = document.createElement('div');
  header.className = 'bmz-section-header';
  if (isActive) header.classList.add('active');
  header.setAttribute('role', 'button');
  header.setAttribute('tabindex', '0');
  header.setAttribute('aria-expanded', String(isActive));

  header.innerHTML = `
    <svg class="bmz-section-icon" width="16" height="16" fill="currentColor" viewBox="0 0 24 24" aria-hidden="true">
      <path d="${config.iconPath}"/>
    </svg>
    <span class="bmz-section-title">${escapeHtml(config.title)}</span>
    <svg class="bmz-section-chevron" width="16" height="16" fill="currentColor" viewBox="0 0 24 24" aria-hidden="true">
      <path d="M7.41,8.58L12,13.17L16.59,8.58L18,10L12,16L6,10L7.41,8.58Z"/>
    </svg>
    <span class="bmz-section-count">${count}</span>
  `;

  const toggle = async () => {
    activeSection = (activeSection === config.stateKey) ? null : config.stateKey;
    await saveSectionState();
    renderBookmarks();
  };

  header.addEventListener('click', toggle);
  header.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      toggle();
    }
  });

  return header;
}

// Quick Access rows. Draggable for reorder within the section only; the tree's
// drop handlers reject this drag context outright, so a pin can never be dropped
// into a real folder.
function createQuickAccessRow(bookmark) {
  const row = createBookmarkElement(bookmark, { mirror: 'quick-access' });
  const pinKey = normalizeUrlKey(bookmark.url);

  row.draggable = true;
  row.dataset.pinKey = pinKey;

  row.addEventListener('dragstart', (e) => {
    e.stopPropagation();
    dragContext = 'quick-access';
    e.dataTransfer.effectAllowed = 'move';
    e.dataTransfer.setData('text/plain', pinKey);
    e.dataTransfer.setData('itemType', 'quick-access');
    row.style.opacity = '0.5';
  });

  row.addEventListener('dragend', () => {
    dragContext = null;
    row.style.opacity = '1';
    document.querySelectorAll('.qa-drop-before, .qa-drop-after').forEach(el => {
      el.classList.remove('qa-drop-before', 'qa-drop-after');
    });
  });

  row.addEventListener('dragover', (e) => {
    if (dragContext !== 'quick-access') return;
    e.preventDefault();
    e.stopPropagation();
    e.dataTransfer.dropEffect = 'move';
    const rect = row.getBoundingClientRect();
    document.querySelectorAll('.qa-drop-before, .qa-drop-after').forEach(el => {
      el.classList.remove('qa-drop-before', 'qa-drop-after');
    });
    row.classList.add(e.clientY < rect.top + rect.height * 0.5 ? 'qa-drop-before' : 'qa-drop-after');
  });

  row.addEventListener('dragleave', (e) => {
    if (!row.contains(e.relatedTarget)) {
      row.classList.remove('qa-drop-before', 'qa-drop-after');
    }
  });

  row.addEventListener('drop', async (e) => {
    if (dragContext !== 'quick-access') return;
    e.preventDefault();
    e.stopPropagation();
    const dropBefore = row.classList.contains('qa-drop-before');
    row.classList.remove('qa-drop-before', 'qa-drop-after');
    const fromKey = e.dataTransfer.getData('text/plain');
    dragContext = null;
    if (fromKey && fromKey !== pinKey) {
      await reorderQuickAccess(fromKey, pinKey, dropBefore);
    }
  });

  return row;
}

function buildQuickAccessBody(resolved) {
  const body = document.createElement('div');
  body.className = 'bmz-section-body';

  if (resolved.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'bmz-section-empty';
    empty.textContent = 'Right-click any bookmark and choose Add to Quick Access, or drag one here.';
    body.appendChild(empty);
  } else {
    resolved.forEach(bookmark => body.appendChild(createQuickAccessRow(bookmark)));
  }

  // Dropping a bookmark from the tree onto the body pins it. This mirrors, it
  // never moves the original, so nothing in the real folder structure changes.
  body.addEventListener('dragover', (e) => {
    if (dragContext !== 'tree') return;
    e.preventDefault();
    e.dataTransfer.dropEffect = 'copy';
    body.classList.add('bmz-section-drop-target');
  });

  body.addEventListener('dragleave', (e) => {
    if (!body.contains(e.relatedTarget)) {
      body.classList.remove('bmz-section-drop-target');
    }
  });

  body.addEventListener('drop', async (e) => {
    if (dragContext !== 'tree') return;
    e.preventDefault();
    e.stopPropagation();
    body.classList.remove('bmz-section-drop-target');
    const draggedId = e.dataTransfer.getData('text/plain');
    dragContext = null;
    const item = findBookmarkById(bookmarkTree, draggedId);
    if (item && item.url) {
      await pinBookmark(item);
    }
  });

  return body;
}

function buildRecentBody(resolved) {
  const body = document.createElement('div');
  body.className = 'bmz-section-body';

  if (resolved.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'bmz-section-empty';
    empty.textContent = 'Bookmarks you open will appear here.';
    body.appendChild(empty);
  } else {
    // Read-only mirror: no drag, no reorder. Order is recency.
    resolved.forEach(bookmark => {
      const row = createBookmarkElement(bookmark, { mirror: 'recent' });
      row.draggable = false;
      body.appendChild(row);
    });
  }

  return body;
}

/* [ZeroLabs] 2026-08-17 4:15 PM - added: both sections share one split row */
// One row split in two, with the open section's contents below it. If a display
// option hides one section, the other takes the full row rather than half.
/* [ZeroLabs] 2026-08-27 - added: the deferred-sync notice card (see also: Bookmark-Manager-Zero-Website/js/sidebar-adapted.js) */
// A sync that stops and waits needs to say so without hijacking the panel. The
// toolbar badge covers the panel being SHUT, and the amber sync arrows are the
// standing signal once it is open, but neither explains anything and the badge
// is hidden inside the extensions menu when BMZ is not pinned. This card is the
// explanation, and it replaces showHeldPushDialog opening by itself on panel
// open: one surface per divergence, never a card and a modal at once.
let syncNoticeVisible = false;
let syncNoticeDismissed = false;
let syncNoticeCounts = { fromSnippet: 0, fromDevice: 0, overwrites: 0 };

/* [ZeroLabs] 2026-08-27 - added: the worker can defer while the sidebar is open */
// Everything else here reacts to the sidebar's own syncing. When the background
// worker defers, it writes the flag and sets the toolbar badge, and nothing in
// the sidebar ever heard about it - so with BMZ unpinned, a deferral raised
// while you were looking at it showed you nothing at all.
browser.storage.onChanged.addListener((changes, area) => {
  if (area !== 'local' || !changes.snippet_needs_reconcile) return;
  const needs = !!changes.snippet_needs_reconcile.newValue;
  const manualSyncBtn = document.getElementById('manualSyncBtn');
  if (manualSyncBtn) manualSyncBtn.classList.toggle('sync-attention', needs);
  setSyncNoticeVisible(needs);
});

/* [ZeroLabs] 2026-08-27 - added: name the numbers on the card */
// The card used to say only "found differences", which told you nothing about
// whether this was worth opening now or after dinner. Added as its own line
// rather than folded into the sentence above, so the agreed wording is untouched.
function syncNoticeSummary(counts) {
  const n = (c, one, many) => `${c} ${c === 1 ? one : many}`;
  const parts = [];
  if (counts.fromSnippet > 0) parts.push(n(counts.fromSnippet, 'bookmark', 'bookmarks') + ' to remove from your Snippet');
  if (counts.fromDevice > 0) parts.push(n(counts.fromDevice, 'bookmark', 'bookmarks') + ' to remove from this device');
  if (counts.overwrites > 0) parts.push(n(counts.overwrites, 'bookmark', 'bookmarks') + ' to rename or move');
  return parts.join('  ·  ');
}

function renderSyncNoticeCard(container) {
  if (!syncNoticeVisible || syncNoticeDismissed) return;

  const card = document.createElement('div');
  card.className = 'sync-notice-card';
  // The leading image is the toolbar sync button in its waiting state: the black
  // tanuki with amber arrows, in the same circle. Classes, not ids: #syncArrows
  // already belongs to the header button.
  card.innerHTML = `
    <div class="sync-notice-row">
      <div class="sync-notice-icon">
        <svg viewBox="0 0 24 24" aria-hidden="true">
          <path fill="#000000" d="M22.65 14.39L12 22.13 1.35 14.39a.84.84 0 01-.3-.94l1.22-3.78 2.44-7.51A.42.42 0 014.82 2a.43.43 0 01.58 0 .42.42 0 01.11.18l2.44 7.49h8.1l2.44-7.51A.42.42 0 0118.6 2a.43.43 0 01.58 0 .42.42 0 01.11.18l2.44 7.51L23 13.45a.84.84 0 01-.35.94z"/>
          <g class="sync-notice-arrows" transform="translate(12, 16) scale(0.56) translate(-12, -12)">
            <path d="M12,18A6,6 0 0,1 6,12C6,11 6.25,10.03 6.7,9.2L5.24,7.74C4.46,8.97 4,10.43 4,12A8,8 0 0,0 12,20V23L16,19L12,15M12,4V1L8,5L12,9V6A6,6 0 0,1 18,12C18,13 17.75,13.97 17.3,14.8L18.76,16.26C19.54,15.03 20,13.57 20,12A8,8 0 0,0 12,4Z"/>
          </g>
        </svg>
      </div>
      <div class="sync-notice-text">
        <div class="sync-notice-title">Sync was paused to protect your data</div>
        <div class="sync-notice-body">
          BMZ found differences between your Snippet and your local bookmarks that need
          your approval. Please review the changes to resume syncing.
        </div>
        <div class="sync-notice-summary">${syncNoticeSummary(syncNoticeCounts)}</div>
      </div>
    </div>
    <div class="sync-notice-actions">
      <button class="sync-notice-review-btn" id="syncNoticeReview">Review changes</button>
      <button class="sync-notice-dismiss-btn" id="syncNoticeDismiss">Not now</button>
    </div>
  `;
  container.appendChild(card);

  // Deferred like the setup card here: the element is in the DOM but the rest of
  // the render is still running.
  setTimeout(() => {
    document.getElementById('syncNoticeReview')?.addEventListener('click', () => {
      window.showHeldPushDialog?.();
    });
    // Dismissal lasts until the situation changes. The amber sync arrows and the
    // toolbar badge stay on whatever happens here, so it is never fully silenced.
    document.getElementById('syncNoticeDismiss')?.addEventListener('click', () => {
      syncNoticeDismissed = true;
      renderBookmarks();
    });
  }, 0);
}

/* [ZeroLabs] 2026-08-27 - added: follow the deferral state */
// Called on a genuine change only, so the worker's five-minute poll re-reaching
// the same deferral does not undo a dismissal.
async function setSyncNoticeVisible(needs) {
  const value = !!needs;
  if (value === syncNoticeVisible) return;
  syncNoticeVisible = value;
  if (value) {
    // A new deferral is worth showing again even if the last one was dismissed
    syncNoticeDismissed = false;
    /* [ZeroLabs] 2026-08-27 - added: read the counts for the summary line */
    // Fetched here rather than passed in, because the two callers - the panel's
    // own setSnippetNeedsReconcile and the worker's storage change - know only
    // that something was deferred, not what.
    try {
      const held = await browser.storage.local.get([
        'snippet_push_held_items',
        'snippet_pull_held_items',
        'snippet_overwrite_held_items'
      ]);
      syncNoticeCounts = {
        fromSnippet: (held.snippet_push_held_items || []).length,
        fromDevice: (held.snippet_pull_held_items || []).length,
        overwrites: (held.snippet_overwrite_held_items || []).length
      };
    } catch (error) {
      // The card still stands on its own without the numbers
      syncNoticeCounts = { fromSnippet: 0, fromDevice: 0, overwrites: 0 };
    }
  }
  renderBookmarks();
}

function renderSections(container) {
  const showQuickAccess = displayOptions.quickAccess;
  const showRecent = displayOptions.recent;
  if (!showQuickAccess && !showRecent) return;

  // A hidden section cannot be the active one.
  let active = activeSection;
  if (active === 'quickAccess' && !showQuickAccess) active = showRecent ? 'recent' : null;
  if (active === 'recent' && !showRecent) active = showQuickAccess ? 'quickAccess' : null;

  const wrapper = document.createElement('div');
  wrapper.className = 'bmz-sections';

  const tabs = document.createElement('div');
  tabs.className = 'bmz-section-tabs';
  if (showQuickAccess && showRecent) tabs.classList.add('split');

  const quickResolved = showQuickAccess ? resolveQuickAccess() : [];
  const recentResolved = showRecent ? resolveRecentOpens() : [];

  if (showQuickAccess) {
    tabs.appendChild(buildSectionHeader({
      title: 'Quick Access',
      stateKey: 'quickAccess',
      iconPath: 'M12,17.27L18.18,21L16.54,13.97L22,9.24L14.81,8.62L12,2L9.19,8.62L2,9.24L7.45,13.97L5.82,21L12,17.27Z'
    }, quickResolved.length, active === 'quickAccess'));
  }

  if (showRecent) {
    tabs.appendChild(buildSectionHeader({
      title: 'Recent',
      stateKey: 'recent',
      iconPath: 'M13,3A9,9 0 0,0 4,12H1L4.89,15.89L4.96,16.03L9,12H6A7,7 0 0,1 13,5A7,7 0 0,1 20,12A7,7 0 0,1 13,19C11.07,19 9.32,18.21 8.06,16.94L6.64,18.36C8.27,20 10.51,21 13,21A9,9 0 0,0 22,12A9,9 0 0,0 13,3M12,8V13L16.28,15.54L17,14.33L13.5,12.25V8H12Z'
    }, recentResolved.length, active === 'recent'));
  }

  wrapper.appendChild(tabs);

  if (active === 'quickAccess') {
    wrapper.appendChild(buildQuickAccessBody(quickResolved));
  } else if (active === 'recent') {
    wrapper.appendChild(buildRecentBody(recentResolved));
  }

  container.appendChild(wrapper);
}

// Create a drop zone element that fills the gap between items
function createDropZone(parentId, targetIndex) {
  const dropZone = document.createElement('div');
  dropZone.className = 'inter-item-drop-zone';
  dropZone.dataset.parentId = parentId;
  dropZone.dataset.targetIndex = targetIndex;

  dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    e.stopPropagation();
    e.dataTransfer.dropEffect = 'move';
    dropZone.classList.add('drop-zone-active');
    console.log('[DropZone] Dragover at index', targetIndex, 'in parent', parentId);
  });

  dropZone.addEventListener('dragleave', () => {
    dropZone.classList.remove('drop-zone-active');
  });

  dropZone.addEventListener('drop', async (e) => {
    e.preventDefault();
    e.stopPropagation();
    dropZone.classList.remove('drop-zone-active');

    const draggedId = e.dataTransfer.getData('text/plain');
    console.log('[DropZone] Drop at index', targetIndex, 'in parent', parentId);
    await handleDropToPosition(draggedId, parentId, targetIndex);
  });

  return dropZone;
}

// Recursively render bookmark nodes
function renderNodes(nodes, container, parentId = 'root________') {
  const isRootLevel = (parentId === 'root________');

  nodes.forEach((node) => {
    // Add the actual item
    if (node.type === 'folder') {
      container.appendChild(createFolderElement(node));
    } else if (node.url) {
      container.appendChild(createBookmarkElement(node));
    }
  });
}

/**
 * Check if a URL is a browser privileged/internal URL
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

// Get status icon HTML based on link status
function getStatusDotHtml(linkStatus, url) {
  // Check if privileged URL
  const privilegedInfo = isPrivilegedUrl(url);
  if (privilegedInfo && linkStatus === 'live') {
    const privilegedTooltip = `Link Status: ${privilegedInfo.label}\n\nThis is a ${privilegedInfo.label.toLowerCase()}`;
    const escapedTooltip = privilegedTooltip.replace(/"/g, '&quot;');
    return `
      <span class="status-icon status-live clickable-status" title="${escapedTooltip}" data-status-message="${escapedTooltip}">
        <svg width="14" height="14" fill="currentColor" viewBox="0 0 24 24">
          <path d="M3.9,12C3.9,10.29 5.29,8.9 7,8.9H11V7H7A5,5 0 0,0 2,12A5,5 0 0,0 7,17H11V15.1H7C5.29,15.1 3.9,13.71 3.9,12M8,13H16V11H8V13M17,7H13V8.9H17C18.71,8.9 20.1,10.29 20.1,12C20.1,13.71 18.71,15.1 17,15.1H13V17H17A5,5 0 0,0 22,12A5,5 0 0,0 17,7Z"/>
        </svg>
      </span>
    `;
  }

  const tooltips = {
    'live': 'Link Status: Live\n\n✓ Link is live and accessible\n✓ Returns successful HTTP response',
    'dead': 'Link Status: Dead\n\n✗ Link is dead or unreachable\n✗ Error, timeout, or connection failed',
    'parked': 'Link Status: Parked\n\n⚠ Domain is parked\n⚠ Redirects to domain parking service',
    'checking': 'Link Status: Checking\n\nChecking link status...',
    'unknown': 'Link Status: Unknown\n\nStatus has not been checked yet'
  };

  const tooltip = tooltips[linkStatus] || tooltips['unknown'];
  const escapedTooltip = tooltip.replace(/"/g, '&quot;');

  const statusIcons = {
    'live': `
      <span class="status-icon status-live clickable-status" title="Link is live and accessible
Returns successful HTTP response" data-status-message="${escapedTooltip}">
        <svg width="14" height="14" fill="currentColor" viewBox="0 0 24 24">
          <path d="M3.9,12C3.9,10.29 5.29,8.9 7,8.9H11V7H7A5,5 0 0,0 2,12A5,5 0 0,0 7,17H11V15.1H7C5.29,15.1 3.9,13.71 3.9,12M8,13H16V11H8V13M17,7H13V8.9H17C18.71,8.9 20.1,10.29 20.1,12C20.1,13.71 18.71,15.1 17,15.1H13V17H17A5,5 0 0,0 22,12A5,5 0 0,0 17,7Z"/>
        </svg>
      </span>
    `,
    'dead': `
      <span class="status-icon status-dead clickable-status" title="Link is dead or unreachable
Error, timeout, or connection failed" data-status-message="${escapedTooltip}">
        <svg width="14" height="14" fill="currentColor" viewBox="0 0 24 24">
          <path d="M3.9,12C3.9,10.29 5.29,8.9 7,8.9H11V7H7A5,5 0 0,0 2,12A5,5 0 0,0 7,17H11V15.1H7C5.29,15.1 3.9,13.71 3.9,12M8,13H16V11H8V13M17,7H13V8.9H17C18.71,8.9 20.1,10.29 20.1,12C20.1,13.71 18.71,15.1 17,15.1H13V17H17A5,5 0 0,0 22,12A5,5 0 0,0 17,7Z"/>
        </svg>
      </span>
    `,
    'parked': `
      <span class="status-icon status-parked clickable-status" title="Domain is parked
Redirects to domain parking service" data-status-message="${escapedTooltip}">
        <svg width="14" height="14" viewBox="0 0 24 24">
          <g fill="currentColor">
            <path d="M3.9,12C3.9,10.29 5.29,8.9 7,8.9H11V7H7A5,5 0 0,0 2,12A5,5 0 0,0 7,17H11V15.1H7C5.29,15.1 3.9,13.71 3.9,12M8,13H16V11H8V13M17,7H13V8.9H17C18.71,8.9 20.1,10.29 20.1,12C20.1,13.71 18.71,15.1 17,15.1H13V17H17A5,5 0 0,0 22,12A5,5 0 0,0 17,7Z"/>
          </g>
          <g fill="#eab308">
            <circle cx="18" cy="6" r="5"/>
            <text x="18" y="9.5" text-anchor="middle" font-size="10" font-weight="bold" fill="white">!</text>
          </g>
        </svg>
      </span>
    `,
    'checking': `
      <span class="status-icon status-checking clickable-status" title="Checking link status..." data-status-message="${escapedTooltip}">
        <svg width="14" height="14" fill="currentColor" viewBox="0 0 24 24">
          <path d="M3.9,12C3.9,10.29 5.29,8.9 7,8.9H11V7H7A5,5 0 0,0 2,12A5,5 0 0,0 7,17H11V15.1H7C5.29,15.1 3.9,13.71 3.9,12M8,13H16V11H8V13M17,7H13V8.9H17C18.71,8.9 20.1,10.29 20.1,12C20.1,13.71 18.71,15.1 17,15.1H13V17H17A5,5 0 0,0 22,12A5,5 0 0,0 17,7Z"/>
        </svg>
      </span>
    `,
    'unknown': `
      <span class="status-icon status-unknown clickable-status" title="Status unknown" data-status-message="${escapedTooltip}">
        <svg width="14" height="14" fill="currentColor" viewBox="0 0 24 24">
          <path d="M3.9,12C3.9,10.29 5.29,8.9 7,8.9H11V7H7A5,5 0 0,0 2,12A5,5 0 0,0 7,17H11V15.1H7C5.29,15.1 3.9,13.71 3.9,12M8,13H16V11H8V13M17,7H13V8.9H17C18.71,8.9 20.1,10.29 20.1,12C20.1,13.71 18.71,15.1 17,15.1H13V17H17A5,5 0 0,0 22,12A5,5 0 0,0 17,7Z"/>
        </svg>
      </span>
    `
  };

  return statusIcons[linkStatus] || statusIcons['unknown'];
}

// Get shield indicator HTML based on safety status
function getShieldHtml(safetyStatus, url, safetySources = []) {
  const encodedUrl = encodeURIComponent(url);

  // Check if privileged URL
  const privilegedInfo = isPrivilegedUrl(url);
  if (privilegedInfo && safetyStatus === 'safe') {
    // Check if sources indicate this is privileged
    const isPrivilegedSource = safetySources && safetySources.length > 0 &&
                                safetySources[0].includes('not scanned');
    if (isPrivilegedSource) {
      const privilegedMessage = `Security Check: ${privilegedInfo.label}\n\n✓ ${privilegedInfo.label}\n✓ Not scanned (trusted browser page)`;
      const escapedMessage = privilegedMessage.replace(/"/g, '&quot;');
      return `
        <span class="shield-indicator shield-safe clickable-status" title="${escapedMessage}" data-url="${encodedUrl}" data-status-message="${escapedMessage}">
          <svg width="14" height="14" fill="currentColor" viewBox="0 0 24 24">
            <path d="M12,1L3,5V11C3,16.55 6.84,21.74 12,23C17.16,21.74 21,16.55 21,11V5L12,1Z"/>
          </svg>
        </span>
      `;
    }
  }

  // Build sources text for unsafe tooltip
  const sourcesText = safetySources && safetySources.length > 0
    ? `\n⛔ Detected by: ${safetySources.join(', ')}`
    : '';

  // Build warning text from actual sources
  const warningText = safetySources && safetySources.length > 0
    ? safetySources.map(source => `⚠ ${source}`).join('\n')
    : '⚠ Suspicious pattern detected';

  // Build full messages for click popup
  const messages = {
    'safe': 'Security Check: Safe\n\n✓ Not found in malware databases\n✓ Passed URLhaus + BlockList checks',
    'warning': `Security Check: Warning\n\n${warningText}`,
    'unsafe': `Security Check: UNSAFE\n\n⛔ Malicious domain detected!${sourcesText}\n⛔ DO NOT VISIT - Exercise extreme caution!`,
    'checking': 'Security Check: Analyzing\n\nChecking URL security patterns...',
    'unknown': 'Security Check: Unknown\n\nUnable to determine safety status\nNot in whitelist or blacklist'
  };

  const message = messages[safetyStatus] || messages['unknown'];
  const escapedMessage = message.replace(/"/g, '&quot;');

  const shieldSvgs = {
    'safe': `
      <span class="shield-indicator shield-safe clickable-status" title="Security Check: Safe
✓ Not found in malware databases
✓ Passed URLhaus + BlockList checks" data-status-message="${escapedMessage}">
        <svg width="14" height="14" fill="currentColor" viewBox="0 0 24 24">
          <path d="M12,1L3,5V11C3,16.55 6.84,21.74 12,23C17.16,21.74 21,16.55 21,11V5L12,1M10,17L6,13L7.41,11.59L10,14.18L16.59,7.59L18,9L10,17Z"/>
        </svg>
      </span>
    `,
    'warning': `
      <span class="shield-indicator shield-warning clickable-status" title="Security Check: Warning
${warningText}" data-status-message="${escapedMessage}">
        <svg width="14" height="14" fill="currentColor" viewBox="0 0 24 24">
          <path d="M12,1L3,5V11C3,16.55 6.84,21.74 12,23C17.16,21.74 21,16.55 21,11V5L12,1M13,7H11V13H13V7M13,17H11V15H13V17Z"/>
        </svg>
      </span>
    `,
    'unsafe': `
      <span class="shield-indicator shield-unsafe clickable-status" title="Security Check: UNSAFE
⛔ Malicious domain detected!${sourcesText}
⛔ DO NOT VISIT - Exercise extreme caution!" data-status-message="${escapedMessage}">
        <svg width="14" height="14" fill="currentColor" viewBox="0 0 24 24">
          <path d="M12,1L3,5V11C3,16.55 6.84,21.74 12,23C17.16,21.74 21,16.55 21,11V5L12,1M12,7C13.1,7 14,7.9 14,9V10.5L15.5,10.5C16.3,10.5 17,11.2 17,12V16C17,16.8 16.3,17.5 15.5,17.5H8.5C7.7,17.5 7,16.8 7,16V12C7,11.2 7.7,10.5 8.5,10.5H10V9C10,7.9 10.9,7 12,7M12,8.2C11.2,8.2 10.8,8.7 10.8,9V10.5H13.2V9C13.2,8.7 12.8,8.2 12,8.2Z"/>
        </svg>
      </span>
    `,
    'checking': `
      <span class="shield-indicator shield-scanning clickable-status" title="Security Check: Analyzing
Checking URL security patterns..." data-status-message="${escapedMessage}">
        <svg width="14" height="14" fill="currentColor" viewBox="0 0 24 24">
          <path d="M12,1L3,5V11C3,16.55 6.84,21.74 12,23C17.16,21.74 21,16.55 21,11V5L12,1Z"/>
        </svg>
      </span>
    `,
    'unknown': `
      <span class="shield-indicator shield-unknown clickable-status" title="Security Check: Unknown
Unable to determine safety status
Not in whitelist or blacklist" data-status-message="${escapedMessage}">
        <svg width="14" height="14" fill="currentColor" viewBox="0 0 24 24">
          <path d="M12,1L3,5V11C3,16.55 6.84,21.74 12,23C17.16,21.74 21,16.55 21,11V5L12,1M12.5,7V12.5H11V7H12.5M12.5,14V15.5H11V14H12.5Z"/>
        </svg>
      </span>
    `,
    'whitelisted': `
      <span class="shield-indicator shield-whitelisted clickable-status" title="Security Check: Whitelisted

✓ Manually trusted by user
✓ Bypasses security checks" data-status-message="${escapedMessage}">
        <svg width="14" height="14" fill="currentColor" viewBox="0 0 24 24" style="filter: drop-shadow(0 0 2px rgba(0,0,0,0.5));">
          <path d="M12,1L3,5V11C3,16.55 6.84,21.74 12,23C17.16,21.74 21,16.55 21,11V5L12,1M10,17L6,13L7.41,11.59L10,14.18L16.59,7.59L18,9L10,17Z" fill="#ffffff"/>
        </svg>
      </span>
    `
  };

  // Check if whitelisted
  const isWhitelisted = safetySources && safetySources.includes('Whitelisted by user');
  if (isWhitelisted) {
    return shieldSvgs['whitelisted'];
  }

  return shieldSvgs[safetyStatus] || shieldSvgs['unknown'];
}

// Create folder element
function createFolderElement(folder) {
  const folderDiv = document.createElement('div');
  folderDiv.className = 'folder-item';
  folderDiv.dataset.id = folder.id;
  // Don't make the entire folderDiv draggable - only the header will be draggable

  const isExpanded = expandedFolders.has(folder.id);
  const childCount = countBookmarks(folder);

  const folderTitle = folder.title || 'Unnamed Folder';

  folderDiv.innerHTML = `
    <div class="folder-header" draggable="true" role="button" aria-expanded="${isExpanded}" aria-label="${escapeHtml(folderTitle)} folder with ${childCount} items">
      ${multiSelectMode ? `<input type="checkbox" class="item-checkbox" data-id="${folder.id}" ${selectedItems.has(folder.id) ? 'checked' : ''} aria-label="Select ${escapeHtml(folderTitle)} folder">` : ''}
      <div class="folder-toggle ${isExpanded ? 'expanded' : ''}" aria-hidden="true"></div>
      <div class="folder-icon-container" aria-hidden="true">
        <svg class="folder-icon-outline" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
          <path d="M3 7C3 5.89543 3.89543 5 5 5H9L11 7H19C20.1046 7 21 7.89543 21 9V17C21 18.1046 20.1046 19 19 19H5C3.89543 19 3 18.1046 3 17V7Z"/>
        </svg>
        <div class="folder-count" data-digits="${childCount.toString().length}">${childCount}</div>
      </div>
      <div class="folder-title">${escapeHtml(folderTitle)}</div>
      <button class="bookmark-menu-btn folder-menu-btn" aria-label="More actions for ${escapeHtml(folderTitle)} folder" aria-haspopup="true" aria-expanded="false">⋮</button>
    </div>
    <div class="folder-children ${isExpanded ? 'show' : ''}" style="border-left: 2px solid #818cf8 !important;"></div>
  `;

  // Add click handler for folder toggle
  const header = folderDiv.querySelector('.folder-header');
  const menuBtn = header.querySelector('.folder-menu-btn');

  header.addEventListener('click', (e) => {
    // Don't toggle if clicking menu button or checkbox
    if (e.target.closest('.folder-menu-btn') ||
        e.target.closest('.item-checkbox')) {
      return;
    }
    // In multi-select mode, toggle the checkbox
    if (multiSelectMode) {
      const checkbox = folderDiv.querySelector('.item-checkbox');
      if (checkbox) {
        checkbox.checked = !checkbox.checked;
        checkbox.dispatchEvent(new Event('change', { bubbles: true }));
      }
      return;
    }
    toggleFolder(folder.id, folderDiv);
  });

  // Add menu button handler
  menuBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    toggleFolderMenu(folder);
  });

  // Add right-click context menu support for folder
  folderDiv.addEventListener('contextmenu', (e) => {
    e.preventDefault();
    e.stopPropagation();
    toggleFolderMenu(folder);
  });

  // Drag and drop handlers for folders (attach to header, not entire folderDiv)
  header.addEventListener('dragstart', (e) => {
    e.stopPropagation(); // Prevent event from bubbling to parent folders
    /* [ZeroLabs] 2026-08-17 4:15 PM - added: mark drag context as tree folder */
    // Distinct from 'tree' so the Quick Access section refuses folders; only
    // bookmarks can be pinned.
    dragContext = 'tree-folder';
    e.dataTransfer.effectAllowed = 'move';
    e.dataTransfer.setData('text/plain', folder.id);
    e.dataTransfer.setData('itemType', 'folder');
    folderDiv.style.opacity = '0.5';
  });

  header.addEventListener('dragend', () => {
    /* [ZeroLabs] 2026-08-17 4:15 PM - added: clear drag context */
    dragContext = null;
    folderDiv.style.opacity = '1';
    removeAllDropIndicators();
    document.querySelectorAll('.bmz-section-drop-target').forEach(el => {
      el.classList.remove('bmz-section-drop-target');
    });
  });

  // Attach dragover/drop to header only, not entire folderDiv
  // This prevents intercepting drag events for bookmarks/subfolders within this folder
  header.addEventListener('dragover', (e) => {
    /* [ZeroLabs] 2026-08-17 4:15 PM - added: reject quick access drags */
    if (dragContext === 'quick-access') return;
    e.preventDefault();
    e.stopPropagation(); // Don't let this bubble to parent folders
    e.dataTransfer.dropEffect = 'move';
    const rect = header.getBoundingClientRect();
    removeAllDropIndicators();
    if (e.clientY < rect.top + rect.height * 0.5) {
      folderDiv.classList.add('drop-before');
    } else {
      folderDiv.classList.add('drop-into');
    }
  });

  header.addEventListener('dragleave', (e) => {
    if (!header.contains(e.relatedTarget)) {
      folderDiv.classList.remove('drop-before', 'drop-into');
    }
  });

  header.addEventListener('drop', async (e) => {
    e.preventDefault();
    e.stopPropagation();
    const dropBefore = folderDiv.classList.contains('drop-before');
    removeAllDropIndicators();
    const draggedId = e.dataTransfer.getData('text/plain');
    await handleDrop(draggedId, folder.id, folderDiv, { dropBefore, dropAfter: false, dropInto: !dropBefore });
  });

  // Render children if expanded
  if (isExpanded && folder.children) {
    const childContainer = folderDiv.querySelector('.folder-children');
    renderNodes(folder.children, childContainer, folder.id);
  }

  return folderDiv;
}

// Create bookmark element
/* [ZeroLabs] 2026-08-17 4:15 PM - edited: mirror option for section rows */
// options.mirror ('quick-access' | 'recent') marks a row as a second copy of a
// bookmark already rendered in the tree. Mirrors keep data-id so scan results
// still reach them, but skip the tree drag handlers entirely.
function createBookmarkElement(bookmark, options = {}) {
  const isMirror = Boolean(options.mirror);
  const bookmarkDiv = document.createElement('div');
  bookmarkDiv.className = 'bookmark-item';
  if (!displayOptions.preview) {
    bookmarkDiv.classList.add('no-preview');
  }
  bookmarkDiv.dataset.id = bookmark.id;
  if (isMirror) {
    bookmarkDiv.classList.add('bookmark-item-mirror');
    bookmarkDiv.dataset.mirror = options.mirror;
  }
  bookmarkDiv.draggable = !isMirror;

  // Get link status (default to unknown)
  const linkStatus = bookmark.linkStatus || 'unknown';
  const safetyStatus = bookmark.safetyStatus || 'unknown';
  const safetySources = bookmark.safetySources || [];

  // Build status indicators HTML based on display options
  let statusIndicatorsHtml = '';
  if (displayOptions.safetyStatus) {
    statusIndicatorsHtml += getShieldHtml(safetyStatus, bookmark.url, safetySources);
  }
  if (displayOptions.liveStatus) {
    statusIndicatorsHtml += getStatusDotHtml(linkStatus, bookmark.url);
  }

  // Also build separate shield and chainlink for grid view
  let shieldHtml = '';
  if (displayOptions.safetyStatus) {
    shieldHtml = getShieldHtml(safetyStatus, bookmark.url, safetySources);
  }

  let linkStatusHtml = '';
  if (displayOptions.liveStatus) {
    linkStatusHtml = getStatusDotHtml(linkStatus, bookmark.url);
  }

  // Build favicon HTML based on display options
  let faviconHtml = '';
  if (displayOptions.favicon && bookmark.url) {
    const faviconUrl = getFaviconUrl(bookmark.url);
    if (faviconUrl) {
      // Firefox CSP doesn't allow inline onerror handlers, so we add the event listener after creating the element
      faviconHtml = `<img class="bookmark-favicon" src="${escapeHtml(faviconUrl)}" alt="" loading="lazy" fetchpriority="low" />`;
    }
  }

  // Build bookmark info HTML based on display options
  let bookmarkInfoHtml = '';
  if (displayOptions.title) {
    bookmarkInfoHtml += `<div class="bookmark-title" title="${escapeHtml(bookmark.url)}">${escapeHtml(bookmark.title || bookmark.url)}</div>`;
  }
  if (displayOptions.url) {
    bookmarkInfoHtml += `<div class="bookmark-url" title="${escapeHtml(bookmark.url)}">${escapeHtml(new URL(bookmark.url).hostname)}</div>`;
  }

  const bookmarkTitle = bookmark.title || bookmark.url;

  bookmarkDiv.innerHTML = `
    ${multiSelectMode && !isMirror ? `<input type="checkbox" class="item-checkbox" data-id="${bookmark.id}" ${selectedItems.has(bookmark.id) ? 'checked' : ''} aria-label="Select ${escapeHtml(bookmarkTitle)}">` : ''}
    <div class="status-indicators">
      ${statusIndicatorsHtml}
    </div>
    ${faviconHtml}
    <div class="bookmark-top-row">
      ${shieldHtml}
      ${faviconHtml}
      ${linkStatusHtml}
    </div>
    <div class="bookmark-info">
      ${bookmarkInfoHtml}
    </div>
    <button class="bookmark-menu-btn" aria-label="More actions for ${escapeHtml(bookmarkTitle)}" aria-haspopup="true" aria-expanded="false">⋮</button>
    <div class="bookmark-preview-container">
      <div class="preview-loading">Loading...</div>
      <img class="preview-image" alt="Preview" data-url="${escapeHtml(bookmark.url)}" />
    </div>
  `;

  // Add click handler for bookmark (open in current tab)
  bookmarkDiv.addEventListener('click', (e) => {
    // Don't open if clicking on menu, preview, status indicators, or checkbox
    if (e.target.closest('.bookmark-menu-btn') ||
        e.target.closest('.bookmark-preview-container') ||
        e.target.closest('.status-indicators') ||
        e.target.closest('.bookmark-top-row') ||
        e.target.closest('.item-checkbox')) {
      return;
    }
    // In multi-select mode, toggle the checkbox
    if (multiSelectMode) {
      const checkbox = bookmarkDiv.querySelector('.item-checkbox');
      if (checkbox) {
        checkbox.checked = !checkbox.checked;
        checkbox.dispatchEvent(new Event('change', { bubbles: true }));
      }
      return;
    }
    // Shift+click: open in new window
    if (e.shiftKey) {
      /* [ZeroLabs] 2026-08-17 4:15 PM - added: track recent opens */
      recordRecentOpen(bookmark.url);
      browser.windows.create({ url: bookmark.url });
      return;
    }
    // Ctrl+click (Cmd+click on Mac): open in new tab
    if (e.ctrlKey || e.metaKey) {
      openBookmarkUrl(bookmark.url, true);
      return;
    }
    // Default: open in active tab
    openBookmarkUrl(bookmark.url, false);
  });

  /* [ZeroLabs] 2026-08-17 4:15 PM - edited: record which section opened the menu */
  // Add menu toggle handler
  const menuBtn = bookmarkDiv.querySelector('.bookmark-menu-btn');
  menuBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    contextMenuOrigin = options.mirror || 'tree';
    toggleBookmarkMenu(bookmark);
  });

  // Add right-click context menu support
  bookmarkDiv.addEventListener('contextmenu', (e) => {
    e.preventDefault();
    e.stopPropagation();
    contextMenuOrigin = options.mirror || 'tree';
    toggleBookmarkMenu(bookmark);
  });

  /* [ZeroLabs] 2026-08-17 4:15 PM - edited: skip tree drag wiring on mirror rows */
  // Mirrors get their own handlers from the section that built them, so the
  // move-a-real-bookmark handlers below must never be attached to one.
  if (!isMirror) {
    // Drag and drop handlers
    bookmarkDiv.addEventListener('dragstart', (e) => {
      e.stopPropagation(); // Prevent event from bubbling to parent folders
      dragContext = 'tree';
      e.dataTransfer.effectAllowed = 'move';
      e.dataTransfer.setData('text/plain', bookmark.id);
      e.dataTransfer.setData('itemType', 'bookmark');
      bookmarkDiv.style.opacity = '0.5';
    });

    bookmarkDiv.addEventListener('dragend', () => {
      dragContext = null;
      bookmarkDiv.style.opacity = '1';
      removeAllDropIndicators();
      document.querySelectorAll('.bmz-section-drop-target').forEach(el => {
        el.classList.remove('bmz-section-drop-target');
      });
    });

    bookmarkDiv.addEventListener('dragover', (e) => {
      if (dragContext === 'quick-access') return; // Pins never enter the tree
      e.preventDefault();
      e.stopPropagation(); // Don't let this bubble to parent folder header
      e.dataTransfer.dropEffect = 'move';
      const rect = bookmarkDiv.getBoundingClientRect();
      removeAllDropIndicators();
      if (e.clientY < rect.top + rect.height * 0.5) {
        bookmarkDiv.classList.add('drop-before');
      } else {
        bookmarkDiv.classList.add('drop-after');
      }
    });

    bookmarkDiv.addEventListener('dragleave', (e) => {
      if (!bookmarkDiv.contains(e.relatedTarget)) {
        bookmarkDiv.classList.remove('drop-before', 'drop-after');
      }
    });

    bookmarkDiv.addEventListener('drop', async (e) => {
      if (dragContext === 'quick-access') return;
      e.preventDefault();
      e.stopPropagation();
      const dropBefore = bookmarkDiv.classList.contains('drop-before');
      removeAllDropIndicators();
      const draggedId = e.dataTransfer.getData('text/plain');
      await handleDrop(draggedId, bookmark.id, bookmarkDiv, { dropBefore, dropAfter: !dropBefore, dropInto: false });
    });
  }

  // Preview hover handler - load image on first hover (only if preview is enabled)
  if (displayOptions.preview) {
    const previewContainer = bookmarkDiv.querySelector('.bookmark-preview-container');
    const previewImage = bookmarkDiv.querySelector('.preview-image');
    const previewLoading = bookmarkDiv.querySelector('.preview-loading');

    // Check if preview was already loaded using global state
    // Always use URL as the key for consistency
    const previewKey = bookmark.url;
    const previewAlreadyLoaded = loadedPreviews.has(previewKey);

    // If preview was already loaded, set the image src immediately
    if (previewAlreadyLoaded && bookmark.url) {
      const previewUrl = getPreviewUrl(bookmark.url);
      if (previewUrl) {
        previewImage.src = previewUrl;
        previewImage.classList.add('loaded');
        previewLoading.style.display = 'none';
      }
    }

    // Prevent all interactions with preview (clicks, drags, context menu)
    previewContainer.addEventListener('click', (e) => {
      e.stopPropagation();
      e.preventDefault();
    });

    previewContainer.addEventListener('mousedown', (e) => {
      e.stopPropagation();
      e.preventDefault();
    });

    previewContainer.addEventListener('contextmenu', (e) => {
      e.stopPropagation();
      e.preventDefault();
    });

    previewImage.addEventListener('dragstart', (e) => {
      e.preventDefault();
    });

    // Preview popup on hover
    previewImage.addEventListener('mouseenter', (e) => {
      showPreviewPopup(previewImage, e);
    });

    previewImage.addEventListener('mouseleave', () => {
      hidePreviewPopup();
    });

    bookmarkDiv.addEventListener('mouseenter', () => {
      if (!loadedPreviews.has(previewKey) && bookmark.url) {
        const previewUrl = getPreviewUrl(bookmark.url);

        if (previewUrl) {
          previewLoading.style.display = 'flex';
          previewLoading.textContent = 'Loading...';

          previewImage.onload = () => {
            previewLoading.style.display = 'none';
            previewImage.classList.add('loaded');
            loadedPreviews.add(previewKey); // Mark as loaded in global state
          };

          previewImage.onerror = () => {
            previewLoading.textContent = 'No preview';
            loadedPreviews.add(previewKey); // Mark as loaded even on error
          };

          previewImage.src = previewUrl;
        } else {
          previewLoading.textContent = 'No preview';
          loadedPreviews.add(previewKey); // Mark as loaded
        }
      }
    });
  }

  return bookmarkDiv;
}

// Get preview URL for a bookmark
function getPreviewUrl(url) {
  // Using WordPress mshots service (same as React webapp)
  try {
    const encodedUrl = encodeURIComponent(url);
    return `https://s.wordpress.com/mshots/v1/${encodedUrl}?w=320&h=180`;
  } catch (error) {
    console.error('Error generating preview URL:', error);
    return '';
  }
}

// Preview popup handling
let previewPopup = null;
let previewPopupEnabled = true; // Will be loaded from settings

// Create preview popup element
function createPreviewPopup() {
  if (!previewPopup) {
    previewPopup = document.createElement('div');
    previewPopup.className = 'preview-popup';
    previewPopup.innerHTML = '<img alt="Preview" />';
    document.body.appendChild(previewPopup);
  }
  return previewPopup;
}

// Show preview popup
function showPreviewPopup(previewImage, mouseEvent) {
  if (!previewPopupEnabled || !previewImage.classList.contains('loaded')) {
    return;
  }

  const popup = createPreviewPopup();
  const popupImg = popup.querySelector('img');

  // Get the bookmark URL from the preview image's data attribute
  const bookmarkUrl = previewImage.dataset.url;

  // Load high-quality preview (800x600 instead of 320x180)
  try {
    const encodedUrl = encodeURIComponent(bookmarkUrl);
    popupImg.src = `https://s.wordpress.com/mshots/v1/${encodedUrl}?w=800&h=600`;
  } catch (error) {
    console.error('Error loading high-quality preview:', error);
    popupImg.src = previewImage.src; // Fallback to low-res
  }

  // Position the popup with smart positioning
  const sidebar = document.body;
  const sidebarRect = sidebar.getBoundingClientRect();
  const header = document.querySelector('.header');
  const statusBar = document.querySelector('.scan-status-bar');

  // Get the bookmark element that contains the preview image
  const bookmarkElement = previewImage.closest('.bookmark-item, .folder-item');
  const bookmarkRect = bookmarkElement ? bookmarkElement.getBoundingClientRect() : null;

  // Calculate available space
  const headerBottom = header ? header.getBoundingClientRect().bottom : 0;
  const statusBarTop = statusBar ? statusBar.getBoundingClientRect().top : sidebarRect.bottom;

  // Set max width to 90% of sidebar minus margins
  const maxWidth = sidebarRect.width * 0.9;
  popup.style.maxWidth = `${maxWidth}px`;

  // Show popup to calculate dimensions
  popup.classList.add('show');

  // Wait for image to load dimensions
  if (popupImg.complete) {
    positionPopup();
  } else {
    popupImg.onload = positionPopup;
  }

  function positionPopup() {
    const popupRect = popup.getBoundingClientRect();

    // Center horizontally in sidebar
    const left = sidebarRect.left + (sidebarRect.width - popupRect.width) / 2;

    // Position vertically - above or below bookmark to avoid covering it
    let top;
    if (bookmarkRect) {
      // Calculate space above and below the bookmark
      const spaceAbove = bookmarkRect.top - headerBottom - 20;
      const spaceBelow = statusBarTop - bookmarkRect.bottom - 20;

      // Try to position below first, then above if not enough space
      if (spaceBelow >= popupRect.height) {
        // Position below bookmark
        top = bookmarkRect.bottom + 10;
      } else if (spaceAbove >= popupRect.height) {
        // Position above bookmark
        top = bookmarkRect.top - popupRect.height - 10;
      } else {
        // Not enough space either way, use the side with more space
        if (spaceBelow > spaceAbove) {
          top = bookmarkRect.bottom + 10;
          // Might extend past status bar, but that's okay
        } else {
          top = Math.max(headerBottom + 20, bookmarkRect.top - popupRect.height - 10);
        }
      }
    } else {
      // Fallback: center on mouse position
      top = mouseEvent.clientY - popupRect.height / 2;
      const minTop = headerBottom + 20;
      const maxTop = statusBarTop - popupRect.height - 20;
      top = Math.max(minTop, Math.min(top, maxTop));
    }

    popup.style.left = `${left}px`;
    popup.style.top = `${top}px`;
  }
}

// Hide preview popup
function hidePreviewPopup() {
  if (previewPopup) {
    previewPopup.classList.remove('show');
  }
}

// QR Code popup handling (local generation, privacy-focused)
let qrCodePopup = null;

// Create QR code popup element
function createQRCodePopup() {
  if (!qrCodePopup) {
    qrCodePopup = document.createElement('div');
    qrCodePopup.className = 'qr-popup';
    qrCodePopup.innerHTML = `
      <div class="qr-popup-content">
        <button class="qr-close-btn" aria-label="Close">&times;</button>
        <div class="qr-container"></div>
        <input type="text" class="qr-url-input" placeholder="Enter URL..." />
      </div>
    `;
    document.body.appendChild(qrCodePopup);

    // Add click handler for close button
    const closeBtn = qrCodePopup.querySelector('.qr-close-btn');
    closeBtn.addEventListener('click', hideQRCodePopup);

    // Close on backdrop click
    qrCodePopup.addEventListener('click', (e) => {
      if (e.target === qrCodePopup) {
        hideQRCodePopup();
      }
    });

    // Close on Escape key
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && qrCodePopup && qrCodePopup.classList.contains('show')) {
        hideQRCodePopup();
      }
    });
  }
  return qrCodePopup;
}

// Show QR code popup with locally generated QR code
function showQRCodePopup(url) {
  const popup = createQRCodePopup();
  const qrContainer = popup.querySelector('.qr-container');
  const qrUrlInput = popup.querySelector('.qr-url-input');

  // Set the initial URL in the input
  qrUrlInput.value = url;

  // Function to generate/regenerate QR code
  function generateQR(text) {
    // Clear previous QR code
    qrContainer.innerHTML = '';

    // Generate QR code locally using qrcode-lib.js
    try {
      new QRCode(qrContainer, {
        text: text,
        width: 280,
        height: 280,
        colorDark: '#000000',
        colorLight: '#ffffff',
        correctLevel: QRCode.CorrectLevel.M
      });
    } catch (error) {
      console.error('Error generating QR code:', error);
      qrContainer.innerHTML = '<div style="padding: 20px;">Error generating QR code</div>';
    }
  }

  // Generate initial QR code
  generateQR(url);

  // Regenerate QR code on input change
  qrUrlInput.addEventListener('input', (e) => {
    const newUrl = e.target.value;
    if (newUrl.trim()) {
      generateQR(newUrl);
    }
  });

  // Show popup
  popup.classList.add('show');
}

// Hide QR code popup
function hideQRCodePopup() {
  if (qrCodePopup) {
    qrCodePopup.classList.remove('show');
  }
}

// Load preview popup setting
async function loadPreviewPopupSetting() {
  try {
    const result = await safeStorage.get('previewPopupEnabled');
    if (result.previewPopupEnabled !== undefined) {
      previewPopupEnabled = result.previewPopupEnabled;
      // Update checkbox state
      const checkbox = document.getElementById('displayPreviewPopup');
      if (checkbox) {
        checkbox.checked = previewPopupEnabled;
      }
    }
  } catch (error) {
    console.error('Error loading preview popup setting:', error);
  }
}

// Initialize preview popup setting
loadPreviewPopupSetting();

// Drag and drop helper functions
// Auto-scroll during drag when cursor is near top/bottom edges
// Note: capture phase is required because child drag handlers call stopPropagation()
let dragScrollInterval = null;
let isDragging = false;

document.addEventListener('dragstart', () => { isDragging = true; }, true);
document.addEventListener('dragend', () => { isDragging = false; stopDragScroll(); }, true);
document.addEventListener('drop', () => { isDragging = false; stopDragScroll(); }, true);

bookmarkList.addEventListener('dragover', (e) => {
  if (!isDragging) return;
  const rect = bookmarkList.getBoundingClientRect();
  const scrollZone = 60;
  const maxSpeed = 20;
  const y = e.clientY - rect.top;
  const bottomY = rect.bottom - e.clientY;

  if (y < scrollZone) {
    const speed = Math.ceil(maxSpeed * (1 - y / scrollZone));
    startDragScroll(-speed);
  } else if (bottomY < scrollZone) {
    const speed = Math.ceil(maxSpeed * (1 - bottomY / scrollZone));
    startDragScroll(speed);
  } else {
    stopDragScroll();
  }
}, true);

bookmarkList.addEventListener('dragleave', (e) => {
  if (!bookmarkList.contains(e.relatedTarget)) {
    stopDragScroll();
  }
}, true);

function startDragScroll(speed) {
  if (dragScrollInterval) cancelAnimationFrame(dragScrollInterval);
  const scroll = () => {
    bookmarkList.scrollTop += speed;
    dragScrollInterval = requestAnimationFrame(scroll);
  };
  dragScrollInterval = requestAnimationFrame(scroll);
}

function stopDragScroll() {
  if (dragScrollInterval) {
    cancelAnimationFrame(dragScrollInterval);
    dragScrollInterval = null;
  }
}


function handleDragOver(e, targetElement) {
  // No-op: drop-before/after/into is handled inline in folder/bookmark dragover listeners.
}

function removeDropIndicator(element) {
  element.classList.remove('drop-before', 'drop-after', 'drop-into');
}

function removeAllDropIndicators() {
  document.querySelectorAll('.drop-before, .drop-after, .drop-into').forEach(el => {
    el.classList.remove('drop-before', 'drop-after', 'drop-into');
  });
}

async function handleDropToRoot(draggedId) {
  /* [ZeroLabs] 2026-08-17 4:15 PM - added: reject quick access drags */
  if (dragContext === 'quick-access') return;
  // Drop at the end of root (after all root items)
  const draggedItem = findBookmarkById(bookmarkTree, draggedId);
  if (!draggedItem) {
    console.error('Could not find dragged item');
    return;
  }

  try {
    // Get old parent folder path before moving
    const oldParent = draggedItem.parentId ? await getFolderPath(draggedItem.parentId) : 'Root';

    // Move to root at the last position
    await browser.bookmarks.move(draggedId, {
      parentId: undefined,
      index: bookmarkTree.length
    });

    // Add to changelog
    const itemType = draggedItem.url ? 'bookmark' : 'folder';
    await addChangelogEntry('move', itemType, draggedItem.title, draggedItem.url, { oldParent, newParent: 'Root' });

    await loadBookmarks();
    renderBookmarks();
  } catch (error) {
    console.error('Error moving to root:', error);
    alert('Failed to move item');
  }
}

async function handleDropToPosition(draggedId, targetParentId, targetIndex) {
  /* [ZeroLabs] 2026-08-17 4:15 PM - added: reject quick access drags */
  if (dragContext === 'quick-access') return;
  const draggedItem = findBookmarkById(bookmarkTree, draggedId);
  if (!draggedItem) {
    console.error('Could not find dragged item');
    return;
  }

  try {
    // Get old parent folder path before moving
    const oldParent = draggedItem.parentId ? await getFolderPath(draggedItem.parentId) : 'Root';

    await browser.bookmarks.move(draggedId, {
      parentId: targetParentId === 'root________' ? undefined : targetParentId,
      index: targetIndex
    });

    // Get new parent folder path after moving
    const newParent = targetParentId === 'root________' ? 'Root' : await getFolderPath(targetParentId);

    // Add to changelog
    const itemType = draggedItem.url ? 'bookmark' : 'folder';
    await addChangelogEntry('move', itemType, draggedItem.title, draggedItem.url, { oldParent, newParent });

    await loadBookmarks();
    renderBookmarks();
  } catch (error) {
    console.error('Error moving to position:', error);
    alert('Failed to move item');
  }
}

async function handleDrop(draggedId, targetId, targetElement, dropState) {
  /* [ZeroLabs] 2026-08-17 4:15 PM - added: reject quick access drags */
  if (dragContext === 'quick-access') return;
  if (draggedId === targetId) return; // Can't drop on itself

  try {
    // Get the position to drop (before, after, or into target)
    const dropBefore = dropState.dropBefore;
    const dropInto = dropState.dropInto;

    // Find the dragged and target items in the tree
    const draggedItem = findBookmarkById(bookmarkTree, draggedId);
    const targetItem = findBookmarkById(bookmarkTree, targetId);

    if (!draggedItem || !targetItem) {
      console.error('Could not find dragged or target item');
      return;
    }

    // Determine the parent and index based on drop type
    let targetParentId;
    let targetIndex;

    if (dropInto && targetItem.type === 'folder') {
      // Dropping INTO a folder - item becomes child at index 0
      targetParentId = targetItem.id;
      targetIndex = 0;
    } else {
      // Dropping BEFORE or AFTER - item goes next to target in target's parent
      const targetParent = findParentById(bookmarkTree, targetId);
      targetParentId = targetParent ? targetParent.id : undefined;

      // Get target's index in its parent
      if (targetParent) {
        targetIndex = targetParent.children.findIndex(child => child.id === targetId);
      } else {
        targetIndex = bookmarkTree.findIndex(item => item.id === targetId);
      }

      // Calculate new index based on drop position
      targetIndex = dropBefore ? targetIndex : targetIndex + 1;

      // Adjust for same-parent moves: browser.bookmarks.move removes the dragged item first,
      // which shifts down all items after it. If dragged item is in the same parent and
      // comes before the target, subtract 1 to account for that shift.
      const draggedParent = findParentById(bookmarkTree, draggedId);
      const draggedParentId = draggedParent ? draggedParent.id : undefined;
      if (draggedParentId === targetParentId) {
        const draggedIndex = draggedParent
          ? draggedParent.children.findIndex(c => c.id === draggedId)
          : bookmarkTree.findIndex(i => i.id === draggedId);
        if (draggedIndex < targetIndex) {
          targetIndex -= 1;
        }
      }
    }

    // Check if dropping a folder into itself or its descendants (prevent invalid moves)
    if (draggedItem.type === 'folder' && targetParentId) {
      let currentParent = findBookmarkById(bookmarkTree, targetParentId);
      while (currentParent) {
        if (currentParent.id === draggedId) {
          console.log('Cannot drop folder into itself or its descendants');
          return;
        }
        currentParent = findParentById(bookmarkTree, currentParent.id);
      }
    }

    const newIndex = targetIndex;

    // Move the bookmark using Firefox API
    // Get old parent folder path before moving
    const oldParent = draggedItem.parentId ? await getFolderPath(draggedItem.parentId) : 'Root';

    await browser.bookmarks.move(draggedId, {
      parentId: targetParentId,
      index: newIndex
    });

    // Get new parent folder path after moving
    const newParent = targetParentId ? await getFolderPath(targetParentId) : 'Root';

    // Add to changelog
    const itemType = draggedItem.url ? 'bookmark' : 'folder';
    await addChangelogEntry('move', itemType, draggedItem.title, draggedItem.url, { oldParent, newParent });

    // Reload and re-render
    await loadBookmarks();
    renderBookmarks();
  } catch (error) {
    console.error('Error moving bookmark:', error);
    alert('Failed to move item');
  }
}
// Helper function to find parent of bookmark by ID
function findParentById(nodes, childId, parent = null) {
  for (const node of nodes) {
    if (node.id === childId) return parent;
    if (node.children) {
      const found = findParentById(node.children, childId, node);
      if (found) return found;
    }
  }
  return null;
}

// Toggle folder expanded state
function toggleFolder(folderId, folderElement) {
  const isExpanded = expandedFolders.has(folderId);

  if (isExpanded) {
    expandedFolders.delete(folderId);
  } else {
    expandedFolders.add(folderId);
    // When expanding a folder, check its bookmarks only if cache expired (>7 days) or never scanned
    if (shouldScanFolder(folderId)) {
      console.log(`[Folder Scan Cache] Folder ${folderId} needs scanning (cache expired or never scanned)`);
      setTimeout(async () => {
        /* [ZeroLabs] 2026-08-28 - fixed: only record a scan that happened */
        // The call was not even awaited, so the timestamp was written before the
        // scan started and regardless of whether it ran at all. Expanding a
        // folder with checking switched off marked it scanned for seven days,
        // and it stayed blank long after checking was turned back on.
        const scanned = await autoCheckBookmarkStatuses();
        if (scanned) saveFolderScanTimestamp(folderId);
      }, 100);
    } else {
      const lastScan = folderScanTimestamps[folderId];
      const daysAgo = Math.floor((Date.now() - lastScan) / (24 * 60 * 60 * 1000));
      console.log(`[Folder Scan Cache] Folder ${folderId} already scanned ${daysAgo} day(s) ago, skipping`);
    }
  }

  // Save session state when folder is toggled
  saveSessionStateDebounced();

  // Re-render to reflect changes
  renderBookmarks();
}

// Toggle bookmark menu - opens context menu modal
function toggleBookmarkMenu(bookmark) {
  openContextMenuModal(bookmark, false);
}

// Toggle folder menu - opens context menu modal
function toggleFolderMenu(folder) {
  openContextMenuModal(folder, true);
}

// Open context menu as a modal panel
function openContextMenuModal(item, isFolder) {
  const modal = document.getElementById('contextMenuModal');
  const title = document.getElementById('contextMenuModalTitle');
  const body = document.getElementById('contextMenuModalBody');

  // Set title
  const displayTitle = item.title || (isFolder ? 'Untitled Folder' : 'Untitled Bookmark');
  title.textContent = displayTitle;

  // Build action buttons
  let buttonsHtml = '';

  if (isFolder) {
    buttonsHtml = `
      <button class="action-btn" data-action="rescan-folder">
        <span class="icon"><svg width="14" height="14" fill="currentColor" viewBox="0 0 24 24"><path d="M12,18A6,6 0 0,1 6,12C6,11 6.25,10.03 6.7,9.2L5.24,7.74C4.46,8.97 4,10.43 4,12A8,8 0 0,0 12,20V23L16,19L12,15M12,4V1L8,5L12,9V6A6,6 0 0,1 18,12C18,13 17.75,13.97 17.3,14.8L18.76,16.26C19.54,15.03 20,13.57 20,12A8,8 0 0,0 12,4Z"/></svg></span>
        <span>Rescan Bookmarks in Folder</span>
      </button>
      <button class="action-btn" data-action="add-bookmark">
        <span class="icon"><svg width="14" height="14" fill="currentColor" viewBox="0 0 24 24"><path d="M19,13H13V19H11V13H5V11H11V5H13V11H19V13Z"/></svg></span>
        <span>Add Bookmark Here</span>
      </button>
      <button class="action-btn" data-action="add-subfolder">
        <span class="icon"><svg width="14" height="14" fill="currentColor" viewBox="0 0 24 24"><path d="M13,19V13H19V11H13V5H11V11H5V13H11V19H13M20,18H22V20H2V18H4V10A2,2 0 0,1 6,8H10V6A2,2 0 0,1 12,4H16A2,2 0 0,1 18,6V8H20A2,2 0 0,1 22,10V18M18,10H6V18H18V10M16,6H12V8H16V6Z"/></svg></span>
        <span>Add Subfolder Here</span>
      </button>
      <button class="action-btn" data-action="rename">
        <span class="icon"><svg width="14" height="14" fill="currentColor" viewBox="0 0 24 24"><path d="M20.71,7.04C21.1,6.65 21.1,6 20.71,5.63L18.37,3.29C18,2.9 17.35,2.9 16.96,3.29L15.12,5.12L18.87,8.87M3,17.25V21H6.75L17.81,9.93L14.06,6.18L3,17.25Z"/></svg></span>
        <span>Rename</span>
      </button>
      <button class="action-btn" data-action="move-to">
        <span class="icon"><svg width="14" height="14" fill="currentColor" viewBox="0 0 24 24"><path d="M14,18L12.6,16.6L15.2,14H4V12H15.2L12.6,9.4L14,8L19,13L14,18Z"/></svg></span>
        <span>Move to...</span>
      </button>
      <button class="action-btn danger" data-action="delete">
        <span class="icon"><svg width="14" height="14" fill="currentColor" viewBox="0 0 24 24"><path d="M19,4H15.5L14.5,3H9.5L8.5,4H5V6H19M6,19A2,2 0 0,0 8,21H16A2,2 0 0,0 18,19V7H6V19Z"/></svg></span>
        <span>Delete</span>
      </button>
    `;
  } else {
    buttonsHtml = `
      <button class="action-btn" data-action="open">
        <span class="icon"><svg width="14" height="14" fill="currentColor" viewBox="0 0 24 24"><path d="M3.9,12C3.9,10.29 5.29,8.9 7,8.9H11V7H7A5,5 0 0,0 2,12A5,5 0 0,0 7,17H11V15.1H7C5.29,15.1 3.9,13.71 3.9,12M8,13H16V11H8V13M17,7H13V8.9H17C18.71,8.9 20.1,10.29 20.1,12C20.1,13.71 18.71,15.1 17,15.1H13V17H17A5,5 0 0,0 22,12A5,5 0 0,0 17,7Z"/></svg></span>
        <span>Open</span>
      </button>
      <button class="action-btn" data-action="open-new-tab">
        <span class="icon"><svg width="14" height="14" fill="currentColor" viewBox="0 0 24 24"><path d="M14,3V5H17.59L7.76,14.83L9.17,16.24L19,6.41V10H21V3M19,19H5V5H12V3H5C3.89,3 3,3.9 3,5V19A2,2 0 0,0 5,21H19A2,2 0 0,0 21,19V12H19V19Z"/></svg></span>
        <span>Open in New Tab</span>
      </button>
      <button class="action-btn" data-action="open-new-window">
        <span class="icon"><svg width="14" height="14" fill="currentColor" viewBox="0 0 24 24"><path d="M19,19H5V5H19M19,3H5A2,2 0 0,0 3,5V19A2,2 0 0,0 5,21H19A2,2 0 0,0 21,19V5A2,2 0 0,0 19,3M13.96,12.29L11.21,15.83L9.25,13.47L6.5,17H17.5L13.96,12.29Z"/></svg></span>
        <span>Open in New Window</span>
      </button>
      <button class="action-btn" data-action="reader-view">
        <span class="icon"><svg width="14" height="14" fill="currentColor" viewBox="0 0 24 24"><path d="M21,4H3A2,2 0 0,0 1,6V19A2,2 0 0,0 3,21H21A2,2 0 0,0 23,19V6A2,2 0 0,0 21,4M3,19V6H11V19H3M21,19H13V6H21V19M14,9.5H20V11H14V9.5M14,12H20V13.5H14V12M14,14.5H20V16H14V14.5Z"/></svg></span>
        <span>Open with Textise</span>
      </button>
      <button class="action-btn" data-action="save-pdf">
        <span class="icon"><svg width="14" height="14" fill="currentColor" viewBox="0 0 24 24"><path d="M14,2H6A2,2 0 0,0 4,4V20A2,2 0 0,0 6,22H18A2,2 0 0,0 20,20V8L14,2M18,20H6V4H13V9H18V20M10.1,11.4C10.08,11.44 9.81,13.16 8,16.09C8,16.09 4.5,17.91 5.33,19.27C6,20.35 7.65,19.23 9.07,16.59C9.07,16.59 10.89,15.95 13.31,15.77C13.31,15.77 17.17,17.5 17.7,15.66C18.22,13.8 14.64,14.22 14,14.41C14,14.41 12,13.06 11.5,11.2C11.5,11.2 12.64,7.25 10.89,7.3C9.14,7.35 9.8,10.43 10.1,11.4M10.91,12.44C10.94,12.45 11.38,13.65 12.8,14.9C12.8,14.9 10.47,15.36 9.41,15.8C9.41,15.8 10.41,14.07 10.91,12.44M14.84,15.16C15.42,15 17,14.91 16.88,15.45C16.78,15.97 14.88,15.23 14.84,15.16M10.58,10.34C10.58,10.34 9.7,8.24 10.38,8.23C11.07,8.22 10.88,10.05 10.58,10.34Z"/></svg></span>
        <span>Save Page as PDF</span>
      </button>
      <button class="action-btn" data-action="recheck">
        <span class="icon"><svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg></span>
        <span>Recheck Security Status</span>
      </button>
      <button class="action-btn" data-action="whitelist">
        <span class="icon"><svg width="14" height="14" fill="currentColor" viewBox="0 0 24 24"><path d="M12,1L3,5V11C3,16.55 6.84,21.74 12,23C17.16,21.74 21,16.55 21,11V5L12,1M10,17L6,13L7.41,11.59L10,14.17L16.59,7.58L18,9L10,17Z"/></svg></span>
        <span>Whitelist (Trust Site)</span>
      </button>
      <button class="action-btn" data-action="virustotal">
        <span class="icon"><svg width="14" height="14" fill="currentColor" viewBox="0 0 24 24"><path d="M12,1L3,5V11C3,16.55 6.84,21.74 12,23C17.16,21.74 21,16.55 21,11V5L12,1M12,5A3,3 0 0,1 15,8A3,3 0 0,1 12,11A3,3 0 0,1 9,8A3,3 0 0,1 12,5M17.13,17C15.92,18.85 14.11,20.24 12,20.92C9.89,20.24 8.08,18.85 6.87,17C6.53,16.5 6.24,16 6,15.47C6,13.82 8.71,12.47 12,12.47C15.29,12.47 18,13.79 18,15.47C17.76,16 17.47,16.5 17.13,17Z"/></svg></span>
        <span>Check on VirusTotal</span>
      </button>
      <button class="action-btn" data-action="qr-code">
        <span class="icon"><svg width="14" height="14" fill="currentColor" viewBox="0 0 24 24"><path d="M3,11H11V3H3M5,5H9V9H5M13,3V11H21V3M19,9H15V5H19M3,21H11V13H3M5,15H9V19H5M19,19V21H21V19M13,13H15V15H13M15,15H17V17H15M17,17H19V19H17M19,13V15H21V13M13,21H15V19H13M15,19H17V21H15Z"/></svg></span>
        <span>Generate QR Code</span>
      </button>
      <button class="action-btn" data-action="wayback-save">
        <span class="icon"><svg width="14" height="14" fill="currentColor" viewBox="0 0 24 24"><path d="M12,20A8,8 0 0,0 20,12A8,8 0 0,0 12,4A8,8 0 0,0 4,12A8,8 0 0,0 12,20M12,2A10,10 0 0,1 22,12A10,10 0 0,1 12,22C6.47,22 2,17.5 2,12A10,10 0 0,1 12,2M12.5,7V12.25L17,14.92L16.25,16.15L11,13V7H12.5Z"/></svg></span>
        <span>Save to Wayback Machine</span>
      </button>
      <button class="action-btn" data-action="wayback-browse">
        <span class="icon"><svg width="14" height="14" fill="currentColor" viewBox="0 0 24 24"><path d="M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2M12,20C7.59,20 4,16.41 4,12C4,7.59 7.59,4 12,4C16.41,4 20,7.59 20,12C20,16.41 16.41,20 12,20M16.59,7.58L10,14.17L7.41,11.59L6,13L10,17L18,9L16.59,7.58Z"/></svg></span>
        <span>Browse Wayback Snapshots</span>
      </button>
      <button class="action-btn" data-action="copy-url">
        <span class="icon"><svg width="14" height="14" fill="currentColor" viewBox="0 0 24 24"><path d="M19,21H8V7H19M19,5H8A2,2 0 0,0 6,7V21A2,2 0 0,0 8,23H19A2,2 0 0,0 21,21V7A2,2 0 0,0 19,5M16,1H4A2,2 0 0,0 2,3V17H4V3H16V1Z"/></svg></span>
        <span>Copy URL</span>
      </button>
      <button class="action-btn" data-action="edit">
        <span class="icon"><svg width="14" height="14" fill="currentColor" viewBox="0 0 24 24"><path d="M20.71,7.04C21.1,6.65 21.1,6 20.71,5.63L18.37,3.29C18,2.9 17.35,2.9 16.96,3.29L15.12,5.12L18.87,8.87M3,17.25V21H6.75L17.81,9.93L14.06,6.18L3,17.25Z"/></svg></span>
        <span>Edit</span>
      </button>
      <button class="action-btn" data-action="move-to">
        <span class="icon"><svg width="14" height="14" fill="currentColor" viewBox="0 0 24 24"><path d="M14,18L12.6,16.6L15.2,14H4V12H15.2L12.6,9.4L14,8L19,13L14,18Z"/></svg></span>
        <span>Move to...</span>
      </button>
      <button class="action-btn danger" data-action="delete">
        <span class="icon"><svg width="14" height="14" fill="currentColor" viewBox="0 0 24 24"><path d="M19,4H15.5L14.5,3H9.5L8.5,4H5V6H19M6,19A2,2 0 0,0 8,21H16A2,2 0 0,0 18,19V7H6V19Z"/></svg></span>
        <span>Delete</span>
      </button>
    `;

    /* [ZeroLabs] 2026-08-19 5:23 PM - edited: pin and unpin share one slot above Delete */
    // Both states occupy the SAME position, directly above Delete, so the item
    // never moves when you pin or unpin: only its label and colour change.
    // Only the removal state is red, since adding loses nothing. In the Quick
    // Access menu Delete has been stripped, so it simply lands last there.
    const pinIcon = '<svg width="14" height="14" fill="currentColor" viewBox="0 0 24 24"><path d="M12,17.27L18.18,21L16.54,13.97L22,9.24L14.81,8.62L12,2L9.19,8.62L2,9.24L7.45,13.97L5.82,21L12,17.27Z"/></svg>';
    const pinned = isPinned(item.url);

    if (contextMenuOrigin === 'quick-access') {
      // Opened from the Quick Access section. Delete and Move to belong to the
      // real bookmark, and neither should be reachable from a mirror, so the
      // whole menu collapses to unpin plus the harmless actions.
      buttonsHtml = buttonsHtml
        .replace(/\s*<button class="action-btn danger" data-action="delete">[\s\S]*?<\/button>/, '')
        .replace(/\s*<button class="action-btn" data-action="move-to">[\s\S]*?<\/button>/, '');
    }

    const pinButton = `
      <button class="action-btn${pinned ? ' danger' : ''}" data-action="${pinned ? 'unpin-quick-access' : 'pin-quick-access'}">
        <span class="icon">${pinIcon}</span>
        <span>${pinned ? 'Remove from Quick Access' : 'Add to Quick Access'}</span>
      </button>
    `;

    // Function replacer, not a $1 string, so the SVG path can never be read as
    // a substitution pattern.
    const deleteButton = /<button class="action-btn danger" data-action="delete">[\s\S]*?<\/button>/;
    if (deleteButton.test(buttonsHtml)) {
      buttonsHtml = buttonsHtml.replace(deleteButton, (match) => pinButton + match);
    } else {
      buttonsHtml += pinButton;
    }
  }

  body.innerHTML = buttonsHtml;

  // Add click handlers to all action buttons
  body.querySelectorAll('.action-btn').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      e.stopPropagation();
      const action = btn.dataset.action;
      closeContextMenuModal();
      if (isFolder) {
        await handleFolderAction(action, item);
      } else {
        await handleBookmarkAction(action, item);
      }
    });
  });

  // Show modal
  modal.classList.remove('hidden');
  modal.setAttribute('aria-hidden', 'false');
  trapFocus(modal);
}

// Close context menu modal
function closeContextMenuModal() {
  const modal = document.getElementById('contextMenuModal');
  if (!modal || modal.classList.contains('hidden')) return;
  const content = modal.querySelector('.context-menu-modal-content');
  if (content) {
    content.classList.add('closing');
    content.addEventListener('animationend', () => {
      content.classList.remove('closing');
      modal.classList.add('hidden');
      modal.setAttribute('aria-hidden', 'true');
      releaseFocusTrap();
    }, { once: true });
  } else {
    modal.classList.add('hidden');
    modal.setAttribute('aria-hidden', 'true');
    releaseFocusTrap();
  }
}

// Handle folder actions
async function handleFolderAction(action, folder) {
  switch (action) {
    case 'rescan-folder':
      await rescanFolder(folder.id, folder.title);
      break;

    case 'add-bookmark':
      // Open add bookmark modal with this folder pre-selected
      await openAddBookmarkModal();
      // Pre-select this folder
      const folderSelect = document.getElementById('newBookmarkFolder');
      if (folderSelect) {
        folderSelect.value = folder.id;
      }
      break;

    case 'add-subfolder':
      // Open add folder modal with this folder pre-selected as parent
      openAddFolderModal();
      // Pre-select this folder as parent
      const parentSelect = document.getElementById('newFolderParent');
      if (parentSelect) {
        parentSelect.value = folder.id;
      }
      break;

    case 'rename':
      openEditModal(folder, true);
      break;

    case 'move-to':
      openMoveToModal(folder, true);
      break;

    case 'delete':
      // SAFETY: Enhanced confirmation showing number of items to be deleted
      const itemCount = await countFolderItems(folder.id);
      const warningMessage = itemCount > 0
        ? `⚠ Delete folder "${folder.title}" and ALL ${itemCount} item(s) inside?\n\nYou can undo this from the toast or the changelog.`
        : `Delete empty folder "${folder.title}"?`;

      if (confirm(warningMessage)) {
        await deleteFolder(folder.id);
      }
      break;
  }
}

// Rescan all bookmarks in a folder and its subfolders
async function rescanFolder(folderId, folderTitle) {
  try {
    console.log(`[Folder Rescan] Starting rescan for folder: ${folderTitle} (${folderId})`);

    // Get all bookmarks recursively from this folder
    const bookmarks = [];
    const collectBookmarks = async (nodeId) => {
      const nodes = await browser.bookmarks.getChildren(nodeId);
      for (const node of nodes) {
        // Skip separators
        if (node.type === 'separator') continue;

        if (node.url) {
          // It's a bookmark
          bookmarks.push(node);
        } else if (node.children || node.type === 'folder') {
          // It's a folder, recurse into it
          await collectBookmarks(node.id);
        }
      }
    };

    await collectBookmarks(folderId);

    if (bookmarks.length === 0) {
      alert(`Folder "${folderTitle}" has no bookmarks to scan.`);
      return;
    }

    console.log(`[Folder Rescan] Found ${bookmarks.length} bookmark(s) in folder "${folderTitle}"`);

    // Update status bar to show scanning
    /* [ZeroLabs] 2026-08-28 - edited: register as an operation */
    setScanningStatus(RESCAN_FOLDER_OP, `Preparing scan...`);

    // Ensure blocklist database is ready (triggers update if needed, then waits for completion)
    // This prevents getting 'unknown' results during database download
    try {
      setScanningStatus(RESCAN_FOLDER_OP, `Loading security database...`);
      console.log('[Folder Rescan] Ensuring blocklist database is ready...');

      const response = await browser.runtime.sendMessage({ action: 'ensureBlocklistReady' });

      console.log(`[Folder Rescan] Blocklist ready with ${response.size} domains`);
    } catch (error) {
      console.warn('[Folder Rescan] Could not ensure blocklist is ready:', error);
    }

    setScanningStatus(RESCAN_FOLDER_OP, `Scanning folder: 0/${bookmarks.length}`);

    // Track statistics
    let scanned = 0;
    let unsafe = 0;
    let warning = 0;
    let dead = 0;

    // Process bookmarks in batches to avoid overwhelming the background service
    const BATCH_SIZE = 10;
    for (let i = 0; i < bookmarks.length; i += BATCH_SIZE) {
      const batch = bookmarks.slice(i, i + BATCH_SIZE);

      // Process each bookmark in the batch
      const batchPromises = batch.map(async (bookmark) => {
        try {
          // Check safety status (bypass cache for folder rescan)
          const safetyResult = await browser.runtime.sendMessage({
            action: 'checkURLSafety',
            url: bookmark.url,
            bypassCache: true
          });

          // Check link status (bypass cache for folder rescan)
          const linkResult = await browser.runtime.sendMessage({
            action: 'checkLinkStatus',
            url: bookmark.url,
            bypassCache: true
          });

          // Update the bookmark tree with the results so they persist
          updateBookmarkInTree(bookmark.id, {
            linkStatus: linkResult?.status || 'unknown',
            safetyStatus: safetyResult?.status || 'unknown',
            safetySources: safetyResult?.sources || []
          });

          // Track statistics
          if (safetyResult) {
            if (safetyResult.status === 'unsafe') unsafe++;
            if (safetyResult.status === 'warning') warning++;
          }

          if (linkResult) {
            if (linkResult.status === 'dead' || linkResult.status === 'parked') dead++;
          }

          scanned++;

          // Update status bar immediately after each bookmark
          setScanningStatus(RESCAN_FOLDER_OP, `Scanning folder: ${scanned}/${bookmarks.length}`);

          console.log(`[Folder Rescan] Progress: ${scanned}/${bookmarks.length} - Safety: ${safetyResult?.status || 'unknown'}, Link: ${linkResult?.status || 'unknown'}`);
        } catch (error) {
          console.error(`[Folder Rescan] Error checking bookmark ${bookmark.id}:`, error);
        }
      });

      // Wait for batch to complete
      await Promise.all(batchPromises);

      // Update UI after each batch to show progress
      renderBookmarks();

      // Force UI update and add small delay to ensure progress is visible
      await new Promise(resolve => setTimeout(resolve, 50));

      // Add delay between batches to avoid overwhelming background service
      if (i + BATCH_SIZE < bookmarks.length) {
        await new Promise(resolve => setTimeout(resolve, 300));
      }
    }

    // Save the updated folder scan timestamp
    saveFolderScanTimestamp(folderId);

    // Mark all rescanned bookmarks as checked so they won't be auto-scanned again
    bookmarks.forEach(bookmark => {
      checkedBookmarks.add(bookmark.id);
    });

    // Refresh the display with updated status icons
    renderBookmarks();

    // Clear checkedBookmarks to free memory after folder scan completes
    checkedBookmarks.clear();

    console.log(`[Folder Rescan] Complete for "${folderTitle}": ${scanned} scanned, ${unsafe} unsafe, ${warning} warnings, ${dead} dead`);

    /* [ZeroLabs] 2026-08-28 - edited: the outcome stays this operation's message */
    setScanningStatus(RESCAN_FOLDER_OP, `Scan complete: ${scanned}/${bookmarks.length}`);
    setTimeout(() => clearScanningStatus(RESCAN_FOLDER_OP), 2000);

  } catch (error) {
    console.error('[Folder Rescan] Error:', error);
    alert(`Failed to rescan folder: ${error.message}`);
    /* [ZeroLabs] 2026-08-28 - added: the bar was left stuck on a failed scan */
    // The catch reset nothing, so an error left "Scanning folder: 3/40" on the
    // bar permanently - there was no operation to clear and nothing to correct it.
    clearScanningStatus(RESCAN_FOLDER_OP);
  }
}

// SAFETY: Count total items in a folder (recursive)
async function countFolderItems(folderId) {
  try {
    const subtree = await browser.bookmarks.getSubTree(folderId);
    if (!subtree[0] || !subtree[0].children) return 0;

    let count = 0;
    const countRecursive = (items) => {
      for (const item of items) {
        count++;
        if (item.children) {
          countRecursive(item.children);
        }
      }
    };
    countRecursive(subtree[0].children);
    return count;
  } catch (error) {
    console.error('Error counting folder items:', error);
    return 0;
  }
}

// Find folder/item by ID in the bookmark tree (unified implementation)
function findFolderById(nodes, id) {
  for (const node of nodes) {
    if (node.id === id) return node;
    if (node.children) {
      const found = findFolderById(node.children, id);
      if (found) return found;
    }
  }
  return null;
}

// Delete folder
/* [ZeroLabs] 2026-08-27 - added: record a deletion from the data we already hold */
// Recording relied entirely on the background worker's onRemoved listener and its
// `removeInfo.node`. For a folder that is ONE event for the whole subtree, and
// whether the payload carries `children` is exactly the sort of thing that
// differs between browsers - where it does not, none of the folder's URLs were
// recorded as deleted, the next reconcile read them as additions sitting in the
// snippet, and it faithfully put the entire folder back. Every sync returned it.
//
// The delete handlers already deep-copy the subtree for the changelog, so the
// data is in hand. Recording it here does not depend on the event payload at all.
// The worker's listener stays: it is what catches deletions made outside BMZ.
async function recordLocalDeletion(node) {
  if (!node) return;
  const urls = [];
  const walk = (n) => {
    if (!n) return;
    if (n.url) urls.push(n.url);
    if (Array.isArray(n.children)) n.children.forEach(walk);
  };
  walk(node);
  // A folder with no bookmarks in it records nothing, and correctly so:
  // attribution is URL-based. Folders are handled by the toAdd filter instead.
  if (urls.length === 0) return;

  try {
    const stored = await safeStorage.get(['snippet_local_deleted', 'snippet_local_created']);
    const deleted = new Set(stored.snippet_local_deleted || []);
    const created = new Set(stored.snippet_local_created || []);
    urls.forEach(url => { deleted.add(url); created.delete(url); });
    await safeStorage.set({
      snippet_local_deleted: Array.from(deleted).slice(-2000),
      snippet_local_created: Array.from(created)
    });
  } catch (error) {
    console.error('[Sync] Could not record local deletion:', error);
  }
}

/* [ZeroLabs] 2026-08-28 - added: folders left empty by an approved removal */
// A folder deleted on another device arrives here as the removal of the
// bookmarks that were inside it. The snippet has no record of the folder itself:
// collectSnippetEntries is keyed by URL, and folders survive only as path
// segments on the bookmarks they hold. So the bookmarks went and the folder
// stayed behind, empty, on every device that did not do the deleting.
//
// Only folders emptied BY the operation that calls this are pruned, and only
// while they are strictly empty. An empty folder made here on purpose is never
// touched - the snippet never knew about it, so a sync has nothing to say about
// it. For the same reason a folder still holding an empty subfolder survives:
// that subfolder is local-only content, and taking it out with its parent would
// destroy something the snippet never carried.
//
// Top level on purpose: showHeldPushDialog lives inside setupEventListeners in
// this file, and inner scope can reach out to here but not the other way round.
async function pruneEmptyFolderChain(startId) {
  const rootFolderIds = ['toolbar_____', 'menu________', 'unfiled_____', 'mobile______', 'root________'];
  let id = startId;

  // The chain is walked upward, so a bad parentId must not spin forever
  for (let guard = 0; id && guard < 50; guard++) {
    if (rootFolderIds.includes(id)) return;

    let node;
    try {
      [node] = await browser.bookmarks.get(id);
    } catch (error) {
      return; // Already gone
    }
    if (!node || node.url) return;
    if (!node.parentId || rootFolderIds.includes(node.id)) return;

    const children = await browser.bookmarks.getChildren(id);
    if (children.length > 0) return;

    const fullData = JSON.parse(JSON.stringify(node));
    // Safe as a plain remove rather than removeTree: it has just been proven empty
    await browser.bookmarks.remove(id);
    await addChangelogEntry('delete', 'folder', node.title || 'Unnamed Folder', null, { fullData });

    id = node.parentId;
  }
}

async function deleteFolder(id) {
  // SAFETY: Prevent deletion of Firefox's built-in bookmark folders
  const protectedFolderIds = ['menu________', 'toolbar_____', 'unfiled_____', 'mobile______'];
  if (protectedFolderIds.includes(id)) {
    alert('⚠ Cannot delete built-in Firefox bookmark folders (Bookmarks Menu, Bookmarks Toolbar, Other Bookmarks, Mobile Bookmarks).\n\nThis is a safety feature to protect your bookmark structure.');
    return;
  }

  try {
    // Get folder details before deleting for undo functionality
    const folderInfo = await browser.bookmarks.getSubTree(id);
    const folder = folderInfo[0];

    // Deep copy folder data for changelog (browser.bookmarks.getSubTree already includes parentId)
    const fullData = JSON.parse(JSON.stringify(folder));

    // Add to changelog before deleting (store complete folder data for restoration)
    await addChangelogEntry('delete', 'folder', folder.title || 'Untitled', null, {
      fullData: fullData
    });

    /* [ZeroLabs] 2026-08-27 - added: record it from the copy we just took */
    await recordLocalDeletion(fullData);

    // Delete the folder
    await browser.bookmarks.removeTree(id);

    // Show undo toast
    showUndoToast({
      type: 'folder',
      data: folder,
      message: `Folder "${folder.title || 'Untitled'}" deleted`
    });

    await loadBookmarks();
    renderBookmarks();

    /* [ZeroLabs] 2026-08-27 - added: ask about this deletion now */
    window.syncAfterLocalDeletion?.();
  } catch (error) {
    console.error('Error deleting folder:', error);
    alert('Failed to delete folder');
  }
}

// Undo System Functions

// Show undo toast with countdown
function showUndoToast(options) {
  // Clear any existing undo data and timers
  hideUndoToast();

  // Store the undo data
  undoData = options;

  // Update message
  undoMessage.textContent = options.message;

  // Show the toast
  undoToast.classList.remove('hidden');

  // Start countdown
  let countdown = 5;
  undoCountdownEl.textContent = countdown;

  undoCountdown = setInterval(() => {
    countdown--;
    undoCountdownEl.textContent = countdown;

    if (countdown <= 0) {
      hideUndoToast();
    }
  }, 1000);

  // Auto-hide after 5 seconds
  undoTimer = setTimeout(() => {
    hideUndoToast();
  }, 5000);
}

// Hide undo toast and clear timers
function hideUndoToast() {
  if (undoTimer) {
    clearTimeout(undoTimer);
    undoTimer = null;
  }

  if (undoCountdown) {
    clearInterval(undoCountdown);
    undoCountdown = null;
  }

  undoToast.classList.add('hidden');
  undoData = null;
}

/* [ZeroLabs] 2026-08-27 - added: restore one deleted item (shared by single and bulk undo) */
async function restoreDeletedItem(type, data) {
  /* [ZeroLabs] 2026-08-27 - added: the recorded index may no longer exist */
  // Deleting items at index 3, 5 and 7 leaves the folder with two children, so
  // restoring index 7 throws "Index out of bounds". Clamping puts it as close to
  // where it was as the folder now allows.
  //
  // A missing parent means an ancestor folder was deleted in the same batch and
  // has already been restored WITH this item inside it - creating it again would
  // duplicate it, so it is skipped.
  let siblings;
  try {
    siblings = await browser.bookmarks.getChildren(data.parentId);
  } catch (error) {
    console.warn('[Undo] Parent no longer exists, already restored with it:', data.title);
    return;
  }
  const index = Math.min(
    typeof data.index === 'number' ? data.index : siblings.length,
    siblings.length
  );

  if (type === 'bookmark') {
    await browser.bookmarks.create({
      title: data.title,
      url: data.url,
      parentId: data.parentId,
      index
    });
  } else if (type === 'folder') {
    await restoreFolderRecursive(data, data.parentId, index);
  }
}

// Undo the last deletion
async function performUndo() {
  if (!undoData) return;

  const { type, data, isPreview } = undoData;

  try {
    if (isPreview) {
      // Preview mode: restore to mock data
      if (type === 'bookmark') {
        // Restore bookmark to its parent array
        if (data.parentArray) {
          data.parentArray.splice(data.parentIndex, 0, {
            id: data.id,
            title: data.title,
            url: data.url
          });
        }
      } else if (type === 'folder') {
        // Restore folder with all children
        if (data.parentArray) {
          const folderToRestore = JSON.parse(JSON.stringify(data));
          delete folderToRestore.parentArray;
          delete folderToRestore.parentIndex;
          data.parentArray.splice(data.parentIndex, 0, folderToRestore);
        }
      }

      renderBookmarks();
      hideUndoToast();
      console.log(`Undo successful (preview): ${type} restored`);
    } else {
      // Real extension mode
      /* [ZeroLabs] 2026-08-27 - edited: one item or many, same restore */
      if (type === 'bulk') {
        /* [ZeroLabs] 2026-08-27 - added: ascending index, or the order comes back scrambled */
        // Each restore fills a slot, so earlier indexes must go first for the
        // later ones to still be reachable.
        const ordered = [...(data || [])].sort(
          (a, b) => (a.data.index || 0) - (b.data.index || 0));
        for (const entry of ordered) {
          await restoreDeletedItem(entry.type, entry.data);
        }
      } else {
        await restoreDeletedItem(type, data);
      }

      // Reload and hide toast
      await loadBookmarks();
      renderBookmarks();
      hideUndoToast();

      console.log(`Undo successful: ${type} restored`);
    }
  } catch (error) {
    console.error('Error during undo:', error);
    alert('Failed to undo deletion');
    hideUndoToast();
  }
}

// Recursively restore a folder and all its contents
async function restoreFolderRecursive(folderData, parentId, index) {
  // Create the folder
  const newFolder = await browser.bookmarks.create({
    title: folderData.title,
    parentId: parentId,
    index: index
  });

  // Restore children if any
  if (folderData.children && folderData.children.length > 0) {
    for (let i = 0; i < folderData.children.length; i++) {
      const child = folderData.children[i];
      if (child.url) {
        // It's a bookmark
        await browser.bookmarks.create({
          title: child.title,
          url: child.url,
          parentId: newFolder.id,
          index: i
        });
      } else {
        // It's a folder
        await restoreFolderRecursive(child, newFolder.id, i);
      }
    }
  }
}

// Adjust dropdown position to prevent overflow
function adjustDropdownPosition(dropdown) {
  if (!dropdown) return;

  // Reset any previous adjustments
  dropdown.style.left = '';
  dropdown.style.right = '';
  dropdown.style.transform = '';
  dropdown.style.top = '';
  dropdown.style.bottom = '';
  dropdown.style.marginTop = '';
  dropdown.style.marginBottom = '';

  // Wait for next frame to ensure menu is visible and has dimensions
  requestAnimationFrame(() => {
    const rect = dropdown.getBoundingClientRect();
    const viewportWidth = window.innerWidth;
    const viewportHeight = window.innerHeight;

    // Check horizontal overflow
    if (rect.right > viewportWidth) {
      // Menu extends beyond right edge
      const overflow = rect.right - viewportWidth;
      dropdown.style.right = '0';
      dropdown.style.transform = `translateX(-${overflow + 8}px)`;
    } else if (rect.left < 0) {
      // Menu extends beyond left edge
      dropdown.style.left = '0';
      dropdown.style.right = 'auto';
    }

    // Check vertical overflow
    if (rect.bottom > viewportHeight) {
      // Menu extends beyond bottom edge - show above button instead
      dropdown.style.top = 'auto';
      dropdown.style.bottom = '100%';
      dropdown.style.marginBottom = '4px';
      dropdown.style.marginTop = '0';
    }
  });
}

// Position dropdown menu with fixed positioning and overflow detection
function positionFixedDropdown(dropdown, button) {
  if (!dropdown || !button) return;

  const buttonRect = button.getBoundingClientRect();
  const viewportWidth = window.innerWidth;
  const viewportHeight = window.innerHeight;

  // Set max width to prevent horizontal overflow
  dropdown.style.maxWidth = `${viewportWidth - 16}px`;

  // Position below button by default
  dropdown.style.position = 'fixed';
  dropdown.style.top = `${buttonRect.bottom + 4}px`;
  dropdown.style.right = `${viewportWidth - buttonRect.right}px`;
  dropdown.style.zIndex = '99999';

  // Wait for next frame to check if menu fits
  requestAnimationFrame(() => {
    const dropdownRect = dropdown.getBoundingClientRect();

    // Check if menu overflows bottom
    if (dropdownRect.bottom > viewportHeight - 8) {
      // Position above button instead
      dropdown.style.top = 'auto';
      dropdown.style.bottom = `${viewportHeight - buttonRect.top + 4}px`;
    }

    // Check horizontal overflow
    if (dropdownRect.left < 8) {
      // Constrain width if needed
      dropdown.style.maxWidth = `${buttonRect.right - 8}px`;
    }
  });
}

// Close all open menus
function closeAllMenus() {
  openMenuBookmarkId = null; // Clear tracked menu state
  closeContextMenuModal();

  // Close and reset toolbar menus
  [settingsMenu, themeMenu, viewMenu, zoomMenu].forEach(menu => {
    if (menu) {
      menu.classList.remove('show');
      // Delay resetting positioning styles until after the close transition completes
      setTimeout(() => {
        if (!menu.classList.contains('show')) {
          menu.style.position = '';
          menu.style.top = '';
          menu.style.bottom = '';
          menu.style.right = '';
          menu.style.maxWidth = '';
          menu.style.zIndex = '';
        }
      }, 200); // Match CSS transition duration
    }
  });
}

// Check link status using background script
async function checkLinkStatus(url, bypassCache = false) {
  try {
    const response = await browser.runtime.sendMessage({
      action: 'checkLinkStatus',
      url: url,
      bypassCache: bypassCache
    });
    return response.status || 'unknown';
  } catch (error) {
    console.error('Error checking link status:', error);
    return 'unknown';
  }
}

// Check URL safety with heuristic-based security check
// Uses pattern matching and domain reputation checks
// Checks for: HTTPS, suspicious patterns, URL shorteners, known safe domains
async function checkSafetyStatus(url, bypassCache = false) {
  // Check if URL is whitelisted
  try {
    const hostname = new URL(url).hostname;
    if (whitelistedUrls.has(hostname)) {
      const result = { status: 'safe', sources: ['Whitelisted by user'] };
      trackSafetyChange(url, result.status, result.sources);
      return result;
    }
  } catch (error) {
    console.error('Error parsing URL for whitelist check:', error);
  }

  try {
    const response = await browser.runtime.sendMessage({
      action: 'checkURLSafety',
      url: url,
      bypassCache: bypassCache
    });
    const result = {
      status: response.status || 'unknown',
      sources: response.sources || []
    };
    // Track status change
    trackSafetyChange(url, result.status, result.sources);
    return result;
  } catch (error) {
    console.error('Error checking URL safety:', error);
    return { status: 'unknown', sources: [] };
  }
}

// Recheck bookmark status (link + safety)
async function recheckBookmarkStatus(bookmarkId) {
  const bookmark = findBookmarkById(bookmarkTree, bookmarkId);
  if (!bookmark || !bookmark.url) return;

  // Skip if both checking types are disabled
  if (!linkCheckingEnabled && !safetyCheckingEnabled) {
    alert('Both link checking and safety checking are disabled.\n\nEnable at least one in Settings to recheck bookmark status.');
    return;
  }

  const checkingUpdates = {};
  if (linkCheckingEnabled) checkingUpdates.linkStatus = 'checking';
  if (safetyCheckingEnabled) checkingUpdates.safetyStatus = 'checking';
  updateBookmarkInTree(bookmarkId, checkingUpdates);
  renderBookmarks();

  const results = {};
  if (linkCheckingEnabled) {
    results.linkStatus = await checkLinkStatus(bookmark.url, true); // Bypass cache for rescan
  }
  if (safetyCheckingEnabled) {
    const safetyStatusResult = await checkSafetyStatus(bookmark.url, true); // Bypass cache for rescan
    results.safetyStatus = safetyStatusResult.status;
    results.safetySources = safetyStatusResult.sources;
  }

  updateBookmarkInTree(bookmarkId, results);
  renderBookmarks();
}

// Find bookmark by ID in tree
function findBookmarkById(nodes, id) {
  for (const node of nodes) {
    if (node.id === id) return node;
    if (node.type === 'folder' && node.children) {
      const found = findBookmarkById(node.children, id);
      if (found) return found;
    }
  }
  return null;
}

// Update bookmark in tree
function updateBookmarkInTree(bookmarkId, updates) {
  const updateNode = (nodes) => {
    return nodes.map(node => {
      if (node.id === bookmarkId) {
        return { ...node, ...updates };
      }
      if (node.type === 'folder' && node.children) {
        return { ...node, children: updateNode(node.children) };
      }
      return node;
    });
  };
  bookmarkTree = updateNode(bookmarkTree);
}

// Update status indicators in DOM for a specific bookmark (without full re-render)
/* [ZeroLabs] 2026-08-17 4:15 PM - edited: update every copy of a bookmark */
// A pinned or recently opened bookmark is in the DOM more than once under the
// same data-id. querySelector would only ever reach the first copy, leaving the
// others stuck on a stale scan result, so every match gets updated.
function updateBookmarkStatusInDOM(bookmarkId, updates) {
  const matches = document.querySelectorAll(`[data-id="${bookmarkId}"]`);
  if (!matches.length) return;

  // Get the bookmark data from tree to access its URL
  const bookmark = findBookmarkById(bookmarkTree, bookmarkId);
  if (!bookmark) return;

  matches.forEach(bookmarkElement => {
    if (!bookmarkElement.classList.contains('bookmark-item')) {
      return; // Not currently visible as a bookmark row, or is a folder
    }
    applyStatusToElement(bookmarkElement, bookmark, updates);
  });
}

function applyStatusToElement(bookmarkElement, bookmark, updates) {
  // Update status indicators container (for list view)
  const statusIndicatorsContainer = bookmarkElement.querySelector('.status-indicators');
  if (statusIndicatorsContainer && (displayOptions.safetyStatus || displayOptions.liveStatus)) {
    let statusHtml = '';

    if (displayOptions.safetyStatus && updates.safetyStatus) {
      statusHtml += getShieldHtml(updates.safetyStatus, bookmark.url, updates.safetySources || []);
    }

    if (displayOptions.liveStatus && updates.linkStatus) {
      statusHtml += getStatusDotHtml(updates.linkStatus, bookmark.url);
    }

    statusIndicatorsContainer.innerHTML = statusHtml;
  }

  // Update top row indicators (for grid view)
  const topRow = bookmarkElement.querySelector('.bookmark-top-row');
  if (topRow) {
    // Update shield in top row
    if (displayOptions.safetyStatus && updates.safetyStatus) {
      const shieldHtml = getShieldHtml(updates.safetyStatus, bookmark.url, updates.safetySources || []);
      const shieldContainer = topRow.querySelector('.shield-indicator');
      if (shieldContainer) {
        const tempDiv = document.createElement('div');
        tempDiv.innerHTML = shieldHtml;
        const newShield = tempDiv.firstChild;
        if (newShield) {
          shieldContainer.replaceWith(newShield);
        }
      }
    }

    // Update link status in top row
    if (displayOptions.liveStatus && updates.linkStatus) {
      const linkStatusHtml = getStatusDotHtml(updates.linkStatus, bookmark.url);
      const linkStatusContainer = topRow.querySelector('.status-icon');
      if (linkStatusContainer) {
        const tempDiv = document.createElement('div');
        tempDiv.innerHTML = linkStatusHtml;
        const newLinkStatus = tempDiv.firstChild;
        if (newLinkStatus) {
          linkStatusContainer.replaceWith(newLinkStatus);
        }
      }
    }
  }
}

// Whitelist a bookmark (trust it regardless of safety checks)
async function whitelistBookmark(bookmark) {
  if (!bookmark || !bookmark.url) return;

  const hostname = new URL(bookmark.url).hostname;

  if (whitelistedUrls.has(hostname)) {
    const remove = confirm(`"${hostname}" is already whitelisted.\n\nDo you want to remove it from the whitelist?`);
    if (remove) {
      whitelistedUrls.delete(hostname);
      await saveWhitelist();
      alert(`Removed "${hostname}" from whitelist.\n\nIt will be scanned normally on next check.`);
      // Recheck the bookmark
      await recheckBookmarkStatus(bookmark.id);
    }
  } else {
    const confirm_add = confirm(`Add "${hostname}" to whitelist?\n\nWhitelisted sites are marked as safe regardless of security scan results.\n\nOnly whitelist sites you trust completely.`);
    if (confirm_add) {
      whitelistedUrls.add(hostname);
      await saveWhitelist();
      // Update safety status to safe
      updateBookmarkInTree(bookmark.id, {
        safetyStatus: 'safe',
        safetySources: ['Whitelisted by user']
      });
      renderBookmarks();
      alert(`"${hostname}" added to whitelist.\n\nAll bookmarks from this site will be marked as safe.`);
    }
  }
}

// Save whitelist to storage
async function saveWhitelist() {
  try {
    await safeStorage.set({
      whitelistedUrls: Array.from(whitelistedUrls)
    });
  } catch (error) {
    console.error('Failed to save whitelist:', error);
  }
}

// Load whitelist from storage
async function loadWhitelist() {
  try {
    const result = await safeStorage.get('whitelistedUrls');
    if (result.whitelistedUrls && Array.isArray(result.whitelistedUrls)) {
      whitelistedUrls = new Set(result.whitelistedUrls);
      console.log(`Loaded ${whitelistedUrls.size} whitelisted URLs`);
    }
  } catch (error) {
    console.error('Failed to load whitelist:', error);
  }
}

// Save safety history to storage
async function saveSafetyHistory() {
  try {
    await safeStorage.set({ safetyHistory });
  } catch (error) {
    console.error('Failed to save safety history:', error);
  }
}

// Load safety history from storage
async function loadSafetyHistory() {
  try {
    const result = await safeStorage.get('safetyHistory');
    if (result.safetyHistory) {
      safetyHistory = result.safetyHistory;
      console.log(`Loaded safety history for ${Object.keys(safetyHistory).length} URLs`);
    }
  } catch (error) {
    console.error('Failed to load safety history:', error);
  }
}

// Clean up safetyHistory to remove entries for URLs no longer in bookmarks
function cleanupSafetyHistory() {
  if (!bookmarkTree || bookmarkTree.length === 0) return;

  // Collect all current bookmark URLs
  const currentUrls = new Set();
  const collectUrls = (nodes) => {
    nodes.forEach(node => {
      if (node.url) {
        currentUrls.add(node.url);
      }
      if (node.children) {
        collectUrls(node.children);
      }
    });
  };
  collectUrls(bookmarkTree);

  // Remove history entries for URLs that no longer exist in bookmarks
  const historyUrls = Object.keys(safetyHistory);
  let removedCount = 0;
  historyUrls.forEach(url => {
    if (!currentUrls.has(url)) {
      delete safetyHistory[url];
      removedCount++;
    }
  });

  if (removedCount > 0) {
    console.log(`[Memory Cleanup] Removed ${removedCount} stale entries from safetyHistory`);
    saveSafetyHistory(); // Persist the cleanup
  }
}

// Track safety status change and alert if degraded
function trackSafetyChange(url, newStatus, sources) {
  if (!url) return;

  const timestamp = Date.now();

  // Initialize history for this URL if needed
  if (!safetyHistory[url]) {
    safetyHistory[url] = [];
  }

  const history = safetyHistory[url];
  const lastStatus = history.length > 0 ? history[history.length - 1].status : null;

  // Only track if status has actually changed
  if (lastStatus === newStatus) {
    return; // No change, skip adding duplicate entry
  }

  // Add new entry only when status changes
  history.push({ timestamp, status: newStatus, sources });

  // Keep only last 10 entries per URL
  if (history.length > 10) {
    history.shift();
  }

  // Alert if status degraded from safe to unsafe/suspicious
  if (lastStatus === 'safe' && (newStatus === 'unsafe' || newStatus === 'suspicious')) {
    const hostname = new URL(url).hostname;
    console.warn(`⚠️ Security alert: ${hostname} changed from safe to ${newStatus}`);

    // Show alert to user
    setTimeout(() => {
      const message = `⚠️ SECURITY ALERT\n\n"${hostname}" was previously marked as SAFE but is now flagged as ${newStatus.toUpperCase()}!\n\nSources: ${sources.join(', ')}\n\nPlease verify this site before visiting.`;
      alert(message);
    }, 100);
  }

  // Save history only when status changes
  saveSafetyHistory();
}

// Handle bookmark actions
async function handleBookmarkAction(action, bookmark) {
  switch (action) {
    /* [ZeroLabs] 2026-08-17 4:15 PM - added: quick access pin actions */
    case 'pin-quick-access':
      await pinBookmark(bookmark);
      break;

    /* [ZeroLabs] 2026-08-19 5:23 PM - edited: confirm before unpinning */
    case 'unpin-quick-access': {
      // Unpin only. The bookmark itself is never touched from here, and the
      // message says so, because the red styling would otherwise imply deletion.
      const pinLabel = bookmark.title || bookmark.url;
      if (!confirm(`Remove "${pinLabel}" from Quick Access?\n\nThis only unpins it. The bookmark itself will not be deleted.`)) {
        break;
      }
      await unpinUrl(bookmark.url);
      break;
    }

    case 'open':
      // Open in active tab
      /* [ZeroLabs] 2026-08-17 4:15 PM - added: track recent opens */
      recordRecentOpen(bookmark.url);
      const tabs = await browser.tabs.query({ active: true, currentWindow: true });
      if (tabs[0]) {
        browser.tabs.update(tabs[0].id, { url: bookmark.url });
      } else {
        browser.tabs.create({ url: bookmark.url });
      }
      break;

    case 'open-new-tab':
      openBookmarkUrl(bookmark.url, true);
      break;

    case 'open-new-window':
      // Open in new window
      /* [ZeroLabs] 2026-08-17 4:15 PM - added: track recent opens */
      recordRecentOpen(bookmark.url);
      browser.windows.create({ url: bookmark.url });
      break;

    case 'reader-view':
      // Open in text-only view using Textise
      const textiseUrl = `https://www.textise.net/showText.aspx?strURL=${encodeURIComponent(bookmark.url)}`;
      browser.tabs.create({ url: textiseUrl });
      break;

    case 'save-pdf':
      // Save page as PDF
      // Open the page in a new tab and save as PDF
      const tab = await browser.tabs.create({ url: bookmark.url });

      // Wait for the page to load before saving as PDF
      const listener = (tabId, changeInfo) => {
        if (tabId === tab.id && changeInfo.status === 'complete') {
          browser.tabs.onUpdated.removeListener(listener);
          // Trigger the save as PDF action
          browser.tabs.saveAsPDF(tab.id).then(() => {
            console.log('PDF save initiated');
          }).catch(err => {
            console.error('Failed to save PDF:', err);
            alert('Failed to save page as PDF. Please try using the browser\'s built-in print-to-PDF feature.');
          });
        }
      };
      browser.tabs.onUpdated.addListener(listener);
      break;

    case 'edit':
      editBookmark(bookmark);
      break;

    case 'recheck':
      await recheckBookmarkStatus(bookmark.id);
      break;

    case 'whitelist':
      await whitelistBookmark(bookmark);
      break;

    case 'virustotal':
      // Extract domain from URL and open VirusTotal search
      try {
        const domain = new URL(bookmark.url).hostname;
        const vtUrl = `https://www.virustotal.com/gui/search/${domain}`;
        browser.tabs.create({ url: vtUrl });
      } catch (error) {
        console.error('Error opening VirusTotal:', error);
        alert('Failed to open VirusTotal. Invalid URL.');
      }
      break;

    case 'qr-code':
      // Generate and show QR code for bookmark URL (local, privacy-focused)
      showQRCodePopup(bookmark.url);
      break;

    case 'wayback-save':
      // Save to Wayback Machine - open the save page with URL pre-filled
      {
        // Wayback's save page doesn't accept URL in path, so we copy URL first
        // and open their save page where user can paste and submit
        try {
          await navigator.clipboard.writeText(bookmark.url);
          const waybackSaveUrl = 'https://web.archive.org/save';
          browser.tabs.create({ url: waybackSaveUrl });
          // Brief notification that URL was copied
          setTimeout(() => {
            alert(`URL copied to clipboard!\n\n"${bookmark.url}"\n\nPaste it into the Wayback Machine save page that just opened.`);
          }, 100);
        } catch (error) {
          console.error('Error copying URL:', error);
          // Fallback: just open the save page
          const waybackSaveUrl = 'https://web.archive.org/save';
          browser.tabs.create({ url: waybackSaveUrl });
        }
      }
      break;

    case 'wayback-browse':
      // Browse Wayback Machine snapshots
      {
        const waybackBrowseUrl = `https://web.archive.org/web/*/${bookmark.url}`;
        browser.tabs.create({ url: waybackBrowseUrl });
      }
      break;

    case 'copy-url':
      // Copy URL to clipboard
      try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
          await navigator.clipboard.writeText(bookmark.url);
          // Show brief success feedback
          console.log('URL copied to clipboard:', bookmark.url);
          // Optional: Could show a toast notification here
        } else {
          // Fallback for older browsers
          const textArea = document.createElement('textarea');
          textArea.value = bookmark.url;
          textArea.style.position = 'fixed';
          textArea.style.left = '-999999px';
          document.body.appendChild(textArea);
          textArea.select();
          document.execCommand('copy');
          document.body.removeChild(textArea);
          console.log('URL copied to clipboard (fallback):', bookmark.url);
        }
      } catch (error) {
        console.error('Error copying URL:', error);
        alert('Failed to copy URL to clipboard.');
      }
      break;

    case 'edit':
      openEditModal(bookmark, false);
      break;

    case 'move-to':
      openMoveToModal(bookmark, false);
      break;

    case 'delete':
      if (confirm(`Delete "${bookmark.title}"?`)) {
        await deleteBookmark(bookmark.id);
      }
      break;
  }
}

// Open edit modal
function openEditModal(item, isFolder = false) {
  currentEditItem = item;

  const modal = document.getElementById('editModal');
  const modalTitle = document.getElementById('editModalTitle');
  const editTitle = document.getElementById('editTitle');
  const editUrl = document.getElementById('editUrl');
  const editUrlGroup = document.getElementById('editUrlGroup');

  // Set modal title
  modalTitle.textContent = isFolder ? 'Rename Folder' : 'Edit Bookmark';

  // Populate fields
  editTitle.value = item.title || '';

  if (isFolder) {
    // Hide URL field for folders
    editUrlGroup.style.display = 'none';
  } else {
    // Show URL field for bookmarks
    editUrlGroup.style.display = 'block';
    editUrl.value = item.url || '';
  }

  modal.classList.remove('hidden');
  modal.setAttribute('aria-hidden', 'false');
  trapFocus(modal);
}

// Close edit modal
function closeEditModal() {
  const modal = document.getElementById('editModal');
  modal.classList.add('hidden');
  modal.setAttribute('aria-hidden', 'true');
  releaseFocusTrap();
  currentEditItem = null;
}

// Save edit modal
async function saveEditModal() {
  if (!currentEditItem) return;

  const editTitle = document.getElementById('editTitle');
  const editUrl = document.getElementById('editUrl');

  const isFolder = !currentEditItem.url;
  const updates = { title: editTitle.value };

  if (!isFolder) {
    let url = editUrl.value.trim();
    /* [ZeroLabs] 2026-08-27 - edited: same warning the add dialog gives */
    // Editing could break a working bookmark exactly the way adding could - a
    // pasted address with a stray space saved and synced with no warning, then
    // rejected by every stricter client. No swap offered here: the bookmark
    // already has a title, so a mixed-up pair is not the likely cause.
    if (url) {
      const check = classifyBookmarkUrl(url);
      if (check.problem) {
        const choice = await showUrlWarningDialog({
          typed: check.typed,
          problem: check.problem,
          canSwap: false
        });
        if (choice !== 'save') return;
      }
      url = check.url;
    }
    updates.url = url;
  }

  try {
    // Log changes
    const oldTitle = currentEditItem.title;
    const oldUrl = currentEditItem.url;
    const itemType = isFolder ? 'folder' : 'bookmark';

    await browser.bookmarks.update(currentEditItem.id, updates);

    // Add to changelog
    const changeDetails = {};
    if (oldTitle !== updates.title) {
      changeDetails.oldTitle = oldTitle;
      changeDetails.newTitle = updates.title;
    }
    if (!isFolder && oldUrl !== updates.url) {
      changeDetails.oldUrl = oldUrl;
      changeDetails.newUrl = updates.url;
    }

    if (Object.keys(changeDetails).length > 0) {
      await addChangelogEntry('update', itemType, updates.title, updates.url, changeDetails);
    }

    await loadBookmarks();
    renderBookmarks();
    closeEditModal();
  } catch (error) {
    console.error('Error updating:', error);
    alert('Failed to update ' + (isFolder ? 'folder' : 'bookmark'));
  }
}

// Edit bookmark (legacy wrapper)
async function editBookmark(bookmark) {
  openEditModal(bookmark, false);
}

// Delete bookmark
async function deleteBookmark(id) {
  try {
    // Get bookmark details before deleting for undo functionality
    const bookmarks = await browser.bookmarks.get(id);
    const bookmark = bookmarks[0];

    // Deep copy bookmark data for changelog (browser.bookmarks.get already includes parentId)
    const fullData = JSON.parse(JSON.stringify(bookmark));

    // Add to changelog before deleting (store complete bookmark data for restoration)
    await addChangelogEntry('delete', 'bookmark', bookmark.title || 'Untitled', bookmark.url, {
      fullData: fullData
    });

    /* [ZeroLabs] 2026-08-27 - added: record it from the copy we just took */
    await recordLocalDeletion(fullData);

    // Delete the bookmark
    await browser.bookmarks.remove(id);

    // Show undo toast
    showUndoToast({
      type: 'bookmark',
      data: bookmark,
      message: `Bookmark "${bookmark.title || 'Untitled'}" deleted`
    });

    await loadBookmarks();
    renderBookmarks();

    /* [ZeroLabs] 2026-08-27 - added: ask about this deletion now */
    window.syncAfterLocalDeletion?.();
  } catch (error) {
    console.error('Error deleting bookmark:', error);
    alert('Failed to delete bookmark');
  }
}

// Build folder list for dropdowns
function buildFolderList(nodes, indent = 0) {
  const folders = [];
  for (const node of nodes) {
    if (node.type === 'folder') {
      folders.push({
        id: node.id,
        title: '  '.repeat(indent) + (node.title || 'Unnamed Folder'),
        indent
      });
      if (node.children) {
        folders.push(...buildFolderList(node.children, indent + 1));
      }
    }
  }
  return folders;
}

// Populate folder dropdown
function populateFolderDropdown(selectElement, sortAlphabetically = false) {
  let folders = buildFolderList(bookmarkTree);

  // Sort alphabetically if requested
  if (sortAlphabetically) {
    folders.sort((a, b) => {
      // Remove indentation for comparison
      const titleA = a.title.trim().toLowerCase();
      const titleB = b.title.trim().toLowerCase();
      return titleA.localeCompare(titleB);
    });
  }

  selectElement.innerHTML = '<option value="">Root</option>';
  folders.forEach(folder => {
    const option = document.createElement('option');
    option.value = folder.id;
    option.textContent = folder.title;
    selectElement.appendChild(option);
  });
}

// Open add bookmark modal
async function openAddBookmarkModal() {
  const modal = document.getElementById('addBookmarkModal');
  const titleInput = document.getElementById('newBookmarkTitle');
  const urlInput = document.getElementById('newBookmarkUrl');
  const folderSelect = document.getElementById('newBookmarkFolder');

  // Try to get the current active tab to pre-populate fields
  try {
    const tabs = await browser.tabs.query({ active: true, currentWindow: true });
    if (tabs && tabs.length > 0) {
      const currentTab = tabs[0];
      titleInput.value = currentTab.title || '';
      urlInput.value = currentTab.url || '';
    } else {
      titleInput.value = '';
      urlInput.value = '';
    }
  } catch (error) {
    console.error('Error getting current tab:', error);
    titleInput.value = '';
    urlInput.value = '';
  }

  // Load sort preference and populate dropdown
  const sortCheckbox = document.getElementById('sortBookmarkFoldersAlpha');
  const sortPref = localStorage.getItem('sortFoldersAlphabetically') === 'true';
  sortCheckbox.checked = sortPref;
  populateFolderDropdown(folderSelect, sortPref);

  // Set default folder - prefer last used, then Bookmarks Menu, then first available
  const lastUsedFolder = localStorage.getItem('lastBookmarkFolder');
  if (lastUsedFolder && folderSelect.querySelector(`option[value="${lastUsedFolder}"]`)) {
    folderSelect.value = lastUsedFolder;
  } else {
    // Find Bookmarks Menu folder (usually has 'menu' in the ID)
    const menuOption = Array.from(folderSelect.options).find(opt =>
      opt.value.includes('menu') || opt.textContent.toLowerCase().includes('bookmarks menu')
    );
    if (menuOption) {
      folderSelect.value = menuOption.value;
    } else if (folderSelect.options.length > 1) {
      // Fallback to first non-root option
      folderSelect.selectedIndex = 1;
    }
  }

  // Add event listener for sort checkbox
  sortCheckbox.addEventListener('change', (e) => {
    const sortAlpha = e.target.checked;
    localStorage.setItem('sortFoldersAlphabetically', sortAlpha);
    populateFolderDropdown(folderSelect, sortAlpha);
  });

  modal.classList.remove('hidden');
  modal.setAttribute('aria-hidden', 'false');
  trapFocus(modal);
  // Select all text in title for easy editing
  titleInput.select();
}

// Close add bookmark modal
function closeAddBookmarkModal() {
  const modal = document.getElementById('addBookmarkModal');
  modal.classList.add('hidden');
  modal.setAttribute('aria-hidden', 'true');
  releaseFocusTrap();
}

// Save new bookmark
/* [ZeroLabs] 2026-08-27 - added: warn on a doubtful address, never block it (see also: Bookmark-Manager-Zero-Website/js/sidebar-adapted.js) */
// A bookmark saved with a malformed address does not just fail here - it syncs,
// and then every stricter client rejects it. Firefox refuses to create it at all
// and raises the unplaceable-items dialog on every sync until it is deleted.
//
// But this only ever WARNS. Nonsense is the user's to save if they want it.
function classifyBookmarkUrl(typed) {
  const raw = (typed || '').trim();
  let url = raw;
  let weAddedScheme = false;

  const hasScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(url);
  // "localhost:3000" and "myserver:8080" match the scheme pattern but are really
  // host:port. Without this they were stored as scheme "localhost:" and broke.
  const isHostPort = /^[a-zA-Z][a-zA-Z0-9+.-]*:\d/.test(url);
  if (!hasScheme || isHostPort) {
    url = 'https://' + url;
    weAddedScheme = true;
  }

  let parsed;
  try {
    parsed = new URL(url);
  } catch (e) {
    // Nothing can store this - the dot check below cannot even run, since there
    // is no parsed host to inspect.
    return { url, typed: raw, problem: 'invalid' };
  }

  // Only suspicious when WE supplied the scheme. A scheme the user typed
  // themselves - about:, chrome://, file:// - was meant, and those legitimately
  // have no dot. An absent host is schemeless by design, not dotless.
  const host = parsed.hostname;
  if (weAddedScheme && host && !host.includes('.') && host !== 'localhost' && !host.startsWith('[')) {
    return { url, typed: raw, problem: 'nodot' };
  }

  return { url, typed: raw, problem: null };
}

// Resolves to 'save', 'swap' or 'edit'.
function showUrlWarningDialog({ typed, problem, canSwap }) {
  return new Promise((resolve) => {
    const modal = document.createElement('div');
    modal.style.cssText = 'position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.7); z-index: 10003; display: flex; align-items: center; justify-content: center;';

    const dialog = document.createElement('div');
    dialog.className = 'bmz-dialog';
    dialog.style.cssText = 'background: var(--md-sys-color-surface, #1e1e1e); padding: 24px; border-radius: 12px; max-width: 440px; width: 90%; color: var(--md-sys-color-on-surface, #e0e0e0);';

    // A space almost always means the two fields were swapped, so that one asks
    // outright. A dotless host is usually a typo, where swapping would rarely be
    // the right answer, so it only suggests editing.
    const reason = problem === 'invalid'
      ? `"${escapeHtml(typed)}" isn't a valid link. Did you mix up the address and the title?`
      : `"${escapeHtml(typed)}" has no domain ending like .com. If that wasn't intended, change it before saving.`;

    const btn = (id, label, primary) => `
      <button id="${id}" style="width: 100%; padding: 12px; border-radius: 8px; border: none; cursor: pointer; font-size: 14px; ${primary
        ? 'background: #f59e0b; color: #1a1a1a; font-weight: 600;'
        : 'background: var(--md-sys-color-surface-variant, #2a2a2a); color: var(--md-sys-color-on-surface, #e0e0e0);'}">${label}</button>`;

    dialog.innerHTML = `
      <h2 style="margin: 0 0 12px 0; font-size: 18px; color: #f59e0b; text-align: center;">That doesn't look like a web address</h2>
      <p style="margin: 0 0 20px 0; font-size: 14px;">${reason}</p>
      <div style="display: flex; flex-direction: column; gap: 12px;">
        ${canSwap ? btn('urlWarnSwap', 'Swap them for me', true) : ''}
        ${btn('urlWarnSave', 'Save it anyway', !canSwap)}
        ${btn('urlWarnEdit', 'Go back and edit', false)}
      </div>
    `;

    modal.appendChild(dialog);
    document.body.appendChild(modal);

    const done = (choice) => { modal.remove(); resolve(choice); };
    dialog.querySelector('#urlWarnSwap')?.addEventListener('click', () => done('swap'));
    dialog.querySelector('#urlWarnSave').addEventListener('click', () => done('save'));
    dialog.querySelector('#urlWarnEdit').addEventListener('click', () => done('edit'));
    modal.addEventListener('click', (e) => { if (e.target === modal) done('edit'); });
  });
}

async function saveNewBookmark() {
  const title = document.getElementById('newBookmarkTitle').value;
  let url = document.getElementById('newBookmarkUrl').value.trim();
  const parentId = document.getElementById('newBookmarkFolder').value || undefined;

  if (!url) {
    alert('Please enter a URL');
    return;
  }

  /* [ZeroLabs] 2026-08-27 - edited: warn on a doubtful address, offer the swap */
  // The prepend stays - a bookmark stored without a scheme does not open
  // correctly - but a result that cannot be a link now says so instead of being
  // saved silently and then rejected by every stricter client on sync.
  const check = classifyBookmarkUrl(url);
  if (check.problem) {
    const titleEl = document.getElementById('newBookmarkTitle');
    const choice = await showUrlWarningDialog({
      typed: check.typed,
      problem: check.problem,
      // Swapping into an empty title would hand back a blank address, which is
      // worse than what they started with.
      canSwap: !!(titleEl && titleEl.value.trim())
    });
    if (choice === 'edit') return;
    if (choice === 'swap') {
      const oldTitle = titleEl.value;
      titleEl.value = check.typed;
      document.getElementById('newBookmarkUrl').value = oldTitle;
      // Re-run, so a swap that is still wrong asks again rather than saving quietly
      return saveNewBookmark();
    }
  }
  url = check.url;

  // Check if trying to create bookmark at root level
  if (!parentId) {
    alert('Firefox does not allow creating bookmarks at the root level. Please select a parent folder (Bookmarks Menu, Bookmarks Toolbar, Other Bookmarks, or any existing folder/subfolder) to create your bookmark in.');
    return;
  }

  try {
    // SAFETY: Check for duplicate bookmarks to prevent accidental duplication
    const existingBookmarks = await browser.bookmarks.search({ url });
    if (existingBookmarks.length > 0) {
      const duplicateInfo = existingBookmarks.map(b => `  • "${b.title}" in folder ${b.parentId}`).join('\n');
      const confirmed = confirm(
        `⚠ Warning: This URL already exists in your bookmarks:\n\n${duplicateInfo}\n\nDo you want to create a duplicate bookmark anyway?`
      );
      if (!confirmed) {
        closeAddBookmarkModal();
        return;
      }
    }

    const newBookmark = await browser.bookmarks.create({
      title: title || url,
      url,
      parentId
    });

    // Add to changelog
    await addChangelogEntry('create', 'bookmark', newBookmark.title, newBookmark.url);

    // Remember the selected folder for next time
    if (parentId) {
      localStorage.setItem('lastBookmarkFolder', parentId);
    }

    await loadBookmarks();
    renderBookmarks();
    closeAddBookmarkModal();
  } catch (error) {
    console.error('Error creating bookmark:', error);
    alert('Failed to create bookmark');
  }
}

// Open add folder modal
function openAddFolderModal() {
  const modal = document.getElementById('addFolderModal');
  const nameInput = document.getElementById('newFolderName');
  const parentSelect = document.getElementById('newFolderParent');

  nameInput.value = '';

  // Load sort preference and populate dropdown
  const sortCheckbox = document.getElementById('sortFolderParentsAlpha');
  const sortPref = localStorage.getItem('sortFoldersAlphabetically') === 'true';
  sortCheckbox.checked = sortPref;
  populateFolderDropdown(parentSelect, sortPref);

  // Set default folder - prefer last used, then Bookmarks Menu, then first available
  const lastUsedParent = localStorage.getItem('lastFolderParent');
  if (lastUsedParent && parentSelect.querySelector(`option[value="${lastUsedParent}"]`)) {
    parentSelect.value = lastUsedParent;
  } else {
    // Find Bookmarks Menu folder (usually has 'menu' in the ID)
    const menuOption = Array.from(parentSelect.options).find(opt =>
      opt.value.includes('menu') || opt.textContent.toLowerCase().includes('bookmarks menu')
    );
    if (menuOption) {
      parentSelect.value = menuOption.value;
    } else if (parentSelect.options.length > 1) {
      // Fallback to first non-root option
      parentSelect.selectedIndex = 1;
    }
  }

  // Add event listener for sort checkbox
  sortCheckbox.addEventListener('change', (e) => {
    const sortAlpha = e.target.checked;
    localStorage.setItem('sortFoldersAlphabetically', sortAlpha);
    populateFolderDropdown(parentSelect, sortAlpha);
  });

  modal.classList.remove('hidden');
  modal.setAttribute('aria-hidden', 'false');
  trapFocus(modal);
}

// Close add folder modal
function closeAddFolderModal() {
  const modal = document.getElementById('addFolderModal');
  modal.classList.add('hidden');
  modal.setAttribute('aria-hidden', 'true');
  releaseFocusTrap();
}

// Save new folder
async function saveNewFolder() {
  const title = document.getElementById('newFolderName').value;
  const parentId = document.getElementById('newFolderParent').value || undefined;

  if (!title) {
    alert('Please enter a folder name');
    return;
  }

  // Check if trying to create folder at root level
  if (!parentId) {
    alert('Firefox does not allow creating folders at the root level. Please select a parent folder (Bookmarks Menu, Bookmarks Toolbar, Other Bookmarks, or any existing folder/subfolder) to create your folder in.');
    return;
  }

  try {
    const newFolder = await browser.bookmarks.create({
      title,
      type: 'folder',
      parentId
    });

    // Add to changelog
    await addChangelogEntry('create', 'folder', newFolder.title);

    // Remember the selected parent folder for next time
    if (parentId) {
      localStorage.setItem('lastFolderParent', parentId);
    }

    await loadBookmarks();
    renderBookmarks();
    closeAddFolderModal();
  } catch (error) {
    console.error('Error creating folder:', error);
    alert('Failed to create folder');
  }
}

// Track item being moved for the Move To modal
let moveToItem = null;
let moveToIsFolder = false;

// Open move-to modal
async function openMoveToModal(item, isFolder) {
  // Prevent moving Firefox's built-in root folders
  const protectedFolderIds = ['menu________', 'toolbar_____', 'unfiled_____', 'mobile______', 'root________'];
  if (isFolder && protectedFolderIds.includes(item.id)) {
    alert('Cannot move built-in Firefox bookmark folders.');
    return;
  }

  moveToItem = item;
  moveToIsFolder = isFolder;

  const modal = document.getElementById('moveToModal');
  const itemNameDisplay = document.getElementById('moveToItemName');
  const folderSelect = document.getElementById('moveToFolder');
  const sortCheckbox = document.getElementById('sortMoveToFoldersAlpha');

  // Show item name
  const itemLabel = isFolder ? `\uD83D\uDCC1 ${item.title || 'Unnamed Folder'}` : (item.title || 'Unnamed Bookmark');
  itemNameDisplay.textContent = itemLabel;

  // Load sort preference and populate dropdown
  const sortPref = localStorage.getItem('sortFoldersAlphabetically') === 'true';
  sortCheckbox.checked = sortPref;
  populateFolderDropdown(folderSelect, sortPref);

  // Remove the "Root" option — Firefox doesn't allow items at the actual root level
  const rootOption = folderSelect.querySelector('option[value=""]');
  if (rootOption) rootOption.remove();

  // If moving a folder, remove itself and all its descendants from the dropdown
  if (isFolder) {
    try {
      const subtree = await browser.bookmarks.getSubTree(item.id);
      const descendantIds = new Set();
      const collectIds = (nodes) => {
        for (const node of nodes) {
          descendantIds.add(node.id);
          if (node.children) collectIds(node.children);
        }
      };
      collectIds(subtree);

      Array.from(folderSelect.options).forEach(option => {
        if (descendantIds.has(option.value)) {
          option.remove();
        }
      });
    } catch (error) {
      console.error('Error filtering descendant folders:', error);
    }
  }

  // Pre-select the item's current parent folder
  if (item.parentId && folderSelect.querySelector(`option[value="${item.parentId}"]`)) {
    folderSelect.value = item.parentId;
  } else if (folderSelect.options.length > 0) {
    folderSelect.selectedIndex = 0;
  }

  // Sort checkbox handler
  const sortHandler = (e) => {
    const sortAlpha = e.target.checked;
    localStorage.setItem('sortFoldersAlphabetically', sortAlpha);
    populateFolderDropdown(folderSelect, sortAlpha);
    const rootOpt = folderSelect.querySelector('option[value=""]');
    if (rootOpt) rootOpt.remove();

    if (isFolder) {
      try {
        browser.bookmarks.getSubTree(item.id).then(subtree => {
          const descendantIds = new Set();
          const collectIds = (nodes) => {
            for (const node of nodes) {
              descendantIds.add(node.id);
              if (node.children) collectIds(node.children);
            }
          };
          collectIds(subtree);
          Array.from(folderSelect.options).forEach(option => {
            if (descendantIds.has(option.value)) {
              option.remove();
            }
          });
        });
      } catch (error) {
        console.error('Error filtering descendant folders on sort:', error);
      }
    }

    if (item.parentId && folderSelect.querySelector(`option[value="${item.parentId}"]`)) {
      folderSelect.value = item.parentId;
    }
  };

  sortCheckbox.removeEventListener('change', sortCheckbox._moveToHandler);
  sortCheckbox._moveToHandler = sortHandler;
  sortCheckbox.addEventListener('change', sortHandler);

  modal.classList.remove('hidden');
  modal.setAttribute('aria-hidden', 'false');
  trapFocus(modal);
}

// Close move-to modal
function closeMoveToModal() {
  const modal = document.getElementById('moveToModal');
  modal.classList.add('hidden');
  modal.setAttribute('aria-hidden', 'true');
  releaseFocusTrap();
  moveToItem = null;
  moveToIsFolder = false;
}

// Execute the move
async function saveMoveToModal() {
  if (!moveToItem) return;

  const folderSelect = document.getElementById('moveToFolder');
  const destinationId = folderSelect.value;

  if (!destinationId) {
    alert('Please select a destination folder.');
    return;
  }

  if (destinationId === moveToItem.parentId) {
    alert('The item is already in this folder.');
    return;
  }

  try {
    const oldParent = moveToItem.parentId ? await getFolderPath(moveToItem.parentId) : 'Root';

    await browser.bookmarks.move(moveToItem.id, { parentId: destinationId });

    const newParent = await getFolderPath(destinationId);
    const itemType = moveToItem.url ? 'bookmark' : 'folder';
    await addChangelogEntry('move', itemType, moveToItem.title, moveToItem.url || null, {
      oldParent,
      newParent
    });

    closeMoveToModal();
    await loadBookmarks();
    renderBookmarks();
  } catch (error) {
    console.error('Error moving item:', error);
    alert('Failed to move item: ' + error.message);
  }
}

// Legacy function wrappers for compatibility
async function createNewBookmark() {
  openAddBookmarkModal();
}

async function createNewFolder() {
  openAddFolderModal();
}

// Filter and search bookmarks
function filterAndSearchBookmarks(nodes) {
  return nodes.reduce((acc, node) => {
    // Skip separators (Firefox toolbar separators have type: 'separator')
    if (node.type === 'separator') {
      return acc;
    }

    if (node.type === 'folder') {
      const filteredChildren = filterAndSearchBookmarks(node.children || []);
      if (filteredChildren.length > 0 || (!searchTerm && activeFilters.length === 0)) {
        acc.push({
          ...node,
          children: filteredChildren
        });
      }
    } else if (node.url) {
      if (matchesSearch(node) && matchesFilter(node)) {
        acc.push(node);
      }
    }
    return acc;
  }, []);
}

// Check if bookmark matches search
function matchesSearch(bookmark) {
  if (!searchTerm) return true;

  const term = searchTerm.toLowerCase();
  return (
    (bookmark.title && bookmark.title.toLowerCase().includes(term)) ||
    (bookmark.url && bookmark.url.toLowerCase().includes(term))
  );
}

// Check if bookmark matches filter
function matchesFilter(bookmark) {
  if (activeFilters.length === 0) return true;

  const linkStatus = bookmark.linkStatus || 'unknown';
  const safetyStatus = bookmark.safetyStatus || 'unknown';

  // Separate filters by category
  const linkFilters = activeFilters.filter(f => ['live', 'parked', 'dead'].includes(f));
  const safetyFilters = activeFilters.filter(f => ['safe', 'suspicious', 'unsafe', 'whitelisted'].includes(f));

  // Check link status (OR within category)
  let matchesLink = true;
  if (linkFilters.length > 0) {
    matchesLink = linkFilters.some(filter => {
      switch (filter) {
        case 'live': return linkStatus === 'live';
        case 'parked': return linkStatus === 'parked';
        case 'dead': return linkStatus === 'dead';
        default: return false;
      }
    });
  }

  // Check safety status (OR within category)
  let matchesSafety = true;
  if (safetyFilters.length > 0) {
    matchesSafety = safetyFilters.some(filter => {
      switch (filter) {
        case 'safe': return safetyStatus === 'safe';
        case 'suspicious': return safetyStatus === 'warning';
        case 'unsafe': return safetyStatus === 'unsafe';
        case 'whitelisted': return bookmark.safetySources && bookmark.safetySources.includes('Whitelisted by user');
        default: return false;
      }
    });
  }

  // AND between categories
  return matchesLink && matchesSafety;
}

// Count bookmarks in folder
function countBookmarks(folder) {
  if (!folder.children) return 0;

  return folder.children.reduce((count, child) => {
    if (child.type === 'folder') {
      return count + countBookmarks(child);
    } else if (child.url && child.type !== 'separator') {
      return count + 1;
    }
    return count;
  }, 0);
}

// Get all folders recursively (unified implementation)
function getAllFolders(nodes, depth = 0, folders = []) {
  nodes.forEach(node => {
    // Check both node.type and node.children for compatibility
    if (node.type === 'folder' || node.children) {
      const indent = '  '.repeat(depth);
      folders.push({
        ...node,  // Include all node properties
        title: indent + (node.title || 'Unnamed Folder'),  // Override with indented title
        depth: depth
      });
      if (node.children) {
        getAllFolders(node.children, depth + 1, folders);
      }
    }
  });
  return folders;
}

// Get favicon URL
function getFaviconUrl(url) {
  try {
    const urlObj = new URL(url);
    return `https://www.google.com/s2/favicons?domain=${urlObj.hostname}&sz=32`;
  } catch {
    return '';
  }
}

// Escape HTML
function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// Show error message
function showError(message) {
  bookmarkList.innerHTML = `
    <div style="text-align: center; padding: 40px 20px; color: var(--md-sys-color-error);">
      <div style="font-size: 48px; margin-bottom: 12px;">⚠️</div>
      <div style="font-size: 14px;">${escapeHtml(message)}</div>
    </div>
  `;
}

// Open extension in new tab
async function openInNewTab() {
  try {
    // Get the extension's URL for the sidebar page
    const extensionUrl = browser.runtime.getURL('sidebar.html');
    // Open it in a new tab
    await browser.tabs.create({ url: extensionUrl });
  } catch (error) {
    console.error('Error opening in new tab:', error);
    alert('Failed to open in new tab');
  }
}

// Convert bookmark tree to HTML format
function bookmarksToHTML(bookmarkNodes, indent = 0) {
  let html = '';
  const indentStr = '    '.repeat(indent);

  for (const node of bookmarkNodes) {
    if (node.url) {
      // It's a bookmark
      const addDate = node.dateAdded ? Math.floor(node.dateAdded / 1000) : '';
      html += `${indentStr}<DT><A HREF="${node.url}"${addDate ? ` ADD_DATE="${addDate}"` : ''}>${node.title || node.url}</A>\n`;
    } else if (node.children) {
      // It's a folder
      const addDate = node.dateAdded ? Math.floor(node.dateAdded / 1000) : '';
      html += `${indentStr}<DT><H3${addDate ? ` ADD_DATE="${addDate}"` : ''}>${node.title || 'Untitled Folder'}</H3>\n`;
      html += `${indentStr}<DL><p>\n`;
      html += bookmarksToHTML(node.children, indent + 1);
      html += `${indentStr}</DL><p>\n`;
    }
  }

  return html;
}

// Generate complete HTML bookmark file
function generateBookmarkHTML(bookmarkTree) {
  const timestamp = new Date().toISOString();
  const date = new Date();

  let html = `<!DOCTYPE NETSCAPE-Bookmark-file-1>
<!-- This is an automatically generated file.
     It will be read and overwritten.
     DO NOT EDIT! -->
<META HTTP-EQUIV="Content-Type" CONTENT="text/html; charset=UTF-8">
<TITLE>Bookmarks</TITLE>
<H1>Bookmarks</H1>
<DL><p>
`;

  // Process the bookmark tree
  // Firefox bookmark tree has a root node, we want to export its children
  if (bookmarkTree && bookmarkTree.length > 0) {
    const root = bookmarkTree[0];
    if (root.children) {
      html += bookmarksToHTML(root.children, 1);
    }
  }

  html += `</DL><p>\n`;

  return html;
}

// SAFETY: Export bookmarks as JSON or HTML backup
async function exportBookmarks() {
  try {
    // Ask user for format preference
    const format = confirm(
      'Choose export format:\n\n' +
      'OK = HTML (compatible with all browsers)\n' +
      'Cancel = JSON (Firefox native format)\n\n' +
      'HTML format can be imported into any browser.\n' +
      'JSON format preserves all Firefox bookmark metadata.'
    ) ? 'html' : 'json';

    let data;

    // Export actual bookmarks
    const tree = await browser.bookmarks.getTree();

    // Debug: Log the root folders we're getting
    if (tree && tree.length > 0 && tree[0].children) {
      console.log('[Export] Root folders found:');
      tree[0].children.forEach(folder => {
        console.log(`  - "${folder.title}" (id: ${folder.id}, children: ${folder.children?.length || 0})`);
      });
    }

    // Ensure Mobile Bookmarks folder is included
    // Firefox's getTree() sometimes doesn't include mobile______ if it's empty or hidden
    if (tree && tree.length > 0 && tree[0].children) {
      const hasMobile = tree[0].children.some(folder => folder.id === 'mobile______');

      if (!hasMobile) {
        console.log('[Export] Mobile Bookmarks not in tree, attempting to fetch explicitly...');
        try {
          // Try to get mobile bookmarks folder explicitly
          const mobileFolder = await browser.bookmarks.getSubTree('mobile______');
          if (mobileFolder && mobileFolder.length > 0) {
            console.log(`[Export] Found Mobile Bookmarks: ${mobileFolder[0].children?.length || 0} items`);
            // Add it to the tree
            tree[0].children.push(mobileFolder[0]);
          }
        } catch (e) {
          console.log('[Export] Could not fetch Mobile Bookmarks folder:', e.message);
        }
      }
    }

    data = tree;

    // Generate filename with timestamp
    const date = new Date().toISOString().split('T')[0];
    let filename, blob, url;

    if (format === 'html') {
      // Create HTML file
      const html = generateBookmarkHTML(data);
      blob = new Blob([html], { type: 'text/html;charset=utf-8' });
      url = URL.createObjectURL(blob);
      filename = `bookmarks-${date}.html`;
    } else {
      // Create JSON file
      const json = JSON.stringify(data, null, 2);
      blob = new Blob([json], { type: 'application/json' });
      url = URL.createObjectURL(blob);
      filename = `bookmarks-backup-${date}.json`;
    }

    // Create download link and trigger download
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    if (format === 'html') {
      alert(
        `✓ Bookmarks exported as HTML!\n\n` +
        `File: ${filename}\n\n` +
        `This file can be imported into:\n` +
        `• Firefox: Bookmarks → Manage Bookmarks → Import and Backup → Import Bookmarks from HTML\n` +
        `• Chrome/Edge: Bookmarks → Import bookmarks and settings\n` +
        `• Any browser that supports Netscape bookmark format`
      );
    } else {
      alert(
        `✓ Bookmarks exported as JSON!\n\n` +
        `File: ${filename}\n\n` +
        `This backup can be imported back into Firefox via:\n` +
        `Bookmarks → Manage Bookmarks → Import and Backup → Restore → Choose File`
      );
    }
  } catch (error) {
    console.error('Error exporting bookmarks:', error);
    alert('Failed to export bookmarks. Please try again.');
  }
}

// DUPLICATE DETECTION: Find and manage duplicate bookmarks
async function findDuplicates() {
  try {
    let allBookmarks = [];

    // Get all bookmarks from Firefox
    const tree = await browser.bookmarks.getTree();
    allBookmarks = getAllBookmarksFlat(tree);

    // Group bookmarks by URL
    const urlMap = new Map();
    for (const bookmark of allBookmarks) {
      if (bookmark.url) { // Only process bookmarks (not folders)
        if (!urlMap.has(bookmark.url)) {
          urlMap.set(bookmark.url, []);
        }
        urlMap.get(bookmark.url).push(bookmark);
      }
    }

    // Find duplicates (URLs with more than one bookmark)
    const duplicates = [];
    for (const [url, bookmarks] of urlMap.entries()) {
      if (bookmarks.length > 1) {
        duplicates.push({ url, bookmarks });
      }
    }

    if (duplicates.length === 0) {
      alert('✓ No duplicate bookmarks found!\n\nAll your bookmarks have unique URLs.');
      return;
    }

    // Show duplicates modal
    showDuplicatesModal(duplicates);

  } catch (error) {
    console.error('Error finding duplicates:', error);
    alert('Failed to scan for duplicates. Please try again.');
  }
}

// Helper: Get all bookmarks from tree (recursive, flattened)
function getAllBookmarksFlat(tree, parentPath = '') {
  let bookmarks = [];

  const processNode = (node, path) => {
    // Skip separators
    if (node.type === 'separator') return;

    if (node.url) {
      // It's a bookmark
      bookmarks.push({
        ...node,
        parentPath: path
      });
    }
    if (node.children) {
      // It's a folder - process children
      const newPath = path ? `${path} > ${node.title || 'Untitled'}` : node.title || 'Root';
      for (const child of node.children) {
        processNode(child, newPath);
      }
    }
  };

  if (Array.isArray(tree)) {
    for (const node of tree) {
      processNode(node, parentPath);
    }
  } else {
    processNode(tree, parentPath);
  }

  return bookmarks;
}

// Global storage for current duplicates data
let currentDuplicates = [];

// Show duplicates modal
function showDuplicatesModal(duplicates) {
  const modal = document.getElementById('duplicatesModal');
  const content = document.getElementById('duplicatesContent');

  // Store duplicates for later use in deletion check
  currentDuplicates = duplicates;

  // Build HTML for duplicates
  let html = `
    <div style="margin-bottom: 8px;">
      <p style="font-size: 11px;"><strong>Found ${duplicates.length} URL(s) with duplicates (${duplicates.reduce((sum, d) => sum + d.bookmarks.length, 0)} total bookmarks)</strong></p>
      <p style="color: #666; font-size: 9px;">Select the bookmarks you want to delete:</p>
    </div>
  `;

  for (const duplicate of duplicates) {
    html += `
      <div style="margin-bottom: 10px; padding: 8px; background: rgba(59, 130, 246, 0.05); border-radius: 4px; border: 1px solid rgba(59, 130, 246, 0.2);">
        <div style="margin-bottom: 6px; font-size: 9px;">
          <strong style="color: #1e40af;">URL:</strong>
          <a href="${duplicate.url}" target="_blank" style="color: #2563eb; text-decoration: none; word-break: break-all; font-size: 9px;">${duplicate.url}</a>
        </div>
        <div style="margin-left: 8px;">
    `;

    for (const bookmark of duplicate.bookmarks) {
      html += `
        <div style="margin-bottom: 4px; display: flex; align-items: center; gap: 4px;">
          <input type="checkbox"
                 id="dup-${bookmark.id}"
                 data-bookmark-id="${bookmark.id}"
                 data-url="${duplicate.url}"
                 class="duplicate-checkbox"
                 style="cursor: pointer; width: 10px; height: 10px;">
          <label for="dup-${bookmark.id}" style="cursor: pointer; flex: 1; font-size: 9px;">
            <span style="font-weight: 500;">${bookmark.title || 'Untitled'}</span>
            <span style="color: #666; font-size: 8px;"> - in ${bookmark.parentPath || 'Root'}</span>
          </label>
        </div>
      `;
    }

    html += `
        </div>
      </div>
    `;
  }

  content.innerHTML = html;
  modal.classList.remove('hidden');
  modal.setAttribute('aria-hidden', 'false');
  trapFocus(modal);
}

// Close duplicates modal
function closeDuplicatesModal() {
  const modal = document.getElementById('duplicatesModal');
  modal.classList.add('hidden');
  modal.setAttribute('aria-hidden', 'true');
  releaseFocusTrap();
}

// Delete selected duplicates
async function deleteSelectedDuplicates() {
  const checkboxes = document.querySelectorAll('.duplicate-checkbox:checked');

  if (checkboxes.length === 0) {
    alert('Please select at least one bookmark to delete.');
    return;
  }

  const confirmed = confirm(`⚠ Delete ${checkboxes.length} selected bookmark(s)?\n\nYou can undo this from the toast or the changelog.`);
  if (!confirmed) return;

  // Check if user is deleting ALL copies of any URL
  const selectedIds = new Set(Array.from(checkboxes).map(cb => cb.dataset.bookmarkId));
  const urlsWithAllCopiesSelected = [];

  for (const duplicate of currentDuplicates) {
    const allIdsForThisUrl = duplicate.bookmarks.map(b => b.id);
    const allSelected = allIdsForThisUrl.every(id => selectedIds.has(id));

    if (allSelected) {
      urlsWithAllCopiesSelected.push(duplicate.url);
    }
  }

  // Second warning if deleting all copies of any URL
  if (urlsWithAllCopiesSelected.length > 0) {
    const urlList = urlsWithAllCopiesSelected.map(url => `  • ${url}`).join('\n');
    const finalWarning = confirm(
      `⚠️ WARNING! YOU ARE ABOUT TO DELETE ALL COPIES OF THE FOLLOWING BOOKMARK(S):\n\n${urlList}\n\nTHERE WILL BE NO REMAINING COPIES OF THESE BOOKMARKS!\n\nARE YOU ABSOLUTELY SURE YOU WANT TO CONTINUE?`
    );

    if (!finalWarning) return;
  }

  try {
    let successCount = 0;
    let failCount = 0;
    const deleted = [];

    for (const checkbox of checkboxes) {
      const bookmarkId = checkbox.dataset.bookmarkId;
      try {
        /* [ZeroLabs] 2026-08-27 - added: record before removing, like every other delete */
        const [node] = await browser.bookmarks.get(bookmarkId);
        const fullData = node ? JSON.parse(JSON.stringify(node)) : null;
        await browser.bookmarks.remove(bookmarkId);
        if (fullData) {
          await addChangelogEntry('delete', 'bookmark', fullData.title || 'Untitled', fullData.url || null, { fullData });
          await recordLocalDeletion(fullData);
          deleted.push({ type: 'bookmark', data: fullData });
        }
        successCount++;
      } catch (error) {
        console.error(`Failed to delete bookmark ${bookmarkId}:`, error);
        failCount++;
      }
    }

    // Reload bookmarks
    await loadBookmarks();
    renderBookmarks();

    // Close modal and show result
    closeDuplicatesModal();

    /* [ZeroLabs] 2026-08-27 - added: ask about these deletions now */
    window.syncAfterLocalDeletion?.();

    if (failCount === 0) {
      /* [ZeroLabs] 2026-08-27 - edited: an undo toast instead of a blocking alert */
      showUndoToast({
        type: 'bulk',
        data: deleted,
        message: `${successCount} duplicate${successCount === 1 ? '' : 's'} deleted`
      });
    } else {
      alert(`⚠ Deleted ${successCount} bookmark(s).\n${failCount} failed to delete.`);
    }

  } catch (error) {
    console.error('Error deleting duplicates:', error);
    alert('An error occurred while deleting bookmarks.');
  }
}

// View error logs
async function viewErrorLogs() {
  try {
    const result = await safeStorage.get('errorLogs');
    const errorLogs = result.errorLogs || [];

    if (errorLogs.length === 0) {
      alert('No error logs found. The extension is working smoothly!');
      return;
    }

    // Format error logs for display
    let logText = `ERROR LOGS (${errorLogs.length} total)\n`;
    logText += '='.repeat(60) + '\n\n';

    errorLogs.forEach((log, index) => {
      const date = new Date(log.timestamp);
      logText += `#${index + 1} - ${date.toLocaleString()}\n`;
      logText += `Context: ${log.context}\n`;
      logText += `Message: ${log.message}\n`;
      if (log.stack) {
        logText += `Stack: ${log.stack.split('\n')[0]}\n`;
      }
      logText += '-'.repeat(60) + '\n\n';
    });

    // Show in a prompt to allow copying
    const action = confirm(
      `Found ${errorLogs.length} error log(s).\n\n` +
      `Click OK to view in console, or Cancel to clear logs.`
    );

    if (action) {
      console.log(logText);
      alert('Error logs have been printed to the browser console. Press F12 to view.');
    } else {
      // Clear logs
      const confirmClear = confirm('Are you sure you want to clear all error logs?');
      if (confirmClear) {
        await safeStorage.remove('errorLogs');
        alert('Error logs cleared successfully.');
      }
    }
  } catch (error) {
    console.error('Error viewing logs:', error);
    alert('Failed to load error logs.');
  }
}

// Open changelog modal
async function openChangelogModal() {
  const modal = document.getElementById('changelogModal');
  const changelogList = document.getElementById('changelogList');
  const changelogCount = document.getElementById('changelogCount');

  // Load changelog entries
  const entries = await getChangelogEntries();

  // Update count
  changelogCount.textContent = `${entries.length} ${entries.length === 1 ? 'entry' : 'entries'}`;

  // Render entries
  if (entries.length === 0) {
    changelogList.innerHTML = `
      <div style="text-align: center; padding: 40px 20px; color: var(--md-sys-color-on-surface-variant);">
        <svg width="48" height="48" fill="currentColor" viewBox="0 0 24 24" style="opacity: 0.3; margin-bottom: 12px;">
          <path d="M13.5,8H12V13L16.28,15.54L17,14.33L13.5,12.25V8M13,3A9,9 0 0,0 4,12H1L4.96,16.03L9,12H6A7,7 0 0,1 13,5A7,7 0 0,1 20,12A7,7 0 0,1 13,19C11.07,19 9.32,18.21 8.06,16.94L6.64,18.36C8.27,20 10.5,21 13,21A9,9 0 0,0 22,12A9,9 0 0,0 13,3Z"/>
        </svg>
        <p style="font-size: 14px;">No changes recorded yet.</p>
        <p style="font-size: 12px; opacity: 0.7; margin-top: 8px;">Your bookmark changes will appear here.</p>
      </div>
    `;
  } else {
    let html = '<div style="display: flex; flex-direction: column; gap: 12px;">';

    entries.forEach(entry => {
      const date = new Date(entry.timestamp);
      const timeAgo = getTimeAgo(entry.timestamp);

      let iconColor;
      if (entry.type === 'create') iconColor = '#10b981';
      else if (entry.type === 'delete') iconColor = '#ef4444';
      else if (entry.type === 'move') iconColor = '#3b82f6';
      else if (entry.type === 'undo') iconColor = '#8b5cf6';
      else if (entry.type === 'pre-sync-snapshot') iconColor = '#f59e0b';
      else iconColor = '#f59e0b';

      // SVG icons for operation types
      let icon;
      if (entry.type === 'create') {
        icon = `<svg width="20" height="20" fill="currentColor" viewBox="0 0 24 24" style="color: ${iconColor};"><path d="M19,13H13V19H11V13H5V11H11V5H13V11H19V13Z"/></svg>`;
      } else if (entry.type === 'delete') {
        icon = `<svg width="20" height="20" fill="currentColor" viewBox="0 0 24 24" style="color: ${iconColor};"><path d="M9,3V4H4V6H5V19A2,2 0 0,0 7,21H17A2,2 0 0,0 19,19V6H20V4H15V3H9M7,6H17V19H7V6M9,8V17H11V8H9M13,8V17H15V8H13Z"/></svg>`;
      } else if (entry.type === 'move') {
        icon = `<svg width="20" height="20" fill="currentColor" viewBox="0 0 24 24" style="color: ${iconColor};"><path d="M14,18L12.6,16.6L15.2,14H4V12H15.2L12.6,9.4L14,8L19,13L14,18M20,6H10A2,2 0 0,0 8,8V11H10V8H20V20H10V17H8V20A2,2 0 0,0 10,22H20A2,2 0 0,0 22,20V8A2,2 0 0,0 20,6Z"/></svg>`;
      } else if (entry.type === 'undo') {
        icon = `<svg width="20" height="20" fill="currentColor" viewBox="0 0 24 24" style="color: ${iconColor};"><path d="M12.5,8C9.85,8 7.45,9 5.6,10.6L2,7V16H11L7.38,12.38C8.77,11.22 10.54,10.5 12.5,10.5C16.04,10.5 19.05,12.81 19.56,16H22.01C21.43,12.16 17.97,9 13.9,9H12.5V8M12.5,16C10.54,16 8.77,15.28 7.38,14.12L11,10.5H2V19.5L5.6,15.9C7.45,17.5 9.85,18.5 12.5,18.5C17.1,18.5 20.95,15.4 21.9,11.2H19.38C18.77,14.16 15.76,16.34 12.5,16Z"/></svg>`;
      } else if (entry.type === 'pre-sync-snapshot') {
        icon = `<svg width="20" height="20" fill="currentColor" viewBox="0 0 24 24" style="color: ${iconColor};"><path d="M12,18A6,6 0 0,1 6,12C6,11 6.25,10.03 6.7,9.2L5.24,7.74C4.46,8.97 4,10.43 4,12A8,8 0 0,0 12,20V23L16,19L12,15M12,4V1L8,5L12,9V6A6,6 0 0,1 18,12C18,13 17.75,13.97 17.3,14.8L18.76,16.26C19.54,15.03 20,13.57 20,12A8,8 0 0,0 12,4Z"/></svg>`;
      } else {
        icon = `<svg width="20" height="20" fill="currentColor" viewBox="0 0 24 24" style="color: ${iconColor};"><path d="M20.71,7.04C21.1,6.65 21.1,6 20.71,5.63L18.37,3.29C18,2.9 17.35,2.9 16.96,3.29L15.12,5.12L18.87,8.87M3,17.25V21H6.75L17.81,9.93L14.06,6.18L3,17.25Z"/></svg>`;
      }

      // SVG icons for item types (skip for sync snapshots)
      let itemIcon = '';
      if (entry.type !== 'pre-sync-snapshot') {
        if (entry.itemType === 'folder') {
          itemIcon = `<svg width="16" height="16" fill="currentColor" viewBox="0 0 24 24" style="color: var(--md-sys-color-primary);"><path d="M10,4H4C2.89,4 2,4.89 2,6V18A2,2 0 0,0 4,20H20A2,2 0 0,0 22,18V8C22,6.89 21.1,6 20,6H12L10,4Z"/></svg>`;
        } else {
          itemIcon = `<svg width="16" height="16" fill="currentColor" viewBox="0 0 24 24" style="color: var(--md-sys-color-secondary);"><path d="M17,3H7A2,2 0 0,0 5,5V21L12,18L19,21V5C19,3.89 18.1,3 17,3Z"/></svg>`;
        }
      }

      let detailsHtml = '';
      if (entry.details) {
        if (entry.type === 'pre-sync-snapshot') {
          detailsHtml = `<div style="font-size: 11px; color: var(--md-sys-color-on-surface-variant); margin-top: 4px;">⚠️ Replaced all local bookmarks with remote data</div>`;
        } else if (entry.type === 'undo') {
          if (entry.details.undoType === 'move') {
            detailsHtml = `<div style="font-size: 11px; color: var(--md-sys-color-on-surface-variant); margin-top: 4px;">Restored to: ${entry.details.restoredToFolder}</div>`;
          } else if (entry.details.undoType === 'update') {
            detailsHtml = `<div style="font-size: 11px; color: var(--md-sys-color-on-surface-variant); margin-top: 4px;">Reverted title from: "${entry.details.previousTitle}"</div>`;
          } else {
            detailsHtml = `<div style="font-size: 11px; color: var(--md-sys-color-on-surface-variant); margin-top: 4px;">Undid ${entry.details.undoType} operation</div>`;
          }
        } else if (entry.type === 'move' && entry.details.oldParent && entry.details.newParent) {
          detailsHtml = `<div style="font-size: 11px; color: var(--md-sys-color-on-surface-variant); margin-top: 4px;">From: ${entry.details.oldParent} → ${entry.details.newParent}</div>`;
        } else if (entry.type === 'update') {
          if (entry.details.oldTitle && entry.details.newTitle && entry.details.oldTitle !== entry.details.newTitle) {
            detailsHtml = `<div style="font-size: 11px; color: var(--md-sys-color-on-surface-variant); margin-top: 4px;">Renamed from: ${entry.details.oldTitle}</div>`;
          }
          if (entry.details.oldUrl && entry.details.newUrl && entry.details.oldUrl !== entry.details.newUrl) {
            detailsHtml += `<div style="font-size: 11px; color: var(--md-sys-color-on-surface-variant); margin-top: 2px;">URL changed</div>`;
          }
        }
      }

      const urlHtml = entry.url ? `<div class="changelog-url" data-url="${entry.url}" style="font-size: 11px; color: var(--md-sys-color-primary); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; cursor: pointer; text-decoration: underline;" title="Click to copy: ${entry.url}">${entry.url}</div>` : '';

      let restoreButtonHtml = '';
      if (entry.type === 'pre-sync-snapshot') {
        restoreButtonHtml = `
          <button class="changelog-restore-btn" data-entry-id="${entry.id}" title="Restore pre-sync bookmarks" style="margin-left: auto; padding: 6px 12px; border: 1px solid ${iconColor}; border-radius: 6px; background: ${iconColor}; color: #000; cursor: pointer; font-size: 12px; font-weight: 600;">
            Restore Pre-Sync Bookmarks
          </button>
        `;
      } else if ((entry.type === 'delete' || entry.type === 'move' || entry.type === 'update') && entry.type !== 'undo') {
        const restoreTitle = entry.type === 'delete' ? 'Restore this item' :
                            entry.type === 'move' ? 'Move back to original location' :
                            'Revert changes';
        restoreButtonHtml = `
          <button class="changelog-restore-btn" data-entry-id="${entry.id}" title="${restoreTitle}" style="margin-left: auto; padding: 4px 8px; border: 1px solid var(--md-sys-color-outline); border-radius: 4px; background: var(--md-sys-color-surface); color: var(--md-sys-color-on-surface); cursor: pointer; font-size: 11px; opacity: 0.7; transition: opacity 0.2s;">
            Restore
          </button>
        `;
      }

      html += `
        <div style="padding: 12px; background: var(--md-sys-color-surface-variant); border-radius: 8px; border-left: 3px solid ${iconColor};">
          <div style="display: flex; align-items: start; gap: 8px;">
            <div style="font-size: 20px; flex-shrink: 0;">${icon}</div>
            <div style="flex: 1; min-width: 0;">
              <div style="display: flex; align-items: center; gap: 6px; margin-bottom: 2px;">
                <span style="font-size: 14px;">${itemIcon}</span>
                <span style="font-size: 13px; font-weight: 600; color: var(--md-sys-color-on-surface);">${entry.title || 'Untitled'}</span>
                ${restoreButtonHtml}
              </div>
              ${urlHtml}
              ${detailsHtml}
              <div style="font-size: 11px; color: var(--md-sys-color-on-surface-variant); margin-top: 6px; opacity: 0.7;">${timeAgo}</div>
            </div>
          </div>
        </div>
      `;
    });

    html += '</div>';
    changelogList.innerHTML = html;

    // Add click handlers to URLs for copying to clipboard
    const urlElements = changelogList.querySelectorAll('.changelog-url');
    urlElements.forEach(urlEl => {
      urlEl.addEventListener('click', async (e) => {
        e.stopPropagation();
        const url = urlEl.getAttribute('data-url');
        try {
          await navigator.clipboard.writeText(url);
          // Show visual feedback
          const originalText = urlEl.textContent;
          const originalColor = urlEl.style.color;
          urlEl.textContent = '✓ Copied!';
          urlEl.style.color = '#10b981';
          setTimeout(() => {
            urlEl.textContent = originalText;
            urlEl.style.color = originalColor;
          }, 1500);
        } catch (error) {
          console.error('Failed to copy URL:', error);
          alert('Failed to copy URL to clipboard');
        }
      });
    });

    // Add click handlers to restore buttons
    const restoreButtons = changelogList.querySelectorAll('.changelog-restore-btn');
    restoreButtons.forEach(restoreBtn => {
      restoreBtn.addEventListener('click', async (e) => {
        e.stopPropagation();
        const entryId = restoreBtn.getAttribute('data-entry-id');
        await restoreChangelogEntry(entryId);
      });
    });
  }

  // Show modal
  modal.classList.remove('hidden');
  modal.setAttribute('aria-hidden', 'false');
  trapFocus(modal);
}

// Close modal (generic)
function closeModal(modal) {
  modal.classList.add('hidden');
  modal.setAttribute('aria-hidden', 'true');
  releaseFocusTrap();
}

// Close changelog modal
function closeChangelogModal() {
  const modal = document.getElementById('changelogModal');
  modal.classList.add('hidden');
  modal.setAttribute('aria-hidden', 'true');
  releaseFocusTrap();
}

// Restore a changelog entry (undo the operation)
async function restoreChangelogEntry(entryId) {
  try {
    const entries = await getChangelogEntries();
    const entry = entries.find(e => e.id == entryId);

    if (!entry) {
      alert('Changelog entry not found.');
      return;
    }

    // Handle pre-sync-snapshot restoration
    if (entry.type === 'pre-sync-snapshot') {
      if (!entry.details || !entry.details.snapshot) {
        alert('Snapshot data not found. Cannot restore pre-sync bookmarks.');
        return;
      }

      const confirmed = confirm(
        `⚠️ RESTORE PRE-SYNC BOOKMARKS\n\n` +
        `This will replace ALL your current bookmarks with the bookmarks you had BEFORE the sync operation.\n\n` +
        `Operation: ${entry.details.operation || 'Sync'}\n` +
        `Date: ${new Date(entry.timestamp).toLocaleString()}\n\n` +
        `Are you sure you want to proceed?`
      );

      if (!confirmed) return;

      try {
        showToast('Restoring pre-sync bookmarks...', 'info');

        const snapshot = entry.details.snapshot;

        // Delete all current bookmarks
        const currentTree = await browser.bookmarks.getTree();
        const roots = currentTree[0].children;
        for (const root of roots) {
          if (root.children) {
            for (const child of root.children) {
              try {
                await browser.bookmarks.removeTree(child.id);
              } catch (error) {
                console.warn(`Failed to remove bookmark ${child.id}:`, error);
              }
            }
          }
        }

        // Restore from snapshot
        const createNodes = async (nodes, parentId) => {
          for (const node of nodes) {
            if (node.url) {
              await browser.bookmarks.create({
                parentId: parentId,
                title: node.title || 'Untitled',
                url: node.url
              });
            } else if (node.children) {
              const newFolder = await browser.bookmarks.create({
                parentId: parentId,
                title: node.title || 'Untitled Folder'
              });
              await createNodes(node.children, newFolder.id);
            }
          }
        };

        // Re-fetch tree to get current root IDs
        const freshTree = await browser.bookmarks.getTree();
        const freshRoots = freshTree[0].children;
        const toolbar = freshRoots.find(r => r.id === 'toolbar_____');
        const menu = freshRoots.find(r => r.id === 'menu________');
        const unfiled = freshRoots.find(r => r.id === 'unfiled_____');
        const mobile = freshRoots.find(r => r.id === 'mobile______');

        // Recreate bookmark structure from snapshot
        if (snapshot.roots) {
          if (snapshot.roots.bookmark_bar && snapshot.roots.bookmark_bar.children && toolbar) {
            await createNodes(snapshot.roots.bookmark_bar.children, toolbar.id);
          }
          if (snapshot.roots.menu && snapshot.roots.menu.children && menu) {
            await createNodes(snapshot.roots.menu.children, menu.id);
          }
          if (snapshot.roots.other && snapshot.roots.other.children && unfiled) {
            await createNodes(snapshot.roots.other.children, unfiled.id);
          }
          if (snapshot.roots.mobile && snapshot.roots.mobile.children && mobile) {
            await createNodes(snapshot.roots.mobile.children, mobile.id);
          }
        }

        // Clear changelog since we've restored to a previous state
        await clearChangelog();

        showToast('✓ Pre-sync bookmarks restored successfully!', 'success');

        // Refresh UI
        await loadBookmarks();
        renderBookmarks();

        // Close changelog modal
        closeChangelogModal();

        return;
      } catch (error) {
        console.error('[Restore Snapshot] Error:', error);
        showToast(`Failed to restore snapshot: ${error.message}`, 'error');
        return;
      }
    }

    // Only allow restoring certain operation types
    if (!['delete', 'move', 'update'].includes(entry.type)) {
      alert('This operation type cannot be restored.');
      return;
    }

    const confirmed = confirm(`Restore this ${entry.type} operation: "${entry.title}"?\n\nThis will attempt to undo the change.`);
    if (!confirmed) return;

    if (entry.type === 'delete') {
      // Check if we have the full data stored
      if (!entry.details || !entry.details.fullData) {
        alert('Delete operations cannot be automatically restored from the changelog.\n\nThis deletion was logged before full data storage was implemented.\n\nUse the undo feature immediately after deletion for full restoration.');
        return;
      }

      // Restore the deleted item
      const fullData = entry.details.fullData;

      try {
        /* [ZeroLabs] 2026-08-27 - edited: use the shared restore, and survive a missing parent */
        // The folder branch created an EMPTY folder and told the user its contents
        // were lost - but fullData holds the whole subtree, and restoreDeletedItem
        // rebuilds it, which is what the undo toast has always done. A parent that
        // no longer exists now falls back instead of throwing.
        // Two different reasons to relocate, and they deserve different wording: an
        // entry logged before a parent was recorded knows nothing about where it was,
        // which is not the same as its folder being gone.
        let targetParentId = fullData.parentId;
        let relocated = null;
        let parentTitle = '';
        if (!targetParentId) {
          relocated = 'unknown';
        } else {
          try {
            const [p] = await browser.bookmarks.get(targetParentId);
            parentTitle = p ? p.title : '';
          } catch (e) {
            relocated = 'missing';
          }
        }
        if (relocated) {
          const roots = await browser.bookmarks.getChildren('0');
          const fallback = roots && roots[0];
          targetParentId = fallback ? fallback.id : null;
          parentTitle = fallback ? fallback.title : '';
          if (!fallback) relocated = null;
        }
        if (!targetParentId) {
          const roots = await browser.bookmarks.getChildren('0');
          const fallback = roots && roots[0];
          targetParentId = fallback ? fallback.id : null;
          parentTitle = fallback ? fallback.title : '';
          relocated = !!fallback;
        }
      
        if (!targetParentId) {
          alert('Could not restore: there is nowhere to put it.');
          return;
        }
      
        const where = relocated
          ? (relocated === 'unknown'
              ? `

BMZ did not record where this was, so it was restored to "${parentTitle}".`
              : `

Its original folder no longer exists, so it was restored to "${parentTitle}".`)
          : '';
      
        await restoreDeletedItem(
          entry.itemType === 'folder' ? 'folder' : 'bookmark',
          { ...fullData, parentId: targetParentId }
        );
      
        alert(entry.itemType === 'folder'
          ? `Folder "${fullData.title}" and its contents have been restored.${where}`
          : `Bookmark "${fullData.title}" has been restored successfully!${where}`);

        // Refresh UI
        await loadBookmarks();
        await renderBookmarks();

        // Close and reopen changelog modal to refresh
        closeChangelogModal();
        setTimeout(() => openChangelogModal(), 100);

        return;
      } catch (error) {
        console.error('[Changelog Restore] Failed to restore deleted item:', error);
        alert(`Failed to restore item: ${error.message}`);
        return;
      }
    }

    if (entry.type === 'move') {
      if (entry.details && entry.details.oldParent) {
        const items = await browser.bookmarks.search({ title: entry.title });
        const matchingItem = items.find(item =>
          item.title === entry.title &&
          (!entry.url || item.url === entry.url)
        );

        if (matchingItem) {
          let targetParentId = null;
          const folderPath = entry.details.oldParent;

          if (folderPath === 'Root') {
            targetParentId = undefined;
          } else if (folderPath) {
            const allBookmarks = await browser.bookmarks.getTree();
            const pathParts = folderPath.split(' > ');

            function findFolderByPath(nodes, parts, index) {
              if (index >= parts.length) return null;
              
              for (const node of nodes) {
                if (node.title === parts[index] && !node.url) {
                  if (index === parts.length - 1) {
                    return node.id;
                  }
                  if (node.children) {
                    const found = findFolderByPath(node.children, parts, index + 1);
                    if (found) return found;
                  }
                }
              }
              return null;
            }

            targetParentId = findFolderByPath(allBookmarks[0].children, pathParts, 0);
          }

          if (folderPath !== 'Root' && !targetParentId) {
            alert(`Original folder "${folderPath}" not found. The folder may have been deleted.`);
            return;
          }

          try {
            const moveOptions = { parentId: targetParentId };
            if (targetParentId === undefined) {
              moveOptions.index = bookmarkTree.length;
            }
            await browser.bookmarks.move(matchingItem.id, moveOptions);
            alert(`Moved "${entry.title}" back to ${entry.details.oldParent || 'Root'}`);
            
            const itemType = matchingItem.url ? 'bookmark' : 'folder';
            await addChangelogEntry('undo', itemType, entry.title, matchingItem.url || null, {
              undoType: 'move',
              originalOperation: entry,
              restoredToFolder: entry.details.oldParent
            });
            
            await loadBookmarks();
            renderBookmarks();
          } catch (error) {
            alert('Failed to move item back: ' + error.message);
          }
        } else {
          alert('Could not find the moved item. It may have been deleted or renamed.');
        }
      } else {
        alert('Not enough information to restore this move operation.');
      }
    }

    if (entry.type === 'update') {
      if (entry.details && entry.details.oldTitle) {
        const items = await browser.bookmarks.search({ title: entry.title });
        const matchingItem = items.find(item =>
          item.title === entry.title &&
          (!entry.url || item.url === entry.url)
        );

        if (matchingItem) {
          try {
            await browser.bookmarks.update(matchingItem.id, { title: entry.details.oldTitle });
            alert(`Restored title from "${entry.title}" back to "${entry.details.oldTitle}"`);
            
            const itemType = matchingItem.url ? 'bookmark' : 'folder';
            await addChangelogEntry('undo', itemType, entry.details.oldTitle, matchingItem.url || null, {
              undoType: 'update',
              originalOperation: entry,
              restoredTitle: entry.details.oldTitle,
              previousTitle: entry.title
            });
            
            await loadBookmarks();
            renderBookmarks();
          } catch (error) {
            alert('Failed to restore title: ' + error.message);
          }
        } else {
          alert('Could not find the updated item. It may have been deleted.');
        }
      } else {
        alert('Not enough information to restore this update operation.');
      }
    }
  } catch (error) {
    console.error('Failed to restore changelog entry:', error);
    alert('Failed to restore the operation: ' + error.message);
  }
}

// Helper to get relative time
function getTimeAgo(timestamp) {
  const seconds = Math.floor((Date.now() - timestamp) / 1000);

  if (seconds < 60) return 'Just now';

  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes} minute${minutes !== 1 ? 's' : ''} ago`;

  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours} hour${hours !== 1 ? 's' : ''} ago`;

  const days = Math.floor(hours / 24);
  if (days < 30) return `${days} day${days !== 1 ? 's' : ''} ago`;

  const months = Math.floor(days / 30);
  if (months < 12) return `${months} month${months !== 1 ? 's' : ''} ago`;

  const years = Math.floor(months / 12);
  return `${years} year${years !== 1 ? 's' : ''} ago`;
}

// Close extension
async function closeExtension() {
  try {
    // Check if we're running in a sidebar or a tab
    const currentTab = await browser.tabs.getCurrent();

    if (currentTab && currentTab.id) {
      // We're in a tab, so close the tab
      await browser.tabs.remove(currentTab.id);
    } else {
      // We're in a sidebar, use sidebarAction to close it
      // Note: Firefox doesn't have a direct API to close sidebar programmatically
      // We'll try to close the window, which works for sidebar panels
      window.close();
    }
  } catch (error) {
    console.error('Error closing extension:', error);
    // Fallback: just try to close the window
    window.close();
  }
}

// Clear cache for link status and safety checks
// Calculate cache size in KB
async function calculateCacheSize() {
  try {
    const result = await safeStorage.get(['linkStatusCache', 'safetyStatusCache', 'whitelistedUrls', 'safetyHistory']);

    // Calculate size by stringifying the data
    let totalSize = 0;
    if (result.linkStatusCache) {
      totalSize += JSON.stringify(result.linkStatusCache).length;
    }
    if (result.safetyStatusCache) {
      totalSize += JSON.stringify(result.safetyStatusCache).length;
    }
    if (result.whitelistedUrls) {
      totalSize += JSON.stringify(result.whitelistedUrls).length;
    }
    if (result.safetyHistory) {
      totalSize += JSON.stringify(result.safetyHistory).length;
    }

    // Convert bytes to KB
    return (totalSize / 1024).toFixed(2);
  } catch (error) {
    console.error('Error calculating cache size:', error);
    return 0;
  }
}

// Update cache size display
async function updateCacheSizeDisplay() {
  const cacheSizeElement = document.getElementById('cacheSize');
  if (!cacheSizeElement) return;

  const sizeKB = await calculateCacheSize();

  if (sizeKB === 0) {
    cacheSizeElement.textContent = 'Empty';
  } else if (sizeKB < 1) {
    cacheSizeElement.textContent = '< 1 KB';
  } else if (sizeKB >= 1024) {
    const sizeMB = (sizeKB / 1024).toFixed(2);
    cacheSizeElement.textContent = `${sizeMB} MB`;
  } else {
    cacheSizeElement.textContent = `${sizeKB} KB`;
  }
}

// Clear old cache entries based on auto-clear setting
async function clearOldCacheEntries(maxAgeDays) {
  if (maxAgeDays === 'never') {
    return;
  }

  try {
    const maxAgeMs = parseInt(maxAgeDays) * 24 * 60 * 60 * 1000;
    const cutoffTime = Date.now() - maxAgeMs;

    const result = await safeStorage.get(['linkStatusCache', 'safetyStatusCache', 'safetyHistory', 'lastCacheClear']);

    let updated = false;

    // Clear old link status cache entries
    if (result.linkStatusCache) {
      const linkCache = result.linkStatusCache;
      Object.keys(linkCache).forEach(url => {
        if (linkCache[url].timestamp && linkCache[url].timestamp < cutoffTime) {
          delete linkCache[url];
          updated = true;
        }
      });
      if (updated) {
        await safeStorage.set({ linkStatusCache: linkCache });
      }
    }

    // Clear old safety status cache entries
    if (result.safetyStatusCache) {
      const safetyCache = result.safetyStatusCache;
      Object.keys(safetyCache).forEach(url => {
        if (safetyCache[url].timestamp && safetyCache[url].timestamp < cutoffTime) {
          delete safetyCache[url];
          updated = true;
        }
      });
      if (updated) {
        await safeStorage.set({ safetyStatusCache: safetyCache });
      }
    }

    // Clear old safety history entries
    if (result.safetyHistory) {
      const history = result.safetyHistory;
      Object.keys(history).forEach(url => {
        if (Array.isArray(history[url])) {
          history[url] = history[url].filter(entry => entry.timestamp && entry.timestamp >= cutoffTime);
          if (history[url].length === 0) {
            delete history[url];
          }
          updated = true;
        }
      });
      if (updated) {
        await safeStorage.set({ safetyHistory: history });
      }
    }

    // Update last clear timestamp
    await safeStorage.set({ lastCacheClear: Date.now() });

    if (updated) {
      console.log(`Cleared cache entries older than ${maxAgeDays} days`);
      await updateCacheSizeDisplay();
    }
  } catch (error) {
    console.error('Error clearing old cache entries:', error);
  }
}

async function clearCache() {
  try {
    // Clear storage cache (current)
    await safeStorage.remove(['linkStatusCache', 'safetyStatusCache']);

    // ALSO CLEAR: Reset in-memory bookmark statuses
    function resetStatuses(nodes) {
      nodes.forEach(node => {
        if (node.url) {
          node.linkStatus = 'unknown';
          node.safetyStatus = 'unknown';
          node.safetySources = [];
        }
        if (node.children) resetStatuses(node.children);
      });
    }
    resetStatuses(bookmarkTree);

    // Re-render to show cleared states
    renderBookmarks();

    // Clear IndexedDB cache too (if scanner service available)
    if (window.scannerService && window.scannerService.clearAllCache) {
      await window.scannerService.clearAllCache();
    }

    /* [ZeroLabs] 2026-08-28 - added: forget WHEN folders were scanned, too */
    // Clearing the results but keeping the timestamps left every folder marked
    // "already scanned 0 days ago", so shouldScanFolder skipped them all. The
    // folderHasCachedStatuses check now catches that on its own, but a stale
    // timestamp should not outlive the results it refers to either way.
    folderScanTimestamps = {};
    // Removed the same way saveFolderScanTimestamp writes it - directly, NOT
    // via safeStorage, which diverts to session storage in private mode and
    // would leave the real key in place.
    await browser.storage.local.remove('folderScanTimestamps');

    console.log('Cache cleared successfully');
    alert('Cache cleared! Status indicators reset to unknown.');

    // Update cache size display
    await updateCacheSizeDisplay();
  } catch (error) {
    console.error('Error clearing cache:', error);
    alert('Failed to clear cache. Please try again.');
  }
}

// Update selected items count
function updateSelectedCount() {
  const selectedCount = document.getElementById('selectedCount');
  if (selectedCount) {
    selectedCount.textContent = selectedItems.size;
  }
}

// Bulk recheck selected items
async function bulkRecheckItems() {
  if (selectedItems.size === 0) {
    alert('No items selected. Please select items to recheck.');
    return;
  }

  if (!confirm(`Are you sure you want to recheck ${selectedItems.size} selected item(s)?`)) {
    return;
  }

  const itemsToRecheck = Array.from(selectedItems);

  // Get current bookmark tree
  const tree = await browser.bookmarks.getTree();
  const allBookmarks = tree[0].children || [];

  // Find all bookmarks in selected items (including bookmarks in selected folders)
  const bookmarksToRecheck = [];

  for (const itemId of itemsToRecheck) {
    const item = findBookmarkById(allBookmarks, itemId);
    if (item) {
      if (item.type === 'bookmark') {
        bookmarksToRecheck.push(item);
      } else if (item.type === 'folder') {
        // Get all bookmarks in folder recursively
        const folderBookmarks = getAllBookmarksInFolder(item);
        bookmarksToRecheck.push(...folderBookmarks);
      }
    }
  }

  // Remove from checked set to force recheck
  bookmarksToRecheck.forEach(b => checkedBookmarks.delete(b.id));

  // Recheck
  await autoCheckBookmarkStatuses();

  alert(`Rechecked ${bookmarksToRecheck.length} bookmark(s).`);
}

// Bulk move selected items
async function bulkMoveItems() {
  if (selectedItems.size === 0) {
    alert('No items selected. Please select items to move.');
    return;
  }

  // Get current bookmark tree
  const tree = await browser.bookmarks.getTree();
  const allBookmarks = tree[0].children || [];

  // Get all folders for selection
  const folders = getAllFolders(allBookmarks);

  // Create folder selection prompt
  let folderList = 'Select destination folder by number:\n\n';
  folders.forEach((folder, index) => {
    const indent = '  '.repeat(folder.depth || 0);
    folderList += `${index + 1}. ${indent}${folder.title || 'Unnamed Folder'}\n`;
  });

  const selection = prompt(folderList + '\nEnter folder number:');
  if (!selection) return;

  const folderIndex = parseInt(selection) - 1;
  if (isNaN(folderIndex) || folderIndex < 0 || folderIndex >= folders.length) {
    alert('Invalid folder selection.');
    return;
  }

  const destinationFolder = folders[folderIndex];

  if (!confirm(`Move ${selectedItems.size} item(s) to "${destinationFolder.title}"?`)) {
    return;
  }

  try {
    // Move each selected item
    for (const itemId of selectedItems) {
      // Get item details before moving
      const items = await browser.bookmarks.get(itemId);
      const item = items[0];
      const oldParent = item.parentId ? await getFolderPath(item.parentId) : 'Root';

      await browser.bookmarks.move(itemId, { parentId: destinationFolder.id });

      // Add to changelog
      const itemType = item.url ? 'bookmark' : 'folder';
      const newParent = await getFolderPath(destinationFolder.id);
      await addChangelogEntry('move', itemType, item.title, item.url, { oldParent, newParent });
    }

    selectedItems.clear();
    await loadBookmarks();
    renderBookmarks();
    updateSelectedCount();

    alert(`Successfully moved items to "${destinationFolder.title}".`);
  } catch (error) {
    console.error('Error moving items:', error);
    alert('Failed to move some items. Please try again.');
  }
}

// Bulk delete selected items
async function bulkDeleteItems() {
  if (selectedItems.size === 0) {
    alert('No items selected. Please select items to delete.');
    return;
  }

  if (!confirm(`⚠️ This will delete ${selectedItems.size} selected item(s) and all their contents.\n\nYou can undo this from the toast or the changelog. Are you sure?`)) {
    return;
  }

  try {
    /* [ZeroLabs] 2026-08-27 - added: record before removing, like every other delete */
    // Bulk delete wrote nothing to the changelog and showed no undo toast, so the
    // single most destructive action in BMZ was the only one with no way back.
    /* [ZeroLabs] 2026-08-27 - added: drop selections contained by another selection */
    // A folder and a bookmark inside it can both be ticked. removeTree on the
    // folder takes the child with it, so removing the child afterwards threw and
    // the whole bulk delete reported failure - and capturing both would have
    // duplicated the child on undo.
    const covered = new Set();
    for (const id of selectedItems) {
      try {
        const [n] = await browser.bookmarks.getSubTree(id);
        const walk = (node) => (node.children || []).forEach(c => { covered.add(c.id); walk(c); });
        if (n) walk(n);
      } catch (error) { /* already gone; the filter below handles it */ }
    }
    const topLevelIds = Array.from(selectedItems).filter(id => !covered.has(id));

    const deleted = [];
    for (const itemId of topLevelIds) {
      // getSubTree, not get: a folder must be captured with its contents or the
      // restore brings back an empty shell.
      const [node] = await browser.bookmarks.getSubTree(itemId);
      if (!node) continue;
      const fullData = JSON.parse(JSON.stringify(node));
      const itemType = node.url ? 'bookmark' : 'folder';
      await browser.bookmarks.removeTree(itemId);
      await addChangelogEntry('delete', itemType, node.title || 'Untitled', node.url || null, { fullData });
      /* [ZeroLabs] 2026-08-27 - added: record it from the copy we just took */
      await recordLocalDeletion(fullData);
      deleted.push({ type: itemType, data: fullData });
    }

    selectedItems.clear();
    await loadBookmarks();
    renderBookmarks();
    updateSelectedCount();

    showUndoToast({
      type: 'bulk',
      data: deleted,
      message: `${deleted.length} item${deleted.length === 1 ? '' : 's'} deleted`
    });

    /* [ZeroLabs] 2026-08-27 - added: ask about these deletions now */
    window.syncAfterLocalDeletion?.();
  } catch (error) {
    console.error('Error deleting items:', error);
    alert('Failed to delete some items. Please try again.');
  }
}

// Bulk open selected items in new tabs
async function bulkOpenItems() {
  if (selectedItems.size === 0) {
    alert('No items selected. Please select bookmarks to open.');
    return;
  }
  const tree = await browser.bookmarks.getTree();
  const allBookmarks = tree[0].children || [];
  const urlsToOpen = [];
  for (const itemId of selectedItems) {
    const item = findBookmarkById(allBookmarks, itemId);
    if (!item) continue;
    if (item.type === 'bookmark') {
      urlsToOpen.push(item.url);
    } else if (item.type === 'folder') {
      getAllBookmarksInFolder(item).forEach(b => urlsToOpen.push(b.url));
    }
  }
  if (urlsToOpen.length === 0) {
    alert('No bookmarks found in the selection to open.');
    return;
  }
  for (const url of urlsToOpen) {
    browser.tabs.create({ url, active: false });
  }
}

// Bulk open selected items each in a new window
async function bulkOpenInWindows() {
  if (selectedItems.size === 0) {
    alert('No items selected. Please select bookmarks to open.');
    return;
  }
  const tree = await browser.bookmarks.getTree();
  const allBookmarks = tree[0].children || [];
  const urlsToOpen = [];
  for (const itemId of selectedItems) {
    const item = findBookmarkById(allBookmarks, itemId);
    if (!item) continue;
    if (item.type === 'bookmark') {
      urlsToOpen.push(item.url);
    } else if (item.type === 'folder') {
      getAllBookmarksInFolder(item).forEach(b => urlsToOpen.push(b.url));
    }
  }
  if (urlsToOpen.length === 0) {
    alert('No bookmarks found in the selection to open.');
    return;
  }
  for (const url of urlsToOpen) {
    browser.windows.create({ url });
  }
}

// Get all bookmarks in a folder recursively
function getAllBookmarksInFolder(folder) {
  const bookmarks = [];

  function traverse(node) {
    // Skip separators
    if (node.type === 'separator') return;

    if (node.type === 'bookmark') {
      bookmarks.push(node);
    } else if (node.type === 'folder' && node.children) {
      node.children.forEach(child => traverse(child));
    }
  }

  if (folder.children) {
    folder.children.forEach(child => traverse(child));
  }

  return bookmarks;
}

// Module-level reference so renderBookmarks can call it before the inner function is in scope
let openSnippetSyncDialog = null;

/* [ZeroLabs] 2026-08-17 4:15 PM - added: quick access sync bridge */
// Same pattern: the snippet sync machinery lives inside a closure, so pin edits
// reach it through a reference assigned at startup. No-op until then, and a
// no-op forever for anyone not using GitLab sync.
let markQuickAccessChanged = () => {};

// Setup event listeners
function setupEventListeners() {
  // Search
  /* [ZeroLabs] 2026-08-19 7:12 PM - added: clear search button */
  // Shown only while there is something to clear, so it never sits in an empty
  // box. Restores focus so typing can continue straight after clearing.
  const searchClear = document.getElementById('searchClear');
  const updateSearchClear = () => {
    if (searchClear) searchClear.classList.toggle('hidden', !searchInput.value);
  };

  searchInput.addEventListener('input', (e) => {
    searchTerm = e.target.value;
    updateSearchClear();
    renderBookmarks();
    saveSessionStateDebounced();
  });

  if (searchClear) {
    searchClear.addEventListener('click', () => {
      searchInput.value = '';
      searchTerm = '';
      updateSearchClear();
      renderBookmarks();
      saveSessionStateDebounced();
      searchInput.focus();
    });
  }

  // A restored session can arrive with a search term already in the box
  updateSearchClear();

  // Filter toggle
  filterToggle.addEventListener('click', () => {
    filterBar.classList.toggle('hidden');
  });

  // Display toggle
  displayToggle.addEventListener('click', () => {
    displayBar.classList.toggle('hidden');
  });

  // Display option toggles
  const displayTitle = document.getElementById('displayTitle');
  const displayUrl = document.getElementById('displayUrl');

  displayTitle.addEventListener('change', (e) => {
    // Ensure at least Title or URL is checked
    if (!e.target.checked && !displayUrl.checked) {
      e.target.checked = true;
      return;
    }
    displayOptions.title = e.target.checked;
    renderBookmarks();
  });

  displayUrl.addEventListener('change', (e) => {
    // Ensure at least Title or URL is checked
    if (!e.target.checked && !displayTitle.checked) {
      e.target.checked = true;
      return;
    }
    displayOptions.url = e.target.checked;
    renderBookmarks();
  });

  const displayFavicon = document.getElementById('displayFavicon');
  displayFavicon.addEventListener('change', (e) => {
    displayOptions.favicon = e.target.checked;
    renderBookmarks();
  });

  const displayLiveStatus = document.getElementById('displayLiveStatus');
  const displaySafetyStatus = document.getElementById('displaySafetyStatus');
  const displayPreview = document.getElementById('displayPreview');

  displayLiveStatus.addEventListener('change', (e) => {
    displayOptions.liveStatus = e.target.checked;
    renderBookmarks();
  });

  displaySafetyStatus.addEventListener('change', (e) => {
    displayOptions.safetyStatus = e.target.checked;
    renderBookmarks();
  });

  displayPreview.addEventListener('change', (e) => {
    displayOptions.preview = e.target.checked;
    renderBookmarks();
  });

  const displayPreviewPopup = document.getElementById('displayPreviewPopup');
  displayPreviewPopup.addEventListener('change', async (e) => {
    previewPopupEnabled = e.target.checked;
    await safeStorage.set({ previewPopupEnabled: previewPopupEnabled });
    if (!previewPopupEnabled) {
      hidePreviewPopup();
    }
  });

  /* [ZeroLabs] 2026-08-17 4:15 PM - added: section visibility toggles */
  const displayQuickAccess = document.getElementById('displayQuickAccess');
  const displayRecent = document.getElementById('displayRecent');

  if (displayQuickAccess) {
    displayQuickAccess.checked = displayOptions.quickAccess;
    displayQuickAccess.addEventListener('change', async (e) => {
      displayOptions.quickAccess = e.target.checked;
      await saveDisplaySections();
      renderBookmarks();
    });
  }

  if (displayRecent) {
    displayRecent.checked = displayOptions.recent;
    displayRecent.addEventListener('change', async (e) => {
      displayOptions.recent = e.target.checked;
      await saveDisplaySections();
      renderBookmarks();
    });
  }

  // Filter chips
  document.querySelectorAll('.filter-chip').forEach(chip => {
    chip.addEventListener('click', () => {
      const filter = chip.dataset.filter;

      const index = activeFilters.indexOf(filter);
      if (index > -1) {
        // Remove filter if already active
        activeFilters.splice(index, 1);
        chip.classList.remove('active');
      } else {
        // Add filter
        activeFilters.push(filter);
        chip.classList.add('active');
      }

      renderBookmarks();
      saveSessionStateDebounced();
    });
  });

  // Save scroll position when user scrolls
  if (bookmarkList) {
    bookmarkList.addEventListener('scroll', () => {
      saveSessionStateDebounced();
    });
  }

  // QR Code button - generate QR for current page URL
  if (qrCodeBtn) {
    qrCodeBtn.addEventListener('click', async () => {
      // Get the current active tab URL
      try {
        const tabs = await browser.tabs.query({ active: true, currentWindow: true });
        if (tabs && tabs[0] && tabs[0].url) {
          showQRCodePopup(tabs[0].url);
        } else {
          // Fallback: show with empty URL so user can paste one
          showQRCodePopup('');
        }
      } catch (error) {
        console.error('Error getting current tab URL:', error);
        // Fallback: show with empty URL so user can paste one
        showQRCodePopup('');
      }
    });
  }

  // Theme menu
  themeBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    const wasOpen = themeMenu.classList.contains('show');
    closeAllMenus();
    if (!wasOpen) {
      menuJustOpened = true;
      themeMenu.classList.add('show');

      // Calculate available width and position menu within sidebar constraints
      const buttonRect = themeBtn.getBoundingClientRect();
      const viewportWidth = window.innerWidth;
      const margin = 16; // Safety margin from edges

      // Set max-width to fit within margins
      const maxWidth = viewportWidth - (margin * 2);
      themeMenu.style.maxWidth = `${maxWidth}px`;
      themeMenu.style.position = 'fixed';
      themeMenu.style.top = `${buttonRect.bottom + 4}px`;

      // Position menu to stay within margins on both sides
      // Start by aligning with button, then adjust if it would overflow
      let leftPos = buttonRect.left;

      // Ensure menu doesn't overflow left edge
      if (leftPos < margin) {
        leftPos = margin;
      }

      // Ensure menu doesn't overflow right edge
      // (menu will be maxWidth or less, so check if leftPos + maxWidth exceeds viewport)
      if (leftPos + maxWidth > viewportWidth - margin) {
        leftPos = viewportWidth - margin - maxWidth;
      }

      themeMenu.style.left = `${leftPos}px`;
      themeMenu.style.right = 'auto';
    }
  });

  // Theme selection
  // Theme dropdown
  const themeSelect = document.getElementById('themeSelect');
  if (themeSelect) {
    themeSelect.addEventListener('change', () => {
      setTheme(themeSelect.value);
    });
  }

  // Tint control event listeners
  const tintHueInput = document.getElementById('tintHue');
  const tintSaturationInput = document.getElementById('tintSaturation');
  const hueValueSpan = document.getElementById('hueValue');
  const saturationValueSpan = document.getElementById('saturationValue');

  if (tintHueInput && tintSaturationInput) {
    tintHueInput.addEventListener('input', (e) => {
      const hue = e.target.value;
      if (hueValueSpan) hueValueSpan.textContent = `${hue}°`;
      applyTintSettings(parseInt(hue), parseInt(tintSaturationInput.value));
    });

    tintSaturationInput.addEventListener('input', (e) => {
      const saturation = e.target.value;
      if (saturationValueSpan) saturationValueSpan.textContent = `${saturation}%`;
      applyTintSettings(parseInt(tintHueInput.value), parseInt(saturation));
    });
  }

  // View menu
  viewBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    const wasOpen = viewMenu.classList.contains('show');
    closeAllMenus();
    if (!wasOpen) {
      menuJustOpened = true;
      viewMenu.classList.add('show');

      // Calculate available width and position menu within sidebar constraints
      const buttonRect = viewBtn.getBoundingClientRect();
      const viewportWidth = window.innerWidth;
      const margin = 16; // Safety margin from edges

      // Set max-width to fit within margins
      const maxWidth = viewportWidth - (margin * 2);
      viewMenu.style.maxWidth = `${maxWidth}px`;
      viewMenu.style.position = 'fixed';
      viewMenu.style.top = `${buttonRect.bottom + 4}px`;

      // Position menu to stay within margins on both sides
      let leftPos = buttonRect.left;

      // Ensure menu doesn't overflow left edge
      if (leftPos < margin) {
        leftPos = margin;
      }

      // Ensure menu doesn't overflow right edge
      if (leftPos + maxWidth > viewportWidth - margin) {
        leftPos = viewportWidth - margin - maxWidth;
      }

      viewMenu.style.left = `${leftPos}px`;
      viewMenu.style.right = 'auto';
    }
  });

  // View selection
  viewMenu.querySelectorAll('.action-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const selectedView = btn.dataset.view;
      setView(selectedView);
      closeAllMenus();
    });
  });

  // Zoom menu
  zoomBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    const wasOpen = zoomMenu.classList.contains('show');
    closeAllMenus();
    if (!wasOpen) {
      menuJustOpened = true;
      zoomMenu.classList.add('show');

      // Calculate available width and position menu within sidebar constraints
      const buttonRect = zoomBtn.getBoundingClientRect();
      const viewportWidth = window.innerWidth;
      const margin = 16; // Safety margin from edges

      // Set max-width to fit within margins
      const maxWidth = viewportWidth - (margin * 2);
      zoomMenu.style.maxWidth = `${maxWidth}px`;
      zoomMenu.style.position = 'fixed';
      zoomMenu.style.top = `${buttonRect.bottom + 4}px`;

      // Position menu to stay within margins on both sides
      let leftPos = buttonRect.left;

      // Ensure menu doesn't overflow left edge
      if (leftPos < margin) {
        leftPos = margin;
      }

      // Ensure menu doesn't overflow right edge
      if (leftPos + maxWidth > viewportWidth - margin) {
        leftPos = viewportWidth - margin - maxWidth;
      }

      zoomMenu.style.left = `${leftPos}px`;
      zoomMenu.style.right = 'auto';
    }
  });

  // Zoom slider
  zoomSlider.addEventListener('input', (e) => {
    const newZoom = parseInt(e.target.value);
    setZoom(newZoom);
  });

  // Font size slider
  fontSizeSlider.addEventListener('input', (e) => {
    const newSize = parseInt(e.target.value);
    setFontSize(newSize);
  });

  // Settings menu
  settingsBtn.addEventListener('click', async (e) => {
    e.stopPropagation();
    const wasOpen = settingsMenu.classList.contains('show');
    closeAllMenus();
    if (!wasOpen) {
      menuJustOpened = true;
      settingsMenu.classList.add('show');

      // Calculate available width and position menu within sidebar constraints
      const buttonRect = settingsBtn.getBoundingClientRect();
      const viewportWidth = window.innerWidth;
      const margin = 16; // Safety margin from edges

      // Set max-width to fit within margins
      const maxWidth = viewportWidth - (margin * 2);
      settingsMenu.style.maxWidth = `${maxWidth}px`;
      settingsMenu.style.position = 'fixed';
      settingsMenu.style.top = `${buttonRect.bottom + 4}px`;

      // Position menu to stay within margins on both sides
      let leftPos = buttonRect.left;

      // Ensure menu doesn't overflow left edge
      if (leftPos < margin) {
        leftPos = margin;
      }

      // Ensure menu doesn't overflow right edge
      if (leftPos + maxWidth > viewportWidth - margin) {
        leftPos = viewportWidth - margin - maxWidth;
      }

      settingsMenu.style.left = `${leftPos}px`;
      settingsMenu.style.right = 'auto';

      // Update cache size display when menu opens
      await updateCacheSizeDisplay();
    }
  });

  // Open in new tab
  openInTabBtn.addEventListener('click', () => {
    openInNewTab();
    closeAllMenus();
  });

  // Export bookmarks (backup)
  exportBookmarksBtn.addEventListener('click', () => {
    exportBookmarks();
    closeAllMenus();
  });

  // Clear cache
  clearCacheBtn.addEventListener('click', async () => {
    await clearCache();
    closeAllMenus();
  });

  // Auto-clear cache setting
  autoClearCacheSelect.addEventListener('change', async (e) => {
    const autoClearDays = e.target.value;
    await safeStorage.set({ autoClearCacheDays: autoClearDays });
    console.log(`Auto-clear cache set to: ${autoClearDays === 'never' ? 'Never' : autoClearDays + ' days'}`);

    // Run auto-clear immediately if enabled
    if (autoClearDays !== 'never') {
      await clearOldCacheEntries(autoClearDays);
    }
  });

  // Start folder setting
  startFolderSelect.addEventListener('change', async (e) => {
    startFolderId = e.target.value || null;
    await safeStorage.set({ startFolderId: startFolderId });
    console.log(`Start folder set to: ${startFolderId || 'Root'}`);

    // Clear expanded folders and expand to new start folder
    expandedFolders.clear();
    await expandToStartFolder();
    renderBookmarks();
  });

  // Container opacity slider
  if (containerOpacitySlider) {
    containerOpacitySlider.addEventListener('input', (e) => {
      e.stopPropagation();
      const opacity = e.target.value;
      containerOpacityValue.textContent = `${opacity}%`;
      localStorage.setItem('containerOpacity', opacity);
      applyContainerOpacity(opacity);
    });

    // Prevent menu from closing when clicking the slider
    containerOpacitySlider.addEventListener('click', (e) => {
      e.stopPropagation();
    });
  }

  // Dark text toggle removed - no longer needed

  // Custom text color picker
  if (textColorPicker) {
    textColorPicker.addEventListener('input', (e) => {
      const color = e.target.value;
      applyCustomTextColor(color);
      localStorage.setItem('customTextColor', color);
    });
  }

  // Reset text color button
  if (resetTextColorBtn) {
    resetTextColorBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      resetCustomTextColor();
      textColorPicker.value = '#e8e8e8'; // Light gray default
    });
  }

  // Initialize text color on page load (matches accent color pattern - load after event listeners)
  loadCustomTextColor();

  // Link checking toggle
  const enableLinkCheckingToggle = document.getElementById('enableLinkChecking');
  enableLinkCheckingToggle.addEventListener('change', (e) => {
    linkCheckingEnabled = e.target.checked;
    localStorage.setItem('linkCheckingEnabled', linkCheckingEnabled);
    mirrorCheckingSettingsToExtensionStorage();
    console.log(`Link checking ${linkCheckingEnabled ? 'enabled' : 'disabled'}`);
  });

  // Safety checking toggle
  const enableSafetyCheckingToggle = document.getElementById('enableSafetyChecking');
  enableSafetyCheckingToggle.addEventListener('change', (e) => {
    safetyCheckingEnabled = e.target.checked;
    localStorage.setItem('safetyCheckingEnabled', safetyCheckingEnabled);
    mirrorCheckingSettingsToExtensionStorage();
    console.log(`Safety checking ${safetyCheckingEnabled ? 'enabled' : 'disabled'}`);
  });

  /* [ZeroLabs] 2026-06-20 10:50 AM - added: scan concurrency + jitter sliders (DNS load) */
  const scanConcurrencySlider = document.getElementById('scanConcurrencySlider');
  const scanConcurrencyValueLabel = document.getElementById('scanConcurrencyValue');
  if (scanConcurrencySlider) {
    scanConcurrencySlider.addEventListener('input', (e) => {
      const value = parseInt(e.target.value, 10);
      if (scanConcurrencyValueLabel) scanConcurrencyValueLabel.textContent = value;
      browser.storage.local.set({ scanConcurrency: value });
      browser.runtime.sendMessage({ action: 'setScanConcurrency', value }).catch(() => {});
    });
  }

  const scanJitterSlider = document.getElementById('scanJitterSlider');
  const scanJitterValueLabel = document.getElementById('scanJitterValue');
  if (scanJitterSlider) {
    scanJitterSlider.addEventListener('input', (e) => {
      const value = parseInt(e.target.value, 10);
      if (scanJitterValueLabel) scanJitterValueLabel.textContent = value + 'ms';
      browser.storage.local.set({ scanJitter: value });
      browser.runtime.sendMessage({ action: 'setScanJitter', value }).catch(() => {});
    });
  }

  // Accent color picker
  accentColorPicker.addEventListener('input', (e) => {
    const color = e.target.value;
    applyAccentColor(color);
    localStorage.setItem('customAccentColor', color);
  });

  // Reset accent color
  resetAccentColorBtn.addEventListener('click', () => {
    const defaultColor = getDefaultAccentColor();
    accentColorPicker.value = defaultColor;
    applyAccentColor(defaultColor);
    localStorage.removeItem('customAccentColor');
  });

  // Load saved accent color on startup
  function loadSavedAccentColor() {
    const savedColor = localStorage.getItem('customAccentColor');
    if (savedColor) {
      accentColorPicker.value = savedColor;
      applyAccentColor(savedColor);
    } else {
      const defaultColor = getDefaultAccentColor();
      accentColorPicker.value = defaultColor;
    }
  }

  // Get default accent color based on current theme
  function getDefaultAccentColor() {
    const isDarkMode = document.body.classList.contains('blue-dark') || document.body.classList.contains('dark');
    if (document.body.classList.contains('dark')) {
      return '#bb86fc'; // Pure dark theme purple
    } else if (isDarkMode) {
      return '#818cf8'; // Blue dark theme
    } else {
      return '#6366f1'; // Light theme default
    }
  }

  // Apply accent color by calling the global function
  function applyAccentColor(color) {
    applyCustomAccentColor(color);
  }

  // Initialize accent color on page load
  loadSavedAccentColor();

  // Background image controls
  let isDragging = false;

  // Choose background image
  chooseBackgroundImageBtn.addEventListener('click', () => {
    backgroundImagePicker.click();
  });

  backgroundImagePicker.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (event) => {
        const imageData = event.target.result;
        localStorage.setItem('backgroundImage', imageData);
        applyBackgroundImage(
          imageData,
          backgroundOpacitySlider.value,
          backgroundBlurSlider.value,
          backgroundSizeSelect.value,
          localStorage.getItem('backgroundPositionX') || 50,
          localStorage.getItem('backgroundPositionY') || 50,
          backgroundScaleSlider.value
        );
      };
      reader.readAsDataURL(file);
    }
  });

  // Remove background image
  removeBackgroundImageBtn.addEventListener('click', () => {
    localStorage.removeItem('backgroundImage');
    localStorage.removeItem('backgroundOpacity');
    localStorage.removeItem('backgroundBlur');
    localStorage.removeItem('backgroundSize');
    localStorage.removeItem('backgroundPositionX');
    localStorage.removeItem('backgroundPositionY');
    localStorage.removeItem('backgroundScale');
    applyBackgroundImage(null);
    backgroundOpacitySlider.value = 100;
    opacityValue.textContent = '100%';
    backgroundBlurSlider.value = 0;
    blurValue.textContent = '0px';
    backgroundSizeSelect.value = 'contain';
    backgroundScaleSlider.value = 200;
    scaleValue.textContent = '200%';
  });

  // Opacity slider
  backgroundOpacitySlider.addEventListener('input', (e) => {
    const opacity = e.target.value;
    opacityValue.textContent = `${opacity}%`;
    const savedImage = localStorage.getItem('backgroundImage');
    if (savedImage) {
      localStorage.setItem('backgroundOpacity', opacity);
      applyBackgroundImage(
        savedImage,
        opacity,
        backgroundBlurSlider.value,
        backgroundSizeSelect.value,
        localStorage.getItem('backgroundPositionX') || 50,
        localStorage.getItem('backgroundPositionY') || 50,
        backgroundScaleSlider.value
      );
    }
  });

  // Blur slider
  backgroundBlurSlider.addEventListener('input', (e) => {
    const blur = e.target.value;
    blurValue.textContent = `${blur}px`;
    const savedImage = localStorage.getItem('backgroundImage');
    if (savedImage) {
      localStorage.setItem('backgroundBlur', blur);
      applyBackgroundImage(
        savedImage,
        backgroundOpacitySlider.value,
        blur,
        backgroundSizeSelect.value,
        localStorage.getItem('backgroundPositionX') || 50,
        localStorage.getItem('backgroundPositionY') || 50,
        backgroundScaleSlider.value
      );
    }
  });

  // Size select
  backgroundSizeSelect.addEventListener('change', (e) => {
    const size = e.target.value;
    const savedImage = localStorage.getItem('backgroundImage');
    if (savedImage) {
      localStorage.setItem('backgroundSize', size);
      applyBackgroundImage(
        savedImage,
        backgroundOpacitySlider.value,
        backgroundBlurSlider.value,
        size,
        localStorage.getItem('backgroundPositionX') || 50,
        localStorage.getItem('backgroundPositionY') || 50,
        backgroundScaleSlider.value
      );
    }
  });

  // Scale slider
  backgroundScaleSlider.addEventListener('input', (e) => {
    const scale = e.target.value;
    scaleValue.textContent = `${scale}%`;
    const savedImage = localStorage.getItem('backgroundImage');
    if (savedImage) {
      localStorage.setItem('backgroundScale', scale);
      applyBackgroundImage(
        savedImage,
        backgroundOpacitySlider.value,
        backgroundBlurSlider.value,
        backgroundSizeSelect.value,
        localStorage.getItem('backgroundPositionX') || 50,
        localStorage.getItem('backgroundPositionY') || 50,
        scale
      );
    }
  });

  // Reposition background (drag mode)
  repositionBackgroundBtn.addEventListener('click', (e) => {
    e.preventDefault();
    e.stopPropagation();
    const savedImage = localStorage.getItem('backgroundImage');
    if (!savedImage) {
      return;
    }

    const bgOverlay = document.getElementById('background-overlay');
    if (!bgOverlay) return;

    // Reload current position from localStorage when entering drag mode
    let currentPosX = parseFloat(localStorage.getItem('backgroundPositionX')) || 50;
    let currentPosY = parseFloat(localStorage.getItem('backgroundPositionY')) || 50;
    let dragStartX = 0;
    let dragStartY = 0;

    // Show the drag mode overlay and close all menus
    dragModeOverlay.style.display = 'flex';
    closeAllMenus();

    // Enable dragging - raise z-index above content (50) but below header (100)
    bgOverlay.style.cursor = 'move';
    bgOverlay.style.pointerEvents = 'auto';
    bgOverlay.style.zIndex = '50';

    // Keep banner at same z-index as header
    dragModeOverlay.style.zIndex = '100';

    const handleMouseDown = (event) => {
      // Don't start dragging if clicking on the exit button
      if (event.target === closeDragModeBtn || closeDragModeBtn.contains(event.target)) {
        return;
      }

      isDragging = true;
      dragStartX = event.clientX;
      dragStartY = event.clientY;
      event.preventDefault();
      event.stopPropagation();
    };

    const handleMouseMove = (event) => {
      if (!isDragging) return;

      const deltaX = event.clientX - dragStartX;
      const deltaY = event.clientY - dragStartY;

      // Convert pixel movement to percentage based on window size
      const percentX = (deltaX / window.innerWidth) * 100;
      const percentY = (deltaY / window.innerHeight) * 100;

      // Update positions with stricter limits (-50% to 150%)
      currentPosX = Math.max(-50, Math.min(150, currentPosX + percentX));
      currentPosY = Math.max(-50, Math.min(150, currentPosY + percentY));

      dragStartX = event.clientX;
      dragStartY = event.clientY;

      applyBackgroundImage(
        savedImage,
        backgroundOpacitySlider.value,
        backgroundBlurSlider.value,
        backgroundSizeSelect.value,
        currentPosX,
        currentPosY,
        backgroundScaleSlider.value
      );
    };

    const handleMouseUp = () => {
      if (isDragging) {
        isDragging = false;
        localStorage.setItem('backgroundPositionX', currentPosX);
        localStorage.setItem('backgroundPositionY', currentPosY);
      }
    };

    const handleWheel = (event) => {
      event.preventDefault();
      event.stopPropagation();

      // Get current scale from slider
      let currentScale = parseFloat(backgroundScaleSlider.value);

      // Adjust scale based on scroll direction
      const scaleChange = event.deltaY > 0 ? -5 : 5;
      currentScale = Math.max(10, Math.min(1000, currentScale + scaleChange));

      // Update slider and display
      backgroundScaleSlider.value = currentScale;
      scaleValue.textContent = `${currentScale}%`;

      // Save to localStorage
      localStorage.setItem('backgroundScale', currentScale);

      // Apply the new scale
      applyBackgroundImage(
        savedImage,
        backgroundOpacitySlider.value,
        backgroundBlurSlider.value,
        backgroundSizeSelect.value,
        currentPosX,
        currentPosY,
        currentScale
      );
    };

    const stopDragging = () => {
      // Hide overlay
      dragModeOverlay.style.display = 'none';

      // Reset background overlay
      bgOverlay.style.cursor = '';
      bgOverlay.style.pointerEvents = 'none';
      bgOverlay.style.zIndex = '0';

      // Remove event listeners
      document.removeEventListener('mousedown', handleMouseDown);
      document.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('mouseup', handleMouseUp);
      document.removeEventListener('wheel', handleWheel);
      closeDragModeBtn.removeEventListener('click', stopDragging);

      // Save final position
      localStorage.setItem('backgroundPositionX', currentPosX);
      localStorage.setItem('backgroundPositionY', currentPosY);
    };

    // Listen on document instead of bgOverlay to bypass any blocking elements
    document.addEventListener('mousedown', handleMouseDown);
    document.addEventListener('mousemove', handleMouseMove);
    document.addEventListener('mouseup', handleMouseUp);
    document.addEventListener('wheel', handleWheel, { passive: false });

    // Set up banner close handler
    closeDragModeBtn.addEventListener('click', stopDragging);
  });

  // GUI Scale select
  if (guiScaleSelect) {
    guiScaleSelect.addEventListener('change', (e) => {
      guiScale = parseInt(e.target.value);
      localStorage.setItem('guiScale', guiScale.toString());
      applyGuiScale();
    });
  }

  // Rescan all bookmarks button
  if (rescanAllBtn) {
    rescanAllBtn.addEventListener('click', async () => {
      if (!linkCheckingEnabled && !safetyCheckingEnabled) {
        alert('Both link checking and safety checking are disabled.\n\nEnable at least one in Settings to rescan bookmarks.');
        return;
      }

      try {
        // Stop any ongoing background scan first
        await browser.runtime.sendMessage({ action: 'stopScan' });

        // Wait a moment for the scan to stop
        await new Promise(resolve => setTimeout(resolve, 500));

        // Clear the checkedBookmarks set to allow re-checking
        checkedBookmarks.clear();

        // Reset all bookmark statuses to unknown
        function resetStatuses(nodes) {
          nodes.forEach(node => {
            if (node.url) {
              node.linkStatus = 'unknown';
              node.safetyStatus = 'unknown';
            }
            if (node.children) {
              resetStatuses(node.children);
            }
          });
        }
        resetStatuses(bookmarkTree);
        renderBookmarks();

        // Get all bookmarks from Firefox
        const tree = await browser.bookmarks.getTree();
        const allBookmarks = getAllBookmarksFlat(tree);

        // Start background scan (runs in background script)
        const response = await browser.runtime.sendMessage({ action: 'startScan', bookmarks: allBookmarks, bypassCache: true });

        if (!response.success) {
          console.error('Failed to start background scan:', response.message);
          alert('Failed to start scan: ' + response.message);
        }
      } catch (error) {
        console.error('Error rescanning bookmarks:', error);
        alert('Failed to rescan bookmarks. Please try again.');
      }
    });

    // Stop scan button
    const stopScanBtn = document.getElementById('stopScanBtn');
    if (stopScanBtn) {
      stopScanBtn.addEventListener('click', async () => {
        /* [ZeroLabs] 2026-06-20 12:21 AM - edited: cancel front-end + worker scans */
        // Cancel BOTH engines: the front-end auto-check loop (via scanCancelled)
        // and the background worker scan. Previously only the worker was stopped,
        // so Stop was a no-op against the auto-check that runs on load/expand.
        await cancelAllScans();
        console.log('User requested scan cancellation');
      });
    }
  }

  // Set Google API Key
  setApiKeyBtn.addEventListener('click', async () => {
    const currentKey = await getDecryptedApiKey('googleSafeBrowsingApiKey');
    const hasKey = currentKey && currentKey.length > 0;

    const promptMessage = hasKey
      ? 'Google Safe Browsing API Key is currently set.\n\nEnter a new key to update, or leave blank to remove:'
      : 'Enter your Google Safe Browsing API Key:\n\n(Get a free key at: https://developers.google.com/safe-browsing/v4/get-started)\nFree tier: 10,000 requests/day\n\nLeave blank to disable Google Safe Browsing redundancy check.';

    const apiKey = prompt(promptMessage, '');

    if (apiKey !== null) { // User clicked OK (not Cancel)
      if (apiKey.trim() === '') {
        // Remove API key
        await safeStorage.remove('googleSafeBrowsingApiKey');
        alert('Google Safe Browsing API key removed.\n\nOnly URLhaus will be used for safety checking.');
      } else {
        // Save encrypted API key
        await storeEncryptedApiKey('googleSafeBrowsingApiKey', apiKey.trim());
        alert('Google Safe Browsing API key saved securely!\n\nSafety checking will now use:\n1. URLhaus (primary)\n2. Google Safe Browsing (redundancy)');
      }
      updateApiKeyButtonLabels();
    }
    closeAllMenus();
  });

  // Set VirusTotal API Key
  document.getElementById('setVirusTotalApiKeyBtn').addEventListener('click', async () => {
    const currentKey = await getDecryptedApiKey('virusTotalApiKey');
    const hasKey = currentKey && currentKey.length > 0;

    const promptMessage = hasKey
      ? 'VirusTotal API Key is currently set.\n\nEnter a new key to update, or leave blank to remove:'
      : 'Enter your VirusTotal API Key:\n\n(Get a free key at: https://www.virustotal.com/gui/my-apikey)\nFree tier: 500 requests/day, 4 requests/minute\n\nLeave blank to disable VirusTotal checking.';

    const apiKey = prompt(promptMessage, '');

    if (apiKey !== null) { // User clicked OK (not Cancel)
      if (apiKey.trim() === '') {
        // Remove API key
        await safeStorage.remove('virusTotalApiKey');
        alert('VirusTotal API key removed.\n\nVirusTotal checking is now disabled.');
      } else {
        // Save encrypted API key
        await storeEncryptedApiKey('virusTotalApiKey', apiKey.trim());
        alert('VirusTotal API key saved securely!\n\nSafety checking will now include VirusTotal scans.');
      }
      updateApiKeyButtonLabels();
    }
    closeAllMenus();
  });

  // Set Yandex API Key
  document.getElementById('setYandexApiKeyBtn').addEventListener('click', async () => {
    const currentKey = await getDecryptedApiKey('yandexApiKey');
    const hasKey = currentKey && currentKey.length > 0;

    const promptMessage = hasKey
      ? 'Yandex Safe Browsing API Key is currently set.\n\nEnter a new key to update, or leave blank to remove:'
      : 'Enter your Yandex Safe Browsing API Key:\n\n(Register at: https://yandex.com/dev/)\nFree tier: 100,000 requests/day\n\nLeave blank to disable Yandex Safe Browsing.';

    const apiKey = prompt(promptMessage, '');

    if (apiKey !== null) { // User clicked OK (not Cancel)
      if (apiKey.trim() === '') {
        // Remove API key
        await safeStorage.remove('yandexApiKey');
        alert('Yandex Safe Browsing API key removed.\n\nYandex checking is now disabled.');
      } else {
        // Save encrypted API key
        await storeEncryptedApiKey('yandexApiKey', apiKey.trim());
        alert('Yandex Safe Browsing API key saved securely!\n\nSafety checking will now include Yandex Safe Browsing.');
      }
      updateApiKeyButtonLabels();
    }
    closeAllMenus();
  });

  // Function to update API key button labels
  async function updateApiKeyButtonLabels() {
    const googleKey = await getDecryptedApiKey('googleSafeBrowsingApiKey');
    const vtKey = await getDecryptedApiKey('virusTotalApiKey');
    const yandexKey = await getDecryptedApiKey('yandexApiKey');

    const googleBtn = document.querySelector('#setApiKeyBtn span:last-child');
    const vtBtn = document.querySelector('#setVirusTotalApiKeyBtn span:last-child');
    const yandexBtn = document.querySelector('#setYandexApiKeyBtn span:last-child');

    if (googleBtn) {
      googleBtn.textContent = (googleKey && googleKey.length > 0)
        ? 'Change/Remove Google API Key'
        : 'Set Google API Key';
    }
    if (vtBtn) {
      vtBtn.textContent = (vtKey && vtKey.length > 0)
        ? 'Change/Remove VirusTotal API Key'
        : 'Set VirusTotal API Key';
    }
    if (yandexBtn) {
      yandexBtn.textContent = (yandexKey && yandexKey.length > 0)
        ? 'Change/Remove Yandex API Key'
        : 'Set Yandex API Key';
    }
  }

  // Update button labels on load
  updateApiKeyButtonLabels();

  // Help & Documentation
  const helpDocsBtn = document.getElementById('helpDocsBtn');
  helpDocsBtn.addEventListener('click', () => {
    const readmeUrl = 'https://bmz.absolutezero.fyi/';
    browser.tabs.create({ url: readmeUrl });
    closeAllMenus();
  });

  // Buy Me a Coffee
  const buyMeCoffeeBtn = document.getElementById('buyMeCoffeeBtn');
  buyMeCoffeeBtn.addEventListener('click', () => {
    const coffeeUrl = 'https://buymeacoffee.com/absolutexyzero';
    browser.tabs.create({ url: coffeeUrl });
    closeAllMenus();
  });

  // View Changelog
  const viewChangelogBtn = document.getElementById('viewChangelogBtn');
  const changelogModal = document.getElementById('changelogModal');
  const changelogModalClose = document.getElementById('changelogModalClose');
  const changelogModalOk = document.getElementById('changelogModalOk');
  const clearChangelogBtn = document.getElementById('clearChangelogBtn');
  const changelogList = document.getElementById('changelogList');
  const changelogCount = document.getElementById('changelogCount');

  viewChangelogBtn.addEventListener('click', async () => {
    await openChangelogModal();
    closeAllMenus();
  });

  changelogModalClose.addEventListener('click', () => {
    closeModal(changelogModal);
  });

  changelogModalOk.addEventListener('click', () => {
    closeModal(changelogModal);
  });

  clearChangelogBtn.addEventListener('click', async () => {
    if (confirm('Are you sure you want to clear all changelog history? This action cannot be undone.')) {
      await clearChangelog();
      await openChangelogModal(); // Refresh the display
    }
  });

  // Close extension
  closeExtensionBtn.addEventListener('click', () => {
    closeExtension();
    closeAllMenus();
  });

  // New bookmark
  document.getElementById('newBookmarkBtn').addEventListener('click', createNewBookmark);

  // New folder
  document.getElementById('newFolderBtn').addEventListener('click', createNewFolder);

  // Find duplicates
  document.getElementById('findDuplicatesBtn').addEventListener('click', findDuplicates);

  // Header collapse/expand
  headerCollapseBtn.addEventListener('click', () => {
    const isCollapsed = collapsibleHeader.classList.toggle('collapsed');
    headerCollapseBtn.classList.toggle('collapsed');
    headerCollapseBtn.title = isCollapsed ? 'Expand header' : 'Collapse header';

    // Save state to localStorage
    localStorage.setItem('headerCollapsed', isCollapsed);
  });

  // Restore header collapse state
  const headerCollapsed = localStorage.getItem('headerCollapsed') === 'true';
  if (headerCollapsed) {
    collapsibleHeader.classList.add('collapsed');
    headerCollapseBtn.classList.add('collapsed');
    headerCollapseBtn.title = 'Expand header';
  }

  // Track when menus are opened to prevent immediate closing
  let menuJustOpened = false;

  // Close menus when clicking outside
  document.addEventListener('click', (e) => {
    // Don't close if menu was just opened
    if (menuJustOpened) {
      menuJustOpened = false;
      return;
    }

    if (!e.target.closest('#contextMenuModal .modal-content') &&
        !e.target.closest('.bookmark-menu-btn') &&
        !e.target.closest('.bookmark-preview-container') &&
        !e.target.closest('.settings-menu') &&
        !e.target.closest('#settingsBtn') &&
        !e.target.closest('.theme-btn-wrapper') &&
        !e.target.closest('.view-btn-wrapper') &&
        !e.target.closest('.zoom-btn-wrapper')) {
      closeAllMenus();
    }

    // Handle clicks on status icons (shield and chain)
    const statusIcon = e.target.closest('.clickable-status');
    if (statusIcon) {
      e.stopPropagation();
      const message = statusIcon.dataset.statusMessage;
      if (message) {
        alert(message);
      }
    }
  });

  // Edit modal event listeners
  const editModal = document.getElementById('editModal');
  const editModalClose = document.getElementById('editModalClose');
  const editModalCancel = document.getElementById('editModalCancel');
  const editModalSave = document.getElementById('editModalSave');
  const editModalOverlay = editModal.querySelector('.modal-overlay');

  editModalClose.addEventListener('click', closeEditModal);
  editModalCancel.addEventListener('click', closeEditModal);
  editModalSave.addEventListener('click', saveEditModal);
  editModalOverlay.addEventListener('click', closeEditModal);

  // Allow Enter key to save in modal
  editModal.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      saveEditModal();
    } else if (e.key === 'Escape') {
      closeEditModal();
    }
  });

  // Add Bookmark modal event listeners
  const addBookmarkModal = document.getElementById('addBookmarkModal');
  const addBookmarkModalClose = document.getElementById('addBookmarkModalClose');
  const addBookmarkModalCancel = document.getElementById('addBookmarkModalCancel');
  const addBookmarkModalSave = document.getElementById('addBookmarkModalSave');
  const addBookmarkModalOverlay = addBookmarkModal.querySelector('.modal-overlay');

  addBookmarkModalClose.addEventListener('click', closeAddBookmarkModal);
  addBookmarkModalCancel.addEventListener('click', closeAddBookmarkModal);
  addBookmarkModalSave.addEventListener('click', saveNewBookmark);
  addBookmarkModalOverlay.addEventListener('click', closeAddBookmarkModal);

  addBookmarkModal.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      saveNewBookmark();
    } else if (e.key === 'Escape') {
      closeAddBookmarkModal();
    }
  });

  // Add Folder modal event listeners
  const addFolderModal = document.getElementById('addFolderModal');
  const addFolderModalClose = document.getElementById('addFolderModalClose');
  const addFolderModalCancel = document.getElementById('addFolderModalCancel');
  const addFolderModalSave = document.getElementById('addFolderModalSave');
  const addFolderModalOverlay = addFolderModal.querySelector('.modal-overlay');

  addFolderModalClose.addEventListener('click', closeAddFolderModal);
  addFolderModalCancel.addEventListener('click', closeAddFolderModal);
  addFolderModalSave.addEventListener('click', saveNewFolder);
  addFolderModalOverlay.addEventListener('click', closeAddFolderModal);

  addFolderModal.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      saveNewFolder();
    } else if (e.key === 'Escape') {
      closeAddFolderModal();
    }
  });

  // Move To modal event listeners
  const moveToModal = document.getElementById('moveToModal');
  const moveToModalClose = document.getElementById('moveToModalClose');
  const moveToModalCancel = document.getElementById('moveToModalCancel');
  const moveToModalSave = document.getElementById('moveToModalSave');
  const moveToModalOverlay = moveToModal.querySelector('.modal-overlay');

  moveToModalClose.addEventListener('click', closeMoveToModal);
  moveToModalCancel.addEventListener('click', closeMoveToModal);
  moveToModalSave.addEventListener('click', saveMoveToModal);
  moveToModalOverlay.addEventListener('click', closeMoveToModal);

  moveToModal.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      saveMoveToModal();
    } else if (e.key === 'Escape') {
      closeMoveToModal();
    }
  });

  // Context menu modal event listeners
  const contextMenuModal = document.getElementById('contextMenuModal');
  const contextMenuModalClose = document.getElementById('contextMenuModalClose');
  const contextMenuModalOverlay = contextMenuModal.querySelector('.modal-overlay');

  contextMenuModalClose.addEventListener('click', closeContextMenuModal);
  contextMenuModalOverlay.addEventListener('click', closeContextMenuModal);

  contextMenuModal.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      closeContextMenuModal();
    }
  });

  // Duplicates modal event listeners
  const duplicatesModal = document.getElementById('duplicatesModal');
  const duplicatesModalClose = document.getElementById('duplicatesModalClose');
  const duplicatesModalCancel = document.getElementById('duplicatesModalCancel');
  const duplicatesModalDelete = document.getElementById('duplicatesModalDelete');
  const duplicatesModalOverlay = duplicatesModal.querySelector('.modal-overlay');

  duplicatesModalClose.addEventListener('click', closeDuplicatesModal);
  duplicatesModalCancel.addEventListener('click', closeDuplicatesModal);
  duplicatesModalDelete.addEventListener('click', deleteSelectedDuplicates);
  duplicatesModalOverlay.addEventListener('click', closeDuplicatesModal);

  duplicatesModal.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      closeDuplicatesModal();
    }
  });

  // ============================================================================
  // SUPABASE MANAGER
  // ============================================================================

  const SUPABASE_URL = 'https://zkwmxywegwgqcgssgfqv.supabase.co';
  const SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Inprd214eXdlZ3dncWNnc3NnZnF2Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzY3OTE5MjIsImV4cCI6MjA5MjM2NzkyMn0.-fvMiySTdda2ACXvFXk2Y0Dlu2tXhgxd94UzYvqPx8I';

  const supabase = {
    session: null,

    get authHeaders() {
      return {
        'Content-Type': 'application/json',
        'apikey': SUPABASE_ANON_KEY,
        'Authorization': `Bearer ${this.session?.access_token || SUPABASE_ANON_KEY}`
      };
    },

    get isSignedIn() {
      return !!this.session?.access_token;
    },

    async loadSession() {
      const result = await safeStorage.get('supabase_session');
      if (!result.supabase_session) return null;
      try {
        this.session = JSON.parse(result.supabase_session);
        if (this.session?.expires_at) {
          const expiresAt = this.session.expires_at * 1000;
          if (Date.now() > expiresAt - 60000) {
            return await this.refreshSession();
          }
        }
        return this.session;
      } catch {
        return null;
      }
    },

    async saveSession() {
      await safeStorage.set({ supabase_session: JSON.stringify(this.session) });
    },

    async clearSession() {
      await browser.storage.local.remove('supabase_session');
      this.session = null;
    },

    async refreshSession() {
      if (!this.session?.refresh_token) return null;
      try {
        const res = await fetch(`${SUPABASE_URL}/auth/v1/token?grant_type=refresh_token`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'apikey': SUPABASE_ANON_KEY },
          body: JSON.stringify({ refresh_token: this.session.refresh_token })
        });
        if (!res.ok) { this.session = null; await this.clearSession(); return null; }
        this.session = await res.json();
        await this.saveSession();
        return this.session;
      } catch {
        return null;
      }
    },

    async signInWithGitLab() {
      const redirectUrl = browser.identity.getRedirectURL();
      const authUrl = `${SUPABASE_URL}/auth/v1/authorize?provider=gitlab&redirect_to=${encodeURIComponent(redirectUrl)}`;

      let responseUrl;
      try {
        responseUrl = await browser.identity.launchWebAuthFlow({ url: authUrl, interactive: true });
      } catch (e) {
        // Treat any popup-closure/cancellation as a silent null return
        if (!e.message || /cancel|clos|denied|dismissed|abort|interact/i.test(e.message)) return null;
        throw e;
      }

      if (!responseUrl) return null;

      const hash = new URL(responseUrl).hash.slice(1);
      const params = new URLSearchParams(hash);

      const oauthError = params.get('error');
      if (oauthError) {
        const desc = params.get('error_description');
        throw new Error(desc ? decodeURIComponent(desc.replace(/\+/g, ' ')) : oauthError);
      }

      const accessToken = params.get('access_token');
      const refreshToken = params.get('refresh_token');
      const expiresIn = parseInt(params.get('expires_in') || '3600', 10);

      if (!accessToken) throw new Error('GitLab sign-in did not return an access token');

      const userRes = await fetch(`${SUPABASE_URL}/auth/v1/user`, {
        headers: { 'apikey': SUPABASE_ANON_KEY, 'Authorization': `Bearer ${accessToken}` }
      });
      if (!userRes.ok) throw new Error('Failed to fetch account info after sign-in');
      const user = await userRes.json();

      this.session = {
        access_token: accessToken,
        refresh_token: refreshToken,
        expires_at: Math.floor(Date.now() / 1000) + expiresIn,
        user
      };
      await this.saveSession();
      return this.session;
    },

    // Fetch wrapper that retries once after refreshing session on 401
    async authFetch(url, options = {}) {
      const run = () => fetch(url, { ...options, headers: { ...this.authHeaders, ...(options.headers || {}) } });
      let res = await run();
      if (res.status === 401) {
        const refreshed = await this.refreshSession();
        if (refreshed) res = await run();
      }
      return res;
    },

    async getGitLabToken() {
      const res = await this.authFetch(`${SUPABASE_URL}/rest/v1/gitlab_tokens?select=token,expires_at`);
      if (!res.ok) return null;
      const rows = await res.json();
      return rows[0] || null;
    },

    async saveGitLabToken(token, expiresAt) {
      const userId = this.session?.user?.id;
      if (!userId) throw new Error('Not signed in to Supabase');

      const patchRes = await this.authFetch(
        `${SUPABASE_URL}/rest/v1/gitlab_tokens?user_id=eq.${userId}`,
        {
          method: 'PATCH',
          headers: { 'Prefer': 'return=representation' },
          body: JSON.stringify({ token, expires_at: expiresAt, updated_at: new Date().toISOString() })
        }
      );
      if (patchRes.ok) {
        const rows = await patchRes.json().catch(() => []);
        if (Array.isArray(rows) && rows.length > 0) return;
      }

      const postRes = await this.authFetch(`${SUPABASE_URL}/rest/v1/gitlab_tokens`, {
        method: 'POST',
        headers: { 'Prefer': 'return=minimal' },
        body: JSON.stringify({ user_id: userId, token, expires_at: expiresAt })
      });
      if (!postRes.ok) {
        const err = await postRes.json().catch(() => ({}));
        throw new Error(err.message || 'Failed to save token to Supabase');
      }
    },

    async deleteGitLabToken() {
      if (!this.isSignedIn) return;
      try {
        await this.authFetch(
          `${SUPABASE_URL}/rest/v1/gitlab_tokens?user_id=eq.${this.session.user.id}`,
          { method: 'DELETE' }
        );
      } catch (e) { console.warn('[Supabase] Failed to delete token row:', e); }
    },

    async checkAndRotateIfNeeded(currentToken) {
      // Prevent concurrent prompts if multiple triggers fire close together
      if (rotationPromptActive) return currentToken;

      try {
        // Fast-path: skip API call if cached expiry shows > 30 days remaining
        const cached = await safeStorage.get('gitlab_token_expires');
        if (cached.gitlab_token_expires) {
          const cachedDaysLeft = (new Date(cached.gitlab_token_expires) - Date.now()) / (1000 * 60 * 60 * 24);
          if (cachedDaysLeft > 30) return currentToken;
        }

        const res = await fetchGitLab('https://gitlab.com/api/v4/personal_access_tokens/self', {
          headers: { 'Authorization': `Bearer ${currentToken}` }
        });
        if (res.status === 401) {
          showToast('GitLab token is invalid or expired. Please re-enter it in the sync settings.', 'error');
          return currentToken;
        }
        if (!res.ok) return currentToken;

        const info = await res.json();
        if (!info.expires_at) return currentToken;

        // Update cached expiry with fresh value from API
        await safeStorage.set({ gitlab_token_expires: info.expires_at });

        const daysLeft = (new Date(info.expires_at) - Date.now()) / (1000 * 60 * 60 * 24);
        if (daysLeft > 30) return currentToken;

        // Check 24-hour snooze
        const snoozeData = await safeStorage.get('bmz_rotation_snooze');
        if (snoozeData.bmz_rotation_snooze) {
          const snoozeAge = Date.now() - snoozeData.bmz_rotation_snooze;
          if (snoozeAge < 24 * 60 * 60 * 1000) return currentToken;
        }

        // Prompt user before rotating
        rotationPromptActive = true;
        const choice = await showPreRotationPrompt(daysLeft);
        // rotationPromptActive is cleared inside showPreRotationPrompt's dismiss()
        if (choice === 'snooze') {
          await safeStorage.set({ bmz_rotation_snooze: Date.now() });
          return currentToken;
        }

        console.log(`[TokenRotation] User approved. Expires in ${Math.floor(daysLeft)} days, rotating...`);

        const newExpiry = new Date();
        newExpiry.setDate(newExpiry.getDate() + 350);
        const newExpiryStr = newExpiry.toISOString().split('T')[0];

        const rotateRes = await fetchGitLab('https://gitlab.com/api/v4/personal_access_tokens/self/rotate', {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${currentToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ expires_at: newExpiryStr })
        });
        if (!rotateRes.ok) {
          if (rotateRes.status === 403) {
            showToast('Token renewal failed: insufficient scopes. Your token needs the "api" scope. Please create a new token manually.', 'error');
          } else if (rotateRes.status === 429) {
            showToast('Token renewal failed: GitLab rate limit hit. It will be retried on the next sync.', 'error');
          } else {
            showToast(`Token renewal failed (${rotateRes.status}). Please try again later.`, 'error');
          }
          return currentToken;
        }

        const rotated = await rotateRes.json();
        const mode = await getTokenMode();

        if (mode === 'supabase' && this.isSignedIn) {
          try {
            const encrypted = await encryptForSupabase(rotated.token, this.session.user.id);
            await this.saveGitLabToken(encrypted, rotated.expires_at);
          } catch (e) { console.warn('[TokenRotation] Supabase save failed:', e); }
          await storeSnippetToken(rotated.token, rotated.expires_at);
          showPostRotationModal(rotated.token, 'supabase');
        } else {
          await storeSnippetToken(rotated.token, rotated.expires_at);
          showPostRotationModal(rotated.token, 'local');
        }

        await browser.storage.local.remove('bmz_rotation_snooze');
        console.log(`[TokenRotation] Rotated, new expiry: ${rotated.expires_at}`);
        return rotated.token;
      } catch (err) {
        rotationPromptActive = false;
        console.error('[TokenRotation] Failed:', err);
        return currentToken;
      }
    }
  };

  // Show Supabase login dialog — single GitLab OAuth button
  async function showSupabaseLoginDialog() {
    return new Promise((resolve) => {
      const modal = document.createElement('div');
      modal.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.7);z-index:10001;display:flex;align-items:center;justify-content:center;';

      modal.innerHTML = `
        <div style="background:var(--md-sys-color-surface,#1e1e1e);padding:24px;border-radius:12px;max-width:360px;width:90%;color:var(--md-sys-color-on-surface,#e0e0e0);text-align:center;">
          <h2 style="margin:0 0 8px 0;font-size:18px;">Sign in to BMZ Sync</h2>
          <p style="margin:0 0 20px 0;font-size:13px;color:var(--md-sys-color-on-surface-variant,#aaa);">Your GitLab token will be stored securely in the cloud and auto-renewed across all your devices.</p>
          <button id="gitlabSignInBtn" style="width:100%;padding:12px;border-radius:8px;border:none;background:#fc6d26;color:#fff;font-size:14px;cursor:pointer;margin-bottom:8px;display:flex;align-items:center;justify-content:center;gap:8px;">
            <svg width="16" height="16" viewBox="0 0 380 380" fill="white"><path d="M380 220.8L337.7 91.3 296.1 3.8C294.4.8 291.3-.7 288 .3c-2.5.7-4.5 2.6-5.3 5.1L233.5 160h-87L97.3 5.4C96.5 2.9 94.5 1 92 .3 88.7-.7 85.6.8 83.9 3.8L42.3 91.3 0 220.8c-1.3 3.8.1 8 3.5 10.2l186.5 135.5 186.5-135.5c3.4-2.2 4.8-6.4 3.5-10.2z"/></svg>
            Sign in with GitLab
          </button>
          <div id="sbError" style="display:none;margin-bottom:8px;padding:10px;background:var(--md-sys-color-error-container,#3b1a1a);color:var(--md-sys-color-on-error-container,#f9dedc);border-radius:8px;font-size:13px;text-align:left;"></div>
          <button id="sbCancel" style="width:100%;padding:10px;border-radius:8px;border:none;background:var(--md-sys-color-surface-variant,#2a2a2a);color:var(--md-sys-color-on-surface-variant,#aaa);font-size:14px;cursor:pointer;">Cancel</button>
        </div>
      `;

      document.body.appendChild(modal);

      const sbError = modal.querySelector('#sbError');
      const gitlabBtn = modal.querySelector('#gitlabSignInBtn');

      gitlabBtn.addEventListener('click', async () => {
        gitlabBtn.disabled = true;
        gitlabBtn.innerHTML = '<span style="opacity:0.8">Opening GitLab…</span>';
        sbError.style.display = 'none';
        try {
          const session = await supabase.signInWithGitLab();
          modal.remove();
          resolve(session);
        } catch (err) {
          sbError.textContent = err.message || 'Sign in failed';
          sbError.style.display = 'block';
        } finally {
          gitlabBtn.disabled = false;
          gitlabBtn.innerHTML = `<svg width="16" height="16" viewBox="0 0 380 380" fill="white"><path d="M380 220.8L337.7 91.3 296.1 3.8C294.4.8 291.3-.7 288 .3c-2.5.7-4.5 2.6-5.3 5.1L233.5 160h-87L97.3 5.4C96.5 2.9 94.5 1 92 .3 88.7-.7 85.6.8 83.9 3.8L42.3 91.3 0 220.8c-1.3 3.8.1 8 3.5 10.2l186.5 135.5 186.5-135.5c3.4-2.2 4.8-6.4 3.5-10.2z"/></svg> Sign in with GitLab`;
        }
      });

      modal.querySelector('#sbCancel').addEventListener('click', () => {
        modal.remove();
        resolve(null);
      });
    });
  }

  // ============================================================================
  // GITLAB SNIPPET SYNC
  // ============================================================================

  // GitLab Snippet global variables
  let snippetToken = null;
  let snippetId = null;
  let snippetSyncInterval = null;
  let rotationPromptActive = false;
  let supabaseExpiredToastShown = false;
  let snippetLastSyncTime = 0;
  let snippetIsSyncing = false;
  let snippetLocalVersion = 0;
  /* [ZeroLabs] 2026-08-27 1:05 PM - removed: snippetPushDebounceTimer, snippetMinSyncInterval (dead with markSnippetChanges) */

  // Encrypt and store GitLab token locally only
  async function storeSnippetToken(token, expiresAt = null) {
    const encrypted = await encryptApiKey(token);
    const update = { gitlab_token: encrypted };
    if (expiresAt) update.gitlab_token_expires = expiresAt;
    await safeStorage.set(update);
    snippetToken = token;
    console.log('GitLab token stored securely');
  }

  // Retrieve and decrypt GitLab token
  // In Supabase mode: try Supabase first (decrypting with UID), cache locally
  // In local mode: local storage only
  async function loadSnippetToken() {
    const mode = await getTokenMode();

    if (mode === 'supabase') {
      if (!supabase.isSignedIn) {
        if (!supabaseExpiredToastShown) {
          supabaseExpiredToastShown = true;
          showToast('Supabase session expired. Sign in via GitLab sync to reload your token.', 'error');
        }
      } else {
        supabaseExpiredToastShown = false; // reset once signed in
        try {
          const row = await supabase.getGitLabToken();
          if (row?.token) {
            const decrypted = await decryptFromSupabase(row.token, supabase.session.user.id);
            await storeSnippetToken(decrypted, row.expires_at);
            return snippetToken;
          }
        } catch (e) {
          // decryptFromSupabase already showed a toast explaining the key mismatch.
          // Clear local token so the user isn't silently served a stale/unreadable one.
          await clearSnippetToken();
          return null;
        }
      }
    }

    // Local fallback (or local mode)
    const result = await safeStorage.get(['gitlab_token']);
    if (result.gitlab_token) {
      snippetToken = await decryptApiKey(result.gitlab_token);
      return snippetToken;
    }
    return null;
  }

  // Clear GitLab token
  async function clearSnippetToken() {
    await browser.storage.local.remove(['gitlab_token', 'gitlab_token_expires']);
    snippetToken = null;
    console.log('GitLab token cleared');
  }

  // Show informational popup for GitLab service errors (5xx)
  function showGitLabServiceErrorPopup(retryCallback) {
    // Remove any existing popup
    const existingPopup = document.getElementById('gitlab-service-error-popup');
    if (existingPopup) {
      existingPopup.remove();
    }

    const popup = document.createElement('div');
    popup.id = 'gitlab-service-error-popup';
    popup.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: rgba(0, 0, 0, 0.5);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 10000;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    `;

    const dialog = document.createElement('div');
    dialog.style.cssText = `
      background: var(--md-sys-color-surface, #1e1e1e);
      color: var(--md-sys-color-on-surface, #e0e0e0);
      border-radius: 12px;
      padding: 24px;
      max-width: 450px;
      width: 90%;
      box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
      position: relative;
    `;

    dialog.innerHTML = `
      <h2 style="margin: 0 0 16px 0; font-size: 18px; font-weight: 600; color: var(--md-sys-color-error, #f44336);">
        GitLab Service Error
      </h2>
      <p style="margin: 0 0 16px 0; line-height: 1.5;">
        GitLab returned a server error. This indicates a temporary issue on GitLab's side, not a token problem.
      </p>
      <p style="margin: 0 0 20px 0; line-height: 1.5;">
        Try again later.
      </p>
      <div style="display: flex; gap: 12px; justify-content: flex-end;">
        <button id="gitlab-service-error-cancel" style="
          background: var(--md-sys-color-surface-variant, #2a2a2a);
          color: var(--md-sys-color-on-surface-variant, #aaa);
          border: none;
          padding: 10px 20px;
          border-radius: 6px;
          cursor: pointer;
          font-size: 14px;
        ">Cancel</button>
        <button id="gitlab-service-error-retry" style="
          background: var(--md-sys-color-primary, #818cf8);
          color: var(--md-sys-color-on-primary, #fff);
          border: none;
          padding: 10px 20px;
          border-radius: 6px;
          cursor: pointer;
          font-size: 14px;
          font-weight: 500;
        ">Retry</button>
      </div>
    `;

    popup.appendChild(dialog);
    document.body.appendChild(popup);

    // Event listeners
    dialog.querySelector('#gitlab-service-error-cancel').addEventListener('click', () => {
      popup.remove();
    });

    dialog.querySelector('#gitlab-service-error-retry').addEventListener('click', () => {
      popup.remove();
      // Wait a short delay before retrying
      setTimeout(() => {
        if (retryCallback) {
          retryCallback();
        }
      }, 2000); // 2 second delay
    });

    // Close on background click
    popup.addEventListener('click', (e) => {
      if (e.target === popup) {
        popup.remove();
      }
    });

    // Close on Escape key
    document.addEventListener('keydown', function closeOnEscape(e) {
      if (e.key === 'Escape') {
        popup.remove();
        document.removeEventListener('keydown', closeOnEscape);
      }
    });
  }

  // Show informational popup for GitLab authentication errors
  function showGitLabAuthErrorPopup(retryCallback, isPermissionError = false) {
    // Remove any existing popup
    const existingPopup = document.getElementById('gitlab-auth-error-popup');
    if (existingPopup) {
      existingPopup.remove();
    }

    const popup = document.createElement('div');
    popup.id = 'gitlab-auth-error-popup';
    popup.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: rgba(0, 0, 0, 0.5);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 10000;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    `;

    const dialog = document.createElement('div');
    dialog.style.cssText = `
      background: var(--md-sys-color-surface, #1e1e1e);
      color: var(--md-sys-color-on-surface, #e0e0e0);
      border-radius: 12px;
      padding: 24px;
      max-width: 450px;
      width: 90%;
      box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
      position: relative;
    `;

    if (isPermissionError) {
      dialog.innerHTML = `
        <h2 style="margin: 0 0 16px 0; font-size: 18px; font-weight: 600; color: var(--md-sys-color-error, #f44336);">
          GitLab Permission Error
        </h2>
        <p style="margin: 0 0 16px 0; line-height: 1.5;">
          The token is valid, but GitLab denied access. This usually means insufficient permissions or scopes, or the account cannot access the resource.
        </p>
        <p style="margin: 0 0 20px 0; line-height: 1.5;">
          Ensure the token has "api" scope and the account has proper access.
        </p>
        <div style="display: flex; gap: 12px; justify-content: flex-end;">
          <button id="gitlab-auth-cancel" style="
            background: var(--md-sys-color-surface-variant, #2a2a2a);
            color: var(--md-sys-color-on-surface-variant, #aaa);
            border: none;
            padding: 10px 20px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 14px;
          ">Cancel</button>
          <button id="gitlab-auth-retry" style="
            background: var(--md-sys-color-primary, #818cf8);
            color: var(--md-sys-color-on-primary, #fff);
            border: none;
            padding: 10px 20px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 500;
          ">Retry</button>
        </div>
      `;
    } else {
      dialog.innerHTML = `
        <h2 style="margin: 0 0 16px 0; font-size: 18px; font-weight: 600; color: var(--md-sys-color-error, #f44336);">
          GitLab Authentication Error
        </h2>
        <p style="margin: 0 0 16px 0; line-height: 1.5;">
          The PAT returned an authentication error from GitLab. The most likely cause of this is a typo, an expired token (Gitlab tokens expire every 12 months), or the token was created without the required "api" scope.
        </p>
        <p style="margin: 0 0 16px 0; line-height: 1.5;">
          If expired, create a new token with the "api" scope. If still active, you may edit it in GitLab to add the "api" scope, then retry.
        </p>
        <p style="margin: 0 0 20px 0; font-size: 14px; opacity: 0.8;">
          Account issues may also cause 401 (e.g., flagged or restricted account).
        </p>
        <div style="display: flex; gap: 12px; justify-content: flex-end;">
          <button id="gitlab-auth-cancel" style="
            background: var(--md-sys-color-surface-variant, #2a2a2a);
            color: var(--md-sys-color-on-surface-variant, #aaa);
            border: none;
            padding: 10px 20px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 14px;
          ">Cancel</button>
          <button id="gitlab-auth-retry" style="
            background: var(--md-sys-color-primary, #818cf8);
            color: var(--md-sys-color-on-primary, #fff);
            border: none;
            padding: 10px 20px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 500;
          ">Retry with New Token</button>
        </div>
      `;
    }

    popup.appendChild(dialog);
    document.body.appendChild(popup);

    // Event listeners
    dialog.querySelector('#gitlab-auth-cancel').addEventListener('click', () => {
      popup.remove();
    });

    dialog.querySelector('#gitlab-auth-retry').addEventListener('click', () => {
      popup.remove();
      if (retryCallback) {
        retryCallback();
      }
    });

    // Close on background click
    popup.addEventListener('click', (e) => {
      if (e.target === popup) {
        popup.remove();
      }
    });

    // Close on Escape key
    document.addEventListener('keydown', function closeOnEscape(e) {
      if (e.key === 'Escape') {
        popup.remove();
        document.removeEventListener('keydown', closeOnEscape);
      }
    });
  }

  // Show informational popup for GitLab rate limit errors
  function showGitLabRateLimitPopup() {
    // Remove any existing popup
    const existingPopup = document.getElementById('gitlab-rate-limit-popup');
    if (existingPopup) {
      existingPopup.remove();
    }

    const popup = document.createElement('div');
    popup.id = 'gitlab-rate-limit-popup';
    popup.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: rgba(0, 0, 0, 0.5);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 10000;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    `;

    const dialog = document.createElement('div');
    dialog.style.cssText = `
      background: var(--md-sys-color-surface, #1e1e1e);
      color: var(--md-sys-color-on-surface, #e0e0e0);
      border-radius: 12px;
      padding: 24px;
      max-width: 450px;
      width: 90%;
      box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
      position: relative;
    `;

    dialog.innerHTML = `
      <h2 style="margin: 0 0 16px 0; font-size: 18px; font-weight: 600; color: var(--md-sys-color-error, #f44336);">
        GitLab Rate Limit Reached
      </h2>
      <p style="margin: 0 0 20px 0; line-height: 1.5;">
        Too many requests were sent; GitLab temporarily blocked further requests.
        <br><br>
        No token changes required. Wait and try again later.
      </p>
      <div style="display: flex; gap: 12px; justify-content: flex-end;">
        <button id="gitlab-rate-limit-ok" style="
          background: var(--md-sys-color-primary, #818cf8);
          color: var(--md-sys-color-on-primary, #fff);
          border: none;
          padding: 10px 20px;
          border-radius: 6px;
          cursor: pointer;
          font-size: 14px;
          font-weight: 500;
        ">OK</button>
      </div>
    `;

    popup.appendChild(dialog);
    document.body.appendChild(popup);

    // Event listeners
    dialog.querySelector('#gitlab-rate-limit-ok').addEventListener('click', () => {
      popup.remove();
    });

    // Close on background click
    popup.addEventListener('click', (e) => {
      if (e.target === popup) {
        popup.remove();
      }
    });

    // Close on Escape key
    document.addEventListener('keydown', function closeOnEscape(e) {
      if (e.key === 'Escape') {
        popup.remove();
        document.removeEventListener('keydown', closeOnEscape);
      }
    });
  }

  // Get GitLab API headers
  function getSnippetHeaders() {
    if (!snippetToken) {
      showToast('GitLab token not found. Please reconnect in the sync settings.', 'error');
      throw new Error('No GitLab token available');
    }
    return {
      'Authorization': `Bearer ${snippetToken}`,
      'Content-Type': 'application/json'
    };
  }

  // Validate GitLab token
  async function validateSnippetToken(retryCallback = null) {
    try {
      const response = await fetchGitLab('https://gitlab.com/api/v4/user', {
        headers: getSnippetHeaders()
      });
    if (!response.ok) {
      if (response.status === 429) {
        showGitLabRateLimitPopup();
        return null;
      } else if (response.status >= 500 && response.status < 600) {
        // Show service error popup and allow retry
        showGitLabServiceErrorPopup(retryCallback);
        return null;
      } else if (response.status === 401) {
        // Show informational popup and allow retry
        showGitLabAuthErrorPopup(retryCallback, false);
        return null;
      } else if (response.status === 403) {
        // Show permission error popup and allow retry
        showGitLabAuthErrorPopup(retryCallback, true);
        return null;
      } else {
        throw new Error(`GitLab API error: ${response.status}`);
      }
    }
      const user = await response.json();
      console.log('GitLab token validated for user:', user.username);
      return user;
    } catch (error) {
      console.error('Token validation failed:', error);
      return null;
    }
  }

  // Get all user's snippets
  async function getAllSnippets(retryCallback = null) {
    try {
      const response = await fetchGitLab('https://gitlab.com/api/v4/snippets', {
        headers: getSnippetHeaders()
      });
      if (!response.ok) {
        if (response.status === 401) {
          // Show informational popup and allow retry
          showGitLabAuthErrorPopup(retryCallback, false);
          return null;
        } else if (response.status === 403) {
          // Show permission error popup and allow retry
          showGitLabAuthErrorPopup(retryCallback, true);
          return null;
        } else if (response.status >= 500 && response.status < 600) {
          // Show service error popup and allow retry
          showGitLabServiceErrorPopup(retryCallback);
          return null;
        } else {
          throw new Error(`Failed to fetch snippets: ${response.status}`);
        }
      }
      return await response.json();
    } catch (error) {
      console.error('Failed to fetch snippets:', error);
      throw error;
    }
  }

  // Find bookmark snippet
  async function findBookmarkSnippet() {
    try {
      const snippets = await getAllSnippets();
      if (!snippets) return null; // 401/403/429 — getAllSnippets already showed a popup
      const bookmarkSnippet = snippets.find(s =>
        s.title?.includes('BMZ') ||
        s.title?.includes('Bookmark Manager Zero') ||
        s.file_name === 'bookmarks.json'
      );
      if (bookmarkSnippet) {
        console.log('Found bookmark Snippet:', bookmarkSnippet.id);
        return bookmarkSnippet.id;
      }
      return null;
    } catch (error) {
      console.error('Failed to find bookmark Snippet:', error);
      throw error;
    }
  }

  // Create new bookmark snippet
  async function createBookmarkSnippet(bookmarkTree = null) {
    try {
      let tree = bookmarkTree;

      // If no tree provided, get current Firefox bookmarks
      if (!tree) {
        const bookmarkRoot = await browser.bookmarks.getTree();
        tree = await firefoxBookmarksToSnippetFormat(bookmarkRoot);
      }

      const response = await fetchGitLab('https://gitlab.com/api/v4/snippets', {
        method: 'POST',
        headers: getSnippetHeaders(),
        body: JSON.stringify({
          title: 'BMZ Bookmarks - Managed by Bookmark Manager Zero',
          visibility: 'private',
          files: [
            {
              file_path: 'bookmarks.json',
              content: JSON.stringify(tree, null, 2)
            }
          ]
        })
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Failed to create Snippet: ${response.status} - ${errorText}`);
      }

      const snippet = await response.json();
      snippetId = snippet.id;
      await safeStorage.set({ bmz_snippet_id: snippetId });
      console.log('Created bookmark Snippet:', snippetId);
      return snippet.id;
    } catch (error) {
      console.error('Failed to create bookmark Snippet:', error);
      throw error;
    }
  }

  // Read bookmarks from snippet
  async function readBookmarksFromSnippet(id = null) {
    const useId = id || snippetId;
    if (!useId) {
      throw new Error('No Snippet ID provided');
    }

    try {
      const response = await fetchGitLab(`https://gitlab.com/api/v4/snippets/${useId}`, {
        headers: getSnippetHeaders()
      });

      if (!response.ok) {
        if (response.status === 404) {
          throw new Error('Bookmark Snippet not found');
        }
        throw new Error(`Failed to read Snippet: ${response.status}`);
      }

      const snippet = await response.json();

      // GitLab snippets have a 'files' array
      const bookmarkFile = snippet.files?.find(f =>
        f.path === 'bookmarks.json' || f.file_name === 'bookmarks.json'
      );
      if (!bookmarkFile) {
        throw new Error('Snippet does not contain bookmarks.json');
      }

      // Get file content
      let content = bookmarkFile.content;

      // If content is not in the response, fetch it using the raw endpoint
      if (!content) {
        const fileResponse = await fetch(
          `https://gitlab.com/api/v4/snippets/${useId}/files/main/bookmarks.json/raw`,
          { headers: getSnippetHeaders() }
        );
        if (!fileResponse.ok) {
          throw new Error(`Failed to fetch file content: ${fileResponse.status}`);
        }
        content = await fileResponse.text();
      }

      // If content is empty or just whitespace, return empty structure
      if (!content || content.trim() === '') {
        console.log('Snippet file is empty, returning empty bookmark structure');
        return {
          version: 1,
          checksum: '',
          lastModified: Date.now(),
          roots: {
            bookmark_bar: { id: '1', title: 'Bookmarks Toolbar', name: 'Bookmarks Toolbar', type: 'folder', dateAdded: Date.now(), children: [] },
            menu: { id: '2', title: 'Bookmarks Menu', name: 'Bookmarks Menu', type: 'folder', dateAdded: Date.now(), children: [] },
            other: { id: '3', title: 'Other Bookmarks', name: 'Other Bookmarks', type: 'folder', dateAdded: Date.now(), children: [] },
            mobile: { id: '4', title: 'Mobile Bookmarks', name: 'Mobile Bookmarks', type: 'folder', dateAdded: Date.now(), children: [] }
          }
        };
      }

      return JSON.parse(content);
    } catch (error) {
      console.error('Failed to read bookmarks from Snippet:', error);
      throw error;
    }
  }

  /* [ZeroLabs] 2026-08-17 4:15 PM - added: quick access meta file in snippet */
  // Pins live in their own file so a client that has never heard of Quick Access
  // cannot blank them: GitLab only rewrites the files named in the request, and
  // every older build names only bookmarks.json.
  const META_FILE = 'bmz-meta.json';
  let metaFileExists = false;

  async function readQuickAccessMeta(id = null) {
    const useId = id || snippetId;
    if (!useId) return null;

    try {
      const response = await fetchGitLab(`https://gitlab.com/api/v4/snippets/${useId}`, {
        headers: getSnippetHeaders()
      });
      if (!response.ok) return null;

      const snippet = await response.json();
      const metaFile = snippet.files?.find(f =>
        f.path === META_FILE || f.file_name === META_FILE
      );

      // A snippet with no meta file means no pins yet, which is the normal state
      // of every snippet that existed before this feature. Not an error.
      if (!metaFile) {
        metaFileExists = false;
        return { pins: [], tombstones: [] };
      }
      metaFileExists = true;

      let content = metaFile.content;
      if (!content) {
        const fileResponse = await fetch(
          `https://gitlab.com/api/v4/snippets/${useId}/files/main/${META_FILE}/raw`,
          { headers: getSnippetHeaders() }
        );
        if (!fileResponse.ok) return { pins: [], tombstones: [] };
        content = await fileResponse.text();
      }

      if (!content || content.trim() === '') return { pins: [], tombstones: [] };

      const parsed = JSON.parse(content);
      return {
        pins: Array.isArray(parsed.quickAccess) ? parsed.quickAccess : [],
        tombstones: Array.isArray(parsed.quickAccessRemoved) ? parsed.quickAccessRemoved : []
      };
    } catch (error) {
      console.error('Failed to read quick access meta from Snippet:', error);
      return null;
    }
  }

  // Pull the pins for a snippet and fold them into the local list. Until this
  // has run for the current snippet, pushes must not include the meta file.
  async function loadQuickAccessForSnippet(id = null) {
    const useId = id || snippetId;
    if (!useId) return;

    const remote = await readQuickAccessMeta(useId);
    if (!remote) return; // Network or auth failure; keep local as-is and retry later

    if (quickAccessSnippetTag && quickAccessSnippetTag !== useId) {
      // Switched snippets. The cached pins belong to the previous snippet and
      // must not leak into this one, so they are discarded rather than merged.
      quickAccessPins = [];
      quickAccessTombstones = [];
    }

    mergeQuickAccess(remote.pins, remote.tombstones);
    quickAccessSnippetTag = useId;
    quickAccessMetaLoaded = true;
    await saveQuickAccess();
    renderBookmarks();
  }

  function buildQuickAccessMetaContent() {
    return JSON.stringify({
      metaVersion: 1,
      lastModified: Date.now(),
      quickAccess: quickAccessPins,
      quickAccessRemoved: quickAccessTombstones
    }, null, 2);
  }

  // Update bookmarks in snippet
  async function updateBookmarksInSnippet(bookmarkTree, version = null) {
    if (!snippetId) {
      throw new Error('No Snippet ID provided');
    }

    /* [ZeroLabs] 2026-08-17 4:15 PM - added: load pins before any push */
    // Every push path goes through here (plain sync, merge, replace-remote), and
    // hooking only syncToSnippet meant the merge and replace paths silently
    // omitted the meta file. Loading here makes all of them correct.
    if (!quickAccessMetaLoaded || quickAccessSnippetTag !== snippetId) {
      await loadQuickAccessForSnippet(snippetId);
    }

    try {
      const dataWithMeta = {
        ...bookmarkTree,
        version: version !== null ? version : (bookmarkTree.version || 1) + 1,
        checksum: await calculateChecksum(bookmarkTree),
        lastModified: Date.now()
      };

      /* [ZeroLabs] 2026-08-17 4:15 PM - edited: push quick access meta alongside */
      const files = [
        {
          action: 'update',
          file_path: 'bookmarks.json',
          content: JSON.stringify(dataWithMeta, null, 2)
        }
      ];

      // Only ever write pins for a snippet whose meta has already been read.
      // Otherwise a snippet switch followed by a fast auto-sync would overwrite
      // the new snippet's pins with the previous snippet's cache.
      if (quickAccessMetaLoaded && quickAccessSnippetTag === snippetId) {
        files.push({
          action: metaFileExists ? 'update' : 'create',
          file_path: META_FILE,
          content: buildQuickAccessMetaContent()
        });
      }

      const response = await fetchGitLab(`https://gitlab.com/api/v4/snippets/${snippetId}`, {
        method: 'PUT',
        headers: getSnippetHeaders(),
        body: JSON.stringify({ files })
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Failed to update Snippet: ${response.status} - ${errorText}`);
      }

      // A successful write means the file is there now, so later pushes update
      // rather than create.
      if (files.length > 1) metaFileExists = true;

      console.log('Updated bookmarks in Snippet:', snippetId);
      return await response.json();
    } catch (error) {
      console.error('Failed to update bookmarks in Snippet:', error);
      throw error;
    }
  }

  // Calculate diff between local and remote bookmark trees
  /* [ZeroLabs] 2026-08-27 12:44 AM - added: shared folder title normalizer (see also: Bookmark-Manager-Zero-Chrome/sidepanel.js) */
  // Normalize folder titles to handle Chrome vs Firefox naming differences.
  // IMPORTANT: Must use same normalization as Chrome for cross-browser sync.
  // Lifted out of calculateBookmarkDiff unchanged: the diff builds its paths
  // with this, so anything resolving one of those paths back to a real folder
  // has to use the identical function or the two will disagree on root names.
  function normalizeBookmarkTitle(title) {
    // Treat empty string and "Untitled" as equivalent (empty)
    if (!title || title === 'Untitled' || title === 'Untitled Folder') {
      return '';
    }

    const normalized = {
      'Bookmarks Toolbar': 'Bookmarks bar',   // Firefox → Chrome standard
      'Bookmarks bar': 'Bookmarks bar',        // Chrome → Chrome standard
      'Other Bookmarks': 'Other bookmarks',    // Normalize to Chrome's lowercase
      'Other bookmarks': 'Other bookmarks',    // Chrome → Chrome standard
      'Mobile Bookmarks': 'Mobile Bookmarks',
      'Bookmarks Menu': 'Bookmarks Menu'
    };
    return normalized[title] || title;
  }

  /* [ZeroLabs] 2026-08-27 12:44 AM - added: resolve a diff path to a local folder */
  // Walks the local tree segment by segment, creating folders that do not exist
  // yet, and returns the id of the last one. Root folders are matched but never
  // created: a path whose first segment names no local root is unresolvable and
  // returns null rather than inventing a folder at the top level.
  async function resolveOrCreateFolderPath(segments) {
    if (!segments || segments.length === 0) return null;

    const tree = await browser.bookmarks.getTree();
    const roots = (tree[0] && tree[0].children) || [];
    const root = roots.find(r => normalizeBookmarkTitle(r.title || '') === segments[0]);
    if (!root) {
      console.warn('[AddFromSnippet] No local root matches path segment:', segments[0]);
      return null;
    }

    let parentId = root.id;
    for (let i = 1; i < segments.length; i++) {
      const children = await browser.bookmarks.getChildren(parentId);
      let match = children.find(c => !c.url && normalizeBookmarkTitle(c.title || '') === segments[i]);
      if (!match) {
        match = await browser.bookmarks.create({ parentId, title: segments[i] });
      }
      parentId = match.id;
    }

    return parentId;
  }

  /* [ZeroLabs] 2026-08-27 12:44 AM - added: add chosen snippet-only items to this device */
  // The third option between "snippet wins" and "this device wins", both of
  // which destroy one side. These items exist in the snippet and not here, so
  // creating them locally and pushing the result loses nothing on either side.
  //
  // Folders are created before bookmarks and shallower paths before deeper ones,
  // so a parent always exists by the time its contents are placed.
  /* [ZeroLabs] 2026-08-27 2:26 AM - added: confirm a push the background refused to make */
  // The background will not remove anything from the snippet on its own, so
  // when a local deletion needs to travel it parks the push and raises the
  // badge. This is where it gets settled, since only the sidebar can ask.
  /* [ZeroLabs] 2026-08-27 2:20 PM - added: snippet items with their folders (mirrors background.js) */
  // The diff keys on url plus path, so a rename or move looks like a delete and
  // an add of two different things. Comparing entries instead makes "same
  // bookmark, different name or place" visible as what it is.
  /* [ZeroLabs] 2026-08-29 - added: a URL is an address, not an identity (mirrors background.js) */
  // Keyed on the URL alone, two bookmarks pointing at the same place overwrote
  // each other, so a library holding the same link twice reported one fewer item
  // than it had and a device rebuilding from the snippet created only one of the
  // pair. It never healed, either: the missing copy was never seen as missing.
  //
  // The Nth copy of a URL is keyed "<url>\u0000#N". The FIRST copy keeps the bare
  // URL, so anything appearing once has exactly the key it always had.
  //
  // Copies are numbered by sorted location, not by tree order, so two browsers
  // walking their trees differently still agree on which copy is which. Declared
  // in this scope rather than the file's, so collectSnippetEntries can reach it.
  const SNIPPET_COPY_SEP = '\u0000#';

  function keyByUrlCopy(list) {
    const location = (e) => [e.rootKey].concat(e.segments || []).join('/') + '/' + (e.title || '');
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
      group.sort((a, b) => location(a).localeCompare(location(b)));
      group.forEach((entry, i) => {
        keyed.set(i === 0 ? url : `${url}${SNIPPET_COPY_SEP}${i + 1}`, entry);
      });
    });
    return keyed;
  }

  function collectSnippetEntries(snippetData) {
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

  /* [ZeroLabs] 2026-08-27 2:02 PM - added: place a bookmark by snippet root key (moved from: background.js) */
  // The held items carry the snippet's own root key rather than a folder title,
  // because the two browsers name their roots differently and a title would not
  // survive the trip. Firefox has a real menu root, so unlike Chrome nothing has
  // to be folded into Other Bookmarks.
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

  /* [ZeroLabs] 2026-08-27 11:36 AM - edited: covers removals in both directions */
  // A deferral has two possible shapes and they can occur together: bookmarks
  // you deleted here that the snippet still holds, and bookmarks the snippet no
  // longer holds that are still here because another device deleted them. Both
  // resolve to a removal, which is the whole reason the sync stopped.
  /* [ZeroLabs] 2026-08-27 - added: a deletion asks now, not whenever you next open BMZ */
  // Deleting defers for consent, and that consent used to wait for the 30s
  // background push and then sit as an amber card until BMZ was next opened - so
  // the deletion simply did not reach the snippet, possibly for days. This runs the
  // same reconcile in the foreground, so the modal appears while you are still
  // looking at what you deleted and the change can go straight out.
  //
  // Delayed past the 5s undo window: the modal must not land on top of the undo
  // toast, and undoing makes the whole question moot. The timer is shared, so
  // deleting several in a row asks once rather than once per bookmark.
  // snippetId, snippetToken and reconcileWithSnippet all live inside
  // setupEventListeners in this file, so this must too - and the delete
  // handlers that call it are at top level, hence the window handoff. Same
  // arrangement as showHeldPushDialog.
  let localDeleteSyncTimer = null;
  function syncAfterLocalDeletion() {
    clearTimeout(localDeleteSyncTimer);
    localDeleteSyncTimer = setTimeout(async () => {
      if (!snippetId || !snippetToken || !navigator.onLine) return;
      try {
        const outcome = await reconcileWithSnippet();
        if (outcome && outcome.deferred) {
          await window.showHeldPushDialog?.();
        }
      } catch (error) {
        console.error('[Sync] Post-delete sync failed:', error);
      }
    }, 6000);
  }
  window.syncAfterLocalDeletion = syncAfterLocalDeletion;

  async function showHeldPushDialog() {
    const stored = await safeStorage.get([
      'snippet_push_held',
      'snippet_push_held_items',
      'snippet_pull_held_items',
      'snippet_overwrite_held_items',
      'snippet_added_here_items',
      'snippet_pending_push_items'
    ]);
    if (!stored.snippet_push_held) return;

    const fromSnippet = stored.snippet_push_held_items || [];
    const fromDevice = stored.snippet_pull_held_items || [];
    /* [ZeroLabs] 2026-08-27 2:02 PM - added: renames and moves wait here too */
    const overwrites = stored.snippet_overwrite_held_items || [];
    if (fromSnippet.length === 0 && fromDevice.length === 0 && overwrites.length === 0) return;

    const modal = document.createElement('div');
    modal.style.cssText = 'position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.7); z-index: 10001; display: flex; align-items: center; justify-content: center;';

    const dialog = document.createElement('div');
    dialog.style.cssText = 'background: var(--md-sys-color-surface, #1e1e1e); padding: 24px; border-radius: 12px; max-width: 560px; width: 90%; max-height: 80%; overflow-y: auto; color: var(--md-sys-color-on-surface, #e0e0e0);';
    dialog.className = 'bmz-dialog';

    const renderList = (items) => {
      let out = '';
      items.slice(0, 50).forEach(item => {
        out += `<div style="padding: 8px; margin-bottom: 4px; background: rgba(244, 67, 54, 0.1); border-left: 3px solid #f44336; border-radius: 4px;">
          <div style="font-weight: 500;">${escapeHtml(item.title || 'Untitled')}</div>
          <div style="font-size: 11px; color: #888; margin-top: 4px;">${escapeHtml(item.url || '')}</div>
        </div>`;
      });
      if (items.length > 50) {
        out += `<div style="font-size: 12px; color: #aaa; padding: 8px;">...and ${items.length - 50} more</div>`;
      }
      return out;
    };

    /* [ZeroLabs] 2026-08-27 - added: account for the safe additions as well */
    // Additions never need consent, so they are already applied by the time this
    // opens - but bookmarks appearing while a modal asks about something else is
    // unexplained unless the modal says so. Past tense, because it is done.
    const addedHere = stored.snippet_added_here_items || [];
    const pendingPush = stored.snippet_pending_push_items || [];
    const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;

    /* [ZeroLabs] 2026-08-27 - added: a count you cannot inspect is half an answer */
    // These two are stated rather than asked about, so they are collapsed by
    // default - but the bookmarks are nameable and the user should be able to see
    // which ones. Same chevron behaviour as Snippet Sync Options.
    let noteId = 0;
    const collapsibleNote = (sentence, items, colour) => {
      const id = `syncNote${noteId++}`;
      const rows = items.slice(0, 50).map(item => `
        <div style="padding: 4px 8px; font-size: 12px; color: #aaa;">
          ${escapeHtml(item.title || item.url || 'Untitled')}
          ${item.path ? `<span style="color: #777;"> — ${escapeHtml(item.path)}</span>` : ''}
        </div>`).join('');
      const more = items.length > 50
        ? `<div style="padding: 4px 8px; font-size: 12px; color: #777;">...and ${items.length - 50} more</div>` : '';
      return `
        <div style="margin: 0 0 12px 0;">
          <button type="button" id="${id}Toggle" aria-expanded="false" style="display: flex; align-items: center; gap: 6px; width: 100%; padding: 0; background: none; border: none; color: ${colour}; font-size: 14px; text-align: left; cursor: pointer; font-family: inherit;">
            <span>${sentence}</span>
            <svg id="${id}Chevron" width="16" height="16" viewBox="0 0 24 24" fill="currentColor" style="flex-shrink: 0; margin-right: auto; transition: transform 0.2s ease; transform: rotate(-90deg);"><path d="M7.41,8.58L12,13.17L16.59,8.58L18,10L12,16L6,10L7.41,8.58Z"/></svg>
          </button>
          <div id="${id}List" style="display: none; margin-top: 6px; border-left: 2px solid ${colour}; padding-left: 6px;">${rows}${more}</div>
        </div>`;
    };

    let body = '';
    if (addedHere.length > 0) {
      body += collapsibleNote(
        `Already added ${plural(addedHere.length, 'bookmark', 'bookmarks')} to this device.`,
        addedHere, '#4caf50');
    }
    // Approve pushes, so this device's own additions travel as part of it
    if (pendingPush.length > 0) {
      body += collapsibleNote(
        `Add ${plural(pendingPush.length, 'bookmark', 'bookmarks')} from this device to your Snippet.`,
        pendingPush, 'var(--md-sys-color-on-surface, #e0e0e0)');
    }
    if (fromSnippet.length > 0) {
      body += `<p style="margin: 0 0 12px 0; font-size: 14px;">
        Remove ${fromSnippet.length} bookmark${fromSnippet.length === 1 ? '' : 's'} from your snippet to match this device.
      </p>
      <div style="margin-bottom: 20px;">${renderList(fromSnippet)}</div>`;
    }
    if (fromDevice.length > 0) {
      body += `<p style="margin: 0 0 12px 0; font-size: 14px;">
        Remove ${fromDevice.length} bookmark${fromDevice.length === 1 ? '' : 's'} from this device to match the snippet.
      </p>
      <div style="margin-bottom: 20px;">${renderList(fromDevice)}</div>`;
    }

    /* [ZeroLabs] 2026-08-27 2:02 PM - added: the rename and move section */
    // Shown with both versions, because the choice is between two names rather
    // than between keeping and losing something.
    if (overwrites.length > 0) {
      body += `<p style="margin: 0 0 12px 0; font-size: 14px;">
        Rename or move ${overwrites.length} bookmark${overwrites.length === 1 ? '' : 's'} on this device to match the snippet.
      </p>`;
      let list = '';
      overwrites.slice(0, 50).forEach(item => {
        const renamed = item.title !== item.remoteTitle;
        const relocated = item.localPath !== item.remotePath;
        list += `<div style="padding: 8px; margin-bottom: 4px; background: rgba(255, 152, 0, 0.1); border-left: 3px solid #ff9800; border-radius: 4px;">
          <div style="font-weight: 500;">${escapeHtml(item.title || 'Untitled')}</div>
          ${renamed ? `<div style="font-size: 12px; color: #aaa;">Name: ${escapeHtml(item.title || '')} → ${escapeHtml(item.remoteTitle || '')}</div>` : ''}
          ${relocated ? `<div style="font-size: 12px; color: #aaa;">Folder: ${escapeHtml(item.localPath || '')} → ${escapeHtml(item.remotePath || '')}</div>` : ''}
          <div style="font-size: 11px; color: #888; margin-top: 4px;">${escapeHtml(item.url || '')}</div>
        </div>`;
      });
      if (overwrites.length > 50) {
        list += `<div style="font-size: 12px; color: #aaa; padding: 8px;">...and ${overwrites.length - 50} more</div>`;
      }
      body += `<div style="margin-bottom: 20px;">${list}</div>`;
    }

    dialog.innerHTML = `
      <!-- [ZeroLabs] 2026-08-27 11:36 AM - edited: centered heading -->
      <h2 style="margin: 0 0 12px 0; font-size: 18px; color: #ff9800; text-align: center;">Sync changes to review</h2>
      <p style="margin: 0 0 16px 0; font-size: 14px;">
        Syncing would:
      </p>
      ${body}
      <div style="display: flex; flex-direction: column; gap: 12px;">
        <button id="heldPushConfirm" style="width: 100%; padding: 12px; border-radius: 8px; border: none; background: #f59e0b; color: #1a1a1a; cursor: pointer; font-size: 14px; font-weight: 600;">
          Approve
        </button>
        <button id="heldPushLater" style="width: 100%; padding: 12px; border-radius: 8px; border: none; background: var(--md-sys-color-surface-variant, #2a2a2a); color: var(--md-sys-color-on-surface-variant, #aaa); cursor: pointer; font-size: 14px;">
          Cancel
        </button>
      </div>
    `;

    modal.appendChild(dialog);
    document.body.appendChild(modal);

    /* [ZeroLabs] 2026-08-27 - added: expand the collapsed notes */
    dialog.querySelectorAll('[id$="Toggle"]').forEach(toggle => {
      const base = toggle.id.replace(/Toggle$/, '');
      const list = dialog.querySelector(`#${base}List`);
      const chevron = dialog.querySelector(`#${base}Chevron`);
      if (!list) return;
      toggle.addEventListener('click', () => {
        const open = list.style.display !== 'none';
        list.style.display = open ? 'none' : 'block';
        toggle.setAttribute('aria-expanded', String(!open));
        if (chevron) chevron.style.transform = open ? 'rotate(-90deg)' : 'rotate(0deg)';
      });
    });

    const clearHold = () => safeStorage.set({
      snippet_push_held: false,
      snippet_push_held_items: [],
      snippet_pull_held_items: [],
      snippet_overwrite_held_items: []
    });

    dialog.querySelector('#heldPushConfirm').addEventListener('click', async () => {
      modal.remove();
      await clearHold();

      /* [ZeroLabs] 2026-08-27 11:36 AM - added: apply the device-side removals too */
      // Deleting these locally is what makes the push carry the other device's
      // deletion. Logged to the changelog so they stay undoable like any delete.
      /* [ZeroLabs] 2026-08-28 - added: collect the folders these leave behind */
      const vacated = new Set();

      if (fromDevice.length > 0) {
        for (const item of fromDevice) {
          try {
            const matches = await browser.bookmarks.search({ url: item.url });
            for (const node of matches) {
              const fullData = JSON.parse(JSON.stringify(node));
              if (node.parentId) vacated.add(node.parentId);
              await browser.bookmarks.remove(node.id);
              await addChangelogEntry('delete', 'bookmark', node.title || 'Untitled', node.url || null, { fullData });
            }
          } catch (error) {
            console.warn('[SnippetPush] Could not remove locally:', item.url, error.message);
          }
        }
        await loadBookmarks();
        renderBookmarks();
      }

      /* [ZeroLabs] 2026-08-27 2:02 PM - added: apply the approved renames and moves */
      // Moved here from the background: this overwrites data on the device, so
      // it only ever runs with consent, next to the removals approved above.
      if (overwrites.length > 0) {
        for (const item of overwrites) {
          try {
            const matches = await browser.bookmarks.search({ url: item.url });
            const node = matches && matches[0];
            if (!node) continue;

            /* [ZeroLabs] 2026-08-27 - added: log approved renames and moves */
            // A rename made in BMZ's own edit dialog writes an 'update' entry and
            // is undoable from the changelog. One arriving through sync changed
            // the bookmark just as much and left no trace at all, so it could not
            // be reviewed afterwards or undone. Same vocabulary as the edit dialog.
            const oldTitle = node.title;
            if (item.remoteTitle && node.title !== item.remoteTitle) {
              await browser.bookmarks.update(node.id, { title: item.remoteTitle });
              await addChangelogEntry('update', 'bookmark', item.remoteTitle, item.url || null, {
                oldTitle,
                newTitle: item.remoteTitle
              });
            }

            if (item.localPath !== item.remotePath && Array.isArray(item.remoteSegments)) {
              const rootId = firefoxRootForSnippetKey(item.remoteRootKey);
              if (rootId) {
                const parentId = await resolveOrCreateFolderUnder(rootId, item.remoteSegments);
                // An approved move empties a folder just as a removal does
                if (node.parentId && node.parentId !== parentId) vacated.add(node.parentId);
                await browser.bookmarks.move(node.id, { parentId });
                await addChangelogEntry('move', 'bookmark', item.remoteTitle || oldTitle, item.url || null, {
                  fromFolder: item.localPath,
                  toFolder: item.remotePath
                });
              }
            }
          } catch (error) {
            console.warn('[SnippetPush] Could not apply change to:', item.url, error.message);
          }
        }
        await loadBookmarks();
        renderBookmarks();
      }

      /* [ZeroLabs] 2026-08-28 - added: run the prune once everything has moved */
      // Deferred to here rather than done inline, because a folder emptied by a
      // removal can be refilled by a move later in the same resolution.
      if (vacated.size > 0) {
        for (const parentId of vacated) {
          await pruneEmptyFolderChain(parentId);
        }
        await loadBookmarks();
        renderBookmarks();
      }

      await syncToSnippet(true);
      await setSnippetNeedsReconcile(false);
      /* [ZeroLabs] 2026-08-27 2:41 PM - edited: one result, not the push's pair */
      showToast('Sync approved and applied.');
    });
    dialog.querySelector('#heldPushLater').addEventListener('click', () => modal.remove());
  }

  /* [ZeroLabs] 2026-08-27 - added: reachable from the notice card */
  // The card is rendered at module level, and in Firefox this function lives
  // inside setupEventListeners, so a direct call from the card would be a
  // ReferenceError - the same scope trap that broke the v4.5 announcement
  // card's button in v4.6. Exposed here so both browsers call it the same way.
  window.showHeldPushDialog = showHeldPushDialog;

  /* [ZeroLabs] 2026-08-27 12:20 PM - added: the sidebar's copy of the background's reconcile */
  // Same four outcomes and the same classification the background uses, so a
  // manual sync and an automatic one can never disagree about what is safe. The
  // difference is only what happens on a deferral: the background asks for
  // consent, while this returns the diff so the caller can offer every option.
  async function reconcileWithSnippet() {
    const remoteData = await readBookmarksFromSnippet(snippetId);
    const localTree = await browser.bookmarks.getTree();
    const remoteAsFirefox = snippetFormatToFirefoxBookmarks(remoteData);
    const diff = calculateBookmarkDiff(localTree[0], remoteAsFirefox[0]);

    const hasChanges = diff.added.length + diff.removed.length +
                       diff.moved.length + diff.modified.length > 0;

    if (!hasChanges) {
      snippetLocalVersion = Number(remoteData?.version) || snippetLocalVersion;
      await safeStorage.set({ snippet_local_version: snippetLocalVersion });
      await setSnippetNeedsReconcile(false);
      return { changed: false, deferred: false, addedLocally: 0, pushed: false };
    }

    const events = await safeStorage.get([
      'snippet_local_created',
      'snippet_local_deleted',
      'snippet_local_edited'
    ]);
    const createdHere = new Set(events.snippet_local_created || []);
    const deletedHere = new Set(events.snippet_local_deleted || []);

    /* [ZeroLabs] 2026-08-27 1:32 PM - added: pair renames and moves before judging removals (see also: Bookmark-Manager-Zero-Chrome/sidepanel.js) */
    // calculateBookmarkDiff keys on `bookmark:<url>:<path>` and path includes the
    // bookmark's own title, so renaming or moving one changes its key and the
    // same bookmark appears in BOTH added and removed, as though it were deleted
    // here and created there. Left alone that defers and offers to delete the
    // bookmark you just renamed, and would re-create the old title as a
    // duplicate.
    //
    // A URL on both lists is therefore an edit, not an add and not a delete.
    // Neither is destructive, so neither defers; the push carries the local
    // version, which is the same "local wins" the background applies.
    const addedUrls = new Set(diff.added.filter(item => item.url).map(item => item.url));
    const removedUrls = new Set(diff.removed.filter(item => item.url).map(item => item.url));

    // In the snippet and not here because you deleted it here: syncing removes
    // it from the snippet. Here and not in the snippet without this device
    // having seen it created: it came from elsewhere, so syncing removes it here.
    const removesFromSnippet = diff.added.filter(item =>
      item.url && deletedHere.has(item.url) && !removedUrls.has(item.url));
    const removesFromDevice = diff.removed.filter(item =>
      item.url && !createdHere.has(item.url) && !addedUrls.has(item.url));

    // Renamed and moved bookmarks are already here under their local title, so
    // creating the snippet's copy would duplicate them.
    /* [ZeroLabs] 2026-08-27 - edited: folders are not exempt from attribution */
    // This used to keep every folder unconditionally, because `!item.url` is true
    // for one and folders carry no URL to attribute. So a folder deleted here and
    // still in the snippet was recreated locally on every reconcile, and the push
    // that followed sent it straight back up - the deletion undid itself, for ever.
    //
    // Attribution is URL-based, so a folder inherits it from its contents: create
    // one only when a bookmark is actually going into it. An empty folder made on
    // another device therefore does not travel, which is the same limitation that
    // already applies to renaming and moving one.
    const wanted = (item) => item.url
      && !deletedHere.has(item.url) && !removedUrls.has(item.url);
    const toAdd = diff.added.filter(item => item.url
      ? wanted(item)
      : diff.added.some(other => other.path && item.path
          && other.path.startsWith(item.path + '/') && wanted(other)));

    /* [ZeroLabs] 2026-08-27 - edited: removals use the consent dialog, like everywhere else */
    // This used to hand the raw diff back, and the caller showed the diff dialog:
    // "2 item(s) only in the snippet", with a Merge button. That is the same fact
    // told backwards. A bookmark you deleted here that the snippet still holds is
    // not something you are missing - it is your deletion waiting to travel, and
    // Merge would have put it straight back. The worker and the Website both use
    // the consent dialog for this; the panel was the odd one out.
    if (removesFromSnippet.length > 0 || removesFromDevice.length > 0) {
      // Safe additions still land - they are never what the deferral is about.
      await bringSidesTogether(toAdd, true, false);

      const strip = (items) => items
        .filter(item => item.url)
        .map(item => ({ url: item.url, title: item.title, path: item.path }))
        .slice(0, 200);

      await safeStorage.set({
        snippet_push_held: true,
        snippet_push_held_items: strip(removesFromSnippet),
        snippet_pull_held_items: strip(removesFromDevice),
        snippet_overwrite_held_items: [],
        /* [ZeroLabs] 2026-08-27 - added: report the safe additions too */
        snippet_added_here_items: toAdd.filter(i => i.url)
          .map(i => ({ url: i.url, title: i.title, path: i.path })).slice(0, 200),
        snippet_pending_push_items: diff.removed
          .filter(item => item.url && createdHere.has(item.url))
          .map(i => ({ url: i.url, title: i.title, path: i.path })).slice(0, 200)
      });
      await setSnippetNeedsReconcile(true);
      return { changed: true, deferred: true, consent: true, diff, remoteData };
    }

    /* [ZeroLabs] 2026-08-27 2:20 PM - added: renames and moves, same rule as the background */
    // Without this the sidebar knew only about creates and deletes, so a rename
    // made elsewhere fell through to "nothing to add" and the push below sent
    // this device's old title back over it. Manual syncing quietly reverted the
    // other device's rename.
    const editedHere = new Set(events.snippet_local_edited || []);
    const localEntries = collectSnippetEntries(await firefoxBookmarksToSnippetFormat(localTree));
    const remoteEntries = collectSnippetEntries(remoteData);
    const overwritesOnDevice = [];

    localEntries.forEach((localEntry, key) => {
      const remoteEntry = remoteEntries.get(key);
      if (!remoteEntry) return;

      const movedOrRenamed =
        localEntry.title !== remoteEntry.title ||
        localEntry.rootKey !== remoteEntry.rootKey ||
        localEntry.segments.join('/') !== remoteEntry.segments.join('/');
      if (!movedOrRenamed) return;

      // Edited here means you meant it, so the push below carries it. Edited
      // elsewhere would overwrite a name on this device, which waits for consent.
      if (!editedHere.has(localEntry.url)) {
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

    if (overwritesOnDevice.length > 0) {
      // The diff dialog cannot express "take on their rename", so this uses the
      // consent dialog, the same one the background raises.
      await safeStorage.set({
        snippet_push_held: true,
        snippet_push_held_items: [],
        snippet_pull_held_items: [],
        snippet_overwrite_held_items: overwritesOnDevice.slice(0, 200),
        /* [ZeroLabs] 2026-08-27 - added: report the safe additions too */
        snippet_added_here_items: toAdd.filter(i => i.url)
          .map(i => ({ url: i.url, title: i.title, path: i.path })).slice(0, 200),
        snippet_pending_push_items: diff.removed
          .filter(item => item.url && createdHere.has(item.url))
          .map(i => ({ url: i.url, title: i.title, path: i.path })).slice(0, 200)
      });
      /* [ZeroLabs] 2026-08-27 - added: additions must not wait on a rename */
      // Without this, approving the rename pushed a tree that had never received
      // the snippet's new bookmarks, deleting them from the snippet. Created but
      // deliberately not pushed - the rename is still unresolved.
      await bringSidesTogether(toAdd, true, false);

      await setSnippetNeedsReconcile(true);
      return { changed: true, deferred: true, consent: true, diff, remoteData };
    }

    await bringSidesTogether(toAdd, true);

    return {
      changed: true,
      deferred: false,
      addedLocally: toAdd.length,
      pushed: true
    };
  }

  /* [ZeroLabs] 2026-08-27 2:44 AM - added: report and place what a merge could not add */
  // Nothing is lost when an item cannot be placed: it stays in the snippet and
  // this device simply does not have it yet. The dialog says so, and offers to
  // put them somewhere of the user's choosing rather than only reporting.
  function showUnplaceableItemsDialog(skippedItems, createdCount) {
    const modal = document.createElement('div');
    modal.style.cssText = 'position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.7); z-index: 10001; display: flex; align-items: center; justify-content: center;';

    const dialog = document.createElement('div');
    dialog.style.cssText = 'background: var(--md-sys-color-surface, #1e1e1e); padding: 24px; border-radius: 12px; max-width: 560px; width: 90%; max-height: 80%; overflow-y: auto; color: var(--md-sys-color-on-surface, #e0e0e0);';
    dialog.className = 'bmz-dialog';

    let list = '';
    skippedItems.forEach(({ item, reason }) => {
      list += `<div style="padding: 8px; margin-bottom: 8px; background: rgba(255, 152, 0, 0.1); border-left: 3px solid #ff9800; border-radius: 4px;">
        <div style="font-weight: 500;">${escapeHtml(item.title || 'Untitled')}</div>
        <div style="font-size: 12px; color: #aaa;">${escapeHtml(item.path || '')}</div>
        ${item.url ? `<div style="font-size: 11px; color: #888; margin-top: 4px;">${escapeHtml(item.url)}</div>` : ''}
        <div style="font-size: 12px; color: #ff9800; margin-top: 6px;">${escapeHtml(reason)}</div>
      </div>`;
    });

    dialog.innerHTML = `
      <h2 style="margin: 0 0 12px 0; font-size: 18px; color: #ff9800;">${skippedItems.length} item(s) could not be added</h2>
      <p style="margin: 0 0 16px 0; font-size: 14px;">
        ${createdCount > 0 ? `${createdCount} item(s) were added and synced. ` : ''}These could not be placed on this device.
        They are still in the snippet and on your other devices, so nothing has been lost.
      </p>
      <div style="margin-bottom: 20px;">${list}</div>
      <label style="display: block; font-size: 13px; color: var(--md-sys-color-on-surface-variant, #aaa); margin-bottom: 6px;">
        Save them to this folder instead:
      </label>
      <select id="unplaceableFolder" style="width: 100%; padding: 10px; border-radius: 8px; border: 1px solid var(--md-sys-color-outline, #444); background: var(--md-sys-color-surface-variant, #2a2a2a); color: var(--md-sys-color-on-surface, #e0e0e0); font-size: 14px; margin-bottom: 12px;"></select>
      <div style="display: flex; flex-direction: column; gap: 12px;">
        <button id="unplaceableSave" style="width: 100%; padding: 12px; border-radius: 8px; border: none; background: var(--md-sys-color-primary, #90caf9); color: var(--md-sys-color-on-primary, #000); cursor: pointer; font-size: 14px; font-weight: 500;">
          Save them there and sync
        </button>
        <button id="unplaceableClose" style="width: 100%; padding: 12px; border-radius: 8px; border: none; background: var(--md-sys-color-surface-variant, #2a2a2a); color: var(--md-sys-color-on-surface-variant, #aaa); cursor: pointer; font-size: 14px;">
          Leave them in the snippet only
        </button>
      </div>
    `;

    modal.appendChild(dialog);
    document.body.appendChild(modal);

    const folderSelect = dialog.querySelector('#unplaceableFolder');
    populateFolderDropdown(folderSelect, false);
    // "Root" is not a real parent in Firefox's bookmark tree, so it is not offered
    const rootOption = folderSelect.querySelector('option[value=""]');
    if (rootOption) rootOption.remove();

    dialog.querySelector('#unplaceableSave').addEventListener('click', async () => {
      const parentId = folderSelect.value;
      if (!parentId) {
        showToast('Choose a folder first', 'error');
        return;
      }

      modal.remove();
      showToast(`Saving ${skippedItems.length} item(s)...`);

      // Flat into the chosen folder. Their original structure is what could not
      // be reproduced here, so recreating a path is exactly what is impossible.
      const stillSkipped = [];
      let placed = 0;
      for (const { item } of skippedItems) {
        try {
          await browser.bookmarks.create(item.type === 'folder'
            ? { parentId, title: item.title || 'Untitled' }
            : { parentId, title: item.title || item.url, url: item.url });
          placed++;
        } catch (error) {
          stillSkipped.push({ item, reason: error.message || 'The browser refused to create it.' });
        }
      }

      await loadBookmarks();
      renderBookmarks();
      await syncToSnippet(true);

      if (stillSkipped.length > 0) {
        showUnplaceableItemsDialog(stillSkipped, placed);
      } else {
        showToast(`Saved ${placed} item(s) and synced.`);
      }
    });

    dialog.querySelector('#unplaceableClose').addEventListener('click', () => modal.remove());
    modal.addEventListener('click', (e) => {
      if (e.target === modal) modal.remove();
    });
  }

  /* [ZeroLabs] 2026-08-27 2:26 AM - edited: additive only, no selection */
  /* [ZeroLabs] 2026-08-27 - edited: allow create-without-push */
  // A deferral needs the safe additions applied locally but must NOT push,
  // because pushing while a removal is unresolved would put back the very
  // bookmark the other side deleted.
  async function bringSidesTogether(items, silent = false, push = true) {
    const toAdd = items || [];

    try {
      /* [ZeroLabs] 2026-08-27 2:41 PM - edited: only the outermost caller speaks */
      // This runs inside reconcileWithSnippet, which reports the outcome itself.
      // Every layer toasting produced five notifications for one sync.
      if (!silent) {
        showToast(toAdd.length > 0
          ? `Adding ${toAdd.length} item(s) to this device...`
          : 'Syncing...');
      }

      /* [ZeroLabs] 2026-08-29 - edited: depth from segments, not a string split */
      // A title containing "/" inflated this count and put items in the wrong
      // creation order, so a child could be attempted before its parent existed.
      const depth = (item) => Array.isArray(item.segments)
        ? item.segments.length
        : (item.path || '').split('/').length;
      const ordered = [...toAdd].sort((a, b) => {
        const aIsFolder = a.type === 'folder' ? 0 : 1;
        const bIsFolder = b.type === 'folder' ? 0 : 1;
        if (aIsFolder !== bIsFolder) return aIsFolder - bIsFolder;
        return depth(a) - depth(b);
      });

      let created = 0;
      /* [ZeroLabs] 2026-08-27 2:44 AM - edited: record why each skip happened */
      // A count in a toast told the user something went wrong and nothing they
      // could act on. Each failure now carries the item and the reason.
      const skippedItems = [];

      for (const item of ordered) {
        /* [ZeroLabs] 2026-08-29 - fixed: never split a path back apart on "/" */
        // This used to do `(item.path || '').split('/')`. Titles contain slashes
        // constantly - "simulot/immich-go: ...", "owner/repo: ..." - so a
        // bookmark like that produced one segment too many and the last-but-one
        // was treated as its folder, inventing a folder named after half the
        // bookmark's own title. A fresh device pulling a whole library turned
        // 2911 bookmarks into 4476.
        //
        // The diff now carries `segments` as an array, so a title is one element
        // whatever is in it. The split is kept only as a fallback for a diff
        // built by an older version that has no segments.
        const segments = Array.isArray(item.segments)
          ? item.segments
          : (item.path || '').split('/');
        if (segments.length < 2) {
          skippedItems.push({ item, reason: 'The snippet lists it outside any folder, so there is nowhere to put it.' });
          continue;
        }

        try {
          if (item.type === 'folder') {
            const folderId = await resolveOrCreateFolderPath(segments);
            if (folderId) {
              created++;
            } else {
              skippedItems.push({ item, reason: `This device has no top-level folder called "${segments[0]}".` });
            }
            continue;
          }

          const parentId = await resolveOrCreateFolderPath(segments.slice(0, -1));
          if (!parentId) {
            skippedItems.push({ item, reason: `This device has no top-level folder called "${segments[0]}".` });
            continue;
          }

          await browser.bookmarks.create({
            parentId,
            title: item.title || item.url,
            url: item.url
          });
          created++;
        } catch (itemError) {
          // Firefox rejects some URLs outright (javascript:, malformed
          // schemes), and one bad entry must not take the rest of the merge.
          skippedItems.push({ item, reason: itemError.message || 'The browser refused to create it.' });
        }
      }

      await loadBookmarks();
      renderBookmarks();

      // Push the combined result. Silent: the inner push has no business
      // announcing itself when a caller above is already reporting the outcome.
      if (push) await syncToSnippet(true);

      /* [ZeroLabs] 2026-08-27 2:44 AM - edited: name what could not be placed */
      // The unplaceable dialog is shown even when silent, because it is a
      // problem the user has to act on rather than a progress message.
      if (skippedItems.length > 0) {
        showUnplaceableItemsDialog(skippedItems, created);
      } else if (!silent) {
        showToast(created > 0
          ? `Added ${created} item(s) and synced.`
          : 'Snippet updated.');
      }
    } catch (error) {
      console.error('[AddFromSnippet] Failed:', error);
      showToast(`Error: ${error.message}`, 'error');
    }
  }

  function calculateBookmarkDiff(localTree, remoteTree) {
    const diff = {
      added: [],
      removed: [],
      moved: [],
      modified: []
    };

    const localMap = new Map();
    const remoteMap = new Map();

    const rootFolderIds = ['toolbar_____', 'menu________', 'unfiled_____', 'mobile______', 'root________'];

    /* [ZeroLabs] 2026-08-27 12:44 AM - edited: use the shared normalizer */
    // Moved up so the folder path resolver can match a diff path against the
    // real local tree using exactly the same rules the diff used.
    const normalizeTitle = normalizeBookmarkTitle;

    /* [ZeroLabs] 2026-08-17 4:15 PM - added: match browser-rewritten internal URLs */
    // BMZ stores and transmits every URL verbatim, but chrome.bookmarks.create
    // canonicalizes browser-internal URLs before writing them, so a bookmark
    // pushed as about:debugging#/runtime/this-firefox comes back from Chrome as
    // chrome://debugging/#/runtime/this-firefox. Nothing in BMZ changed it and
    // neither did the user, so the diff must not report it as an edit.
    //
    // Comparison only. Nothing is rewritten, stored, or applied: each browser
    // keeps the URL its own engine insists on.
    const normalizeUrlForDiff = (url) => {
      if (!url) return url;
      const scheme = /^(about:|chrome:\/\/)/i.exec(url);
      if (!scheme) return url; // Ordinary URLs are compared exactly as before

      let rest = url.slice(scheme[0].length);
      // chrome:// parses the first segment as a host and gives it a trailing
      // slash that the opaque about: form does not have
      rest = rest.replace(/\/(?=#)/, '').replace(/\/$/, '');
      return `internal:${rest.toLowerCase()}`;
    };

    /* [ZeroLabs] 2026-08-29 - fixed: a "/" in a TITLE was read as a folder break */
    // `path` is titles joined with "/", and the code that recreates a bookmark
    // used to split it back apart on "/" to find its folder. Titles contain
    // slashes all the time - "simulot/immich-go: ...", "owner/repo: ..." - so a
    // bookmark like that split into an extra segment and the receiving device
    // invented a folder called "simulot" to put it in. On a fresh device pulling
    // a whole library that happened to hundreds of bookmarks at once: 2911 real
    // bookmarks arrived as 4476.
    //
    // `segments` carries the same information as an ARRAY, so a title is one
    // element no matter what characters are in it and nothing has to be parsed
    // back out of a string. `path` is kept purely for display in the dialogs.
    // This is how the website has always done it, which is why it never had
    // this bug.
    const mapItems = (node, map, parentPath = '', parentSegments = []) => {
      // Normalize title for consistent paths, then build path
      const normalizedTitle = normalizeTitle(node.title || '');
      const path = parentPath ? `${parentPath}/${normalizedTitle}` : normalizedTitle;
      const segments = parentSegments.concat(normalizedTitle);

      // Don't include root folders themselves in the comparison, only their contents
      if (!rootFolderIds.includes(node.id)) {
        // Use content-based key instead of ID (since Chrome and Firefox use different ID systems)
        const isBookmark = node.url || node.type === 'bookmark';
        const baseKey = isBookmark
          ? `bookmark:${normalizeUrlForDiff(node.url)}:${path}`
          : `folder:${path}`;

        /* [ZeroLabs] 2026-08-29 - added: a second identical item is a second item */
        // map.set on a key already present replaced the first one, so two copies
        // of the same bookmark in the same folder counted as one, and a device
        // rebuilding from the snippet created only one of them - permanently,
        // since the missing copy was never seen as missing on any later sync.
        //
        // A collision here means the two are identical in url, folder AND title,
        // so which of them takes the suffix cannot matter. Only that both survive
        // to be compared against the other side.
        let key = baseKey;
        let copy = 1;
        while (map.has(key)) key = `${baseKey}#${++copy}`;

        map.set(key, { node, path, segments, parentId: node.parentId || null, originalId: node.id });
      }

      if (node.children) {
        node.children.forEach(child => mapItems(child, map, path, segments));
      }
    };

    if (localTree && localTree.children) {
      localTree.children.forEach(root => mapItems(root, localMap));
    }

    if (remoteTree) {
      if (remoteTree.roots) {
        Object.values(remoteTree.roots).forEach(root => {
          if (root) mapItems(root, remoteMap);
        });
      } else if (remoteTree.children) {
        remoteTree.children.forEach(root => mapItems(root, remoteMap));
      }
    }

    remoteMap.forEach((remoteItem, key) => {
      if (!localMap.has(key)) {
        diff.added.push({
          id: remoteItem.originalId,
          title: remoteItem.node.title,
          path: remoteItem.path,
          // Carried so the receiving side never has to split `path` on "/"
          segments: remoteItem.segments,
          type: remoteItem.node.type || (remoteItem.node.url ? 'bookmark' : 'folder'),
          url: remoteItem.node.url
        });
      }
    });

    localMap.forEach((localItem, key) => {
      if (!remoteMap.has(key)) {
        diff.removed.push({
          id: localItem.originalId,
          title: localItem.node.title,
          path: localItem.path,
          segments: localItem.segments,
          type: localItem.node.url ? 'bookmark' : 'folder',
          url: localItem.node.url
        });
      }
    });

    localMap.forEach((localItem, key) => {
      const remoteItem = remoteMap.get(key);
      if (remoteItem) {
        const localNode = localItem.node;
        const remoteNode = remoteItem.node;

        // Check if the path changed (item moved to different folder)
        if (localItem.path !== remoteItem.path) {
          diff.moved.push({
            id: localItem.originalId,
            title: localNode.title,
            from: localItem.path,
            to: remoteItem.path,
            type: localNode.url ? 'bookmark' : 'folder'
          });
        }

        // Check if modified (different title or URL)
        // Normalize titles to ignore differences like empty string vs "Untitled"
        const normalizedLocalTitle = normalizeTitle(localNode.title || '');
        const normalizedRemoteTitle = normalizeTitle(remoteNode.title || '');
        const titleDiffers = normalizedLocalTitle !== normalizedRemoteTitle;
        /* [ZeroLabs] 2026-08-17 4:15 PM - edited: ignore browser-rewritten internal URLs */
        // Same normalization as the content key above. Without it the pair
        // matches as the same bookmark and then immediately reports as an edit.
        const urlDiffers = normalizeUrlForDiff(localNode.url) !== normalizeUrlForDiff(remoteNode.url);
        if (titleDiffers || urlDiffers) {
          diff.modified.push({
            id: localItem.originalId,
            oldTitle: localNode.title,
            newTitle: remoteNode.title,
            oldUrl: localNode.url,
            newUrl: remoteNode.url,
            path: remoteItem.path,
            type: localNode.url ? 'bookmark' : 'folder'
          });
        }
      }
    });

    return diff;
  }

  // Convert Snippet format to Firefox bookmarks structure
  function snippetFormatToFirefoxBookmarks(snippetData) {
    const convertNode = (node, parentId = null) => {
      if (node.type === 'bookmark' || node.url) {
        return {
          id: node.id,
          title: node.title,
          url: node.url,
          parentId: parentId,
          dateAdded: node.dateAdded || Date.now()
        };
      } else {
        const folder = {
          id: node.id,
          title: node.title || node.name || 'Unnamed Folder',
          parentId: parentId,
          dateAdded: node.dateAdded || Date.now(),
          children: []
        };
        if (node.children && node.children.length > 0) {
          folder.children = node.children.map(child => convertNode(child, node.id));
        }
        return folder;
      }
    };

    const firefoxRoots = [];
    if (snippetData.roots) {
      if (snippetData.roots.bookmark_bar) {
        firefoxRoots.push(convertNode({ ...snippetData.roots.bookmark_bar, id: 'toolbar_____', title: 'Bookmarks Toolbar', name: 'Bookmarks Toolbar' }, 'root'));
      }
      if (snippetData.roots.menu) {
        firefoxRoots.push(convertNode({ ...snippetData.roots.menu, id: 'menu________', title: 'Bookmarks Menu', name: 'Bookmarks Menu' }, 'root'));
      }
      if (snippetData.roots.other) {
        firefoxRoots.push(convertNode({ ...snippetData.roots.other, id: 'unfiled_____', title: 'Other Bookmarks', name: 'Other Bookmarks' }, 'root'));
      }
      if (snippetData.roots.mobile) {
        firefoxRoots.push(convertNode({ ...snippetData.roots.mobile, id: 'mobile______', title: 'Mobile Bookmarks', name: 'Mobile Bookmarks' }, 'root'));
      }
    }

    return [{
      id: 'root',
      children: firefoxRoots
    }];
  }

  // Calculate SHA-256 checksum for conflict detection
  async function calculateChecksum(data) {
    const { checksum, lastModified, version, editLock, ...dataToHash } = data;
    const str = JSON.stringify(dataToHash, Object.keys(dataToHash).sort());
    const buffer = new TextEncoder().encode(str);
    const hash = await crypto.subtle.digest('SHA-256', buffer);
    return Array.from(new Uint8Array(hash))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  // Convert Firefox bookmarks to Snippet format
  async function firefoxBookmarksToSnippetFormat(firefoxTree) {
    const convertNode = (node) => {
      if (node.url) {
        return {
          id: node.id,
          title: node.title,
          url: node.url,
          type: 'bookmark',
          dateAdded: node.dateAdded || Date.now()
        };
      } else {
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
      }
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

    // Ensure all folders exist
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
  
    snippetData.checksum = await calculateChecksum(snippetData);
    return snippetData;
  }

  // Show sync diff dialog
  async function showSyncDiffDialog(diff, remoteSnippetData) {
    const modal = document.createElement('div');
    modal.style.cssText = 'position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.7); z-index: 10000; display: flex; align-items: center; justify-content: center;';

    const dialog = document.createElement('div');
    dialog.style.cssText = 'background: var(--md-sys-color-surface, #1e1e1e); padding: 24px; border-radius: 12px; max-width: 700px; width: 90%; max-height: 80%; overflow-y: auto; color: var(--md-sys-color-on-surface, #e0e0e0);';
    dialog.className = 'bmz-dialog';

    const hasChanges = diff.added.length + diff.removed.length + diff.moved.length + diff.modified.length > 0;

    /* [ZeroLabs] 2026-08-27 12:44 AM - added: label items this device deleted */
    // A snippet-only bookmark is usually one another device added, but it can
    // also be one deleted here whose deletion has not reached the snippet yet.
    // Those deserve opposite answers and look identical in a list, so the
    // changelog is consulted. It only proves the positive case: deletions made
    // in Firefox's own Library never reach the changelog, so an absent entry
    // says nothing either way.
    const deletedHereByUrl = new Map();
    try {
      const changelogEntries = await getChangelogEntries();
      changelogEntries.forEach(entry => {
        if (entry.type === 'delete' && entry.url && !deletedHereByUrl.has(entry.url)) {
          deletedHereByUrl.set(entry.url, new Date(entry.timestamp).toLocaleDateString());
        }
      });
    } catch (error) {
      console.error('[SyncDiff] Could not read changelog for deletion hints:', error);
    }

    let content = '<h2 style="margin: 0 0 16px 0; font-size: 20px;">Snippet Sync Changes</h2>';

    if (!hasChanges) {
      content += '<p style="color: var(--md-sys-color-on-surface-variant, #aaa);">No changes detected. Your local bookmarks match the Snippet.</p>';
    } else {
      // Summary
      content += '<div style="margin-bottom: 20px; padding: 16px; background: var(--md-sys-color-surface-variant, #2a2a2a); border-radius: 8px;">';
      content += '<h3 style="margin: 0 0 12px 0; font-size: 16px;">Summary</h3>';
      /* [ZeroLabs] 2026-08-27 2:33 AM - edited: say where each side's items are, not "remove" */
      // Both of these end up on both sides after a merge. Calling one "to
      // remove" in red read as a threat to bookmarks that were never in danger.
      if (diff.added.length > 0) content += `<div style="margin-bottom: 4px; color: #4caf50;">${diff.added.length} item(s) only in the snippet</div>`;
      if (diff.removed.length > 0) content += `<div style="margin-bottom: 4px; color: #90caf9;">${diff.removed.length} item(s) only on this device</div>`;
      /* [ZeroLabs] 2026-08-27 3:02 AM - edited: drop the leading glyphs */
      if (diff.moved.length > 0) content += `<div style="margin-bottom: 4px; color: #ff9800;">${diff.moved.length} item(s) to move</div>`;
      if (diff.modified.length > 0) content += `<div style="color: #2196f3;">${diff.modified.length} item(s) to modify</div>`;
      content += '</div>';

      // Detailed changes
      if (diff.added.length > 0) {
        /* [ZeroLabs] 2026-08-27 12:44 AM - edited: tickable list with deletion history */
        // These are the only items that can be brought over without destroying
        // anything, so they get checkboxes and their own action.
        /* [ZeroLabs] 2026-08-27 2:26 AM - edited: plain list, no per-item selection */
        // The checkboxes were solving a problem nobody had. Bringing the two
        // sides together takes everything, so the list is here to be read.
        /* [ZeroLabs] 2026-08-27 3:02 AM - edited: short label, caption cut */
        content += '<div style="margin-bottom: 20px;"><h3 style="margin: 0 0 12px 0; font-size: 16px; color: #4caf50;">From Snippet</h3>';
        diff.added.forEach(item => {
          const deletedOn = item.url ? deletedHereByUrl.get(item.url) : null;
          content += `<div style="padding: 8px; margin-bottom: 4px; background: rgba(76, 175, 80, 0.1); border-left: 3px solid #4caf50; border-radius: 4px;">
            <div style="font-weight: 500;">${escapeHtml(item.title || 'Untitled')}</div>
            <div style="font-size: 12px; color: #aaa;">${escapeHtml(item.path || '')}</div>
            ${item.url ? `<div style="font-size: 11px; color: #888; margin-top: 4px;">${escapeHtml(item.url)}</div>` : ''}
            ${deletedOn ? `<div style="font-size: 11px; color: #ff9800; margin-top: 4px;">You deleted this here on ${escapeHtml(deletedOn)}. Bringing both sides together puts it back.</div>` : ''}
          </div>`;
        });
        content += '</div>';
      }

      if (diff.removed.length > 0) {
        /* [ZeroLabs] 2026-08-27 2:33 AM - edited: blue, not red, and named for what it is */
        // These are kept and sent up to the snippet. Red made it look like they
        // were about to be deleted, which is the opposite of what happens.
        content += '<div style="margin-bottom: 20px;"><h3 style="margin: 0 0 12px 0; font-size: 16px; color: #90caf9;">From Local</h3>';
        diff.removed.forEach(item => {
          content += `<div style="padding: 8px; margin-bottom: 4px; background: rgba(144, 202, 249, 0.1); border-left: 3px solid #90caf9; border-radius: 4px;">
            <div style="font-weight: 500;">${escapeHtml(item.title || 'Untitled')}</div>
            <div style="font-size: 12px; color: #aaa;">${escapeHtml(item.path || '')}</div>
            ${item.url ? `<div style="font-size: 11px; color: #888; margin-top: 4px;">${escapeHtml(item.url)}</div>` : ''}
          </div>`;
        });
        content += '</div>';
      }

      if (diff.moved.length > 0) {
        content += '<div style="margin-bottom: 20px;"><h3 style="margin: 0 0 12px 0; font-size: 16px; color: #ff9800;">Moved</h3>';
        diff.moved.forEach(item => {
          content += `<div style="padding: 8px; margin-bottom: 4px; background: rgba(255, 152, 0, 0.1); border-left: 3px solid #ff9800; border-radius: 4px;">
            <div style="font-weight: 500;">${escapeHtml(item.title || 'Untitled')}</div>
            <div style="font-size: 12px; color: #aaa;">From: ${escapeHtml(item.from || '')}</div>
            <div style="font-size: 12px; color: #aaa;">To: ${escapeHtml(item.to || '')}</div>
          </div>`;
        });
        content += '</div>';
      }

      if (diff.modified.length > 0) {
        content += '<div style="margin-bottom: 20px;"><h3 style="margin: 0 0 12px 0; font-size: 16px; color: #2196f3;">Modified</h3>';
        diff.modified.forEach(item => {
          content += `<div style="padding: 8px; margin-bottom: 4px; background: rgba(33, 150, 243, 0.1); border-left: 3px solid #2196f3; border-radius: 4px;">
            <div style="font-weight: 500;">${escapeHtml(item.oldTitle || 'Untitled')} → ${escapeHtml(item.newTitle || 'Untitled')}</div>
            <div style="font-size: 12px; color: #aaa;">${escapeHtml(item.path || '')}</div>
            ${item.oldUrl !== item.newUrl ? `<div style="font-size: 11px; color: #888; margin-top: 4px;">URL: ${escapeHtml(item.oldUrl || '')} → ${escapeHtml(item.newUrl || '')}</div>` : ''}
          </div>`;
        });
        content += '</div>';
      }
    }

    content += `
      <div style="display: flex; flex-direction: column; gap: 12px; margin-top: 20px;">
        ${hasChanges ? `
          <!-- [ZeroLabs] 2026-08-27 2:26 AM - edited: one safe action, then the two overwrites -->
          <!-- [ZeroLabs] 2026-08-27 3:02 AM - edited: captions cut, buttons match the section labels -->
          <button id="bringSidesTogether" style="width: 100%; padding: 12px; border-radius: 8px; border: none; background: #4caf50; color: #05230a; cursor: pointer; font-size: 14px; font-weight: 500;">
            Merge
          </button>
          <div style="display: flex; gap: 12px;">
            <button id="pushLocalToRemote" style="flex: 1; padding: 12px; border-radius: 8px; border: none; background: var(--md-sys-color-primary, #90caf9); color: var(--md-sys-color-on-primary, #000); cursor: pointer; font-size: 14px;">
              Overwrite Snippet with Local
            </button>
            <button id="applyRemoteChanges" style="flex: 1; padding: 12px; border-radius: 8px; border: none; background: var(--md-sys-color-error, #f44336); color: var(--md-sys-color-on-error, #fff); cursor: pointer; font-size: 14px;">
              Overwrite Local with Snippet
            </button>
          </div>
        ` : ''}
        <button id="closeDiffDialog" style="width: 100%; padding: 12px; border-radius: 8px; border: none; background: var(--md-sys-color-surface-variant, #2a2a2a); color: var(--md-sys-color-on-surface-variant, #aaa); cursor: pointer; font-size: 14px;">
          Cancel
        </button>
      </div>
    `;

    dialog.innerHTML = content;
    modal.appendChild(dialog);
    document.body.appendChild(modal);

    /* [ZeroLabs] 2026-08-27 2:26 AM - edited: one button, takes everything */
    const bringTogetherBtn = dialog.querySelector('#bringSidesTogether');
    if (bringTogetherBtn) {
      bringTogetherBtn.addEventListener('click', async () => {
        modal.remove();
        /* [ZeroLabs] 2026-08-27 2:41 PM - added: this dialog has no ring to show progress */
      showToast('Merging...');
      await bringSidesTogether(diff.added);
      });
    }

    /* [ZeroLabs] 2026-06-20 11:01 AM - removed: per-sync merge button handler */
    const pushBtn = dialog.querySelector('#pushLocalToRemote');
    if (pushBtn) {
      pushBtn.addEventListener('click', async () => {
        modal.remove();
        /* [ZeroLabs] 2026-08-27 2:41 PM - edited: one result, not the push's pair */
        // The user is looking at the diff and choosing to overwrite, so the
        // outcome is worth one line and the intermediate steps are not.
        await syncToSnippet(true);
        showToast('Snippet overwritten with local bookmarks.');
      });
    }

    const applyBtn = dialog.querySelector('#applyRemoteChanges');
    if (applyBtn) {
      applyBtn.addEventListener('click', async () => {
        modal.remove();
        await applyRemoteChangesToFirefox(remoteSnippetData);
      });
    }

    dialog.querySelector('#closeDiffDialog').addEventListener('click', () => modal.remove());
    modal.addEventListener('click', (e) => {
      if (e.target === modal) modal.remove();
    });
  }

  // Sync from Snippet to Firefox bookmarks
  async function syncFromSnippet(silent = false) {
    if (!snippetId) {
      showToast('No Snippet connected', 'error');
      return;
    }
    if (snippetIsSyncing) {
      if (!silent) showToast('Sync already in progress, please wait.', 'error');
      return;
    }

    /* [ZeroLabs] 2026-08-27 3:14 AM - added: stand down while a held push is pending */
    // A local deletion reaches the diff dialog as "only in the snippet", so both
    // surfaces describe the same divergence from opposite ends and stacked on
    // open, one offering to put the bookmarks back and the other asking to
    // remove them. The held-push dialog knows a push was attempted and why, so
    // it gets the divergence to itself. Checked before the toast, since
    // announcing a check that is about to be abandoned just covers the dialog
    // being read.
    const heldState = await safeStorage.get('snippet_push_held');
    if (heldState.snippet_push_held) {
      console.log('[SyncFromSnippet] Skipped: a held push is waiting for consent');
      return;
    }

    snippetIsSyncing = true;
    try {
      if (!silent) showToast('Checking for Snippet updates...');

      /* [ZeroLabs] 2026-08-17 4:15 PM - added: converge pins on every pull */
      // Ahead of the no-changes early return below, because pins can differ even
      // when the bookmarks themselves are identical.
      await loadQuickAccessForSnippet(snippetId);

      const remoteData = await readBookmarksFromSnippet(snippetId);
      const localTree = await browser.bookmarks.getTree();

      const remoteTreeAsFirefoxFormat = snippetFormatToFirefoxBookmarks(remoteData);

      const diff = calculateBookmarkDiff(localTree[0], remoteTreeAsFirefoxFormat[0]);
      const hasChanges = diff.added.length + diff.removed.length + diff.moved.length + diff.modified.length > 0;

      if (!hasChanges) {
        /* [ZeroLabs] 2026-08-26 11:38 PM - added: clear reconcile flag once in sync */
        // Whatever the snippet had that this device lacked is now here, so the
        // badge has nothing left to point at. Record the version too, otherwise
        // the next push would see a mismatch and block on an identical tree.
        snippetLocalVersion = Number(remoteData?.version) || snippetLocalVersion;
        await safeStorage.set({ snippet_local_version: snippetLocalVersion });
        await setSnippetNeedsReconcile(false);
        if (!silent) showToast('No changes detected. Bookmarks are in sync.');
        return;
      }

      /* [ZeroLabs] 2026-08-27 12:04 PM - edited: automatic pulls stay quiet */
      // The background now reconciles on its own, so a difference it is about to
      // resolve must not nudge either. The old toast told the user to go and
      // review something that was already being handled. Deferrals still
      // surface, through the held dialog.
      if (silent) {
        console.log('[SyncFromSnippet] Differences found; leaving them to the background');
        return;
      }

      await showSyncDiffDialog(diff, remoteData);
    } catch (error) {
      console.error('Sync from Snippet failed:', error);
      showToast(`Error: ${error.message}`, 'error');
    } finally {
      snippetIsSyncing = false;
    }
  }

  /* [ZeroLabs] 2026-08-26 11:38 PM - added: reconcile flag, toolbar badge, sync button state (see also: Bookmark-Manager-Zero-Chrome/sidepanel.js) */
  // Raised when an automatic push is skipped because the snippet moved on
  // without this device. The badge rides the same toolbar button that toggles
  // the sidebar, so the signal and the fix are one click apart, and it is the
  // only signal there is while the sidebar is closed. The sync button carries
  // the same state for when it is open. Both are best effort: an unpinned
  // extension hides its badge inside the browser's extensions panel.
  async function setSnippetNeedsReconcile(needs) {
    try {
      await safeStorage.set({ snippet_needs_reconcile: !!needs });
    } catch (error) {
      console.error('[Snippet] Failed to store reconcile flag:', error);
    }

    try {
      await browser.action.setBadgeText({ text: needs ? '!' : '' });
      if (needs) {
        await browser.action.setBadgeBackgroundColor({ color: '#f59e0b' });
      }
    } catch (error) {
      // Action API unavailable here; the in-sidebar state below still applies
    }

    const manualSyncBtn = document.getElementById('manualSyncBtn');
    if (manualSyncBtn) manualSyncBtn.classList.toggle('sync-attention', !!needs);

    /* [ZeroLabs] 2026-08-27 - added: the card follows the same flag */
    setSyncNoticeVisible(needs);
  }

  // Sync from Firefox bookmarks to Snippet
  /* [ZeroLabs] 2026-08-27 1:05 PM - removed: the version staleness guard (replaced by: reconcileWithSnippet, background.js) */
  // This is now purely "write the local tree to the snippet". Deciding whether
  // that is safe belongs to the reconcile, which classifies each difference from
  // what this device saw you create and delete rather than from a version
  // number, and every caller reaches here having already made that decision: the
  // reconcile after it clears, the held dialog after you consent, the overwrite
  // button after you confirm. The old guard compared versions and had no callers
  // left that could trip it.
  //
  // The remote is still read, for its version: the number written is remote + 1,
  // which is what keeps the counter monotonic for the other clients that do
  // still rely on it.
  /* [ZeroLabs] 2026-08-27 - added: the panel must clear these too (see also: background.js) */
  // This existed ONLY in the worker, so a push made from the panel left the
  // created/deleted records standing. A bookmark deleted here stayed in
  // snippet_local_deleted for ever, and the moment that URL appeared in the
  // snippet again it read as "you deleted this, syncing would remove it" - a
  // deferral over two bookmarks that were nothing but additions.
  async function clearLocalBookmarkEvents() {
    await safeStorage.set({
      snippet_local_created: [],
      snippet_local_deleted: [],
      snippet_local_edited: []
    });
  }

  async function syncToSnippet(silent = false) {
    if (!snippetId) {
      showToast('No Snippet connected', 'error');
      return;
    }
    if (snippetIsSyncing) {
      if (!silent) showToast('Sync already in progress, please wait.', 'error');
      return;
    }
    snippetIsSyncing = true;

    try {
      if (!silent) showToast('Syncing to Snippet...');

      const firefoxTree = await browser.bookmarks.getTree();
      const snippetData = await firefoxBookmarksToSnippetFormat(firefoxTree);

      const remoteData = await readBookmarksFromSnippet(snippetId);
      const remoteVersion = Number(remoteData?.version) || 0;

      await updateBookmarksInSnippet(snippetData, remoteVersion + 1);

      // Cache exactly the number that was written. The old code stored the
      // converter's hardcoded 1, which never matched what it had just pushed.
      snippetLocalVersion = remoteVersion + 1;
      snippetLastSyncTime = Date.now();
      await safeStorage.set({
        snippet_local_version: snippetLocalVersion,
        snippet_last_sync: snippetLastSyncTime
      });
      await setSnippetNeedsReconcile(false);
      /* [ZeroLabs] 2026-08-27 - added: both sides agree, the records are spent */
      await clearLocalBookmarkEvents();

      if (!silent) showToast('Synced to Snippet successfully!');
    } catch (error) {
      console.error('Sync to Snippet failed:', error);
      showToast(`Error: ${error.message}`, 'error');
    } finally {
      snippetIsSyncing = false;
    }
  }

  // Start auto-syncing Snippet every 10 minutes
  function startSnippetAutoSync() {
    if (snippetSyncInterval) {
      clearInterval(snippetSyncInterval);
    }

    const syncInterval = 10 * 60 * 1000;

    /* [ZeroLabs] 2026-08-27 1:06 PM - added: the toggle governs this too */
    // The setting says "background auto-sync", and the sidebar's own timer is
    // part of that from the user's point of view. Switching it off used to stop
    // the background while this kept polling whenever the sidebar was open,
    // which is not what the toggle claims to do.
    const autoSyncAllowed = async () => {
      const stored = await browser.storage.local.get('bmz_auto_sync_enabled');
      return stored.bmz_auto_sync_enabled !== false;
    };

    snippetSyncInterval = setInterval(async () => {
      if (!snippetId || !snippetToken || !navigator.onLine) {
        return;
      }
      // Checked every tick rather than once, so flipping the toggle takes effect
      // without needing the sidebar reopened.
      if (!(await autoSyncAllowed())) {
        return;
      }

      try {
        // Check and auto-rotate token if expiring within 30 days (both modes)
        const rotatedToken = await supabase.checkAndRotateIfNeeded(snippetToken);
        // Only update snippetToken after rotation check fully resolves to avoid
        // a race where syncFromSnippet uses the old (now dead) token mid-rotation
        snippetToken = rotatedToken;
        await syncFromSnippet(true);
      } catch (error) {
        console.error('[Snippet AutoSync] Auto-sync failed:', error);
      }
    }, syncInterval);
  }

  // Stop auto-syncing Snippet
  function stopSnippetAutoSync() {
    if (snippetSyncInterval) {
      clearInterval(snippetSyncInterval);
      snippetSyncInterval = null;
    }
  }

  /* [ZeroLabs] 2026-08-27 1:05 PM - removed: markSnippetChanges (replaced by: background.js reconcile, pushQuickAccessMeta) */
  // The sidebar's debounced tree push. Bookmark changes moved to the background
  // so they sync with the sidebar closed, and pins now write bmz-meta.json
  // directly, which left this with no callers but its own retry.

  // Update GitLab button icon
  function updateGitLabButtonIcon() {
    const gitlabBtnIcon = document.getElementById('gitlabBtnIcon');
    const gitlabBtn = document.getElementById('gitlabBtn');
    const manualSyncBtn = document.getElementById('manualSyncBtn');
    if (!gitlabBtnIcon || !gitlabBtn) return;

    const isLoggedIn = !!snippetToken;

    if (isLoggedIn) {
      // Show logout icon and update tooltip for logged in state
      gitlabBtnIcon.innerHTML = '<path d="M17,7l-1.41,1.41L18.17,11H8v2h10.17l-2.58,2.59L17,17l5-5L17,7z M4,5h8V3H4C2.9,3 2,3.9 2,5v14c0,1.1 0.9,2 2,2h8v-2H4V5z"/>';
      gitlabBtn.title = 'Logout from GitLab account';
      gitlabBtn.setAttribute('aria-label', 'Logout from GitLab account');
      // Show manual sync button when logged in
      if (manualSyncBtn) manualSyncBtn.style.display = '';
    } else {
      // Show GitLab logo with "LOGIN" text overlay and update tooltip for not logged in state
      gitlabBtnIcon.innerHTML = '<path d="M22.65 14.39L12 22.13 1.35 14.39a.84.84 0 01-.3-.94l1.22-3.78 2.44-7.51A.42.42 0 014.82 2a.43.43 0 01.58 0 .42.42 0 01.11.18l2.44 7.49h8.1l2.44-7.51A.42.42 0 0118.6 2a.43.43 0 01.58 0 .42.42 0 01.11.18l2.44 7.51L23 13.45a.84.84 0 01-.35.94z"/><text x="12" y="15" font-size="5" font-weight="900" fill="#000000" text-anchor="middle" font-family="Arial Black, Arial, sans-serif" letter-spacing="0.2">LOGIN</text>';
      gitlabBtn.title = 'Connect your GitLab account';
      gitlabBtn.setAttribute('aria-label', 'GitLab account settings');
      // Hide manual sync button when not logged in
      if (manualSyncBtn) manualSyncBtn.style.display = 'none';
    }
  }

  // Show GitLab disconnect dialog
  async function showGitLabDisconnectDialog() {
    const isSupabase = (await getTokenMode()) === 'supabase';

    const modal = document.createElement('div');
    modal.style.cssText = 'position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.7); z-index: 10000; display: flex; align-items: center; justify-content: center;';

    const dialog = document.createElement('div');
    dialog.style.cssText = 'background: var(--md-sys-color-surface, #1e1e1e); padding: 24px; border-radius: 12px; max-width: 400px; width: 90%; color: var(--md-sys-color-on-surface, #e0e0e0);';
    dialog.className = 'bmz-dialog';

    dialog.innerHTML = `
      <h2 style="margin: 0 0 16px 0; font-size: 18px; display: flex; align-items: center; gap: 8px;">
        <svg width="20" height="20" fill="currentColor" viewBox="0 0 24 24">
          <path d="M22.65 14.39L12 22.13 1.35 14.39a.84.84 0 01-.3-.94l1.22-3.78 2.44-7.51A.42.42 0 014.82 2a.43.43 0 01.58 0 .42.42 0 01.11.18l2.44 7.49h8.1l2.44-7.51A.42.42 0 0118.6 2a.43.43 0 01.58 0 .42.42 0 01.11.18l2.44 7.51L23 13.45a.84.84 0 01-.35.94z"/>
        </svg>
        GitLab Account
      </h2>
      <p style="margin: 0 0 20px 0; font-size: 14px; color: var(--md-sys-color-on-surface-variant, #aaa);">
        ${isSupabase
          ? 'Disconnect this device only, or remove your token from all devices?'
          : 'Disconnect and remove your GitLab token from this device?'}
      </p>
      <div style="display: flex; flex-direction: column; gap: 8px;">
        ${isSupabase ? `
        <button id="disconnectLocal" style="padding: 12px; border-radius: 8px; border: none; background: var(--md-sys-color-surface-variant, #2a2a2a); color: var(--md-sys-color-on-surface, #e0e0e0); cursor: pointer; font-size: 14px;">
          This device only
        </button>
        <button id="disconnectAll" style="padding: 12px; border-radius: 8px; border: none; background: var(--md-sys-color-error, #f44336); color: var(--md-sys-color-on-error, #fff); cursor: pointer; font-size: 14px;">
          All devices
        </button>
        ` : `
        <button id="disconnectLocal" style="padding: 12px; border-radius: 8px; border: none; background: var(--md-sys-color-error, #f44336); color: var(--md-sys-color-on-error, #fff); cursor: pointer; font-size: 14px;">
          Disconnect
        </button>
        `}
        <button id="cancelGitLabDisconnect" style="padding: 12px; border-radius: 8px; border: none; background: var(--md-sys-color-surface-variant, #2a2a2a); color: var(--md-sys-color-on-surface-variant, #aaa); cursor: pointer; font-size: 14px;">
          Cancel
        </button>
      </div>
    `;

    modal.appendChild(dialog);
    document.body.appendChild(modal);

    const doDisconnect = async (removeFromSupabase) => {
      modal.remove();
      stopSnippetAutoSync();
      if (removeFromSupabase) await supabase.deleteGitLabToken();
      await clearSnippetToken();
      await browser.storage.local.remove(['bmz_snippet_id', 'snippet_local_version']);
      await supabase.clearSession();
      await setTokenMode('local');
      snippetId = null;
      snippetLocalVersion = 0;
      updateGitLabButtonIcon();
      showToast(removeFromSupabase ? 'Disconnected from all devices' : 'Disconnected this device');
    };

    dialog.querySelector('#cancelGitLabDisconnect').addEventListener('click', () => modal.remove());
    dialog.querySelector('#disconnectLocal').addEventListener('click', () => doDisconnect(false));
    if (isSupabase) dialog.querySelector('#disconnectAll').addEventListener('click', () => doDisconnect(true));

    modal.addEventListener('click', (e) => {
      if (e.target === modal) modal.remove();
    });
  }

  // Get/set current token storage mode
  async function getTokenMode() {
    const r = await safeStorage.get('bmz_token_mode');
    return r.bmz_token_mode || 'local';
  }
  async function setTokenMode(mode) {
    await safeStorage.set({ bmz_token_mode: mode });
  }

  // Encrypt token for Supabase using AES-GCM keyed on the user's Supabase UID
  async function encryptForSupabase(token, userId) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(userId.padEnd(32, '0').slice(0, 32)), 'AES-GCM', false, ['encrypt']);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, keyMaterial, enc.encode(token));
    const combined = new Uint8Array(iv.length + encrypted.byteLength);
    combined.set(iv); combined.set(new Uint8Array(encrypted), iv.length);
    // Use Array.from instead of spread to avoid call-stack limit on large inputs
    return btoa(Array.from(combined, b => String.fromCharCode(b)).join(''));
  }

  async function decryptFromSupabase(encryptedBase64, userId) {
    try {
      const enc = new TextEncoder();
      const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(userId.padEnd(32, '0').slice(0, 32)), 'AES-GCM', false, ['decrypt']);
      const combined = Uint8Array.from(atob(encryptedBase64), c => c.charCodeAt(0));
      const iv = combined.slice(0, 12);
      const data = combined.slice(12);
      const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, keyMaterial, data);
      return new TextDecoder().decode(decrypted);
    } catch (err) {
      // Decryption fails if the user's Supabase account was recreated (new UID = different key).
      // Surface this explicitly so the user knows to re-enter their token rather than
      // silently falling back to a potentially stale local copy.
      showToast('Could not decrypt token from Supabase. Your account key may have changed — please re-enter your GitLab token in sync settings.', 'error');
      throw err;
    }
  }

  // Prompt user before rotating — returns 'rotate' or 'snooze'
  // Backdrop click / ESC both count as snooze so the prompt doesn't re-appear every 10 minutes
  function showPreRotationPrompt(daysLeft) {
    return new Promise((resolve) => {
      const modal = document.createElement('div');
      modal.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.7);z-index:10002;display:flex;align-items:center;justify-content:center;';
      modal.innerHTML = `
        <div style="background:var(--md-sys-color-surface,#1e1e1e);padding:24px;border-radius:12px;max-width:420px;width:90%;color:var(--md-sys-color-on-surface,#e0e0e0);">
          <h2 style="margin:0 0 12px 0;font-size:18px;">🔑 GitLab Token Expiring Soon</h2>
          <p style="font-size:13px;color:var(--md-sys-color-on-surface-variant,#aaa);margin:0 0 16px 0;">Your GitLab Personal Access Token expires in <strong style="color:var(--md-sys-color-on-surface,#e0e0e0);">${Math.floor(daysLeft)} day${Math.floor(daysLeft) !== 1 ? 's' : ''}</strong>. BMZ can renew it automatically right now.</p>
          <div style="padding:10px 12px;background:rgba(245,158,11,0.12);border:1px solid rgba(245,158,11,0.35);border-radius:8px;font-size:12px;color:var(--md-sys-color-on-surface-variant,#aaa);margin-bottom:16px;">
            ⚠️ Renewing creates a <strong>new token</strong> and immediately invalidates the old one. If you use BMZ on other browsers, the website, or Android, you will need to enter the new token on each of those clients to maintain sync.
          </div>
          <div style="display:flex;flex-direction:column;gap:8px;">
            <button id="rotateNowBtn" style="padding:12px;border-radius:8px;border:none;background:var(--md-sys-color-primary,#818cf8);color:var(--md-sys-color-on-primary,#fff);font-size:14px;cursor:pointer;font-weight:500;">Renew Token Now</button>
            <button id="snoozeDayBtn" style="padding:12px;border-radius:8px;border:none;background:var(--md-sys-color-surface-variant,#2a2a2a);color:var(--md-sys-color-on-surface-variant,#aaa);font-size:14px;cursor:pointer;">Remind me tomorrow</button>
          </div>
        </div>
      `;
      document.body.appendChild(modal);

      const dismiss = (result) => {
        modal.remove();
        rotationPromptActive = false;
        resolve(result);
      };

      modal.querySelector('#rotateNowBtn').addEventListener('click', () => dismiss('rotate'));
      modal.querySelector('#snoozeDayBtn').addEventListener('click', () => dismiss('snooze'));
      // Backdrop click or ESC = snooze so prompt doesn't reappear every 10 min
      modal.addEventListener('click', (e) => { if (e.target === modal) dismiss('snooze'); });
      const onKey = (e) => { if (e.key === 'Escape') { document.removeEventListener('keydown', onKey); dismiss('snooze'); } };
      document.addEventListener('keydown', onKey);
    });
  }

  // Show new token after rotation
  function showPostRotationModal(newToken, mode = 'local') {
    const isSupabase = mode === 'supabase';
    const actionBox = isSupabase
      ? `<div style="padding:12px;background:rgba(34,197,94,0.1);border:1px solid rgba(34,197,94,0.3);border-radius:8px;font-size:12px;margin-bottom:12px;">
           ✅ <strong>Your other BMZ clients will pick up the new token automatically</strong> on their next sync — no action needed on other devices.
         </div>`
      : `<div style="padding:12px;background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.35);border-radius:8px;font-size:12px;margin-bottom:12px;">
           🚨 <strong>Your old token is now invalid.</strong> If you use BMZ on other browsers, the website, or Android, open each one, go to the GitLab sync settings, and paste this new token. Until you do, sync will be broken on those clients.
         </div>`;
    const hintBox = isSupabase
      ? `<div style="padding:10px 12px;background:rgba(99,102,241,0.1);border:1px solid rgba(99,102,241,0.3);border-radius:8px;font-size:12px;color:var(--md-sys-color-on-surface-variant,#aaa);margin-bottom:16px;">
           💡 You can always retrieve your current token from <strong>Settings → Reveal GitLab Token</strong> in BMZ if you ever need it.
         </div>`
      : `<div style="padding:10px 12px;background:rgba(99,102,241,0.1);border:1px solid rgba(99,102,241,0.3);border-radius:8px;font-size:12px;color:var(--md-sys-color-on-surface-variant,#aaa);margin-bottom:16px;">
           💡 You can always retrieve your current token from <strong>Settings → Reveal GitLab Token</strong> in BMZ. Want renewals to sync automatically across all devices? Switch to <strong>Supabase storage</strong> in the GitLab sync dialog.
         </div>`;

    const modal = document.createElement('div');
    modal.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.7);z-index:10002;display:flex;align-items:center;justify-content:center;';
    modal.innerHTML = `
      <div style="background:var(--md-sys-color-surface,#1e1e1e);padding:24px;border-radius:12px;max-width:480px;width:90%;color:var(--md-sys-color-on-surface,#e0e0e0);">
        <h2 style="margin:0 0 12px 0;font-size:18px;">✅ Token Renewed Successfully</h2>
        <p style="font-size:13px;color:var(--md-sys-color-on-surface-variant,#aaa);margin:0 0 8px 0;">Your new GitLab Personal Access Token is shown below. <strong style="color:var(--md-sys-color-error,#ef4444);">Copy it now</strong> — GitLab will never show this token again once you leave this screen.</p>
        <div style="display:flex;gap:8px;align-items:center;margin-bottom:12px;">
          <input type="text" readonly id="rotatedTokenDisplay" style="flex:1;padding:10px;border-radius:8px;border:1px solid var(--md-sys-color-outline,#444);background:var(--md-sys-color-surface-variant,#2a2a2a);color:var(--md-sys-color-on-surface,#e0e0e0);font-size:12px;font-family:monospace;box-sizing:border-box;">
          <button id="copyRotatedToken" style="padding:10px 14px;border-radius:8px;border:none;background:var(--md-sys-color-primary,#818cf8);color:var(--md-sys-color-on-primary,#fff);font-size:13px;cursor:pointer;white-space:nowrap;">Copy</button>
        </div>
        ${actionBox}
        ${hintBox}
        <button id="closeRotationModal" style="width:100%;padding:12px;border-radius:8px;border:none;background:var(--md-sys-color-primary,#818cf8);color:var(--md-sys-color-on-primary,#fff);font-size:14px;cursor:pointer;font-weight:500;">I've copied my token</button>
      </div>
    `;
    document.body.appendChild(modal);
    // Set token value safely via DOM (not innerHTML interpolation)
    modal.querySelector('#rotatedTokenDisplay').value = newToken;
    modal.querySelector('#copyRotatedToken').addEventListener('click', () => {
      navigator.clipboard.writeText(newToken).then(() => {
        const btn = modal.querySelector('#copyRotatedToken');
        btn.textContent = 'Copied!';
        setTimeout(() => { btn.textContent = 'Copy'; }, 2000);
      });
    });
    modal.querySelector('#rotatedTokenDisplay').addEventListener('click', (e) => e.target.select());
    modal.querySelector('#closeRotationModal').addEventListener('click', () => modal.remove());
  }

  // Show current saved token (works in both local and Supabase mode)
  async function showRevealTokenModal() {
    const token = snippetToken || await loadSnippetToken();
    if (!token) {
      showToast('No GitLab token saved on this device.', 'error');
      return;
    }
    const modal = document.createElement('div');
    modal.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.7);z-index:10002;display:flex;align-items:center;justify-content:center;';
    modal.innerHTML = `
      <div style="background:var(--md-sys-color-surface,#1e1e1e);padding:24px;border-radius:12px;max-width:440px;width:90%;color:var(--md-sys-color-on-surface,#e0e0e0);">
        <h2 style="margin:0 0 12px 0;font-size:18px;">🔑 Your GitLab Token</h2>
        <p style="font-size:13px;color:var(--md-sys-color-on-surface-variant,#aaa);margin:0 0 12px 0;">This is the Personal Access Token currently saved in BMZ on this device. Keep it private — it grants access to your GitLab bookmark snippet.</p>
        <div style="display:flex;gap:8px;align-items:center;margin-bottom:16px;">
          <input type="password" readonly id="revealTokenInput" style="flex:1;padding:10px;border-radius:8px;border:1px solid var(--md-sys-color-outline,#444);background:var(--md-sys-color-surface-variant,#2a2a2a);color:var(--md-sys-color-on-surface,#e0e0e0);font-size:12px;font-family:monospace;box-sizing:border-box;">
          <button id="toggleReveal" style="padding:10px 12px;border-radius:8px;border:1px solid var(--md-sys-color-outline,#444);background:var(--md-sys-color-surface-variant,#2a2a2a);color:var(--md-sys-color-on-surface,#e0e0e0);font-size:12px;cursor:pointer;">Show</button>
          <button id="copyRevealToken" style="padding:10px 14px;border-radius:8px;border:none;background:var(--md-sys-color-primary,#818cf8);color:var(--md-sys-color-on-primary,#fff);font-size:13px;cursor:pointer;">Copy</button>
        </div>
        <button id="closeRevealModal" style="width:100%;padding:12px;border-radius:8px;border:none;background:var(--md-sys-color-surface-variant,#2a2a2a);color:var(--md-sys-color-on-surface-variant,#aaa);font-size:14px;cursor:pointer;">Close</button>
      </div>
    `;
    document.body.appendChild(modal);
    const input = modal.querySelector('#revealTokenInput');
    // Set token value via DOM property, not innerHTML, to avoid injection risk
    input.value = token;
    modal.querySelector('#toggleReveal').addEventListener('click', (e) => {
      const isHidden = input.type === 'password';
      input.type = isHidden ? 'text' : 'password';
      e.target.textContent = isHidden ? 'Hide' : 'Show';
    });
    modal.querySelector('#copyRevealToken').addEventListener('click', () => {
      navigator.clipboard.writeText(token).then(() => {
        const btn = modal.querySelector('#copyRevealToken');
        btn.textContent = 'Copied!';
        setTimeout(() => { btn.textContent = 'Copy'; }, 2000);
      });
    });
    modal.querySelector('#closeRevealModal').addEventListener('click', () => modal.remove());
    modal.addEventListener('click', (e) => { if (e.target === modal) modal.remove(); });
  }

  /* [ZeroLabs] 2026-08-17 4:15 PM - added: bind quick access sync bridge */
  // Pinning marks the snippet dirty exactly like a bookmark edit does, so pins
  // ride the existing 30s debounce instead of firing their own request.
  /* [ZeroLabs] 2026-08-27 1:05 PM - added: pins write their own file, nothing else (see also: Bookmark-Manager-Zero-Chrome/sidepanel.js) */
  // Pinning changes bmz-meta.json and nothing else, so it has no business
  // pushing bookmarks.json alongside it. Sending the tree made a pin subject to
  // the whole sync question: it went through syncToSnippet, hit last night's
  // version guard, and a stale version silently dropped the pin. GitLab only
  // rewrites the files named in the request, so naming one file leaves the
  // bookmarks untouched and there is nothing left to guard against.
  async function pushQuickAccessMeta() {
    if (!snippetId || !snippetToken) return;

    // Never write pins for a snippet whose meta has not been read, or a snippet
    // switch followed by a fast push would overwrite the new snippet's pins with
    // the previous one's cache. Same rule updateBookmarksInSnippet follows.
    if (!quickAccessMetaLoaded || quickAccessSnippetTag !== snippetId) {
      await loadQuickAccessForSnippet(snippetId);
    }
    if (!quickAccessMetaLoaded || quickAccessSnippetTag !== snippetId) {
      console.warn('[QuickAccess] Meta not loaded for this snippet; pin push skipped');
      return;
    }

    const response = await fetchGitLab(`https://gitlab.com/api/v4/snippets/${snippetId}`, {
      method: 'PUT',
      headers: getSnippetHeaders(),
      body: JSON.stringify({
        files: [{
          action: metaFileExists ? 'update' : 'create',
          file_path: META_FILE,
          content: buildQuickAccessMetaContent()
        }]
      })
    });

    if (!response.ok) {
      throw new Error(`Failed to update pins: ${response.status}`);
    }

    metaFileExists = true;
    console.log('[QuickAccess] Pins pushed');
  }

  let quickAccessPushTimer = null;

  markQuickAccessChanged = () => {
    if (!snippetId || !snippetToken) return;

    // Short debounce so a run of pin changes collapses into one small write.
    // Nothing here can destroy anything, so it does not need the 30s the tree
    // push uses to batch edits.
    clearTimeout(quickAccessPushTimer);
    quickAccessPushTimer = setTimeout(() => {
      pushQuickAccessMeta().catch(error => {
        console.error('[QuickAccess] Pin push failed:', error);
      });
    }, 5000);
  };

  // Open GitLab Snippet sync dialog
  openSnippetSyncDialog = async function() {
    if (!supabase.isSignedIn) await supabase.loadSession();
    await loadSnippetToken();

    const modal = document.createElement('div');
    modal.id = 'snippetSyncModal';
    modal.className = 'modal';
    modal.style.cssText = 'position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.7); z-index: 10000; display: flex; align-items: center; justify-content: center;';

    const dialog = document.createElement('div');
    dialog.style.cssText = 'background: var(--md-sys-color-surface, #1e1e1e); padding: 24px; border-radius: 12px; max-width: 500px; width: 90%; color: var(--md-sys-color-on-surface, #e0e0e0); max-height: 90vh; overflow-y: auto;';
    dialog.className = 'bmz-dialog';

    const currentMode = await getTokenMode();

    if (snippetToken) {
      const modeLabel = currentMode === 'supabase' ? '☁️ Supabase' : '💻 Local';
      const switchLabel = currentMode === 'supabase' ? 'Switch to Local' : 'Enable Supabase';
      dialog.innerHTML = `
        <!-- [ZeroLabs] 2026-08-27 12:34 PM - edited: centered heading -->
        <h2 style="margin: 0 0 16px 0; font-size: 20px; text-align: center;">GitLab Sync Settings</h2>
        <div style="display: flex; flex-direction: column; gap: 12px;">
          <!-- [ZeroLabs] 2026-08-27 12:20 PM - edited: one sync button instead of two directions -->
          <!-- The old pair was misleading: cloud-to-device only opened a review
               dialog, while device-to-cloud silently overwrote the snippet with
               no confirmation at all. One button runs the same reconcile the
               background runs, and anything that would delete opens the diff. -->
          ${snippetId ? `
            <!-- [ZeroLabs] 2026-08-27 12:34 PM - edited: the header's tanuki, status inside the ring -->
            <!-- Same two layers the header button uses: the GitLab tanuki as the
                 background and the sync arrows over it. Only the inner group
                 spins, so the status text in the middle of the ring stays still. -->
            <!-- [ZeroLabs] 2026-08-27 12:34 PM - edited: the header's tanuki, status inside the ring -->
            <!-- Same two layers the header button uses: the black GitLab tanuki
                 as the background and the sync arrows over it, inside the circle
                 that contains them. Only the inner group spins, so the status
                 text sitting in the middle of the ring stays upright. -->
            <div style="display: flex; justify-content: center; padding: 8px 0;">
              <button id="manualSyncNow" title="Sync with your snippet" aria-label="Sync with your snippet" style="position: relative; width: 128px; height: 128px; max-width: 100%; border-radius: 50%; border: none; background: var(--md-sys-color-surface-container, #2a2a2a); box-shadow: var(--md-elevation-1); cursor: pointer; padding: 0; display: flex; align-items: center; justify-content: center;">
                <!-- The loader rides the circle's edge, which leaves the tanuki
                     and the label alone in the middle instead of fighting them
                     for room. Spinning shows one coloured arc; settled shows the
                     whole ring in the outcome colour. -->
                <span id="manualSyncRing" style="position: absolute; inset: 0; border-radius: 50%; border: 4px solid transparent; box-sizing: border-box; pointer-events: none;"></span>
                <svg width="92" height="92" viewBox="0 0 24 24" style="display: block;">
                  <path fill="#000000" d="M22.65 14.39L12 22.13 1.35 14.39a.84.84 0 01-.3-.94l1.22-3.78 2.44-7.51A.42.42 0 014.82 2a.43.43 0 01.58 0 .42.42 0 01.11.18l2.44 7.49h8.1l2.44-7.51A.42.42 0 0118.6 2a.43.43 0 01.58 0 .42.42 0 01.11.18l2.44 7.51L23 13.45a.84.84 0 01-.35.94z"/>
                </svg>
                <span id="manualSyncStatus" style="position: absolute; left: 50%; top: 56%; transform: translate(-50%, -50%); font-size: 13px; font-weight: 700; color: #ffffff; white-space: nowrap; pointer-events: none; text-shadow: 0 1px 2px rgba(0,0,0,0.8);">Sync</span>
              </button>
            </div>
            <hr style="border: none; border-top: 1px solid var(--md-sys-color-outline, #444); margin: 4px 0;">
          ` : ''}
          <button id="snippetOptionsToggle" aria-expanded="${snippetId ? 'false' : 'true'}" style="padding: 12px; border-radius: 8px; border: none; background: var(--md-sys-color-secondary-container, #2a2a2a); color: var(--md-sys-color-on-secondary-container, #d0bcff); cursor: pointer; font-size: 14px; display: flex; align-items: center; justify-content: space-between; gap: 8px;">
            <span>Snippet Sync Options</span>
            <svg id="snippetOptionsChevron" width="16" height="16" viewBox="0 0 24 24" fill="currentColor" style="flex-shrink:0;transition:transform 0.2s ease;transform:rotate(${snippetId ? '-90' : '0'}deg);"><path d="M7.41,8.58L12,13.17L16.59,8.58L18,10L12,16L6,10L7.41,8.58Z"/></svg>
          </button>
          <div id="snippetOptionsPanel" style="display: ${snippetId ? 'none' : 'flex'}; flex-direction: column; gap: 12px;">
            <p style="margin: 0; color: var(--md-sys-color-on-surface-variant, #aaa); font-size: 13px;">
              ${snippetId ? 'Connected to Snippet: <code style="font-size: 11px;">' + snippetId + '</code>' : 'Not connected to any Snippet'}
            </p>
            <div style="display:flex;align-items:center;justify-content:space-between;padding:8px 12px;background:var(--md-sys-color-surface-variant,#2a2a2a);border-radius:8px;">
              <span style="font-size:13px;color:var(--md-sys-color-on-surface-variant,#aaa);">Token Storage: <strong style="color:var(--md-sys-color-on-surface,#e0e0e0);">${modeLabel}</strong></span>
              <button id="switchTokenMode" style="padding:6px 12px;border-radius:6px;border:none;background:var(--md-sys-color-secondary-container,#3a3a5c);color:var(--md-sys-color-on-secondary-container,#d0bcff);font-size:12px;cursor:pointer;">${switchLabel}</button>
            </div>
            <!-- [ZeroLabs] 2026-08-27 11:36 AM - added: background auto-sync toggle -->
            <div style="padding:8px 12px;background:var(--md-sys-color-surface-variant,#2a2a2a);border-radius:8px;">
              <label style="display:flex;align-items:center;justify-content:space-between;gap:12px;cursor:pointer;">
                <span style="font-size:13px;color:var(--md-sys-color-on-surface,#e0e0e0);">Background auto-sync</span>
                <input type="checkbox" id="autoSyncToggle" style="flex-shrink:0;width:16px;height:16px;cursor:pointer;">
              </label>
              <div style="font-size:12px;color:var(--md-sys-color-on-surface-variant,#aaa);margin-top:6px;">
                Checks for changes every 5 minutes and syncs automatically when nothing would be removed.
                Anything that would delete a bookmark will defer for consent.
              </div>
            </div>
            <button id="createNewSnippet" style="padding: 12px; border-radius: 8px; border: none; background: var(--md-sys-color-secondary-container, #2a2a2a); color: var(--md-sys-color-on-secondary-container, #d0bcff); cursor: pointer; font-size: 14px;">
              Create New Snippet with Current Bookmarks
            </button>
            <button id="selectExistingSnippet" style="padding: 12px; border-radius: 8px; border: none; background: var(--md-sys-color-secondary-container, #2a2a2a); color: var(--md-sys-color-on-secondary-container, #d0bcff); cursor: pointer; font-size: 14px;">
              Select Existing Snippet
            </button>
            ${snippetId ? `
              <!-- [ZeroLabs] 2026-08-27 12:20 PM - added: forcing, always reachable -->
              <!-- The sync button resolves everything it safely can, which means
                   a divergence in renames or moves never surfaces a choice, and a
                   wholesale recovery has no route. These stay available whatever
                   the current difference happens to look like. -->
              <hr style="border: none; border-top: 1px solid var(--md-sys-color-outline, #444); margin: 4px 0;">
              <button id="forceOverwriteSnippet" style="padding: 12px; border-radius: 8px; border: none; background: var(--md-sys-color-error-container, #3b1a1a); color: var(--md-sys-color-on-error-container, #f9dedc); cursor: pointer; font-size: 14px;">
                Overwrite Snippet with Local
              </button>
              <button id="forceOverwriteLocal" style="padding: 12px; border-radius: 8px; border: none; background: var(--md-sys-color-error-container, #3b1a1a); color: var(--md-sys-color-on-error-container, #f9dedc); cursor: pointer; font-size: 14px;">
                Overwrite Local with Snippet
              </button>
            ` : ''}
            <button id="disconnectSnippet" style="padding: 12px; border-radius: 8px; border: none; background: var(--md-sys-color-error-container, #3b1a1a); color: var(--md-sys-color-on-error-container, #f9dedc); cursor: pointer; font-size: 14px;">
              Disconnect & Remove Token
            </button>
          </div>
          <button id="cancelSnippetDialog" style="padding: 12px; border-radius: 8px; border: none; background: var(--md-sys-color-surface-variant, #2a2a2a); color: var(--md-sys-color-on-surface-variant, #aaa); cursor: pointer; font-size: 14px;">
            Cancel
          </button>
        </div>
      `;

      /* [ZeroLabs] 2026-08-19 6:01 PM - added: collapsible snippet options section */
      // Collapsed when a snippet is connected, since the two sync buttons are
      // all most visits need. Expanded when nothing is connected, because then
      // Create and Select are the only useful actions and a collapsed panel
      // would leave the dialog with nothing but Cancel.
      const snippetOptionsToggle = dialog.querySelector('#snippetOptionsToggle');
      const snippetOptionsPanel = dialog.querySelector('#snippetOptionsPanel');
      const snippetOptionsChevron = dialog.querySelector('#snippetOptionsChevron');
      if (snippetOptionsToggle && snippetOptionsPanel) {
        snippetOptionsToggle.addEventListener('click', () => {
          const isOpen = snippetOptionsPanel.style.display !== 'none';
          snippetOptionsPanel.style.display = isOpen ? 'none' : 'flex';
          snippetOptionsToggle.setAttribute('aria-expanded', String(!isOpen));
          if (snippetOptionsChevron) {
            snippetOptionsChevron.style.transform = isOpen ? 'rotate(-90deg)' : 'rotate(0deg)';
          }
        });
      }
    } else {
      dialog.innerHTML = `
        <h2 style="margin: 0 0 16px 0; font-size: 20px; text-align: center;">GitLab Sync Setup</h2>

        <div style="margin-bottom: 16px; padding: 12px; border: 1px solid var(--md-sys-color-outline, #444); border-radius: 8px;">
          <p style="margin: 0 0 10px 0; font-size: 13px; font-weight: 500; color: var(--md-sys-color-on-surface, #e0e0e0);">Token Storage</p>
          <label style="display:flex;align-items:flex-start;gap:8px;cursor:pointer;margin-bottom:10px;font-size:13px;">
            <input type="radio" name="tokenMode" value="local" ${currentMode !== 'supabase' ? 'checked' : ''} style="margin-top:2px;flex-shrink:0;">
            <span><span style="display:inline-flex;align-items:center;gap:5px;"><strong>Local</strong><span class="bmz-tooltip-wrap" style="position:relative;display:inline-flex;align-items:center;"><span style="display:inline-flex;align-items:center;justify-content:center;width:15px;height:15px;border-radius:50%;background:var(--md-sys-color-on-surface-variant,#aaa);color:var(--md-sys-color-surface,#1e1e1e);font-size:10px;font-weight:700;cursor:help;flex-shrink:0;line-height:1;">i</span><span class="bmz-tooltip" style="display:none;position:fixed;background:var(--md-sys-color-inverse-surface,#e0e0e0);color:var(--md-sys-color-inverse-on-surface,#1a1a1a);padding:8px 10px;border-radius:6px;font-size:12px;width:220px;z-index:10010;line-height:1.4;pointer-events:none;white-space:normal;">Token stored on this device only. When it auto-renews, you'll be shown the new token and asked to update your other BMZ clients manually.</span></span></span><br><span style="color:var(--md-sys-color-on-surface-variant,#aaa);font-size:12px;">(this device only)</span></span>
          </label>
          <label style="display:flex;align-items:flex-start;gap:8px;cursor:pointer;font-size:13px;">
            <input type="radio" name="tokenMode" value="supabase" ${currentMode === 'supabase' ? 'checked' : ''} style="margin-top:2px;flex-shrink:0;">
            <span><span style="display:inline-flex;align-items:center;gap:5px;"><strong>Supabase</strong><span class="bmz-tooltip-wrap" style="position:relative;display:inline-flex;align-items:center;"><span style="display:inline-flex;align-items:center;justify-content:center;width:15px;height:15px;border-radius:50%;background:var(--md-sys-color-on-surface-variant,#aaa);color:var(--md-sys-color-surface,#1e1e1e);font-size:10px;font-weight:700;cursor:help;flex-shrink:0;line-height:1;">i</span><span class="bmz-tooltip" style="display:none;position:fixed;background:var(--md-sys-color-inverse-surface,#e0e0e0);color:var(--md-sys-color-inverse-on-surface,#1a1a1a);padding:8px 10px;border-radius:6px;font-size:12px;width:220px;z-index:10010;line-height:1.4;pointer-events:none;white-space:normal;">Your token is encrypted and stored in Supabase. When it renews, all your BMZ clients update silently, with no manual steps. Only your encrypted token is stored; it can only access your GitLab bookmark snippet.</span></span></span><br><span style="color:var(--md-sys-color-on-surface-variant,#aaa);font-size:12px;">(auto-sync across devices)</span></span>
          </label>
          <div id="supabaseQuickLoad" style="display:none;margin-top:12px;padding:10px;background:rgba(99,102,241,0.1);border:1px solid rgba(99,102,241,0.3);border-radius:8px;font-size:12px;color:var(--md-sys-color-on-surface-variant,#aaa);">
            ☁️ Already set up Supabase on another device? <button id="loadFromSupabaseBtn" style="background:none;border:none;color:var(--md-sys-color-primary,#818cf8);cursor:pointer;font-size:12px;text-decoration:underline;padding:0;">Sign in to load your token automatically →</button>
          </div>
        </div>

        <div id="patSection">
          <p style="margin: 0 0 12px 0; color: var(--md-sys-color-on-surface-variant, #aaa); font-size: 13px;">
            Click below to create a GitLab Personal Access Token with the "api" scope. ⚠️ Save it immediately — it's only shown once.
          </p>
          <a href="https://gitlab.com/-/user_settings/personal_access_tokens?name=Bookmark+Manager+Zero&scopes=api" target="_blank" style="display: inline-block; margin-bottom: 12px; padding: 8px 16px; background: var(--md-sys-color-secondary-container, #2a2a2a); color: var(--md-sys-color-on-secondary-container, #d0bcff); text-decoration: none; border-radius: 8px; font-size: 13px;">
            Create Token on GitLab →
          </a>
          <div style="margin-bottom: 16px;">
            <label style="display: block; margin-bottom: 8px; font-size: 14px;">Personal Access Token:</label>
            <input type="password" id="gitlabTokenInput" placeholder="glpat-xxxxxxxxxxxx" style="width: 100%; padding: 10px; border-radius: 8px; border: 1px solid var(--md-sys-color-outline, #444); background: var(--md-sys-color-surface-variant, #2a2a2a); color: var(--md-sys-color-on-surface, #e0e0e0); font-size: 14px; box-sizing: border-box;">
          </div>
        </div>

        <div style="display: flex; gap: 12px;">
          <button id="saveSnippetToken" style="flex: 1; padding: 12px; border-radius: 8px; border: none; background: var(--md-sys-color-primary, #818cf8); color: var(--md-sys-color-on-primary, #fff); cursor: pointer; font-size: 14px;">
            Save & Continue
          </button>
          <button id="cancelSnippetDialog" style="flex: 1; padding: 12px; border-radius: 8px; border: none; background: var(--md-sys-color-surface-variant, #2a2a2a); color: var(--md-sys-color-on-surface-variant, #aaa); cursor: pointer; font-size: 14px;">
            Cancel
          </button>
        </div>
      `;

      // Tooltip hover for i icons — use fixed positioning to stay within viewport
      dialog.querySelectorAll('.bmz-tooltip-wrap').forEach(wrap => {
        const tip = wrap.querySelector('.bmz-tooltip');
        wrap.addEventListener('mouseenter', () => {
          const rect = wrap.getBoundingClientRect();
          const tipWidth = 220;
          let left = rect.left;
          if (left + tipWidth > window.innerWidth - 8) left = window.innerWidth - tipWidth - 8;
          if (left < 8) left = 8;
          tip.style.top = (rect.bottom + 6) + 'px';
          tip.style.left = left + 'px';
          tip.style.display = 'block';
        });
        wrap.addEventListener('mouseleave', () => { tip.style.display = 'none'; });
      });

      // Show/hide Supabase quick-load hint when mode radio changes
      dialog.querySelectorAll('input[name="tokenMode"]').forEach(radio => {
        radio.addEventListener('change', () => {
          const isSupabase = dialog.querySelector('input[name="tokenMode"]:checked')?.value === 'supabase';
          dialog.querySelector('#supabaseQuickLoad').style.display = isSupabase ? '' : 'none';
        });
      });
      // Set initial state
      if (currentMode === 'supabase') dialog.querySelector('#supabaseQuickLoad').style.display = '';

      // "Load from Supabase" quick-load button — sign in and pull token, skip PAT entry
      const loadFromSupabaseBtn = dialog.querySelector('#loadFromSupabaseBtn');
      if (loadFromSupabaseBtn) {
        loadFromSupabaseBtn.addEventListener('click', async () => {
          if (!supabase.isSignedIn) await supabase.loadSession();
          if (!supabase.isSignedIn) {
            const session = await showSupabaseLoginDialog();
            if (!session) return;
          }
          try {
            const row = await supabase.getGitLabToken();
            if (!row?.token) {
              showToast('Signed in! No GitLab token stored yet — enter your PAT below to complete setup.', 'info');
              return;
            }
            const decrypted = await decryptFromSupabase(row.token, supabase.session.user.id);
            await storeSnippetToken(decrypted, row.expires_at);
            await setTokenMode('supabase');
            modal.remove();
            showToast('Token loaded from Supabase');
            updateGitLabButtonIcon();
            if (snippetToken && snippetId && !snippetSyncInterval) startSnippetAutoSync();
            await openSnippetSyncDialog();
          } catch (e) {
            showToast('Failed to load from Supabase: ' + e.message, 'error');
          }
        });
      }
    }

    modal.appendChild(dialog);
    document.body.appendChild(modal);

    const cancelBtn = dialog.querySelector('#cancelSnippetDialog');
    if (cancelBtn) {
      cancelBtn.addEventListener('click', () => modal.remove());
    }

    modal.addEventListener('click', (e) => {
      if (e.target === modal) modal.remove();
    });

    if (snippetToken) {
      /* [ZeroLabs] 2026-08-27 12:20 PM - edited: one button, runs the reconcile */
      const manualSyncNowBtn = dialog.querySelector('#manualSyncNow');
      if (manualSyncNowBtn) {
        /* [ZeroLabs] 2026-08-27 12:34 PM - edited: spin the arrows, keep the label still */
        // Statuses are single words because they sit inside the arrow ring, and
        // that space allows one line. The detail goes to a toast instead.
        const ring = dialog.querySelector('#manualSyncRing');
        const status = dialog.querySelector('#manualSyncStatus');
        let running = false;

        /* [ZeroLabs] 2026-08-27 12:48 PM - edited: a ring loader instead of spinning arrows */
        // Spinning draws one arc and rotates it; settling paints the whole ring
        // in the outcome colour and stops. The label takes the same colour so
        // the two always agree, green matching the header's sync-success state.
        const setSyncState = (colour, spinning) => {
          if (status) status.style.color = colour;
          if (!ring) return;
          if (spinning) {
            ring.style.borderColor = 'transparent';
            ring.style.borderTopColor = colour;
            ring.style.animation = 'spin 1s linear infinite';
          } else {
            ring.style.animation = '';
            ring.style.borderColor = colour;
          }
        };

        const runManualSync = async () => {
          if (running) return;
          running = true;
          setSyncState('#ffffff', true);
          if (status) status.textContent = 'Syncing';

          try {
            const outcome = await reconcileWithSnippet();

            if (outcome.deferred) {
              setSyncState('#ff9800', false);
              if (status) status.textContent = 'Decide';
              modal.remove();
              /* [ZeroLabs] 2026-08-27 - edited: every deferral uses the consent dialog */
              // Removals used to branch to the diff dialog here, which described the
              // same deferral from the wrong end. Both kinds now go to the dialog
              // that says what syncing would do and asks.
              await showHeldPushDialog();
              return;
            }

            setSyncState('#4caf50', false);
            if (status) status.textContent = outcome.changed ? 'Synced' : 'In Sync';
            /* [ZeroLabs] 2026-08-27 2:41 PM - edited: silent when nothing changed */
            // The ring already reads "In Sync", so a toast saying the same is
            // just a second notification for a non-event.
            if (outcome.changed) {
              showToast(outcome.addedLocally > 0
                ? `Synced. ${outcome.addedLocally} added here, snippet updated.`
                : 'Synced. Snippet updated.');
            }
          } catch (error) {
            console.error('[ManualSync] Failed:', error);
            setSyncState('#f44336', false);
            if (status) status.textContent = 'Error';
            showToast(`Sync failed: ${error.message}`, 'error');
          } finally {
            running = false;
          }
        };

        manualSyncNowBtn.addEventListener('click', runManualSync);
        /* [ZeroLabs] 2026-08-29 - edited: opening the dialog no longer syncs */
        // It used to call runManualSync() here, on the reasoning that opening the
        // dialog was itself a request to sync. That made the dialog impossible to
        // reach for any other purpose: turning OFF background auto-sync, or
        // switching snippets, meant triggering the very sync you were trying to
        // stop. The button is right there and clearly labelled; syncing is now
        // always something the user asks for.
      }

      /* [ZeroLabs] 2026-08-27 12:20 PM - added: the two forced overwrites */
      // Both name what is about to be lost before doing it. The snippet one
      // reads the remote first purely so the count is real rather than vague.
      const forceOverwriteSnippetBtn = dialog.querySelector('#forceOverwriteSnippet');
      if (forceOverwriteSnippetBtn) {
        forceOverwriteSnippetBtn.addEventListener('click', async () => {
          try {
            const remoteData = await readBookmarksFromSnippet(snippetId);
            const localTree = await browser.bookmarks.getTree();
            const remoteAsFirefox = snippetFormatToFirefoxBookmarks(remoteData);
            const diff = calculateBookmarkDiff(localTree[0], remoteAsFirefox[0]);
            const losing = diff.added.length;

            const proceed = confirm(losing > 0
              ? `Warning: the snippet will be replaced with this device's bookmarks.\n\n${losing} item(s) currently in the snippet are not on this device and will be lost, on every device using it.\n\nContinue?`
              : 'The snippet will be replaced with this device\'s bookmarks. Nothing in the snippet is missing here, so nothing will be lost.\n\nContinue?');
            if (!proceed) return;

            modal.remove();
            /* [ZeroLabs] 2026-08-27 2:41 PM - edited: one result, not the push's pair */
            await syncToSnippet(true);
            showToast('Snippet overwritten with local bookmarks.');
          } catch (error) {
            console.error('[ForceOverwrite] Snippet overwrite failed:', error);
            showToast(`Error: ${error.message}`, 'error');
          }
        });
      }

      const forceOverwriteLocalBtn = dialog.querySelector('#forceOverwriteLocal');
      if (forceOverwriteLocalBtn) {
        forceOverwriteLocalBtn.addEventListener('click', async () => {
          try {
            const remoteData = await readBookmarksFromSnippet(snippetId);
            modal.remove();
            // applyRemoteChangesToFirefox carries its own double confirmation
            // and takes a pre-sync snapshot into the changelog, so it is not
            // wrapped in another prompt here.
            await applyRemoteChangesToFirefox(remoteData);
          } catch (error) {
            console.error('[ForceOverwrite] Local overwrite failed:', error);
            showToast(`Error: ${error.message}`, 'error');
          }
        });
      }

      const createNewBtn = dialog.querySelector('#createNewSnippet');
      if (createNewBtn) {
        createNewBtn.addEventListener('click', async () => {
          modal.remove();
          await handleCreateNewSnippet();
        });
      }

      const selectExistingBtn = dialog.querySelector('#selectExistingSnippet');
      if (selectExistingBtn) {
        selectExistingBtn.addEventListener('click', async () => {
          modal.remove();
          await handleSelectExistingSnippet();
        });
      }

      const disconnectBtn = dialog.querySelector('#disconnectSnippet');
      if (disconnectBtn) {
        disconnectBtn.addEventListener('click', async () => {
          modal.remove();
          showGitLabDisconnectDialog();
        });
      }

      /* [ZeroLabs] 2026-08-27 11:36 AM - added: bind the auto-sync toggle */
      // Absent means on, so only an explicit false switches it off. Written to
      // browser.storage.local rather than safeStorage because the background
      // reads it directly and never sees the private-mode memory store.
      const autoSyncToggle = dialog.querySelector('#autoSyncToggle');
      if (autoSyncToggle) {
        browser.storage.local.get('bmz_auto_sync_enabled').then(stored => {
          autoSyncToggle.checked = stored.bmz_auto_sync_enabled !== false;
        });
        autoSyncToggle.addEventListener('change', async () => {
          await browser.storage.local.set({ bmz_auto_sync_enabled: autoSyncToggle.checked });
          showToast(autoSyncToggle.checked
            ? 'Background auto-sync enabled'
            : 'Background auto-sync disabled. Manual sync still works.');
        });
      }

      const switchModeBtn = dialog.querySelector('#switchTokenMode');
      if (switchModeBtn) {
        switchModeBtn.addEventListener('click', async () => {
          modal.remove();
          if (currentMode === 'supabase') {
            // Switch to local — remove Supabase row, clear session, set mode
            await supabase.deleteGitLabToken();
            await setTokenMode('local');
            await supabase.clearSession();
            showToast('Switched to local token storage');
          } else {
            // Switch to Supabase — login and upload current token
            if (!supabase.isSignedIn) await supabase.loadSession();
            if (!supabase.isSignedIn) {
              const session = await showSupabaseLoginDialog();
              if (!session) return;
            }
            // Fetch current token expiry
            let expiresAt = null;
            try {
              const r = await fetchGitLab('https://gitlab.com/api/v4/personal_access_tokens/self', {
                headers: { 'Authorization': `Bearer ${snippetToken}` }
              });
              if (r.ok) { const info = await r.json(); expiresAt = info.expires_at; }
            } catch (e) { /* ignore */ }
            try {
              const encrypted = await encryptForSupabase(snippetToken, supabase.session.user.id);
              await supabase.saveGitLabToken(encrypted, expiresAt);
              await setTokenMode('supabase');
              showToast('Switched to Supabase token storage');
            } catch (e) {
              showToast('Failed to save to Supabase: ' + e.message, 'error');
            }
          }
          await openSnippetSyncDialog();
        });
      }
    } else {
      const saveBtn = dialog.querySelector('#saveSnippetToken');
      const tokenInput = dialog.querySelector('#gitlabTokenInput');

      if (saveBtn && tokenInput) {
        saveBtn.addEventListener('click', async () => {
          const selectedMode = dialog.querySelector('input[name="tokenMode"]:checked')?.value || 'local';

          if (selectedMode === 'supabase') {
            // Supabase mode: login first, then check if token already exists before requiring PAT
            if (!supabase.isSignedIn) await supabase.loadSession();
            if (!supabase.isSignedIn) {
              const session = await showSupabaseLoginDialog();
              if (!session) {
                showToast('Supabase login cancelled.', 'error');
                return;
              }
            }
            // Check Supabase for an existing token — no PAT entry needed if found
            try {
              const row = await supabase.getGitLabToken();
              if (row?.token) {
                const decrypted = await decryptFromSupabase(row.token, supabase.session.user.id);
                await storeSnippetToken(decrypted, row.expires_at);
                await setTokenMode('supabase');
                modal.remove();
                showToast('Token loaded from Supabase');
                updateGitLabButtonIcon();
                await openSnippetSyncDialog();
                return;
              }
            } catch (e) { console.warn('[Supabase] Existing token check failed:', e); }
            // No existing token in Supabase — fall through to PAT entry below
            if (!tokenInput.value.trim()) {
              showToast('Signed in successfully! This is your first time using Supabase sync — enter your GitLab PAT below to get started.', 'info');
            }
          }

          const token = tokenInput.value.trim();
          if (!token) {
            showToast('Please enter your Personal Access Token', 'error');
            return;
          }

          snippetToken = token;
          const user = await validateSnippetToken();
          if (!user) {
            snippetToken = null;
            showToast('Invalid token. Please check and try again.', 'error');
            return;
          }

          // Fetch expiry date from GitLab
          let expiresAt = null;
          try {
            const infoRes = await fetchGitLab('https://gitlab.com/api/v4/personal_access_tokens/self', {
              headers: { 'Authorization': `Bearer ${token}` }
            });
            if (infoRes.ok) { const info = await infoRes.json(); expiresAt = info.expires_at; }
          } catch (e) { console.warn('[TokenSave] Could not fetch expiry:', e); }

          if (selectedMode === 'supabase') {
            // Already signed in from above — encrypt and save to Supabase
            try {
              const encrypted = await encryptForSupabase(token, supabase.session.user.id);
              await supabase.saveGitLabToken(encrypted, expiresAt);
              await setTokenMode('supabase');
            } catch (e) {
              console.warn('[Supabase] Save failed:', e);
              showToast('Failed to save to Supabase — saving locally instead.', 'error');
              await setTokenMode('local');
            }
          } else {
            await setTokenMode('local');
          }

          await storeSnippetToken(token, expiresAt);
          showToast(`Authenticated as ${user.username}`);
          updateGitLabButtonIcon();
          modal.remove();

          await openSnippetSyncDialog();
        });

        tokenInput.addEventListener('keypress', (e) => {
          if (e.key === 'Enter') {
            saveBtn.click();
          }
        });

        setTimeout(() => tokenInput.focus(), 100);
      }
    }
  }

  // Handle creating a new Snippet with current bookmarks
  async function handleCreateNewSnippet() {
    try {
      showToast('Creating Snippet with current bookmarks...');

      const firefoxTree = await browser.bookmarks.getTree();
      const snippetData = await firefoxBookmarksToSnippetFormat(firefoxTree);
      // createBookmarkSnippet sets snippetId + saves to storage internally
      await createBookmarkSnippet(snippetData);

      updateGitLabButtonIcon();
      startSnippetAutoSync();

      showToast('Snippet created successfully!');
    } catch (error) {
      console.error('Failed to create Snippet:', error);
      showToast(`Error: ${error.message}`, 'error');
    }
  }

  // Handle selecting an existing Snippet
  // Check if local bookmarks exist
  async function checkLocalBookmarksExist() {
    try {
      const tree = await browser.bookmarks.getTree();
      const bookmarks = getAllBookmarksFlat(tree);
      // Consider local bookmarks to exist if there are more than just the default folders
      return bookmarks.length > 0;
    } catch (error) {
      console.error('Error checking local bookmarks:', error);
      return false;
    }
  }

  // Show backup dialog before replacing bookmarks
  async function showBackupBeforeReplaceDialog() {
    return new Promise((resolve) => {
      const modal = document.createElement('div');
      modal.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background: rgba(0, 0, 0, 0.7);
        display: flex;
        align-items: center;
        justify-content: center;
        z-index: 10003;
      `;

      const dialog = document.createElement('div');
      dialog.style.cssText = `
        background: var(--md-sys-color-surface, #1e1e1e);
        color: var(--md-sys-color-on-surface, #e0e0e0);
        border-radius: 12px;
        padding: 24px;
        max-width: 500px;
        width: 90%;
        box-shadow: 0 8px 32px rgba(0,0,0,0.3);
      `;

      dialog.innerHTML = `
        <h2>💾 Backup Your Bookmarks?</h2>
        <p>You're about to replace your local bookmarks with the snippet data. Would you like to download a backup of your current bookmarks first?</p>
        <p>This creates a safety backup that you can restore later if needed.</p>
        <div style="display: flex; flex-direction: column; gap: 12px;">
          <button id="backupAndReplace" style="padding: 12px; border-radius: 8px; border: none; background: var(--md-sys-color-primary, #4285f4); color: var(--md-sys-color-on-primary, #fff); cursor: pointer; font-size: 14px;">💾 Download Backup & Replace</button>
          <button id="skipBackup" style="padding: 12px; border-radius: 8px; border: none; background: var(--md-sys-color-surface-variant, #2a2a2a); color: var(--md-sys-color-on-surface-variant, #aaa); cursor: pointer; font-size: 14px;">Skip Backup & Replace</button>
          <button id="cancelReplace" style="padding: 12px; border-radius: 8px; border: none; background: var(--md-sys-color-surface-variant, #2a2a2a); color: var(--md-sys-color-on-surface-variant, #aaa); cursor: pointer; font-size: 14px;">Cancel</button>
        </div>
      `;

      modal.appendChild(dialog);
      document.body.appendChild(modal);

      dialog.querySelector('#backupAndReplace').addEventListener('click', () => {
        modal.remove();
        resolve('backup');
      });

      dialog.querySelector('#skipBackup').addEventListener('click', () => {
        modal.remove();
        resolve('skip');
      });

      dialog.querySelector('#cancelReplace').addEventListener('click', () => {
        modal.remove();
        resolve('cancel');
      });
    });
  }

  // Apply remote changes to local Firefox bookmarks (full replace)
  async function applyRemoteChangesToFirefox(remoteSnippetData, skipSnapshot = false) {
    // This is a DESTRUCTIVE operation - it will override local bookmarks
    // Show double confirmation dialog
    return new Promise((resolve) => {
      const modal = document.createElement('div');
      modal.style.cssText = 'position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.8); z-index: 10000; display: flex; align-items: center; justify-content: center;';

      const dialog = document.createElement('div');
      dialog.style.cssText = 'background: var(--md-sys-color-error-container, #3b1a1a); padding: 24px; border-radius: 12px; max-width: 500px; width: 90%; color: var(--md-sys-color-on-error-container, #f9dedc); border: 2px solid var(--md-sys-color-error, #f44336);';

      dialog.innerHTML = `
        <h2 style="margin: 0 0 16px 0; font-size: 20px; color: var(--md-sys-color-error, #f44336);">
          ⚠️ WARNING: This Will Override Your Native Browser Bookmarks
        </h2>
        <p style="margin: 0 0 16px 0; font-size: 14px;">
          This action will <strong>permanently replace</strong> your current Firefox bookmarks with the data from the Snippet.
        </p>
        <p style="margin: 0 0 20px 0; font-size: 14px; font-weight: 500;">
          Are you absolutely sure you want to proceed?
        </p>
        <div style="display: flex; gap: 12px;">
          <button id="cancelOverride" style="flex: 1; padding: 12px; border-radius: 8px; border: none; background: var(--md-sys-color-surface, #1e1e1e); color: var(--md-sys-color-on-surface, #e0e0e0); cursor: pointer; font-size: 14px;">
            Cancel
          </button>
          <button id="confirmOverride" style="flex: 1; padding: 12px; border-radius: 8px; border: none; background: var(--md-sys-color-error, #f44336); color: var(--md-sys-color-on-error, #fff); cursor: pointer; font-size: 14px; font-weight: 500;">
            Yes, Override My Bookmarks
          </button>
        </div>
      `;

      modal.appendChild(dialog);
      document.body.appendChild(modal);

      dialog.querySelector('#cancelOverride').addEventListener('click', () => {
        modal.remove();
        resolve(false);
      });

      dialog.querySelector('#confirmOverride').addEventListener('click', async () => {
        modal.remove();

        // Second confirmation
        const confirmed = confirm(
          'FINAL CONFIRMATION: This will permanently delete all your current Firefox bookmarks and replace them with the Snippet data. This cannot be undone. Click OK to proceed.'
        );

        if (!confirmed) {
          resolve(false);
          return;
        }

        try {
          showToast('Syncing from Snippet... This may take a moment.');

          // Get current bookmark tree
          const currentTree = await browser.bookmarks.getTree();

          // Only create snapshot if not already done (e.g., by merge operation)
          if (!skipSnapshot) {
            // STEP 1: Take a snapshot of current bookmarks before destructive sync
            const preSyncSnapshot = await firefoxBookmarksToSnippetFormat(currentTree);

            // STEP 2: Clear all old changelog entries (they will have invalid IDs after sync)
            await clearChangelog();

            // STEP 3: Add a special changelog entry for this sync operation with full snapshot
            await addChangelogEntry('pre-sync-snapshot', 'sync', 'Pull Remote to Local', null, {
              snapshot: preSyncSnapshot,
              timestamp: Date.now(),
              operation: 'Pull Remote to Local'
            });
          }

          // Get root folders (Firefox has toolbar, menu, unfiled, mobile)
          const roots = currentTree[0].children;

          // Remove all existing bookmarks from each root folder
          console.log('[SYNC] Deleting existing bookmarks...');
          for (const root of roots) {
            console.log(`[SYNC] Processing root: ${root.title} (${root.id}, type: ${root.type})`);
            if (root.children) {
              console.log(`[SYNC] Deleting ${root.children.length} children from ${root.title}`);
              for (const child of root.children) {
                try {
                  await browser.bookmarks.removeTree(child.id);
                } catch (error) {
                  console.warn(`Failed to remove bookmark ${child.id}:`, error);
                }
              }
            }
          }

          console.log('[SYNC] Re-fetching bookmark tree after deletion...');
          // Re-fetch the tree to get current state
          const freshTree = await browser.bookmarks.getTree();
          const freshRoots = freshTree[0].children;

          // Add new bookmarks from Snippet
          let createdCount = 0;
          let errorCount = 0;
          const createNodes = async (nodes, parentId, path = '') => {
            if (!nodes || !Array.isArray(nodes)) {
              console.warn('[createNodes] Invalid nodes array:', nodes);
              return;
            }

            for (const node of nodes) {
              try {
                if (node.url) {
                  // Create bookmark
                  console.log(`[createNodes] Creating bookmark: "${node.title}" at ${path}`);
                  await browser.bookmarks.create({
                    parentId: parentId,
                    title: node.title || 'Untitled',
                    url: node.url
                  });
                  createdCount++;
                } else if (node.children) {
                  // Create folder
                  console.log(`[createNodes] Creating folder: "${node.title}" at ${path}`);
                  const newFolder = await browser.bookmarks.create({
                    parentId: parentId,
                    title: node.title || 'Untitled Folder'
                  });
                  createdCount++;
                  await createNodes(node.children, newFolder.id, `${path}/${node.title || 'Untitled'}`);
                }
              } catch (error) {
                console.error(`[createNodes] Failed to create "${node.title}" at ${path}:`, error);
                errorCount++;
              }
            }
          };

          // Find Firefox root folder IDs from the fresh tree
          // Firefox root folders have type 'folder' but unique IDs
          console.log('[SYNC] Fresh roots:', freshRoots.map(r => ({ id: r.id, title: r.title, type: r.type })));
          const toolbar = freshRoots.find(r => r.id === 'toolbar_____');
          const menu = freshRoots.find(r => r.id === 'menu________');
          const unfiled = freshRoots.find(r => r.id === 'unfiled_____');
          const mobile = freshRoots.find(r => r.id === 'mobile______');

          // Recreate bookmark structure from Snippet
          console.log('[SYNC] Starting bookmark creation from snippet data...');
          console.log('[SYNC] Remote roots:', Object.keys(remoteSnippetData.roots || {}));
          console.log('[SYNC] Found Firefox roots:', { toolbar: !!toolbar, menu: !!menu, unfiled: !!unfiled, mobile: !!mobile });

          if (remoteSnippetData.roots) {
            if (remoteSnippetData.roots.bookmark_bar && remoteSnippetData.roots.bookmark_bar.children && toolbar) {
              console.log(`[SYNC] Creating ${remoteSnippetData.roots.bookmark_bar.children.length} items in Bookmarks Toolbar...`);
              await createNodes(remoteSnippetData.roots.bookmark_bar.children, toolbar.id, 'Bookmarks Toolbar');
            }

            if (remoteSnippetData.roots.menu && remoteSnippetData.roots.menu.children && menu) {
              console.log(`[SYNC] Creating ${remoteSnippetData.roots.menu.children.length} items in Bookmarks Menu...`);
              await createNodes(remoteSnippetData.roots.menu.children, menu.id, 'Bookmarks Menu');
            }

            if (remoteSnippetData.roots.other && remoteSnippetData.roots.other.children && unfiled) {
              console.log(`[SYNC] Creating ${remoteSnippetData.roots.other.children.length} items in Other Bookmarks...`);
              await createNodes(remoteSnippetData.roots.other.children, unfiled.id, 'Other Bookmarks');
            }

            if (remoteSnippetData.roots.mobile && remoteSnippetData.roots.mobile.children && mobile) {
              console.log(`[SYNC] Creating ${remoteSnippetData.roots.mobile.children.length} items in Mobile Bookmarks...`);
              await createNodes(remoteSnippetData.roots.mobile.children, mobile.id, 'Mobile Bookmarks');
            }
          }

          console.log(`[SYNC] Bookmark creation complete! Created: ${createdCount}, Errors: ${errorCount}`);

          // Update local version tracking
          snippetLocalVersion = remoteSnippetData.version || 1;
          await safeStorage.set({ snippet_local_version: snippetLocalVersion });
          /* [ZeroLabs] 2026-08-26 11:38 PM - added: clear reconcile flag after applying remote */
          await setSnippetNeedsReconcile(false);

          showToast('Bookmarks synced successfully!');
          resolve(true);

          // Reload the bookmark view
          await loadBookmarks();
          renderBookmarks();
        } catch (error) {
          console.error('Failed to apply remote changes:', error);
          showToast(`Error: ${error.message}`, 'error');
          resolve(false);
        }
      });

      modal.addEventListener('click', (e) => {
        if (e.target === modal) {
          modal.remove();
          resolve(false);
        }
      });
    });
  }

  // Show merge confirmation dialog
  /* [ZeroLabs] 2026-08-26 11:29 PM - edited: accept counts for the totals line */
  async function showMergeConfirmationDialog(snippetId, type, counts = null) {
    return new Promise((resolve) => {
      const modal = document.createElement('div');
      modal.className = 'modal-overlay';
      modal.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0, 0, 0, 0.7);
        display: flex;
        align-items: center;
        justify-content: center;
        z-index: 10002;
      `;

      const dialog = document.createElement('div');
      dialog.style.cssText = `
        background: var(--md-sys-color-surface, #1e1e1e);
        color: var(--md-sys-color-on-surface, #e0e0e0);
        border-radius: 12px;
        padding: 24px;
        max-width: 500px;
        width: 90%;
        box-shadow: 0 8px 32px rgba(0,0,0,0.3);
      `;

      const actionText = type === 'new' ? 'create a new snippet' : 'use this existing snippet';
      const snippetText = type === 'new' ? 'new snippet' : 'selected snippet';

      /* [ZeroLabs] 2026-08-26 11:29 PM - added: totals line before a destructive choice (see also: Bookmark-Manager-Zero-Chrome/sidepanel.js) */
      // Two of these buttons overwrite one side with the other and the dialog
      // never said how much sat on each. Ported from the share window's totals
      // sentence. The counts come from the read the caller has already done, so
      // this costs no extra request. Values are integers, never user text.
      let totalsLine = '';
      if (counts && typeof counts.local === 'number' && typeof counts.remote === 'number') {
        const noun = (n) => (n === 1 ? 'bookmark' : 'bookmarks');
        let comparison;
        if (counts.remote > counts.local) {
          comparison = `The snippet has ${counts.remote - counts.local} more.`;
        } else if (counts.local > counts.remote) {
          comparison = `This device has ${counts.local - counts.remote} more.`;
        } else {
          comparison = 'Same total, but the contents differ.';
        }
        totalsLine = `
        <p style="margin: -8px 0 16px 0; font-size: 0.9em; color: var(--md-sys-color-on-surface-variant, #aaa);">
          The snippet has ${counts.remote} ${noun(counts.remote)}, this device has ${counts.local} ${noun(counts.local)}. ${comparison}
        </p>`;
      }

      dialog.innerHTML = `
        <h2 style="margin: 0 0 16px 0; color: var(--md-sys-color-primary, #818cf8);">
          📋 Local Bookmarks Detected
        </h2>
        <p style="margin-bottom: 16px;">
          You have bookmarks stored locally. How would you like to handle them?
        </p>
        ${totalsLine}
        <div style="display: flex; flex-direction: column; gap: 12px; margin-bottom: 20px;">
          <button id="keepLocal" style="
            background: var(--md-sys-color-surface-variant, #2a2a2a);
            color: var(--md-sys-color-on-surface-variant, #aaa);
            border: none;
            padding: 12px 16px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 1em;
            text-align: left;
            border-left: 4px solid var(--md-sys-color-secondary, #818cf8);
          ">
            <div style="font-weight: 500;">Keep Local Bookmarks</div>
            <div style="font-size: 0.9em; opacity: 0.8; margin-top: 4px;">
              Cancel setup and keep your local bookmarks unchanged
            </div>
          </button>

          <button id="doMerge" style="
            background: var(--md-sys-color-primary, #818cf8);
            color: var(--md-sys-color-on-primary, #fff);
            border: none;
            padding: 12px 16px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 1em;
            text-align: left;
            border-left: 4px solid var(--md-sys-color-primary, #818cf8);
            font-weight: 500;
          ">
            <!-- [ZeroLabs] 2026-08-27 2:33 AM - edited: the name is honest again -->
            <div style="font-weight: 500;">Merge Bookmarks</div>
            <div style="font-size: 0.9em; opacity: 0.9; margin-top: 4px;">
              Show what each side has that the other does not, then combine them so both end up with everything. Nothing is deleted.
            </div>
          </button>

          <button id="replaceRemote" style="
            background: var(--md-sys-color-secondary-container, #2a3a2a);
            color: var(--md-sys-color-on-secondary-container, #b8f0b8);
            border: none;
            padding: 12px 16px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 1em;
            text-align: left;
            border-left: 4px solid #4caf50;
          ">
            <div style="font-weight: 500;">Replace Remote Snippet with Local</div>
            <div style="font-size: 0.9em; opacity: 0.8; margin-top: 4px;">
              Overwrite the ${snippetText} with your local bookmarks
            </div>
          </button>

          <button id="replaceLocal" style="
            background: var(--md-sys-color-error-container, #3a2a2a);
            color: var(--md-sys-color-on-error-container, #ffb4ab);
            border: none;
            padding: 12px 16px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 1em;
            text-align: left;
            border-left: 4px solid var(--md-sys-color-error, #f87171);
          ">
            <div style="font-weight: 500;">Replace Local with Remote Snippet</div>
            <div style="font-size: 0.9em; opacity: 0.8; margin-top: 4px;">
              Use the ${snippetText} only (your local bookmarks will be lost)
            </div>
          </button>
        </div>
      `;

      modal.appendChild(dialog);
      document.body.appendChild(modal);

      // Button handlers
      dialog.querySelector('#keepLocal').addEventListener('click', () => {
        modal.remove();
        resolve('keep-local');
      });

      dialog.querySelector('#doMerge').addEventListener('click', () => {
        modal.remove();
        resolve('merge');
      });

      dialog.querySelector('#replaceRemote').addEventListener('click', () => {
        modal.remove();
        resolve('replace-remote');
      });

      dialog.querySelector('#replaceLocal').addEventListener('click', () => {
        modal.remove();
        resolve('replace');
      });
    });
  }

  /* [ZeroLabs] 2026-08-27 2:26 AM - removed: mergeLocalBookmarksIntoSnippet + mergeBookmarksIntoTree (replaced by: bringSidesTogether) */

  /* [ZeroLabs] 2026-06-20 11:01 AM - removed: orphaned mergeBidirectional (per-sync merge) */

  async function handleSelectExistingSnippet() {
    try {
      showToast('Loading your Snippets...');
      const snippets = await getAllSnippets();

      const modal = document.createElement('div');
      modal.className = 'modal';
      modal.style.cssText = 'position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.7); z-index: 10000; display: flex; align-items: center; justify-content: center;';

      const dialog = document.createElement('div');
      dialog.style.cssText = 'background: var(--md-sys-color-surface, #1e1e1e); padding: 24px; border-radius: 12px; max-width: 600px; width: 90%; max-height: 80%; overflow-y: auto; color: var(--md-sys-color-on-surface, #e0e0e0);';
      dialog.className = 'bmz-dialog';

      let snippetList = '<h2 style="margin: 0 0 16px 0; font-size: 20px;">Select a Snippet</h2>';

      if (snippets.length === 0) {
        snippetList += '<p style="color: var(--md-sys-color-on-surface-variant, #aaa);">No Snippets found. Create a new one instead.</p>';
      } else {
        snippetList += '<div style="display: flex; flex-direction: column; gap: 8px;">';
        snippets.forEach(snippet => {
          const isBMZ = snippet.title?.includes('BMZ') || snippet.title?.includes('Bookmark Manager Zero');
          snippetList += `
            <button class="select-snippet-btn" data-snippet-id="${escapeHtml(String(snippet.id))}" style="padding: 12px; border-radius: 8px; border: 1px solid var(--md-sys-color-outline, #444); background: var(--md-sys-color-surface-variant, #2a2a2a); color: var(--md-sys-color-on-surface, #e0e0e0); cursor: pointer; text-align: left; font-size: 13px;">
              <div style="font-weight: 500; margin-bottom: 4px;">${escapeHtml(snippet.title || 'Untitled Snippet')} ${isBMZ ? '<span style="color: var(--md-sys-color-primary, #818cf8);">[BMZ]</span>' : ''}</div>
              <div style="font-size: 11px; color: var(--md-sys-color-on-surface-variant, #aaa);">Visibility: ${escapeHtml(snippet.visibility || '')}</div>
              <div style="font-size: 10px; color: var(--md-sys-color-on-surface-variant, #888); margin-top: 4px;">ID: ${escapeHtml(String(snippet.id))}</div>
            </button>
          `;
        });
        snippetList += '</div>';
      }

      snippetList += `
        <button id="cancelSelectSnippet" style="margin-top: 16px; padding: 12px; border-radius: 8px; border: none; background: var(--md-sys-color-surface-variant, #2a2a2a); color: var(--md-sys-color-on-surface-variant, #aaa); cursor: pointer; width: 100%;">
          Cancel
        </button>
      `;

      dialog.innerHTML = snippetList;
      modal.appendChild(dialog);
      document.body.appendChild(modal);

      const selectBtns = dialog.querySelectorAll('.select-snippet-btn');
      selectBtns.forEach(btn => {
        btn.addEventListener('click', async () => {
          const selectedSnippetId = btn.dataset.snippetId;
          modal.remove();

          // Check if local bookmarks exist
          const hasLocalBookmarks = await checkLocalBookmarksExist();

          if (hasLocalBookmarks) {
            /* [ZeroLabs] 2026-08-17 4:15 PM - edited: fall back to the diff when checksums differ */
            // Compare checksums before showing the dialog — skip it if already in sync
            let alreadyInSync = false;
            /* [ZeroLabs] 2026-08-26 11:29 PM - added: keep both totals for the dialog */
            // Only needed when the dialog is actually shown, so it is filled in
            // beside the diff below. Stays null if the read failed, and the
            // dialog then renders exactly as it did before.
            let syncCounts = null;
            /* [ZeroLabs] 2026-08-27 12:14 AM - added: carry the remote version out of the try */
            // Connecting to a snippet that already matches recorded no version at
            // all, so the first background push compared against 0 and skipped.
            let connectRemoteVersion = null;
            /* [ZeroLabs] 2026-08-27 1:05 AM - added: keep the diff for Compare and Choose */
            // The connect flow already computes both of these to decide whether
            // to show this dialog at all, so reusing them costs no extra request.
            let connectDiff = null;
            let connectRemoteData = null;
            try {
              const remoteData = await readBookmarksFromSnippet(selectedSnippetId);
              connectRemoteVersion = Number(remoteData?.version) || 0;
              connectRemoteData = remoteData;
              const localTree = await browser.bookmarks.getTree();
              const localData = await firefoxBookmarksToSnippetFormat(localTree);
              const localChecksum = await calculateChecksum(localData);
              const remoteChecksum = remoteData.checksum || await calculateChecksum(remoteData);
              alreadyInSync = localChecksum === remoteChecksum;

              if (!alreadyInSync) {
                // The checksum is byte-exact over the whole tree, titles included,
                // and Firefox writes its toolbar root as "Bookmarks Toolbar" while
                // Chrome writes "Bookmarks bar". It therefore can never match across
                // browsers, which made this shortcut same-browser only. The diff is
                // the authoritative comparison: it normalizes those root naming
                // differences and the browser's internal-URL rewrites, so an empty
                // diff means genuinely in sync even when the hashes disagree.
                const remoteTreeAsFirefoxFormat = snippetFormatToFirefoxBookmarks(remoteData);
                const diff = calculateBookmarkDiff(localTree[0], remoteTreeAsFirefoxFormat[0]);
                connectDiff = diff;
                alreadyInSync = (diff.added.length + diff.removed.length +
                                 diff.moved.length + diff.modified.length) === 0;
                syncCounts = {
                  local: countBookmarks(localTree[0]),
                  remote: countBookmarks(remoteTreeAsFirefoxFormat[0])
                };
              }
            } catch (e) {
              // Comparison failed — fall through to show dialog as normal
            }

            if (alreadyInSync) {
              snippetId = selectedSnippetId;
              /* [ZeroLabs] 2026-08-27 12:14 AM - edited: record the version we matched */
              snippetLocalVersion = connectRemoteVersion !== null ? connectRemoteVersion : snippetLocalVersion;
              await safeStorage.set({
                bmz_snippet_id: snippetId,
                snippet_local_version: snippetLocalVersion
              });
              updateGitLabButtonIcon();
              startSnippetAutoSync();
              /* [ZeroLabs] 2026-08-17 4:15 PM - added: pull pins on silent connect */
              // Nothing else syncs on this path, so without this the snippet's
              // pins would not appear until the first auto-sync fired.
              loadQuickAccessForSnippet(snippetId).catch(err => {
                console.error('[QuickAccess] Pin load after connect failed:', err);
              });
              showToast('Snippet connected — bookmarks are already in sync.');
              return;
            }

            // Show merge confirmation dialog
            /* [ZeroLabs] 2026-08-26 11:29 PM - edited: pass totals to the dialog */
            const mergeChoice = await showMergeConfirmationDialog(selectedSnippetId, 'existing', syncCounts);

            if (mergeChoice === 'keep-local') {
              // User chose to cancel and keep local bookmarks
              showToast('Cancelled. Local bookmarks unchanged.');
              return;
            } else if (mergeChoice === 'merge') {
              /* [ZeroLabs] 2026-08-27 1:05 AM - edited: item-by-item instead of a blind merge (see also: Bookmark-Manager-Zero-Chrome/sidepanel.js) */
              // Was mergeLocalBookmarksIntoSnippet, a one-way union that pushed
              // local into the snippet and left this device still missing
              // whatever the snippet had. It also silently kept bookmarks
              // deleted here, so they returned on the next pull. The same
              // tickable list the sync diff uses settles each item instead, and
              // both sides end up equal.
              snippetId = selectedSnippetId;
              snippetLocalVersion = connectRemoteVersion !== null ? connectRemoteVersion : snippetLocalVersion;
              await safeStorage.set({
                bmz_snippet_id: snippetId,
                snippet_local_version: snippetLocalVersion
              });
              updateGitLabButtonIcon();

              if (connectDiff && connectRemoteData) {
                await showSyncDiffDialog(connectDiff, connectRemoteData);
              } else {
                // The comparison failed earlier, so there is nothing to show.
                // Connect and let the next sync surface the difference.
                showToast('Connected. Open GitLab sync to compare.', 'error');
              }
            } else if (mergeChoice === 'replace-remote') {
              // Replace remote snippet with local bookmarks
              snippetId = selectedSnippetId;
              await safeStorage.set({ bmz_snippet_id: snippetId });
              updateGitLabButtonIcon();
              try {
                await replaceRemoteWithLocal(selectedSnippetId);
                showToast('Remote snippet replaced with local bookmarks.');
              } catch (error) {
                console.error('Failed to replace remote snippet:', error);
                showToast(`Error: ${error.message}`, 'error');
              }
            } else if (mergeChoice === 'replace') {
              // Replace local bookmarks with snippet data
              snippetId = selectedSnippetId;
              await safeStorage.set({ bmz_snippet_id: snippetId });
              updateGitLabButtonIcon();

              // Show backup dialog before replacing
              const shouldBackup = await showBackupBeforeReplaceDialog();

              if (shouldBackup === 'cancel') {
                // User cancelled, do nothing
                return;
              }

              if (shouldBackup === 'backup') {
                // User wants to backup first
                await exportBookmarks();
              }

              // Get the remote snippet data and apply it directly (full replace)
              try {
                const remoteData = await readBookmarksFromSnippet(selectedSnippetId);
                await applyRemoteChangesToFirefox(remoteData);
              } catch (error) {
                console.error('Failed to replace bookmarks from snippet:', error);
                showToast(`Error: ${error.message}`, 'error');
              }
            }
          } else {
            // No local bookmarks, just connect
            snippetId = selectedSnippetId;
            await safeStorage.set({ bmz_snippet_id: snippetId });
            updateGitLabButtonIcon();
            showToast('Snippet connected: ' + snippetId);
          }
        });
      });

      const cancelBtn = dialog.querySelector('#cancelSelectSnippet');
      if (cancelBtn) {
        cancelBtn.addEventListener('click', () => modal.remove());
      }

      modal.addEventListener('click', (e) => {
        if (e.target === modal) modal.remove();
      });
    } catch (error) {
      console.error('Failed to load Snippets:', error);
      showToast(`Error: ${error.message}`, 'error');
    }
  }

  // Load and initialize GitLab Snippet integration
  async function initGitLabSnippets() {
    try {
      // Load Supabase session first so token rotation works during auto-sync
      await supabase.loadSession();

      await loadSnippetToken();
      const snippetIdResult = await safeStorage.get(['bmz_snippet_id']);
      if (snippetIdResult.bmz_snippet_id) {
        snippetId = snippetIdResult.bmz_snippet_id;
      }
      /* [ZeroLabs] 2026-08-26 11:38 PM - edited: restore last sync time and reconcile flag */
      // snippet_last_sync was read nowhere before, so the 60 second floor in
      // markSnippetChanges measured against 0 and never actually held.
      const versionResult = await safeStorage.get(['snippet_local_version', 'snippet_last_sync', 'snippet_needs_reconcile']);
      if (versionResult.snippet_local_version) {
        snippetLocalVersion = versionResult.snippet_local_version;
      }
      if (versionResult.snippet_last_sync) {
        snippetLastSyncTime = versionResult.snippet_last_sync;
      }
      // A push skipped while the sidebar was shut has to show up when it opens
      if (versionResult.snippet_needs_reconcile) {
        await setSnippetNeedsReconcile(true);
      }
      /* [ZeroLabs] 2026-08-27 - edited: the notice card replaces the modal on open */
      // This opened the consent dialog every time the sidebar was opened with a
      // deferral outstanding. One surface per divergence: the card explains it
      // and the dialog now opens only when asked for, from the card or the sync
      // button. setSnippetNeedsReconcile above already put the card up.

      updateGitLabButtonIcon();

      // Start auto-sync if we have both token and snippet ID
      if (snippetToken && snippetId) {
        startSnippetAutoSync();
        /* [ZeroLabs] 2026-08-17 4:15 PM - added: pull pins on startup */
        // Not awaited: pins render from the local cache immediately and refresh
        // when this lands, so a slow GitLab never delays the sidebar.
        loadQuickAccessForSnippet(snippetId).catch(err => {
          console.error('[QuickAccess] Startup pin load failed:', err);
        });
      }
    } catch (error) {
      console.error('Failed to initialize GitLab Snippets:', error);
    }
  }

  // Initialize GitLab on load
  initGitLabSnippets();

  // Manual sync button
  const manualSyncBtn = document.getElementById('manualSyncBtn');
  if (manualSyncBtn) {
    manualSyncBtn.addEventListener('click', async (e) => {
      e.stopPropagation();
      await openSnippetSyncDialog();
    });
  }

  // GitLab account button
  const gitlabBtn = document.getElementById('gitlabBtn');
  if (gitlabBtn) {
    gitlabBtn.addEventListener('click', async (e) => {
      e.stopPropagation();
      if (snippetToken && snippetId) {
        showGitLabDisconnectDialog();
      } else {
        await openSnippetSyncDialog();
      }
    });
  }

  // Reveal GitLab Token (settings menu)
  const revealGitlabTokenBtn = document.getElementById('revealGitlabTokenBtn');
  if (revealGitlabTokenBtn) {
    revealGitlabTokenBtn.addEventListener('click', async (e) => {
      e.stopPropagation();
      settingsMenu.classList.remove('show');
      await showRevealTokenModal();
    });
  }

  // BIDIRECTIONAL SYNC: Listen for bookmark changes (only in extension mode)
  // This ensures the extension automatically updates when bookmarks change in Firefox
  let syncTimeout = null;

  // Debounced sync function to prevent excessive reloads
  const syncBookmarks = (eventType) => {
    clearTimeout(syncTimeout);
    syncTimeout = setTimeout(async () => {
      try {
        console.log(`[Bookmark Sync] ${eventType} - Syncing bookmarks from Firefox...`);
        await loadBookmarks();
        cleanupSafetyHistory(); // Clean up stale entries after sync
        renderBookmarks();
        console.log('[Bookmark Sync] ✓ Sync complete');
      } catch (error) {
        console.error('[Bookmark Sync] Failed to sync:', error);
      }
    }, 100); // 100ms debounce

    /* [ZeroLabs] 2026-08-26 11:43 PM - removed: event-driven push (moved to: background.js) */
    // The background page now owns every push triggered by a bookmark change, so
    // that one runs whether or not this sidebar is open. Leaving the call here as
    // well would mean two clients pushing the same tree seconds apart. Pins still
    // push from here via markQuickAccessChanged, since the background has no
    // business writing bmz-meta.json.
  };

  browser.bookmarks.onCreated.addListener((id, bookmark) => {
    console.log('[Bookmark Sync] Bookmark created:', bookmark.title || bookmark.url);
    syncBookmarks('onCreated');
  });

  browser.bookmarks.onRemoved.addListener((id, removeInfo) => {
    console.log('[Bookmark Sync] Bookmark removed:', id);
    syncBookmarks('onRemoved');
  });

  browser.bookmarks.onChanged.addListener((id, changeInfo) => {
    console.log('[Bookmark Sync] Bookmark changed:', changeInfo);
    syncBookmarks('onChanged');
  });

  browser.bookmarks.onMoved.addListener((id, moveInfo) => {
    console.log('[Bookmark Sync] Bookmark moved:', id);
    syncBookmarks('onMoved');
  });

  console.log('[Bookmark Sync] ✓ Real-time bidirectional sync enabled');

  // Multi-select toggle button
  const multiSelectToggle = document.getElementById('multiSelectToggle');
  multiSelectToggle.addEventListener('click', () => {
    multiSelectMode = !multiSelectMode;

    // Toggle button appearance and ARIA state
    if (multiSelectMode) {
      multiSelectToggle.style.background = 'var(--md-sys-color-primary)';
      multiSelectToggle.style.color = 'var(--md-sys-color-on-primary)';
      multiSelectToggle.setAttribute('aria-pressed', 'true');
    } else {
      multiSelectToggle.style.background = '';
      multiSelectToggle.style.color = '';
      multiSelectToggle.setAttribute('aria-pressed', 'false');
      selectedItems.clear();
    }

    // Show/hide bulk actions bar
    const bulkActionsBar = document.getElementById('bulkActionsBar');
    bulkActionsBar.classList.toggle('hidden', !multiSelectMode);

    // Re-render to show/hide checkboxes
    renderBookmarks();
  });

  // Long-press to enter multi-select mode
  let longPressTimer = null;
  let longPressStartX = 0;
  let longPressStartY = 0;
  const LONG_PRESS_MS = 750;
  const LONG_PRESS_DRIFT_PX = 8;

  function enterMultiSelectFromLongPress(itemEl) {
    if (!multiSelectMode) {
      multiSelectMode = true;
      multiSelectToggle.style.background = 'var(--md-sys-color-primary)';
      multiSelectToggle.style.color = 'var(--md-sys-color-on-primary)';
      multiSelectToggle.setAttribute('aria-pressed', 'true');
      document.getElementById('bulkActionsBar').classList.remove('hidden');
      renderBookmarks();
    }
    const container = itemEl.closest('.bookmark-item, .folder-item');
    if (container && container.dataset.id) {
      selectedItems.add(container.dataset.id);
      const checkbox = container.querySelector('.item-checkbox');
      if (checkbox) checkbox.checked = true;
      updateSelectedCount();
    }
  }

  bookmarkList.addEventListener('mousedown', (e) => {
    if (e.button !== 0) return;
    if (e.target.closest('.bookmark-menu-btn, .item-checkbox, input, button, a')) return;
    const item = e.target.closest('.bookmark-item, .folder-header');
    if (!item) return;
    longPressStartX = e.clientX;
    longPressStartY = e.clientY;
    longPressTimer = setTimeout(() => {
      longPressTimer = null;
      enterMultiSelectFromLongPress(item);
    }, LONG_PRESS_MS);
  });

  document.addEventListener('mousemove', (e) => {
    if (!longPressTimer) return;
    const dx = e.clientX - longPressStartX;
    const dy = e.clientY - longPressStartY;
    if (Math.sqrt(dx * dx + dy * dy) > LONG_PRESS_DRIFT_PX) {
      clearTimeout(longPressTimer);
      longPressTimer = null;
    }
  });

  document.addEventListener('mouseup', () => {
    if (longPressTimer) {
      clearTimeout(longPressTimer);
      longPressTimer = null;
    }
  });

  bookmarkList.addEventListener('dragstart', () => {
    if (longPressTimer) {
      clearTimeout(longPressTimer);
      longPressTimer = null;
    }
  }, true);

  // Bulk actions event delegation
  bookmarkList.addEventListener('change', (e) => {
    if (e.target.classList.contains('item-checkbox')) {
      const itemId = e.target.dataset.id;
      if (e.target.checked) {
        selectedItems.add(itemId);
      } else {
        selectedItems.delete(itemId);
      }
      updateSelectedCount();
    }
  });

  // Bulk action buttons
  document.getElementById('bulkSelectAll').addEventListener('click', () => {
    // Select all visible items
    const checkboxes = bookmarkList.querySelectorAll('.item-checkbox');
    checkboxes.forEach(cb => {
      cb.checked = true;
      selectedItems.add(cb.dataset.id);
    });
    updateSelectedCount();
  });

  document.getElementById('bulkDeselectAll').addEventListener('click', () => {
    // Deselect all
    const checkboxes = bookmarkList.querySelectorAll('.item-checkbox');
    checkboxes.forEach(cb => {
      cb.checked = false;
    });
    selectedItems.clear();
    updateSelectedCount();
  });

  document.getElementById('bulkOpenTabs').addEventListener('click', async () => {
    await bulkOpenItems();
  });

  document.getElementById('bulkOpenWindows').addEventListener('click', async () => {
    await bulkOpenInWindows();
  });

  document.getElementById('bulkRecheck').addEventListener('click', async () => {
    await bulkRecheckItems();
  });

  document.getElementById('bulkMove').addEventListener('click', async () => {
    await bulkMoveItems();
  });

  document.getElementById('bulkDelete').addEventListener('click', async () => {
    await bulkDeleteItems();
  });

  // Keyboard navigation
  document.addEventListener('keydown', (e) => {
    // Skip if user is typing in an input field
    if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.isContentEditable) {
      return;
    }

    // Skip if a modal is open
    if (!document.getElementById('editModal').classList.contains('hidden') ||
        !document.getElementById('addBookmarkModal').classList.contains('hidden') ||
        !document.getElementById('addFolderModal').classList.contains('hidden') ||
        !document.getElementById('duplicatesModal').classList.contains('hidden')) {
      return;
    }

    // Build list of visible items (both folders and bookmarks)
    const folderElements = Array.from(bookmarkList.querySelectorAll('.folder-item .folder-header'));
    const bookmarkElements = Array.from(bookmarkList.querySelectorAll('.bookmark-item'));

    // Combine and sort by DOM position
    const allElements = [...folderElements, ...bookmarkElements].sort((a, b) => {
      return a.compareDocumentPosition(b) & Node.DOCUMENT_POSITION_FOLLOWING ? -1 : 1;
    });

    if (allElements.length === 0) return;

    switch (e.key) {
      case 'ArrowDown':
        e.preventDefault();
        selectedBookmarkIndex = Math.min(selectedBookmarkIndex + 1, allElements.length - 1);
        highlightSelectedItem(allElements);
        break;

      case 'ArrowUp':
        e.preventDefault();
        selectedBookmarkIndex = Math.max(selectedBookmarkIndex - 1, 0);
        highlightSelectedItem(allElements);
        break;

      case 'ArrowRight':
        e.preventDefault();
        if (selectedBookmarkIndex >= 0 && selectedBookmarkIndex < allElements.length) {
          const selectedElement = allElements[selectedBookmarkIndex];
          if (selectedElement.classList.contains('folder-header')) {
            // Check if folder is already expanded
            const toggle = selectedElement.querySelector('.folder-toggle');
            if (!toggle.classList.contains('expanded')) {
              // Expand folder if collapsed
              selectedElement.click();
              // After expanding, rebuild the list and maintain selection
              setTimeout(() => {
                const updatedFolders = Array.from(bookmarkList.querySelectorAll('.folder-item .folder-header'));
                const updatedBookmarks = Array.from(bookmarkList.querySelectorAll('.bookmark-item'));
                const updatedElements = [...updatedFolders, ...updatedBookmarks].sort((a, b) => {
                  return a.compareDocumentPosition(b) & Node.DOCUMENT_POSITION_FOLLOWING ? -1 : 1;
                });
                highlightSelectedItem(updatedElements);
              }, 50);
            } else {
              // Folder already expanded, move down to next item
              selectedBookmarkIndex = Math.min(selectedBookmarkIndex + 1, allElements.length - 1);
              highlightSelectedItem(allElements);
            }
          } else {
            // For bookmarks, check if preview is already shown
            if (selectedElement.classList.contains('force-preview')) {
              // Preview already shown, move down to next item
              selectedBookmarkIndex = Math.min(selectedBookmarkIndex + 1, allElements.length - 1);
              highlightSelectedItem(allElements);
            } else {
              // Show preview for bookmark
              const previewContainer = selectedElement.querySelector('.bookmark-preview-container');
              if (previewContainer) {
                selectedElement.classList.add('force-preview');
                const previewImg = previewContainer.querySelector('.preview-image');
                const url = previewImg.dataset.url;
                if (url && !loadedPreviews.has(url)) {
                  // Trigger preview load
                  previewImg.src = `https://s0.wp.com/mshots/v1/${encodeURIComponent(url)}?w=400&h=300`;
                  previewImg.onload = () => {
                    previewImg.classList.add('loaded');
                    loadedPreviews.add(url);
                  };
                  loadedPreviews.add(url);
                } else if (url) {
                  previewImg.classList.add('loaded');
                }
              }
            }
          }
        }
        break;

      case 'ArrowLeft':
        e.preventDefault();
        if (selectedBookmarkIndex >= 0 && selectedBookmarkIndex < allElements.length) {
          const selectedElement = allElements[selectedBookmarkIndex];
          if (selectedElement.classList.contains('folder-header')) {
            // Check if folder is expanded
            const toggle = selectedElement.querySelector('.folder-toggle');
            if (toggle.classList.contains('expanded')) {
              // Collapse folder if expanded
              selectedElement.click();
              // After collapsing, rebuild the list and maintain selection
              setTimeout(() => {
                const updatedFolders = Array.from(bookmarkList.querySelectorAll('.folder-item .folder-header'));
                const updatedBookmarks = Array.from(bookmarkList.querySelectorAll('.bookmark-item'));
                const updatedElements = [...updatedFolders, ...updatedBookmarks].sort((a, b) => {
                  return a.compareDocumentPosition(b) & Node.DOCUMENT_POSITION_FOLLOWING ? -1 : 1;
                });
                highlightSelectedItem(updatedElements);
              }, 50);
            } else {
              // Folder already collapsed, move up to previous item
              selectedBookmarkIndex = Math.max(selectedBookmarkIndex - 1, 0);
              highlightSelectedItem(allElements);
            }
          } else {
            // For bookmarks, check if preview is shown
            if (selectedElement.classList.contains('force-preview')) {
              // Hide preview for bookmark
              selectedElement.classList.remove('force-preview');
            } else {
              // Preview already hidden, move up to previous item
              selectedBookmarkIndex = Math.max(selectedBookmarkIndex - 1, 0);
              highlightSelectedItem(allElements);
            }
          }
        }
        break;

      case 'Enter':
        e.preventDefault();
        if (selectedBookmarkIndex >= 0 && selectedBookmarkIndex < allElements.length) {
          const selectedElement = allElements[selectedBookmarkIndex];
          // Check if it's a folder header or bookmark
          if (selectedElement.classList.contains('folder-header')) {
            // Toggle folder
            selectedElement.click();
            // After toggling, rebuild the list and maintain selection
            setTimeout(() => {
              const updatedFolders = Array.from(bookmarkList.querySelectorAll('.folder-item .folder-header'));
              const updatedBookmarks = Array.from(bookmarkList.querySelectorAll('.bookmark-item'));
              const updatedElements = [...updatedFolders, ...updatedBookmarks].sort((a, b) => {
                return a.compareDocumentPosition(b) & Node.DOCUMENT_POSITION_FOLLOWING ? -1 : 1;
              });
              highlightSelectedItem(updatedElements);
            }, 50);
          } else {
            // Open bookmark
            selectedElement.click();
          }
        }
        break;

      case 'Escape':
        // Clear selection
        selectedBookmarkIndex = -1;
        allElements.forEach(el => el.style.outline = '');
        break;
    }
  });

  // Undo toast event listeners
  undoButton.addEventListener('click', () => {
    performUndo();
  });

  undoDismiss.addEventListener('click', () => {
    hideUndoToast();
  });
}

// Highlight the selected item (folder or bookmark) for keyboard navigation
function highlightSelectedItem(allElements) {
  // Remove highlight from all items
  allElements.forEach(el => el.style.outline = '');

  // Add highlight to selected item
  if (selectedBookmarkIndex >= 0 && selectedBookmarkIndex < allElements.length) {
    const selected = allElements[selectedBookmarkIndex];
    selected.style.outline = '2px solid var(--md-sys-color-primary)';
    selected.style.outlineOffset = '2px';
    selected.style.borderRadius = '8px';
    // Scroll into view
    selected.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }
}

// Initialize when DOM is ready - load Firefox bookmarks directly
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initFirefoxExtension);
} else {
  initFirefoxExtension();
}

/* [ZeroLabs] 2026-06-20 7:18 PM - added: scale header title/subtitle to fit beside the buttons (login-aware) */
(function () {
  function fitHeaderText() {
    const MARGIN = 8;                                  // px clearance from the buttons
    ['.logo-title', '.logo-subtitle'].forEach(function (sel) {
      const el = document.querySelector(sel);
      if (!el) return;
      el.style.transformOrigin = 'left center';
      el.style.transform = '';                         // reset before measuring
      const box = el.clientWidth - MARGIN;             // width left beside the current buttons
      const range = document.createRange();
      range.selectNodeContents(el);
      const w = range.getBoundingClientRect().width;   // rendered single-line text width
      if (w > box && box > 0) {
        el.style.transform = 'scale(' + Math.max(0.3, box / w) + ')';
      }
    });
  }
  const schedule = function () { requestAnimationFrame(fitHeaderText); };
  function initHeaderFit() {
    schedule();
    // Re-fit when the button cluster changes width (e.g. GitLab login swaps login -> sync+logout)
    const cluster = document.querySelector('.header-settings');
    if (cluster && window.ResizeObserver && !cluster.dataset.fitObserved) {
      cluster.dataset.fitObserved = '1';
      new ResizeObserver(schedule).observe(cluster);
    }
    // Re-fit when the title/subtitle text changes (e.g. the version string is injected after load)
    ['.logo-title', '.logo-subtitle'].forEach(function (sel) {
      const t = document.querySelector(sel);
      if (t && window.MutationObserver && !t.dataset.fitTextObserved) {
        t.dataset.fitTextObserved = '1';
        new MutationObserver(schedule).observe(t, { childList: true, characterData: true, subtree: true });
      }
    });
    window.addEventListener('resize', schedule);
  }
  window.fitHeaderText = fitHeaderText;
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initHeaderFit);
  } else {
    initHeaderFit();
  }
})();
