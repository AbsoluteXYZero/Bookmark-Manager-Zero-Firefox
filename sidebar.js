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

/* [ZeroLabs] 2026-09-23 3:10 PM - removed: the what's-new card and its flag */
// The card announced the changes of August 27 and was shown once per install.
// Announcements are published through notices.json now, so a new message needs
// no code change in any client. LATEST_CARD_KEY, hasSeenLatestCard,
// loadLatestCardFlag and dismissLatestCard are all gone. The stored
// bmz_latest_card_20260827 flag is left in storage and is simply never read.

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
/* [ZeroLabs] 2026-09-08 7:40 AM - added: errors land in the changelog you can actually read */
// errorLogs already held the message, the stack and the context, but reading it
// needs a console. The changelog is a surface the user can reach on any device,
// so errors go there too. They render as their own type with no Restore button,
// since there is nothing to restore.
//
// Throttled by message: a failing sync or a scan loop can raise the same
// rejection dozens of times a minute, and without this it would push every real
// bookmark change out of the changelog.
const ERROR_REPEAT_WINDOW_MS = 30000;
const recentErrorTimes = new Map();

function shouldRecordError(message) {
  const now = Date.now();

  // Drop anything that aged out, so the map cannot grow without bound.
  for (const [key, at] of recentErrorTimes) {
    if (now - at > ERROR_REPEAT_WINDOW_MS) recentErrorTimes.delete(key);
  }

  if (recentErrorTimes.has(message)) return false;
  recentErrorTimes.set(message, now);
  return true;
}

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

    /* [ZeroLabs] 2026-09-08 7:40 AM - added: mirror it into the changelog */
    // After the errorLogs write on purpose, so a failure here can never cost the
    // error record itself. The first stack frame is carried in details, which is
    // the line that actually identifies where it came from.
    if (shouldRecordError(errorLog.message)) {
      const firstFrame = (errorLog.stack || '')
        .split('\n')
        .map(line => line.trim())
        .find(line => line.startsWith('at ') || line.includes('@')) || '';

      await addChangelogEntry(
        'error',
        'error',
        errorLog.message || 'Unknown error',
        null,
        { context: context || 'Error', frame: firstFrame }
      );
    }
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
  /* [ZeroLabs] 2026-09-07 9:20 PM - added: know the store before the first render */
  // The card is skipped when this has not resolved yet, and the first render is
  // the one most people see, so it is awaited here rather than left to the
  // fire-and-forget call beside its own definition.
  await loadMigrationOfferState();
  /* [ZeroLabs] 2026-09-07 10:05 PM - added: a failure raised while the sidebar was shut */
  // The background page records it and stops. Without this the card only ever
  // appeared if the failure happened while you were looking at the sidebar.
  await loadSyncFailureState();
  renderBookmarks();

  // Check if background scan is in progress and sync UI
  await syncBackgroundScanStatus();

  // Automatically check bookmark statuses after initial render
  autoCheckBookmarkStatuses();

  /* [ZeroLabs] 2026-09-13 - added: look for published notices once the sidebar is up */
  // Not awaited. It fetches, and toasts whenever that lands.
  checkNotices().catch(() => {});
}

/* [ZeroLabs] 2026-09-13 - added: published notices, shown once as a toast */
// notices.json on the BMZ website is the message source, shared by all three
// clients. Publishing is editing the file and pushing; the site sends no-store
// on .json so the edit is live at once. Each entry has a numeric id that only
// ever goes up. The sidebar keeps the highest id it has shown and toasts
// everything above it, so rewording or deleting an old entry never re-notifies
// anyone. Only a new, higher id fires.
//
// A toast auto-dismisses, so the same notice is also written to the Event Log as
// a notice entry. Without that, one shown while the user was not looking is gone
// for good.
//
// Silent on every failure. A missing or malformed file must never disturb the
// sidebar; it simply tries again on the next open.
/* [ZeroLabs] 2026-09-13 - added: a published notice is a dialog, not a toast */
// A corner toast that vanishes in seconds is the wrong shape for an update
// message someone is meant to read. This is centred, sized to be read, and
// stays until the X or Escape is pressed. The backdrop does NOT close it: a
// stray tap, easy on a phone, must not dismiss a message before it was read.
// It resolves when closed, so several notices arrive one after another.
/* [ZeroLabs] 2026-09-23 4:40 PM - added: bullets in a notice become a real list */
// A notice is plain text in a JSON file, and it used to render as one block
// with white-space: pre-line. That was fine for paragraphs and wrong for a
// list: the second and later lines of a long bullet wrapped back to the left
// margin, under the bullet character instead of under the text, which on a
// phone turned a tidy list into a slab.
//
// A line that begins with a bullet character now becomes a real <li>, so the
// browser does the hanging indent. Everything else stays a paragraph. Still
// textContent on every node, never innerHTML: the text comes from a file on
// the web and must never be able to inject markup.
//
// The accepted markers are the bullet, the hyphen and the asterisk, so a
// notice can be written with whichever is convenient.
const NOTICE_BULLET_PATTERN = /^[•\-*]\s+/;

function renderNoticeText(container, text) {
  const lines = String(text).split('\n');
  let list = null;

  const closeList = () => {
    list = null;
  };

  lines.forEach(line => {
    const trimmed = line.trim();

    // A blank line only separates blocks. The margins below do the spacing.
    if (trimmed === '') {
      closeList();
      return;
    }

    if (NOTICE_BULLET_PATTERN.test(trimmed)) {
      if (!list) {
        list = document.createElement('ul');
        list.style.cssText = 'margin: 0 0 12px 0; padding-left: 22px;';
        container.appendChild(list);
      }
      const item = document.createElement('li');
      item.textContent = trimmed.replace(NOTICE_BULLET_PATTERN, '');
      item.style.cssText = 'margin-bottom: 8px; line-height: 1.5;';
      list.appendChild(item);
      return;
    }

    closeList();
    const paragraph = document.createElement('p');
    paragraph.textContent = trimmed;
    paragraph.style.cssText = 'margin: 0 0 12px 0;';
    container.appendChild(paragraph);
  });

  // The last block does not need the gap under it
  const last = container.lastElementChild;
  if (last) last.style.marginBottom = '0';
}

/* [ZeroLabs] 2026-09-23 4:05 PM - edited: one dialog, never a queue of them */
// It used to open one dialog per unseen notice, one after another. That is fine
// for somebody who missed one message, and awful for a new install: with
// seventeen entries in the file, a first run meant seventeen dialogs to close.
//
// Now the NEWEST unseen notice is the dialog, and everything older sits behind
// one collapsed row that opens in place. A brand new user reads the current
// message and may open the history; an existing user with one unseen notice
// sees exactly what they saw before, because the row is not drawn at all when
// there is nothing older.
//
// `notice.date` is optional and is only a heading for the older entries. An
// entry without one still renders, separated by its rule, so the entries
// already published do not have to be rewritten.
function showNoticeDialog(notice, earlier = []) {
  return new Promise(resolve => {
    const overlay = document.createElement('div');
    overlay.style.cssText = 'position: fixed; inset: 0; background: rgba(0,0,0,0.6); backdrop-filter: blur(3px); z-index: 10003; display: flex; align-items: center; justify-content: center; padding: 16px; box-sizing: border-box;';

    const panel = document.createElement('div');
    panel.setAttribute('role', 'dialog');
    panel.setAttribute('aria-modal', 'true');
    panel.setAttribute('aria-labelledby', 'bmzNoticeTitle');
    panel.style.cssText = 'position: relative; background: var(--md-sys-color-surface, #1e1e1e); color: var(--md-sys-color-on-surface, #e0e0e0); border: 1px solid var(--md-sys-color-outline, #444); border-radius: 16px; padding: 28px 28px 20px 28px; width: 100%; max-width: 560px; max-height: 85vh; overflow-y: auto; box-shadow: 0 12px 40px rgba(0,0,0,0.45); box-sizing: border-box;';

    const close = document.createElement('button');
    close.setAttribute('aria-label', 'Close');
    close.textContent = '\u00d7';
    close.style.cssText = 'position: absolute; top: 10px; right: 12px; width: 36px; height: 36px; border: none; background: transparent; color: var(--md-sys-color-on-surface-variant, #aaa); font-size: 26px; line-height: 1; cursor: pointer; border-radius: 8px;';

    const title = document.createElement('h2');
    title.id = 'bmzNoticeTitle';
    title.textContent = 'A message from BMZ';
    title.style.cssText = 'margin: 0 32px 14px 0; font-size: 18px; font-weight: 600; color: var(--md-sys-color-primary, #90caf9);';

    const body = document.createElement('div');
    body.style.cssText = 'font-size: 15px; line-height: 1.6; word-break: break-word;';
    renderNoticeText(body, notice.text);

    panel.appendChild(close);
    panel.appendChild(title);

    if (notice.date) {
      const stamp = document.createElement('div');
      stamp.textContent = notice.date;
      stamp.style.cssText = 'margin-bottom: 10px; font-size: 12px; color: var(--md-sys-color-on-surface-variant, #aaa);';
      panel.appendChild(stamp);
    }

    panel.appendChild(body);

    /* [ZeroLabs] 2026-09-23 4:05 PM - added: every older notice, collapsed */
    // This is the whole archive for this client, not only the unseen ones, so
    // somebody curious about what changed before can read back through it. It
    // is drawn whenever anything older exists, and only a file holding a single
    // notice leaves it out.
    if (earlier.length > 0) {
      const toggle = document.createElement('button');
      toggle.type = 'button';
      toggle.setAttribute('aria-expanded', 'false');
      toggle.style.cssText = 'display: flex; align-items: center; gap: 8px; width: 100%; margin-top: 18px; padding: 10px 12px; background: var(--md-sys-color-surface-variant, #2a2a2a); color: var(--md-sys-color-on-surface, #e0e0e0); border: 1px solid var(--md-sys-color-outline-variant, #333); border-radius: 10px; font-size: 13px; font-weight: 500; cursor: pointer; text-align: left;';

      const caret = document.createElement('span');
      caret.textContent = '▶';
      caret.style.cssText = 'font-size: 10px; transition: transform 0.15s ease;';

      const label = document.createElement('span');
      const plural = earlier.length === 1 ? 'update' : 'updates';
      label.textContent = `${earlier.length} earlier ${plural}`;

      toggle.appendChild(caret);
      toggle.appendChild(label);

      const history = document.createElement('div');
      history.hidden = true;
      history.style.cssText = 'margin-top: 10px;';

      earlier.forEach((older, index) => {
        const entry = document.createElement('div');
        entry.style.cssText = index === 0
          ? 'padding-top: 4px;'
          : 'margin-top: 16px; padding-top: 16px; border-top: 1px solid var(--md-sys-color-outline-variant, #333);';

        if (older.date) {
          const olderStamp = document.createElement('div');
          olderStamp.textContent = older.date;
          olderStamp.style.cssText = 'margin-bottom: 6px; font-size: 12px; font-weight: 600; color: var(--md-sys-color-on-surface-variant, #aaa);';
          entry.appendChild(olderStamp);
        }

        const olderBody = document.createElement('div');
        olderBody.style.cssText = 'font-size: 14px; line-height: 1.55; word-break: break-word; color: var(--md-sys-color-on-surface-variant, #ccc);';
        renderNoticeText(olderBody, older.text);
        entry.appendChild(olderBody);

        history.appendChild(entry);
      });

      toggle.addEventListener('click', () => {
        const opening = history.hidden;
        history.hidden = !opening;
        toggle.setAttribute('aria-expanded', String(opening));
        caret.style.transform = opening ? 'rotate(90deg)' : '';
      });

      panel.appendChild(toggle);
      panel.appendChild(history);
    }

    const foot = document.createElement('div');
    foot.textContent = 'You can read this again at any time in the Event Log.';
    foot.style.cssText = 'margin-top: 20px; padding-top: 12px; border-top: 1px solid var(--md-sys-color-outline-variant, #333); font-size: 12px; color: var(--md-sys-color-on-surface-variant, #aaa);';

    panel.appendChild(foot);
    overlay.appendChild(panel);

    const finish = () => {
      document.removeEventListener('keydown', onKey);
      overlay.remove();
      resolve();
    };
    const onKey = (event) => {
      if (event.key === 'Escape') finish();
    };

    close.addEventListener('click', finish);
    document.addEventListener('keydown', onKey);

    document.body.appendChild(overlay);
    close.focus();
  });
}

/* [ZeroLabs] 2026-09-24 1:35 AM - added: a notice body that copies up to 5.8 cannot see */
// Every copy of BMZ up to and including 5.8 keeps a notice only when its
// `text` is a string, and nothing older reads notices at all. So an entry
// whose body is in `message` instead is skipped by those copies in silence,
// with nothing to deploy to them. This copy reads `message` first and still
// accepts `text`, so the entries written before this change keep working.
//
// Returns the notice with its body in `text`, which is what the dialog and
// the Event Log read, or null when it has no body at all.
function noticeWithBody(notice) {
  if (!notice) return null;
  if (typeof notice.message === 'string') return { ...notice, text: notice.message };
  if (typeof notice.text === 'string') return notice;
  return null;
}

/* [ZeroLabs] 2026-09-24 1:05 AM - added: does this copy run the version a notice is about */
// Versions are compared number by number, so 5.10 is correctly newer than 5.9,
// which a plain string comparison gets wrong. A missing part counts as 0, so
// "5.9" and "5.9.0" are equal. An entry with no `version` is for everyone, and
// so is every entry when this copy's own version cannot be read, which keeps
// the behaviour from before this check existed.
function noticeFitsVersion(notice, appVersion) {
  if (!notice.version || !appVersion) return true;

  const have = String(appVersion).split('.').map(part => parseInt(part, 10) || 0);
  const need = String(notice.version).split('.').map(part => parseInt(part, 10) || 0);
  const length = Math.max(have.length, need.length);

  for (let index = 0; index < length; index++) {
    const mine = have[index] || 0;
    const wanted = need[index] || 0;
    if (mine > wanted) return true;
    if (mine < wanted) return false;
  }
  return true;
}

async function checkNotices() {
  let notices;
  try {
    const response = await fetch('https://bmzweb.absolutezero.fyi/notices.json', { cache: 'no-store' });
    if (!response.ok) return;
    notices = await response.json();
  } catch (error) {
    return;
  }
  if (!Array.isArray(notices)) return;

  const stored = await safeStorage.get('bmz_notices_seen_id');
  const seenId = Number(stored.bmz_notices_seen_id) || 0;

  /* [ZeroLabs] 2026-09-24 1:05 AM - edited: one list of what this client may show, used twice */
  // The headline and the collapsed history used to repeat the same filters, and
  // a filter added to one and not the other would let them disagree.
  const forThisClient = notices
    /* [ZeroLabs] 2026-09-24 1:35 AM - edited: read `message`, fall back to `text` */
    .map(noticeWithBody)
    .filter(notice => notice !== null)
    /* [ZeroLabs] 2026-09-13 - added: a draft stays in the file and goes nowhere */
    // JSON has no comments, and a stray // would invalidate the whole file and
    // silence every notice. This is how the template entry, and any notice
    // written ahead of time, sits in the file without being sent.
    .filter(notice => notice.draft !== true)
    /* [ZeroLabs] 2026-09-13 - added: only notices addressed to this client */
    // A website or Android fix is not news to an extension user, and a Web Store
    // update is not news to the website. Each entry names its targets; one with
    // no targets field goes to everyone.
    .filter(notice => {
      if (!Array.isArray(notice.targets)) return true;
      return notice.targets.includes('firefox');
    })
    /* [ZeroLabs] 2026-09-24 1:05 AM - added: never announce a version this client does not run */
    // The file is read by every installed copy the moment it is published,
    // while a Web Store update reaches people over days. So "Version 5.9 is
    // here" was shown to people still running 5.8. An entry with a `version`
    // now waits until this copy runs that version or newer. It is not marked
    // seen while it waits, so it appears the first time BMZ opens after the
    // update. "Or newer", not "exactly": someone who skips a version still
    // finds its notes in the history.
    .filter(notice => noticeFitsVersion(notice, APP_VERSION));

  const unseen = forThisClient
    .filter(notice => Number(notice.id) > seenId)
    .sort((a, b) => Number(a.id) - Number(b.id));

  if (unseen.length === 0) return;

  /* [ZeroLabs] 2026-09-23 4:05 PM - edited: one dialog holding the newest, with the rest behind it */
  // Was a loop opening one dialog per unseen notice. A new install starting at
  // id 0 therefore had to close one dialog per entry in the file, which does
  // not scale: seventeen entries meant seventeen dialogs.
  //
  // The newest unseen notice is now the message, and EVERY older notice for
  // this client sits behind a collapsed row, whether or not it was seen before.
  // That keeps the dialog to one for everybody and still lets somebody curious
  // read back through what changed.
  const newest = unseen[unseen.length - 1];

  const earlier = forThisClient
    .filter(item => Number(item.id) < Number(newest.id))
    .sort((a, b) => Number(b.id) - Number(a.id));

  await showNoticeDialog(newest, earlier);

  /* [ZeroLabs] 2026-09-23 4:05 PM - edited: record on close, as before */
  // Everything unseen goes to the Event Log, including the entries the user
  // never expanded, so choosing not to read the history loses nothing. The
  // stored id moves only after the dialog is CLOSED, so a dialog abandoned by
  // shutting the sidebar comes back next time and is written once, not twice.
  for (const item of unseen) {
    await addChangelogEntry('notice', 'notice', item.text, null, {});
  }
  await safeStorage.set({ bmz_notices_seen_id: Number(newest.id) });
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
      /* [ZeroLabs] 2026-09-24 6:30 AM - edited: the fullest root folder is shown first */
      // Display only. The root folders are shown most bookmarks first, and
      // everything inside them keeps its own order.
      bookmarkTree = sortRootsByBookmarkCount(firefoxTree[0].children);
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

  /* [ZeroLabs] 2026-09-23 3:10 PM - removed: the August 27 what's-new card */
  // Announcements go through notices.json now, which reaches every client from
  // one file and does not need a code change to publish. The card, its storage
  // flag and its loader are gone with it.

  /* [ZeroLabs] 2026-08-17 4:15 PM - added: quick access and recent sections */
  // Hidden while searching or filtering: the tree is already showing matches
  // from everywhere, so mirrored rows would just duplicate the results.
  /* [ZeroLabs] 2026-08-27 - added: deferred sync notice, above everything else */
  // Ahead of Quick Access, and outside the isNarrowing guard: it is a standing
  // alert rather than a mirrored list, so it should not vanish when you search.
  renderSyncNoticeCard(bookmarkList);

  /* [ZeroLabs] 2026-09-07 10:05 PM - added: a broken sync, above the migration offer */
  // Ahead of the migration card deliberately. When the store is full both would
  // show, and the one saying syncing has already stopped is the more urgent.
  renderSyncFailedCard(bookmarkList);

  /* [ZeroLabs] 2026-09-07 9:20 PM - added: the migration offer, same standing-alert slot */
  renderMigrationCard(bookmarkList);

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

  /* [ZeroLabs] 2026-09-23 1:22 AM - edited: BMZ's pointer drag replaces the native one */
  row.draggable = false;
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
  if (area !== 'local') return;

  /* [ZeroLabs] 2026-09-07 9:20 PM - added: follow the store this device uses */
  // The migration card lives out here with the other cards, while the store
  // state lives inside setupEventListeners. Reading the same storage keys is
  // how the two stay in step without either scope reaching into the other.
  if (changes.bmz_snippet_id || changes.bmz_store_kind || changes.bmz_migration_snoozed_until) {
    loadMigrationOfferState().then(renderBookmarks);
  }

  /* [ZeroLabs] 2026-09-07 10:05 PM - added: follow a failure the background recorded */
  // The background page is where syncing actually fails, and the sidebar had no
  // way to hear about it. Same route the deferral flag already takes.
  if (changes.snippet_sync_failed) {
    loadSyncFailureState().then(renderBookmarks);
  }

  if (!changes.snippet_needs_reconcile) return;
  const needs = !!changes.snippet_needs_reconcile.newValue;
  const manualSyncBtn = document.getElementById('manualSyncBtn');
  if (manualSyncBtn) manualSyncBtn.classList.toggle('sync-attention', needs);
  setSyncNoticeVisible(needs);
});

/* [ZeroLabs] 2026-09-07 9:20 PM - added: what the migration card needs to know */
// Three facts, read from storage rather than passed in: whether this device
// syncs at all, whether it is already on a repository, and when the user last
// asked to be left alone about it.
let migrationOffer = { connected: false, onProject: false, snoozedUntil: 0 };
const MIGRATION_SNOOZE_MS = 7 * 24 * 60 * 60 * 1000;

async function loadMigrationOfferState() {
  try {
    const stored = await browser.storage.local.get([
      'bmz_snippet_id',
      'bmz_store_kind',
      'bmz_migration_snoozed_until'
    ]);
    migrationOffer = {
      connected: !!stored.bmz_snippet_id,
      onProject: stored.bmz_store_kind === 'project',
      snoozedUntil: Number(stored.bmz_migration_snoozed_until) || 0
    };
  } catch (error) {
    // Without this the card simply does not appear, which is the safe direction
    console.error('[Migration] Could not read the store state:', error);
    migrationOffer = { connected: false, onProject: false, snoozedUntil: 0 };
  }
}

loadMigrationOfferState();

/* [ZeroLabs] 2026-09-07 10:05 PM - added: a sync that FAILED gets its own card */
// The deferral card above is for a sync that stopped and is waiting on a
// decision. This one is for a sync that broke. They were the same card, driven by
// the same flag, so a failed background push drew "Sync was paused to protect
// your data" and offered a Review changes button with nothing behind it.
//
// Red, which the stylesheet has been holding back for exactly this: amber already
// means "waiting on you" and violet means "a limit you have not hit yet".
let syncFailure = { failed: false, reason: '', detail: '' };
let syncFailureDismissed = false;

async function loadSyncFailureState() {
  try {
    const stored = await browser.storage.local.get([
      'snippet_sync_failed',
      'snippet_sync_failed_reason',
      'snippet_sync_failed_detail'
    ]);
    const wasFailed = syncFailure.failed;
    syncFailure = {
      failed: !!stored.snippet_sync_failed,
      reason: stored.snippet_sync_failed_reason || 'error',
      detail: stored.snippet_sync_failed_detail || ''
    };
    // A new failure is worth showing again even if the last one was dismissed
    if (syncFailure.failed && !wasFailed) syncFailureDismissed = false;
  } catch (error) {
    console.error('[CloudSync] Could not read the failure state:', error);
    syncFailure = { failed: false, reason: '', detail: '' };
  }
}

function renderSyncFailedCard(container) {
  if (!syncFailure.failed || syncFailureDismissed) return;

  const isFull = syncFailure.reason === 'store-full';

  // Two failures, two honest descriptions. A full store never recovers, so
  // offering Try again there would waste the user's time on our behalf.
  const title = isFull ? 'Syncing has stopped' : 'Sync failed';
  const body = isFull
    ? `GitLab is refusing to save to this snippet. Its storage limit counts every past
       version of your bookmarks, and this one has reached that limit. Your bookmarks are
       safe and nothing has been lost. Moving them to a repository takes about a minute
       and does not have the same limit.`
    : `BMZ could not reach your cloud bookmarks on the last few attempts. Nothing has been
       changed on either side. It will try again when you next add or change a bookmark,
       or you can try now.`;

  const actionLabel = isFull ? 'Move my bookmarks' : 'Try again';

  const card = document.createElement('div');
  card.className = 'sync-notice-card sync-failed-card';
  card.innerHTML = `
    <div class="sync-notice-row">
      <div class="sync-notice-text">
        <div class="sync-notice-title">${title}</div>
        <div class="sync-notice-body">${body}</div>
        ${syncFailure.detail && !isFull
          ? `<div class="sync-notice-summary">${escapeHtml(syncFailure.detail)}</div>`
          : ''}
      </div>
    </div>
    <div class="sync-notice-actions">
      <button class="sync-notice-review-btn" id="syncFailedAction">${actionLabel}</button>
      <button class="sync-notice-dismiss-btn" id="syncFailedDismiss">Not now</button>
    </div>
  `;
  container.appendChild(card);

  // Deferred like the cards around it: the element is in the DOM but the rest of
  // the render is still running.
  setTimeout(() => {
    document.getElementById('syncFailedAction')?.addEventListener('click', async () => {
      if (isFull) {
        window.showSnippetSetup?.('stopped');
        return;
      }
      // Retry through the normal reconcile. Success clears the flag and the card
      // disappears on the next render.
      try {
        await window.reconcileWithSnippet?.();
        await loadSyncFailureState();
        renderBookmarks();
      } catch (error) {
        console.error('[CloudSync] Retry failed:', error);
        showToast(`Still failing: ${error.message}`, 'error');
      }
    });

    // Dismissal lasts until the next new failure. The flag itself is untouched,
    // so the toolbar badge and the sync button keep saying something is wrong.
    document.getElementById('syncFailedDismiss')?.addEventListener('click', () => {
      syncFailureDismissed = true;
      renderBookmarks();
    });
  }, 0);
}

/* [ZeroLabs] 2026-09-07 9:20 PM - added: offer the move before the snippet dies */
// A card rather than a dialog, matching the deferred-sync notice above. A modal
// that opens itself on every launch is what that card was built to replace, and
// this is not urgent yet: it is a warning about a limit that has not been hit.
//
// The modal is still used for the store that has ALREADY stopped accepting
// writes, because that one is blocking and interrupting is honest there.
function shouldOfferMigration() {
  if (!migrationOffer.connected) return false;
  if (migrationOffer.onProject) return false;
  return Date.now() >= migrationOffer.snoozedUntil;
}

function renderMigrationCard(container) {
  if (!shouldOfferMigration()) return;

  const card = document.createElement('div');
  card.className = 'sync-notice-card migration-notice-card';
  card.innerHTML = `
    <div class="sync-notice-row">
      <div class="sync-notice-text">
        <div class="sync-notice-title">Cloud Sync Migration</div>
        <div class="sync-notice-body">
          Your bookmarks are currently synced to a GitLab snippet, which has a storage limit
          that counts every past version of your bookmarks rather than just the current one.
          A large collection reaches that limit eventually, and syncing then stops. To prevent
          this from happening, BMZ will migrate from Snippets to a GitLab repository. This
          takes about a minute and nothing is lost.
        </div>
      </div>
    </div>
    <div class="sync-notice-actions">
      <button class="sync-notice-review-btn" id="migrationCardStart">Migrate now</button>
      <button class="sync-notice-dismiss-btn" id="migrationCardDismiss">Not now</button>
    </div>
  `;
  container.appendChild(card);

  // Deferred for the same reason the sync notice defers: the element is in the
  // DOM but the rest of the render is still running.
  setTimeout(() => {
    document.getElementById('migrationCardStart')?.addEventListener('click', () => {
      window.showSnippetSetup?.('migrate');
    });

    // Snoozed rather than silenced. The limit does not go away, so asking again
    // in a week is the honest behaviour, and it is quiet enough not to nag.
    document.getElementById('migrationCardDismiss')?.addEventListener('click', async () => {
      migrationOffer.snoozedUntil = Date.now() + MIGRATION_SNOOZE_MS;
      await browser.storage.local.set({ bmz_migration_snoozed_until: migrationOffer.snoozedUntil });
      renderBookmarks();
    });
  }, 0);
}

/* [ZeroLabs] 2026-08-27 - added: name the numbers on the card */
// The card used to say only "found differences", which told you nothing about
// whether this was worth opening now or after dinner. Added as its own line
// rather than folded into the sentence above, so the agreed wording is untouched.
function syncNoticeSummary(counts) {
  const n = (c, one, many) => `${c} ${c === 1 ? one : many}`;
  const parts = [];
  if (counts.fromSnippet > 0) parts.push(n(counts.fromSnippet, 'bookmark', 'bookmarks') + ' to remove from your cloud bookmarks');
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
          BMZ found differences between your cloud bookmarks and this device that need
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
      /* [ZeroLabs] 2026-09-07 10:05 PM - edited: a click always gets an answer */
      window.showHeldPushDialog?.(true);
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
/* [ZeroLabs] 2026-09-22 7:41 PM - added: everything inside a folder, at any depth (see also: Bookmark-Manager-Zero-Chrome/sidepanel.js, Bookmark-Manager-Zero-Website/js/sidebar-adapted.js) */
// Bookmarks AND subfolders, so the whole contents can be moved or deleted in
// one action. The folder itself is not included: the point is to act on what
// is inside it, and its own row is already selectable.
//
// Both bulk actions must therefore cope with a folder and its children being
// ticked together. bulkDeleteItems already drops anything contained by another
// selection, and bulkMoveItems now does the same.
function collectContentIdsInFolder(folder) {
  const ids = [];

  const walk = (node) => {
    if (!node) return;
    ids.push(node.id);
    if (Array.isArray(node.children)) node.children.forEach(walk);
  };

  (folder.children || []).forEach(walk);
  return ids;
}

/* [ZeroLabs] 2026-09-22 7:42 PM - added: select or deselect everything in one folder */
// Until now the only choices were everything visible, the folder as a single
// item, or one bookmark at a time.
//
// The same button clears the folder again. It deselects only when every item
// inside is already selected, so pressing it on a partly selected folder
// completes the selection rather than throwing away what is ticked.
function toggleSelectAllInFolder(folder) {
  const ids = collectContentIdsInFolder(folder);

  if (ids.length === 0) {
    showToast('This folder is empty.');
    return;
  }

  const allSelected = ids.every(id => selectedItems.has(id));

  ids.forEach(id => {
    if (allSelected) {
      selectedItems.delete(id);
    } else {
      selectedItems.add(id);
    }
    // Only rows on screen have a checkbox to tick. A collapsed folder's
    // contents change all the same, and render correctly when it opens,
    // because the checkbox is drawn from selectedItems.
    const checkbox = bookmarkList.querySelector(`.item-checkbox[data-id="${id}"]`);
    if (checkbox) checkbox.checked = !allSelected;
  });

  updateSelectedCount();
}

function createFolderElement(folder) {
  const folderDiv = document.createElement('div');
  folderDiv.className = 'folder-item';
  folderDiv.dataset.id = folder.id;
  // Don't make the entire folderDiv draggable - only the header will be draggable

  const isExpanded = expandedFolders.has(folder.id);
  const childCount = countBookmarks(folder);

  const folderTitle = folder.title || 'Unnamed Folder';

  folderDiv.innerHTML = `
    <div class="folder-header" role="button" aria-expanded="${isExpanded}" aria-label="${escapeHtml(folderTitle)} folder with ${childCount} items">
      ${multiSelectMode ? `<input type="checkbox" class="item-checkbox" data-id="${folder.id}" ${selectedItems.has(folder.id) ? 'checked' : ''} aria-label="Select ${escapeHtml(folderTitle)} folder">` : ''}
      <!-- [ZeroLabs] 2026-09-22 7:32 PM - added: select every bookmark in this folder -->
      ${multiSelectMode ? `<button class="bookmark-menu-btn folder-select-all-btn" title="Select or deselect everything in this folder" aria-label="Select or deselect everything in ${escapeHtml(folderTitle)} folder"><svg width="14" height="14" fill="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path d="M0.41,13.41L6,19L7.41,17.58L1.83,12M22.24,5.58L11.66,16.17L7.5,12L6.07,13.41L11.66,19L23.66,7M18,7L16.59,5.58L10.24,11.93L11.66,13.34L18,7Z"/></svg></button>` : ''}
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
    /* [ZeroLabs] 2026-09-22 7:32 PM - edited: the select-all button is not a row click */
    if (e.target.closest('.folder-menu-btn') ||
        e.target.closest('.folder-select-all-btn') ||
        e.target.closest('.item-checkbox')) {
      return;
    }
    /* [ZeroLabs] 2026-09-22 7:46 PM - removed: the row no longer selects the folder */
    // Multi-select mode used to turn the whole folder row into a checkbox, so
    // the folder could not be opened or closed while selecting. Browsing is
    // exactly what a user needs while building a selection. The checkbox at the
    // left selects the folder, and it returns above before reaching here.
    toggleFolder(folder.id, folderDiv);
  });

  // Add menu button handler
  menuBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    toggleFolderMenu(folder);
  });

  /* [ZeroLabs] 2026-09-22 7:32 PM - added: the select-all-in-folder button */
  // Wired like the menu button above. The website needs a capture-phase and
  // touchend version of this for the Android WebView; the sidebar does not.
  const selectAllBtn = header.querySelector('.folder-select-all-btn');
  if (selectAllBtn) {
    selectAllBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      toggleSelectAllInFolder(folder);
    });
  }

  // Add right-click context menu support for folder
  folderDiv.addEventListener('contextmenu', (e) => {
    e.preventDefault();
    e.stopPropagation();
    /* [ZeroLabs] 2026-09-22 7:17 PM - added: a touch hold selects, it does not open the menu */
    // On a touch screen the platform raises contextmenu for a press and hold,
    // which is the same gesture that enters multi-select with a mouse. The
    // mouse path is a 750 ms timer on mousedown, and touch never gets there:
    // the emulated mouse events arrive after the gesture, if at all. So the
    // contextmenu event IS the hold, and it enters multi-select instead. The
    // hamburger button still opens this menu on a tap.
    if (window.isTouchPointer && window.isTouchPointer() && window.enterMultiSelectFromLongPress) {
      window.enterMultiSelectFromLongPress(e.target);
      return;
    }
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
  /* [ZeroLabs] 2026-09-23 1:22 AM - edited: BMZ's pointer drag replaces the native one */
  bookmarkDiv.draggable = false;

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
    /* [ZeroLabs] 2026-09-22 7:17 PM - added: a touch hold selects, it does not open the menu */
    // See the folder handler for why the contextmenu event is the touch hold.
    if (window.isTouchPointer && window.isTouchPointer() && window.enterMultiSelectFromLongPress) {
      window.enterMultiSelectFromLongPress(e.target);
      return;
    }
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
/* [ZeroLabs] 2026-09-22 7:57 PM - edited: one scroll loop, a wider zone and a real speed (see also: Bookmark-Manager-Zero-Firefox/sidebar.js, Bookmark-Manager-Zero-Website/js/sidebar-adapted.js) */
// The list barely moved, and the cause was the loop rather than the numbers.
// startDragScroll cancelled the pending animation frame and scheduled a new one
// on EVERY dragover. While the pointer moves, dragover fires faster than the
// frame rate, so the callback was cancelled before it could ever run and the
// list only crept along while the pointer was still.
//
// Now one loop runs for the whole drag and reads a speed variable, so the
// pointer's event rate cannot starve it. The zone was also a fixed 60px, which
// is hard to sit inside on a phone, and the cap of 20px per frame was low.
let dragScrollFrame = null;
let dragScrollSpeed = 0;
let isDragging = false;

document.addEventListener('dragstart', () => { isDragging = true; }, true);
document.addEventListener('dragend', () => { isDragging = false; stopDragScroll(); }, true);
document.addEventListener('drop', () => { isDragging = false; stopDragScroll(); }, true);

document.addEventListener('dragover', (e) => {
  if (!isDragging) return;

  /* [ZeroLabs] 2026-09-22 9:33 PM - removed: accepting the drag here (reverted) */
  // Calling preventDefault and setting dropEffect from this capture-phase
  // handler made the crossed-circle cursor show for the WHOLE drag instead of
  // fixing it, so it is gone. Do not reintroduce it here.

  updateDragScrollFromPointer(e.clientX, e.clientY);
}, true);

/* [ZeroLabs] 2026-09-22 9:58 PM - removed: three attempts to control the drag cursor */
// Accepting the drag from a document capture listener, from a bookmarkList
// bubble listener, and from a document bubble listener all failed to change the
// crossed-circle cursor. Measurement showed the rows already accept the drag
// with effectAllowed=move and dropEffect=move, so the cursor in the side panel
// is not being decided by drop acceptance the way the spec describes.
//
// Nothing here now. The pointer drag engine removes the question entirely,
// because a pointer drag has no browser-drawn drag cursor at all.


/* [ZeroLabs] 2026-09-22 8:20 PM - edited: one speed, one band, and nothing outside the list */
// Rewritten to Zero's description after two wrong attempts.
//
// The speed was a curve, so it changed with every pixel of pointer movement and
// full speed existed only in a narrow strip he had to hunt for. It is now ONE
// speed: anywhere in the band scrolls at exactly that rate. Nothing ramps,
// nothing accelerates, and there is no dependence on the list's length.
//
// The pointer leaving the list vertically stops the scroll. Scrolling while
// over the toolbar was my own idea and he did not want it.
/* [ZeroLabs] 2026-09-22 8:26 PM - edited: the band is a third of the list, not 90 pixels */
// 90 pixels is a sliver on a tall panel, so the full speed was only reachable
// by putting the cursor on the very edge and hunting for it. The band is now a
// third of the visible list at each end, with a floor for a short panel. The
// middle third still does nothing, which is what makes a precise drop possible.
/* [ZeroLabs] 2026-09-22 9:14 PM - edited: the dead middle is guaranteed by construction */
// The previous version set each band to half the list, so the top and bottom
// bands met in the centre and there was no neutral area left: hovering in the
// middle scrolled. The dead middle is now the thing that is defined first, and
// the bands are whatever is left over, so it can never be squeezed out again.
//
// The steps inside a band stay weighted rather than equal, so the slow speed
// owns the first half of the band and the top speed needs a deliberate move to
// the edge.
const DRAG_SCROLL_DEAD_RATIO = 0.3;   // share of the list that never scrolls
const DRAG_SCROLL_ZONE_MIN_PX = 120;
const DRAG_SCROLL_DEAD_MIN_PX = 80;   // a short panel still keeps a neutral middle

// Depth into the band where the middle speed starts. The top speed is not a
// depth: it is the edge strip defined below.
const DRAG_SCROLL_STEP_2_AT = 0.5;

/* [ZeroLabs] 2026-09-22 9:01 PM - edited: three steps, and the top one is 80 percent of before */
// The band is split into three equal depths and each one has its own fixed
// speed. Within a step nothing changes, so the list travels at a rate the user
// chose rather than one that drifts with every pixel of pointer movement.
//
/* [ZeroLabs] 2026-09-22 9:20 PM - edited: Zero's speeds, and the top one is an edge strip */
// The top speed is no longer a share of the band. It is the outermost 5 percent
// of the list, measured from the edge, so it is reached only by pushing right
// to the end rather than by being deep in the band.
const DRAG_SCROLL_SPEEDS_PX = [3, 8, 15];        // entering the band, mid depth, at the edge
const DRAG_SCROLL_TOP_SPEED_RATIO = 0.05;        // outermost share of the list that gets the top speed

function dragScrollSpeedFor(distanceFromEdge, zone, listHeight) {
  // The top speed is a strip measured from the edge of the list itself
  if (distanceFromEdge <= listHeight * DRAG_SCROLL_TOP_SPEED_RATIO) {
    return DRAG_SCROLL_SPEEDS_PX[2];
  }

  const depth = Math.min(1, Math.max(0, (zone - distanceFromEdge) / zone));
  if (depth < DRAG_SCROLL_STEP_2_AT) return DRAG_SCROLL_SPEEDS_PX[0];
  return DRAG_SCROLL_SPEEDS_PX[1];
}

function updateDragScrollFromPointer(clientX, clientY) {
  const rect = bookmarkList.getBoundingClientRect();

  // Take the neutral middle out first, then split what remains between the two
  // ends. The second clamp is what stops a tall band from eating the middle.
  const wantedZone = Math.max(DRAG_SCROLL_ZONE_MIN_PX, rect.height * (1 - DRAG_SCROLL_DEAD_RATIO) / 2);
  const largestZone = (rect.height - DRAG_SCROLL_DEAD_MIN_PX) / 2;
  const zone = Math.max(0, Math.min(wantedZone, largestZone));

  const insideList =
    clientY >= rect.top && clientY <= rect.bottom &&
    clientX >= rect.left && clientX <= rect.right;

  if (!insideList) {
    setDragScrollSpeed(0);
    return;
  }

  const fromTop = clientY - rect.top;
  const fromBottom = rect.bottom - clientY;

  if (fromTop < zone) {
    setDragScrollSpeed(-dragScrollSpeedFor(fromTop, zone, rect.height));
    return;
  }

  if (fromBottom < zone) {
    setDragScrollSpeed(dragScrollSpeedFor(fromBottom, zone, rect.height));
    return;
  }

  setDragScrollSpeed(0);
}

/* [ZeroLabs] 2026-09-22 8:38 PM - edited: a timer, because rAF is starved during a drag */
// Measured from Zero's console: with the speed correctly set to 45 pixels per
// frame, scrollTop moved 9 pixels in 200 milliseconds. Sixty frames a second
// would have moved about 540. Chromium throttles requestAnimationFrame while a
// native drag is in progress, so the loop ran roughly once per 200ms.
//
// This is why the original autoscroll always felt slow and why changing the
// distances and speeds never helped: the numbers were never the problem, the
// callback was. setInterval keeps its rate during a drag.
const DRAG_SCROLL_TICK_MS = 16;

function setDragScrollSpeed(speed) {
  dragScrollSpeed = speed;

  if (speed === 0) {
    stopDragScroll();
    return;
  }
  // The timer is already running, and it reads the speed on every tick
  if (dragScrollFrame) return;

  dragScrollFrame = setInterval(() => {
    if (!dragScrollSpeed) {
      stopDragScroll();
      return;
    }
    /* [ZeroLabs] 2026-09-22 8:52 PM - edited: bypass the smooth scrolling on the list */
    // #bookmarkList carries scroll-behavior: smooth (sidebar.html:668). A
    // plain scrollTop write is therefore an ANIMATION request, and writing a
    // new one every tick restarts that animation before it has gone anywhere.
    // Measured: 9 pixels in 200ms with the speed set to 45 per tick, which is
    // why no distance or speed I changed ever made a difference. Asking for an
    // instant scroll is what makes the write land.
    bookmarkList.scrollTo({
      top: bookmarkList.scrollTop + dragScrollSpeed,
      behavior: 'instant'
    });
  }, DRAG_SCROLL_TICK_MS);
}

function stopDragScroll() {
  dragScrollSpeed = 0;
  if (dragScrollFrame) {
    clearInterval(dragScrollFrame);
    dragScrollFrame = null;
  }
}


// ============================================================================
/* [ZeroLabs] 2026-09-22 9:14 PM - added: BMZ's own drag, replacing native HTML5 drag */
// Native drag never carried anything but an internal id, and it cost three
// things: the wheel cannot scroll during a native drag (Chromium 41272694, and Firefox is no better),
// touch never starts one at all so Android could not reorder, and the browser
// draws its own drop cursor which no amount of preventDefault would change.
//
// Owning the drag removes all three. The DROP RULES ARE UNCHANGED and still go
// through handleDrop, handleDropToRoot, pinBookmark and reorderQuickAccess: a
// bookmark row is before or after by its midpoint, a folder header is before or
// into, the root zone appends, a Quick Access row reorders pins, and the Quick
// Access body pins a bookmark from the tree.
//
// FIRST CUT IS MOUSE AND PEN ONLY. Touch needs a long press to tell a drag from
// a scroll, and that lands with the website port.
//
// The native dragstart/dragover/drop listeners on rows, headers and zones are
// now inert, because nothing sets draggable any more. They are left in place
// for this round and come out once Zero confirms the engine.
// ============================================================================

const BMZ_DRAG_THRESHOLD_PX = 5;

const bmzDrag = {
  candidate: null,
  active: false,
  kind: null,        // 'tree' | 'tree-folder' | 'quick-access'
  payload: null,     // bookmark or folder id, or a pin key
  sourceEl: null,
  ghost: null,
  grabX: 0,
  grabY: 0,
  target: null       // { el, mode, id }
};

function bmzClearDropIndicators() {
  removeAllDropIndicators();
  document.querySelectorAll('.qa-drop-before, .qa-drop-after').forEach(el => {
    el.classList.remove('qa-drop-before', 'qa-drop-after');
  });
  document.querySelectorAll('.bmz-section-drop-target').forEach(el => {
    el.classList.remove('bmz-section-drop-target');
  });
  document.querySelectorAll('.root-drop-zone.drop-active').forEach(el => {
    el.classList.remove('drop-active');
  });
}

// What is under the pointer, and which half of it. The ghost carries
// pointer-events: none, so it is never the answer.
function bmzResolveDropTarget(x, y) {
  const el = document.elementFromPoint(x, y);
  if (!el) return null;

  const half = (element) => {
    const rect = element.getBoundingClientRect();
    return y < rect.top + rect.height / 2;
  };

  if (bmzDrag.kind === 'quick-access') {
    const row = el.closest('.bookmark-item[data-pin-key]');
    if (!row || row === bmzDrag.sourceEl) return null;
    return { el: row, mode: half(row) ? 'qa-before' : 'qa-after', id: row.dataset.pinKey };
  }

  // Pins are mirrors, so only a real tree bookmark can be dropped into them
  const sectionBody = el.closest('.bmz-section-body');
  if (sectionBody) {
    if (bmzDrag.kind !== 'tree') return null;
    if (!sectionBody.querySelector('.bookmark-item[data-pin-key]') &&
        !sectionBody.querySelector('.bmz-section-empty')) return null;
    return { el: sectionBody, mode: 'pin' };
  }

  const header = el.closest('.folder-header');
  if (header) {
    const folderDiv = header.closest('.folder-item');
    if (!folderDiv) return null;
    // Dropping a folder onto itself does nothing
    if (bmzDrag.sourceEl && folderDiv === bmzDrag.sourceEl.closest('.folder-item')) return null;
    return { el: folderDiv, mode: half(header) ? 'before' : 'into', id: folderDiv.dataset.id };
  }

  const row = el.closest('.bookmark-item:not(.bookmark-item-mirror)');
  if (row) {
    if (row === bmzDrag.sourceEl) return null;
    return { el: row, mode: half(row) ? 'before' : 'after', id: row.dataset.id };
  }

  const rootZone = el.closest('.root-drop-zone');
  if (rootZone) return { el: rootZone, mode: 'root' };

  return null;
}

function bmzPaintDropTarget(target) {
  bmzClearDropIndicators();
  if (!target) return;

  if (target.mode === 'before') target.el.classList.add('drop-before');
  else if (target.mode === 'after') target.el.classList.add('drop-after');
  else if (target.mode === 'into') target.el.classList.add('drop-into');
  else if (target.mode === 'qa-before') target.el.classList.add('qa-drop-before');
  else if (target.mode === 'qa-after') target.el.classList.add('qa-drop-after');
  else if (target.mode === 'pin') target.el.classList.add('bmz-section-drop-target');
  else if (target.mode === 'root') target.el.classList.add('drop-active');
}

function bmzBeginDrag(clientX, clientY) {
  const candidate = bmzDrag.candidate;
  if (!candidate) return;

  bmzDrag.active = true;
  bmzDrag.kind = candidate.kind;
  bmzDrag.payload = candidate.payload;
  bmzDrag.sourceEl = candidate.el;
  bmzDrag.target = null;

  // The old handlers read this to decide what to accept, and handleDrop still
  // refuses a quick-access drag, so it has to be set exactly as before.
  dragContext = candidate.kind;
  isDragging = true;

  const rect = candidate.el.getBoundingClientRect();
  bmzDrag.grabX = candidate.startX - rect.left;
  bmzDrag.grabY = candidate.startY - rect.top;

  const ghost = candidate.el.cloneNode(true);
  ghost.classList.add('bmz-drag-ghost');
  /* [ZeroLabs] 2026-09-22 9:22 PM - added: the clone must not animate its own position */
  // .bookmark-item has transition: all 0.3s (sidepanel.html:1002), which the
  // clone inherits, so every transform update eased over 300ms and the ghost
  // lagged and wallowed behind the cursor instead of tracking it.
  ghost.style.transition = 'none';
  ghost.style.animation = 'none';
  ghost.style.willChange = 'transform';
  ghost.style.position = 'fixed';
  ghost.style.left = '0';
  ghost.style.top = '0';
  ghost.style.width = `${rect.width}px`;
  ghost.style.margin = '0';
  ghost.style.pointerEvents = 'none';
  ghost.style.opacity = '0.9';
  ghost.style.zIndex = '10050';
  ghost.style.borderRadius = '8px';
  ghost.style.boxShadow = '0 10px 28px rgba(0, 0, 0, 0.5)';
  ghost.style.background = 'var(--md-sys-color-surface-variant, #2a2a2a)';
  document.body.appendChild(ghost);
  bmzDrag.ghost = ghost;

  candidate.el.style.opacity = '0.4';
  document.body.style.userSelect = 'none';
  // The whole panel keeps the move cursor, because we draw it now
  document.body.style.cursor = 'grabbing';

  bmzMoveGhost(clientX, clientY);
}

function bmzMoveGhost(clientX, clientY) {
  if (!bmzDrag.ghost) return;
  const x = clientX - bmzDrag.grabX;
  const y = clientY - bmzDrag.grabY;
  bmzDrag.ghost.style.transform = `translate(${x}px, ${y}px)`;
}

function bmzUpdateDrag(clientX, clientY) {
  bmzMoveGhost(clientX, clientY);
  bmzDrag.target = bmzResolveDropTarget(clientX, clientY);
  bmzPaintDropTarget(bmzDrag.target);
  updateDragScrollFromPointer(clientX, clientY);
}

async function bmzFinishDrag() {
  const target = bmzDrag.target;
  const kind = bmzDrag.kind;
  const payload = bmzDrag.payload;

  bmzEndDrag();
  if (!target || !payload) return;

  try {
    if (kind === 'quick-access') {
      if (target.id && target.id !== payload) {
        await reorderQuickAccess(payload, target.id, target.mode === 'qa-before');
      }
      return;
    }

    if (target.mode === 'pin') {
      const item = findBookmarkById(bookmarkTree, payload);
      if (item && item.url) await pinBookmark(item);
      return;
    }

    if (target.mode === 'root') {
      await handleDropToRoot(payload);
      return;
    }

    await handleDrop(payload, target.id, target.el, {
      dropBefore: target.mode === 'before',
      dropAfter: target.mode === 'after',
      dropInto: target.mode === 'into'
    });
  } catch (error) {
    console.error('[BMZDrag] Drop failed:', error);
  }
}

function bmzEndDrag() {
  if (bmzDrag.sourceEl) bmzDrag.sourceEl.style.opacity = '1';
  if (bmzDrag.ghost) bmzDrag.ghost.remove();

  bmzClearDropIndicators();
  stopDragScroll();

  document.body.style.userSelect = '';
  document.body.style.cursor = '';

  dragContext = null;
  isDragging = false;

  bmzDrag.candidate = null;
  bmzDrag.active = false;
  bmzDrag.kind = null;
  bmzDrag.payload = null;
  bmzDrag.sourceEl = null;
  bmzDrag.ghost = null;
  bmzDrag.target = null;
}

// A press on a row is only a CANDIDATE. It becomes a drag after the pointer
// has moved far enough, so an ordinary click still opens the bookmark.
document.addEventListener('pointerdown', (e) => {
  // A drag that ended without a click must not swallow a later real one
  bmzSuppressNextClick = false;

  if (bmzDrag.active) return;
  if (e.pointerType === 'touch') return;   // touch lands with the website port
  if (e.button !== 0) return;

  const el = e.target instanceof Element ? e.target : null;
  if (!el) return;
  if (el.closest('.bookmark-menu-btn, .folder-menu-btn, .folder-select-all-btn, .item-checkbox, input, button, a')) return;

  const qaRow = el.closest('.bookmark-item[data-pin-key]');
  if (qaRow) {
    bmzDrag.candidate = {
      el: qaRow, kind: 'quick-access', payload: qaRow.dataset.pinKey,
      startX: e.clientX, startY: e.clientY
    };
    return;
  }

  // A Recently Opened row is a mirror with no pin key, and is not draggable
  if (el.closest('.bookmark-item-mirror')) return;

  const header = el.closest('.folder-header');
  if (header) {
    const folderDiv = header.closest('.folder-item');
    if (!folderDiv) return;
    bmzDrag.candidate = {
      el: folderDiv, kind: 'tree-folder', payload: folderDiv.dataset.id,
      startX: e.clientX, startY: e.clientY
    };
    return;
  }

  const row = el.closest('.bookmark-item');
  if (row) {
    bmzDrag.candidate = {
      el: row, kind: 'tree', payload: row.dataset.id,
      startX: e.clientX, startY: e.clientY
    };
  }
}, true);

document.addEventListener('pointermove', (e) => {
  if (bmzDrag.active) {
    e.preventDefault();
    bmzUpdateDrag(e.clientX, e.clientY);
    return;
  }

  const candidate = bmzDrag.candidate;
  if (!candidate) return;

  const dx = e.clientX - candidate.startX;
  const dy = e.clientY - candidate.startY;
  if (Math.sqrt(dx * dx + dy * dy) < BMZ_DRAG_THRESHOLD_PX) return;

  bmzBeginDrag(e.clientX, e.clientY);
  bmzUpdateDrag(e.clientX, e.clientY);
});

/* [ZeroLabs] 2026-09-22 9:27 PM - added: a drag must not end in a click */
// Releasing the pointer over a row fires a click there, which opened the
// bookmark that had just been dropped. The click that follows a drag is
// swallowed once, in the capture phase, before any row handler sees it.
let bmzSuppressNextClick = false;

document.addEventListener('pointerup', () => {
  if (bmzDrag.active) {
    bmzSuppressNextClick = true;
    bmzFinishDrag();
    return;
  }
  bmzDrag.candidate = null;
});

document.addEventListener('click', (e) => {
  if (!bmzSuppressNextClick) return;
  bmzSuppressNextClick = false;
  e.preventDefault();
  e.stopPropagation();
}, true);

document.addEventListener('pointercancel', () => {
  if (bmzDrag.active) bmzEndDrag();
  bmzDrag.candidate = null;
});

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && bmzDrag.active) bmzEndDrag();
});

/* [ZeroLabs] 2026-09-22 9:14 PM - added: the wheel, which is the point of all this */
// A pointer drag is not a native drag, so the wheel arrives normally and the
// list scrolls while an item is in hand.
const BMZ_DRAG_WHEEL_MULTIPLIER = 1;

document.addEventListener('wheel', (e) => {
  if (!bmzDrag.active) return;
  e.preventDefault();
  bookmarkList.scrollTo({
    top: bookmarkList.scrollTop + e.deltaY * BMZ_DRAG_WHEEL_MULTIPLIER,
    behavior: 'instant'
  });
  bmzUpdateDrag(e.clientX, e.clientY);
}, { passive: false });

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
    /* [ZeroLabs] 2026-09-23 1:00 AM - removed: the 2000 entry cap (see also: background.js) */
    // This one is the likeliest of all three to hit it: deleting a folder walks
    // its whole subtree in one go. An eviction would drop the record that says
    // this device did the deleting, and the next sync would put those bookmarks
    // straight back.
    await safeStorage.set({
      snippet_local_deleted: Array.from(deleted),
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
/* [ZeroLabs] 2026-09-22 6:54 PM - edited: returns what it removed instead of logging it */
// Its one caller now gathers the whole approved sync into a single changelog
// entry, so the folders this takes belong in that entry rather than in one
// 'delete' entry each. The array is ordered deepest first, the order the chain
// is walked; a restore has to recreate them in reverse.
async function pruneEmptyFolderChain(startId) {
  const rootFolderIds = ['toolbar_____', 'menu________', 'unfiled_____', 'mobile______', 'root________'];
  const pruned = [];
  let id = startId;

  // The chain is walked upward, so a bad parentId must not spin forever
  for (let guard = 0; id && guard < 50; guard++) {
    if (rootFolderIds.includes(id)) return pruned;

    let node;
    try {
      [node] = await browser.bookmarks.get(id);
    } catch (error) {
      return pruned; // Already gone
    }
    if (!node || node.url) return pruned;
    if (!node.parentId || rootFolderIds.includes(node.id)) return pruned;

    const children = await browser.bookmarks.getChildren(id);
    if (children.length > 0) return pruned;

    const fullData = JSON.parse(JSON.stringify(node));
    // Safe as a plain remove rather than removeTree: it has just been proven empty
    await browser.bookmarks.remove(id);
    pruned.push({ title: node.title || 'Unnamed Folder', fullData });

    id = node.parentId;
  }

  return pruned;
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
/* [ZeroLabs] 2026-09-23 12:43 AM - added: the move dialog's folder tree */
// populateFolderDropdown flattens the whole hierarchy into one list and fakes
// the structure by padding titles with spaces. Turn the alphabetical sort on
// and that flat array is reordered across every depth at once, so a subfolder
// can sit above its own parent while still carrying indentation that no longer
// means anything.
//
// This renders the real tree instead: collapsed by default, one row per folder,
// the twisty as its own hit area so opening a folder never selects it. The
// hidden select still holds the value, so every caller that reads
// moveToFolder.value is untouched.
const moveFolderTree = { expanded: new Set() };

/* [ZeroLabs] 2026-09-23 12:52 AM - edited: one picker for every dialog */
// The panel is passed in rather than looked up, so the move dialog, the add
// forms and anything else built later all share this and cannot drift into
// different folder pickers again. The expanded state is deliberately shared:
// opening a branch in one dialog leaves it open in the next.
function renderFolderTree(selectElement, panel, options = {}) {
  if (!panel || !selectElement) return;

  /* [ZeroLabs] 2026-09-23 1:12 AM - removed: the alphabetical sort option */
  // The tree shows the real hierarchy in the real order, so re-sorting it was
  // the flat list's crutch and is gone from every picker.
  const excluded = options.excluded || new Set();
  panel.innerHTML = '';

  const twistySvg = '<svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M8.59,16.58L13.17,12L8.59,7.41L10,6L16,12L10,18L8.59,16.58Z"/></svg>';

  const addRows = (nodes, depth) => {
    if (!Array.isArray(nodes)) return;

    const folders = nodes.filter(node => node.children && !excluded.has(node.id));

    folders.forEach(folder => {
      const hasChildFolders = (folder.children || []).some(
        child => child.children && !excluded.has(child.id)
      );
      const isExpanded = moveFolderTree.expanded.has(folder.id);

      const row = document.createElement('div');
      row.className = 'folder-tree-row';
      row.dataset.folderId = folder.id;
      row.setAttribute('role', 'treeitem');
      row.style.paddingLeft = `${6 + depth * 14}px`;
      if (folder.id === selectElement.value) row.classList.add('selected');

      const twisty = document.createElement('span');
      twisty.className = `folder-tree-twisty${hasChildFolders ? '' : ' leaf'}${isExpanded ? ' expanded' : ''}`;
      twisty.innerHTML = twistySvg;
      if (hasChildFolders) {
        twisty.addEventListener('click', (e) => {
          e.stopPropagation();
          if (isExpanded) {
            moveFolderTree.expanded.delete(folder.id);
          } else {
            moveFolderTree.expanded.add(folder.id);
          }
          renderFolderTree(selectElement, panel, options);
        });
      }

      /* [ZeroLabs] 2026-09-23 3:10 PM - added: the sidebar's folder icon, with its count */
      // The same outline and the same number the sidebar draws, so a folder
      // looks like itself wherever it appears. countBookmarks is the sidebar's
      // own counter, so the two can never disagree: it counts bookmarks all the
      // way down, subfolders included. The icon is smaller here because these
      // rows are compact, and .folder-tree-icon scales the digits to match.
      const icon = document.createElement('span');
      icon.className = 'folder-tree-icon';
      icon.setAttribute('aria-hidden', 'true');
      const folderCount = countBookmarks(folder);
      icon.innerHTML = `
        <svg class="folder-icon-outline" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
          <path d="M3 7C3 5.89543 3.89543 5 5 5H9L11 7H19C20.1046 7 21 7.89543 21 9V17C21 18.1046 20.1046 19 19 19H5C3.89543 19 3 18.1046 3 17V7Z"/>
        </svg>
        <span class="folder-count" data-digits="${folderCount.toString().length}">${folderCount}</span>
      `;

      const name = document.createElement('span');
      name.className = 'folder-tree-name';
      name.textContent = folder.title || 'Unnamed Folder';

      row.appendChild(twisty);
      row.appendChild(icon);
      row.appendChild(name);
      row.addEventListener('click', () => {
        selectElement.value = folder.id;
        panel.querySelectorAll('.folder-tree-row').forEach(other => {
          other.classList.toggle('selected', other.dataset.folderId === folder.id);
        });
      });

      panel.appendChild(row);

      if (isExpanded) addRows(folder.children, depth + 1);
    });
  };

  // bookmarkTree is the array of root containers, which are folders themselves
  addRows(bookmarkTree, 0);
}

/* [ZeroLabs] 2026-09-23 1:02 AM - added: a folder tree for callers with no dialog of their own */
// Bulk move asked for a NUMBER typed into a prompt, against a list of every
// folder at every depth. This gives it, and anything else built later, the same
// tree the real dialogs use. Resolves to a folder id, or null if cancelled.
function pickFolderWithTree({ heading, excluded = new Set(), initialId = '' } = {}) {
  return new Promise((resolve) => {
    const modal = document.createElement('div');
    modal.style.cssText = 'position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.7); z-index: 10001; display: flex; align-items: center; justify-content: center;';

    const dialog = document.createElement('div');
    dialog.className = 'bmz-dialog';
    dialog.style.cssText = 'background: var(--md-sys-color-surface, #1e1e1e); padding: 20px; border-radius: 12px; max-width: 460px; width: 90%; color: var(--md-sys-color-on-surface, #e0e0e0);';

    dialog.innerHTML = `
      <h2 style="margin: 0 0 14px 0; font-size: 17px;">${escapeHtml(heading || 'Choose a folder')}</h2>
      <select id="bmzPickFolderValue" style="display: none;" aria-hidden="true"></select>
      <div id="bmzPickFolderTree" class="folder-tree-picker" role="tree" aria-label="Destination folder"></div>
      <div style="display: flex; gap: 10px; margin-top: 16px;">
        <button id="bmzPickFolderCancel" style="flex: 1; padding: 10px; border-radius: 8px; border: none; background: var(--md-sys-color-surface-variant, #2a2a2a); color: var(--md-sys-color-on-surface-variant, #aaa); cursor: pointer; font-size: 14px;">Cancel</button>
        <button id="bmzPickFolderConfirm" style="flex: 1; padding: 10px; border-radius: 8px; border: none; background: var(--md-sys-color-primary, #90caf9); color: var(--md-sys-color-on-primary, #000); cursor: pointer; font-size: 14px; font-weight: 600;">Move here</button>
      </div>
    `;

    modal.appendChild(dialog);
    document.body.appendChild(modal);

    const valueHolder = dialog.querySelector('#bmzPickFolderValue');
    const treePanel = dialog.querySelector('#bmzPickFolderTree');

    valueHolder.value = initialId || '';
    renderFolderTree(valueHolder, treePanel, { excluded });

    const close = (result) => {
      modal.remove();
      resolve(result);
    };

    dialog.querySelector('#bmzPickFolderCancel').addEventListener('click', () => close(null));
    dialog.querySelector('#bmzPickFolderConfirm').addEventListener('click', () => {
      if (!valueHolder.value) {
        showToast('Choose a destination folder first.');
        return;
      }
      close(valueHolder.value);
    });
  });
}

// Open every ancestor of a folder so it is on screen when the dialog opens
async function expandMoveTreeTo(folderId) {
  let current = folderId;

  for (let guard = 0; current && guard < 200; guard++) {
    let node;
    try {
      [node] = await browser.bookmarks.get(current);
    } catch (error) {
      return;
    }
    if (!node || !node.parentId) return;
    moveFolderTree.expanded.add(node.parentId);
    current = node.parentId;
  }
}

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

  /* [ZeroLabs] 2026-09-23 1:30 AM - edited: the shared folder tree, not a flat list (see also: Bookmark-Manager-Zero-Chrome/sidepanel.js) */
  // Same default as before, last used folder first, then the Bookmarks Menu.
  // It is now resolved against the real tree rather than against a list of
  // option elements, and the path to it is opened so it is visible.
  const treePanel = document.getElementById('newBookmarkFolderTree');
  const lastUsedFolder = localStorage.getItem('lastBookmarkFolder');
  let defaultFolderId = '';

  if (lastUsedFolder && findBookmarkById(bookmarkTree, lastUsedFolder)) {
    defaultFolderId = lastUsedFolder;
  } else {
    const allFolders = buildFolderList(bookmarkTree);
    const menuFolder = allFolders.find(folder =>
      folder.id.includes('menu') || folder.title.toLowerCase().includes('bookmarks menu')
    );
    defaultFolderId = (menuFolder && menuFolder.id) || (allFolders[0] && allFolders[0].id) || '';
  }

  folderSelect.value = defaultFolderId;
  if (defaultFolderId) await expandMoveTreeTo(defaultFolderId);
  renderFolderTree(folderSelect, treePanel);

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
/* [ZeroLabs] 2026-09-23 1:30 AM - edited: async, because the tree opens the path first */
async function openAddFolderModal() {
  const modal = document.getElementById('addFolderModal');
  const nameInput = document.getElementById('newFolderName');
  const parentSelect = document.getElementById('newFolderParent');

  nameInput.value = '';

  /* [ZeroLabs] 2026-09-23 1:30 AM - edited: the shared folder tree, not a flat list (see also: Bookmark-Manager-Zero-Chrome/sidepanel.js) */
  // Same default as before, last used parent first, then the Bookmarks Menu,
  // resolved against the real tree and with the path to it opened.
  const treePanel = document.getElementById('newFolderParentTree');
  const lastUsedParent = localStorage.getItem('lastFolderParent');
  let defaultParentId = '';

  if (lastUsedParent && findBookmarkById(bookmarkTree, lastUsedParent)) {
    defaultParentId = lastUsedParent;
  } else {
    const allFolders = buildFolderList(bookmarkTree);
    const menuFolder = allFolders.find(folder =>
      folder.id.includes('menu') || folder.title.toLowerCase().includes('bookmarks menu')
    );
    defaultParentId = (menuFolder && menuFolder.id) || (allFolders[0] && allFolders[0].id) || '';
  }

  parentSelect.value = defaultParentId;
  if (defaultParentId) await expandMoveTreeTo(defaultParentId);
  renderFolderTree(parentSelect, treePanel);

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

  // Show item name
  const itemLabel = isFolder ? `\uD83D\uDCC1 ${item.title || 'Unnamed Folder'}` : (item.title || 'Unnamed Bookmark');
  itemNameDisplay.textContent = itemLabel;

  /* [ZeroLabs] 2026-09-23 1:30 AM - edited: build the tree, not the flat list (see also: Bookmark-Manager-Zero-Chrome/sidepanel.js) */
  // The three rules the old dropdown enforced all survive, and they are now
  // stated once instead of being repeated in the sort handler: no Root, a
  // folder can never be moved inside itself, and the current parent starts
  // selected. The tree simply does not render an excluded folder at all, so
  // there is nothing to strip out afterwards.
  const excluded = new Set();
  if (isFolder) {
    try {
      const [subtree] = await browser.bookmarks.getSubTree(item.id);
      const collectIds = (node) => {
        if (!node) return;
        excluded.add(node.id);
        (node.children || []).forEach(collectIds);
      };
      collectIds(subtree);
    } catch (error) {
      console.error('Error collecting descendant folders:', error);
    }
  }

  // Start on the item's current parent, with the path to it already open
  const treePanel = document.getElementById('moveToFolderTree');
  folderSelect.value = item.parentId || '';
  if (item.parentId) await expandMoveTreeTo(item.parentId);
  renderFolderTree(folderSelect, treePanel, { excluded });

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

/* [ZeroLabs] 2026-09-24 6:30 AM - added: order the root folders by how full they are */
// Returns a NEW array of the root folders, most bookmarks first, counting
// everything inside their subfolders. Equal counts keep the browser's own
// order. Only the order of the roots changes; their contents are untouched.
function sortRootsByBookmarkCount(roots) {
  return roots
    .map((node, index) => ({ node, index, count: countBookmarks(node) }))
    .sort((a, b) => {
      if (b.count !== a.count) return b.count - a.count;
      return a.index - b.index;
    })
    .map(entry => entry.node);
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
        <p style="font-size: 14px;">No events recorded yet.</p>
        <p style="font-size: 12px; opacity: 0.7; margin-top: 8px;">Bookmark changes and errors will appear here.</p>
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
      /* [ZeroLabs] 2026-09-22 6:54 PM - added: a whole approved sync is one event */
      else if (entry.type === 'sync-apply') iconColor = '#f59e0b';
      /* [ZeroLabs] 2026-09-08 7:40 AM - added: errors are recorded here too */
      else if (entry.type === 'error') iconColor = '#ef4444';
      /* [ZeroLabs] 2026-09-13 - added: published notices are recorded here too */
      else if (entry.type === 'notice') iconColor = '#3b82f6';
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
      } else if (entry.type === 'notice') {
        icon = `<svg width="20" height="20" fill="currentColor" viewBox="0 0 24 24" style="color: ${iconColor};"><path d="M21,19V20H3V19L5,17V11C5,7.9 7.03,5.17 10,4.29C10,4.19 10,4.1 10,4A2,2 0 0,1 12,2A2,2 0 0,1 14,4C14,4.1 14,4.19 14,4.29C16.97,5.17 19,7.9 19,11V17L21,19M14,21A2,2 0 0,1 12,23A2,2 0 0,1 10,21"/></svg>`;
      } else if (entry.type === 'error') {
        icon = `<svg width="20" height="20" fill="currentColor" viewBox="0 0 24 24" style="color: ${iconColor};"><path d="M13,14H11V9H13M13,18H11V16H13M1,21H23L12,2L1,21Z"/></svg>`;
      } else if (entry.type === 'pre-sync-snapshot') {
        icon = `<svg width="20" height="20" fill="currentColor" viewBox="0 0 24 24" style="color: ${iconColor};"><path d="M12,18A6,6 0 0,1 6,12C6,11 6.25,10.03 6.7,9.2L5.24,7.74C4.46,8.97 4,10.43 4,12A8,8 0 0,0 12,20V23L16,19L12,15M12,4V1L8,5L12,9V6A6,6 0 0,1 18,12C18,13 17.75,13.97 17.3,14.8L18.76,16.26C19.54,15.03 20,13.57 20,12A8,8 0 0,0 12,4Z"/></svg>`;
      /* [ZeroLabs] 2026-09-22 6:54 PM - added: the approved-sync event */
      } else if (entry.type === 'sync-apply') {
        icon = `<svg width="20" height="20" fill="currentColor" viewBox="0 0 24 24" style="color: ${iconColor};"><path d="M19.35,10.04C18.67,6.59 15.64,4 12,4C9.11,4 6.6,5.64 5.35,8.04C2.34,8.36 0,10.91 0,14A6,6 0 0,0 6,20H19A5,5 0 0,0 24,15C24,12.36 21.95,10.22 19.35,10.04M10,17L6,13L7.41,11.59L10,14.17L16.59,7.58L18,9L10,17Z"/></svg>`;
      } else {
        icon = `<svg width="20" height="20" fill="currentColor" viewBox="0 0 24 24" style="color: ${iconColor};"><path d="M20.71,7.04C21.1,6.65 21.1,6 20.71,5.63L18.37,3.29C18,2.9 17.35,2.9 16.96,3.29L15.12,5.12L18.87,8.87M3,17.25V21H6.75L17.81,9.93L14.06,6.18L3,17.25Z"/></svg>`;
      }

      // SVG icons for item types (skip for sync snapshots)
      let itemIcon = '';
      /* [ZeroLabs] 2026-09-22 6:54 PM - edited: a sync event is not one item */
      if (entry.type !== 'pre-sync-snapshot' && entry.type !== 'error' &&
          entry.type !== 'notice' && entry.type !== 'sync-apply' && entry.itemType !== 'sync') {
        if (entry.itemType === 'folder') {
          itemIcon = `<svg width="16" height="16" fill="currentColor" viewBox="0 0 24 24" style="color: var(--md-sys-color-primary);"><path d="M10,4H4C2.89,4 2,4.89 2,6V18A2,2 0 0,0 4,20H20A2,2 0 0,0 22,18V8C22,6.89 21.1,6 20,6H12L10,4Z"/></svg>`;
        } else {
          itemIcon = `<svg width="16" height="16" fill="currentColor" viewBox="0 0 24 24" style="color: var(--md-sys-color-secondary);"><path d="M17,3H7A2,2 0 0,0 5,5V21L12,18L19,21V5C19,3.89 18.1,3 17,3Z"/></svg>`;
        }
      }

      let detailsHtml = '';
      if (entry.details) {
        if (entry.type === 'notice') {
          detailsHtml = `<div style="font-size: 11px; color: var(--md-sys-color-on-surface-variant); margin-top: 4px;">Announcement from BMZ</div>`;
        } else if (entry.type === 'error') {
          /* [ZeroLabs] 2026-09-08 7:40 AM - added: the frame is the useful half */
          // The message says what broke; this says where.
          //
          // Escaped locally, because this renderer does no escaping of its own and
          // an error message can carry anything, including markup from a request.
          const safe = (v) => String(v == null ? '' : v)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;')
            .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
          const where = entry.details.frame
            ? `<div style="font-size: 10px; color: var(--md-sys-color-on-surface-variant); margin-top: 4px; word-break: break-all; font-family: monospace;">${safe(entry.details.frame)}</div>`
            : '';
          detailsHtml = `<div style="font-size: 11px; color: var(--md-sys-color-on-surface-variant); margin-top: 4px;">${safe(entry.details.context || 'Error')}</div>${where}`;
        } else if (entry.type === 'pre-sync-snapshot') {
          detailsHtml = `<div style="font-size: 11px; color: var(--md-sys-color-on-surface-variant); margin-top: 4px;">⚠️ Replaced all local bookmarks with remote data</div>`;
        /* [ZeroLabs] 2026-09-22 6:54 PM - added: what the approved sync actually did */
        } else if (entry.type === 'sync-apply') {
          const count = (list) => (list || []).length;
          const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;
          const parts = [];
          if (count(entry.details.removed) > 0) parts.push(`${plural(count(entry.details.removed), 'bookmark', 'bookmarks')} removed from this device`);
          if (count(entry.details.renamed) > 0) parts.push(`${plural(count(entry.details.renamed), 'bookmark', 'bookmarks')} renamed`);
          if (count(entry.details.moved) > 0) parts.push(`${plural(count(entry.details.moved), 'bookmark', 'bookmarks')} moved`);
          if (count(entry.details.prunedFolders) > 0) parts.push(`${plural(count(entry.details.prunedFolders), 'empty folder', 'empty folders')} removed`);
          detailsHtml = `<div style="font-size: 11px; color: var(--md-sys-color-on-surface-variant); margin-top: 4px;">${parts.join(' · ')}</div>`;
        } else if (entry.type === 'undo') {
          if (entry.details.undoType === 'move') {
            detailsHtml = `<div style="font-size: 11px; color: var(--md-sys-color-on-surface-variant); margin-top: 4px;">Restored to: ${entry.details.restoredToFolder}</div>`;
          } else if (entry.details.undoType === 'update') {
            detailsHtml = `<div style="font-size: 11px; color: var(--md-sys-color-on-surface-variant); margin-top: 4px;">Reverted title from: "${entry.details.previousTitle}"</div>`;
          /* [ZeroLabs] 2026-09-22 6:54 PM - added: the undo of a whole approved sync */
          } else if (entry.details.undoType === 'sync-apply') {
            const c = entry.details.counts || {};
            const reversed = (c.removed || 0) + (c.renamed || 0) + (c.moved || 0) + (c.prunedFolders || 0);
            const failedNote = entry.details.failed > 0 ? `, ${entry.details.failed} could not be reversed` : '';
            detailsHtml = `<div style="font-size: 11px; color: var(--md-sys-color-on-surface-variant); margin-top: 4px;">Reversed an approved sync of ${reversed} change${reversed === 1 ? '' : 's'}${failedNote}</div>`;
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
      /* [ZeroLabs] 2026-09-22 6:54 PM - added: undo the approved sync as one action */
      } else if (entry.type === 'sync-apply') {
        restoreButtonHtml = `
          <button class="changelog-restore-btn" data-entry-id="${entry.id}" title="Undo every change this sync applied" style="margin-left: auto; padding: 6px 12px; border: 1px solid ${iconColor}; border-radius: 6px; background: ${iconColor}; color: #000; cursor: pointer; font-size: 12px; font-weight: 600;">
            Undo These Changes
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
      alert('Event not found.');
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

    /* [ZeroLabs] 2026-09-22 6:54 PM - added: undo a whole approved sync at once */
    // An approved sync is one event, so it undoes as one event. The order is
    // deliberate: folders the prune took come back first, outermost before
    // innermost, because the bookmarks below them need somewhere to land. The
    // ids in the entry are the ids those folders had before they were removed,
    // so idMap translates each one to the id it has now.
    if (entry.type === 'sync-apply') {
      const d = entry.details || {};
      const removed = d.removed || [];
      const renamed = d.renamed || [];
      const moved = d.moved || [];
      const prunedFolders = d.prunedFolders || [];
      const total = removed.length + renamed.length + moved.length + prunedFolders.length;

      if (total === 0) {
        alert('This event recorded no changes, so there is nothing to undo.');
        return;
      }

      const lines = [];
      if (removed.length > 0) lines.push(`Put back ${removed.length} removed bookmark${removed.length === 1 ? '' : 's'}`);
      if (renamed.length > 0) lines.push(`Revert ${renamed.length} name${renamed.length === 1 ? '' : 's'}`);
      if (moved.length > 0) lines.push(`Move ${moved.length} bookmark${moved.length === 1 ? '' : 's'} back`);
      if (prunedFolders.length > 0) lines.push(`Recreate ${prunedFolders.length} removed folder${prunedFolders.length === 1 ? '' : 's'}`);

      const confirmed = confirm(`Undo this approved sync?\n\n${lines.join('\n')}\n\nThis changes this device now. The next sync decides what reaches your cloud bookmarks.`);
      if (!confirmed) return;

      const button = document.querySelector(`.changelog-restore-btn[data-entry-id="${entry.id}"]`);
      const buttonLabel = button ? button.textContent : '';
      let stepsDone = 0;
      const step = () => {
        stepsDone++;
        if (button) button.textContent = `Undoing ${stepsDone} of ${total}`;
      };
      if (button) {
        button.disabled = true;
        button.textContent = `Undoing 0 of ${total}`;
      }

      const idMap = new Map();
      let failed = 0;

      for (const folder of prunedFolders.slice().reverse()) {
        const data = folder.fullData || {};
        const parentId = idMap.get(data.parentId) || data.parentId;
        try {
          const siblings = await browser.bookmarks.getChildren(parentId);
          const index = Math.min(
            typeof data.index === 'number' ? data.index : siblings.length,
            siblings.length
          );
          // Proven empty when it was pruned, so a plain create rebuilds it fully
          const created = await browser.bookmarks.create({ title: data.title, parentId, index });
          if (data.id) idMap.set(data.id, created.id);
        } catch (error) {
          console.warn('[Changelog Restore] Could not recreate folder:', data.title, error.message);
          failed++;
        }
        step();
      }

      for (const item of renamed) {
        try {
          const matches = await browser.bookmarks.search({ url: item.url });
          const node = matches && matches[0];
          if (node && item.oldTitle) {
            await browser.bookmarks.update(node.id, { title: item.oldTitle });
          } else {
            failed++;
          }
        } catch (error) {
          console.warn('[Changelog Restore] Could not revert name:', item.url, error.message);
          failed++;
        }
        step();
      }

      for (const item of moved) {
        try {
          const matches = await browser.bookmarks.search({ url: item.url });
          const node = matches && matches[0];
          const parentId = idMap.get(item.fromParentId) || item.fromParentId;
          if (node && parentId) {
            await browser.bookmarks.move(node.id, { parentId });
          } else {
            failed++;
          }
        } catch (error) {
          console.warn('[Changelog Restore] Could not move back:', item.url, error.message);
          failed++;
        }
        step();
      }

      for (const item of removed) {
        const data = item.fullData || {};
        try {
          await restoreDeletedItem('bookmark', {
            ...data,
            parentId: idMap.get(data.parentId) || data.parentId
          });
        } catch (error) {
          console.warn('[Changelog Restore] Could not put back:', item.url, error.message);
          failed++;
        }
        step();
      }

      if (button) {
        button.disabled = false;
        button.textContent = buttonLabel;
      }

      await addChangelogEntry('undo', 'sync', 'Undid an approved sync', null, {
        undoType: 'sync-apply',
        counts: {
          removed: removed.length,
          renamed: renamed.length,
          moved: moved.length,
          prunedFolders: prunedFolders.length
        },
        failed
      });

      await loadBookmarks();
      renderBookmarks();

      alert(failed > 0
        ? `Undo finished. ${total - failed} of ${total} changes were reversed. ${failed} could not be, most likely because the bookmark or folder no longer exists.`
        : `Undo finished. All ${total} changes were reversed.`);

      closeChangelogModal();
      setTimeout(() => openChangelogModal(), 100);
      return;
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

  /* [ZeroLabs] 2026-09-23 1:30 AM - edited: the folder tree, not a typed number (see also: Bookmark-Manager-Zero-Chrome/sidepanel.js) */
  // This asked the user to read a numbered list of every folder at every depth
  // and type an index. It now opens the same tree the other dialogs use.
  //
  // A selected folder and everything inside it is excluded, so a folder cannot
  // be moved into itself or into one of its own descendants.
  const excluded = new Set();
  for (const id of selectedItems) {
    try {
      const [node] = await browser.bookmarks.getSubTree(id);
      const collectIds = (current) => {
        if (!current || !current.children) return;
        excluded.add(current.id);
        current.children.forEach(collectIds);
      };
      collectIds(node);
    } catch (error) {
      console.warn('[BulkMove] Could not read subtree:', id, error.message);
    }
  }

  const count = selectedItems.size;
  const destinationId = await pickFolderWithTree({
    heading: `Move ${count} item${count === 1 ? '' : 's'} to`,
    excluded
  });
  if (!destinationId) return;

  const destinationNode = findBookmarkById(bookmarkTree, destinationId);
  const destinationFolder = {
    id: destinationId,
    title: (destinationNode && destinationNode.title) || 'Unnamed Folder'
  };

  try {
    /* [ZeroLabs] 2026-09-22 7:41 PM - added: drop selections contained by another selection */
    // Same rule bulkDeleteItems already applies, and the move needs it more. A
    // folder and a bookmark inside it can both be ticked, which the new
    // select-all-in-folder button makes ordinary. Moving both would put the
    // subfolder in the destination AND lift its bookmarks out of it, flattening
    // the structure the user was moving.
    const covered = new Set();
    for (const id of selectedItems) {
      try {
        const [n] = await browser.bookmarks.getSubTree(id);
        const walkCovered = (node) => (node.children || []).forEach(c => { covered.add(c.id); walkCovered(c); });
        if (n) walkCovered(n);
      } catch (error) { /* already gone; the loop below skips it */ }
    }
    const topLevelIds = Array.from(selectedItems).filter(id => !covered.has(id));

    // Move each selected item
    for (const itemId of topLevelIds) {
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
    if (confirm('Are you sure you want to clear the entire event log? This action cannot be undone.')) {
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

  /* [ZeroLabs] 2026-09-07 9:20 PM - added: which KIND of store the id names (see also: gitlab-store.js) */
  // storeKind stays unset for existing installs, which means snippet, so nothing
  // changes for anyone until they move to a project repository. Declared here
  // with the rest of the sync state because currentStore reads it on every call.
  let storeKind = null;
  let storeBranch = null;

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
      /* [ZeroLabs] 2026-09-07 9:20 PM - added: creating a snippet says so */
      // Stating the backend rather than leaving whatever was there. Creating a
      // snippet while the stored kind still read "project" pointed the wrong
      // backend at this id, and every call failed with nothing explaining why.
      storeKind = null;
      storeBranch = null;
      await safeStorage.set({ bmz_snippet_id: snippetId });
      await safeStorage.remove(['bmz_store_kind', 'bmz_store_branch']);
      console.log('Created bookmark Snippet:', snippetId);
      return snippet.id;
    } catch (error) {
      console.error('Failed to create bookmark Snippet:', error);
      throw error;
    }
  }

  /* [ZeroLabs] 2026-09-07 9:20 PM - added: the store this sidebar is pointed at (see also: gitlab-store.js) */
  // Mirrors storeForConfig in background.js. fetchGitLab and getSnippetHeaders
  // are handed to the adapter rather than reimplemented, so the timeout handling
  // and auth still wrap every request.
  function currentStore() {
    return BMZGitLabStore.create({
      kind: storeKind || BMZGitLabStore.SNIPPET,
      branch: storeBranch,
      request: fetchGitLab,
      headers: getSnippetHeaders
    });
  }

  // A project-backed store regardless of what this device currently uses. The
  // setup paths need one before the device has adopted anything.
  function projectStore(branch) {
    return BMZGitLabStore.create({
      kind: BMZGitLabStore.PROJECT,
      branch,
      request: fetchGitLab,
      headers: getSnippetHeaders
    });
  }

  /* [ZeroLabs] 2026-09-07 10:05 PM - edited: one definition, in the store adapter */
  // The background page needs this same test, and it is where the failing writes
  // actually happen. A predicate that recognises one exact error string is the
  // last thing that should exist in two places, so it moved into gitlab-store.js
  // and this stays only as the name the call sites already use.
  function isStoreFullError(status, body) {
    return BMZGitLabStore.isStoreFullError(status, body);
  }

  let storeFullNoticeShown = false;

  // Shown once per sidebar session. It repeats on every sync otherwise, and a
  // dialog that reopens on its own is what the deferral card was built to replace.
  function noteStoreIsFull() {
    /* [ZeroLabs] 2026-09-07 10:05 PM - added: record it, not just show it */
    // The dialog is once per session, but the condition is permanent. Writing the
    // flag is what puts the card up on the next sidebar open and keeps the two
    // contexts telling the same story: the background page sets this same flag.
    browser.storage.local.set({
      snippet_sync_failed: true,
      snippet_sync_failed_reason: 'store-full',
      snippet_sync_failed_at: Date.now()
    }).catch(error => {
      console.error('[Store] Could not record the full store:', error);
    });

    if (storeFullNoticeShown) return;
    if (storeKind === BMZGitLabStore.PROJECT) return;
    storeFullNoticeShown = true;

    console.warn('[Store] GitLab is refusing writes to this snippet; offering the move to a repository');
    showSnippetSetup('stopped').catch(error => {
      console.error('[Store] Could not open the migration dialog:', error);
    });
  }

  // This device's bookmarks in snippet format, ready to be written to a store.
  async function buildStoreSeedFiles(existingPaths) {
    const firefoxTree = await browser.bookmarks.getTree();
    const tree = await firefoxBookmarksToSnippetFormat(firefoxTree);
    const payload = {
      ...tree,
      version: 1,
      checksum: await calculateChecksum(tree),
      lastModified: Date.now()
    };

    const verbFor = (path) => existingPaths.includes(path) ? 'update' : 'create';

    const files = [{
      action: verbFor('bookmarks.json'),
      file_path: 'bookmarks.json',
      content: JSON.stringify(payload, null, 2)
    }];

    if (quickAccessMetaLoaded) {
      files.push({
        action: verbFor(META_FILE),
        file_path: META_FILE,
        content: buildQuickAccessMetaContent()
      });
    }

    return files;
  }

  // Shared tail: adopt the project only once its write has actually landed, so a
  // failure leaves this device pointed at the old store rather than at nothing.
  // localVersion is 1 when this device seeded the repository and 0 when it is
  // joining one that already had bookmarks, so the first reconcile treats the
  // remote copy as the newer of the two rather than its own empty history.
  // clearRecords is false when JOINING. Those records are what say "this device
  // added these", and the reconcile needs them to tell an addition from something
  // another device deleted. Clearing them on a join wiped the claim made moments
  // earlier and brought back the very prompt it was written to prevent. After
  // seeding they describe nothing, because both sides already hold the same tree.
  async function adoptProjectStore(projectId, branch, hasMeta, localVersion = 1, clearRecords = true) {
    storeKind = BMZGitLabStore.PROJECT;
    storeBranch = branch;
    snippetId = String(projectId);
    metaFileExists = hasMeta;

    /* [ZeroLabs] 2026-09-07 9:20 PM - added: a held decision belongs to the store it came from */
    // The held decisions always go: they describe differences against the OLD
    // store, and approving them here would remove bookmarks compared against a
    // snippet this device no longer syncs with.
    const stored = {
      bmz_snippet_id: String(projectId),
      bmz_store_kind: BMZGitLabStore.PROJECT,
      bmz_store_branch: branch,
      snippet_local_version: localVersion,
      snippet_push_held: false,
      snippet_push_held_items: [],
      snippet_pull_held_items: [],
      snippet_overwrite_held_items: [],
      snippet_added_here_items: [],
      snippet_pending_push_items: [],
      snippet_needs_reconcile: false,

      /* [ZeroLabs] 2026-09-07 11:40 PM - added: the new store inherits no old failure */
      // Every other flag describing the OLD store was already cleared here. This
      // one was added later and missed, so migrating away from a snippet that had
      // stopped accepting writes left "Syncing has stopped" on screen over a
      // repository that was working perfectly well.
      snippet_sync_failed: false,
      snippet_sync_failed_reason: '',
      snippet_sync_failed_detail: ''
    };

    // The card reads the in-memory copy on the very next render, which happens
    // before any storage event could get back to us.
    syncFailure = { failed: false, reason: '', detail: '' };
    syncFailureDismissed = false;
    storeFullNoticeShown = false;

    // The created and deleted records are different. After seeding they describe
    // nothing, because both sides hold the same tree. After a join they are the
    // only thing that says which bookmarks are this device's own.
    if (clearRecords) {
      stored.snippet_local_created = [];
      stored.snippet_local_deleted = [];
      stored.snippet_local_edited = [];
    }

    await safeStorage.set(stored);

    updateGitLabButtonIcon();
    console.log('[Store] This device now syncs to project', projectId, 'on', branch);
    return String(projectId);
  }

  // Create a brand new private project and seed it from this device.
  async function createProjectStore(name = 'bmz-bookmarks', branch = 'main') {
    const store = projectStore(branch);
    reportSetupProgress('Preparing this device\'s bookmarks');
    const files = await buildStoreSeedFiles([]);
    reportSetupProgress('Creating the repository and uploading your bookmarks');
    const created = await store.create({ title: name, files });
    return await adoptProjectStore(created.id, branch, files.length > 1);
  }

  // Point this device at a project that already exists.
  // projectRef is the numeric project id or the full path, "user/repo".
  async function useProjectStore(projectRef, branch = 'main') {
    if (!projectRef) throw new Error('No project given');

    const store = projectStore(branch);
    const projectId = encodeURIComponent(String(projectRef));

    // Which files are already there decides create against update, and getting
    // that wrong makes GitLab refuse the whole commit.
    reportSetupProgress('Reading the repository');
    const existing = await store.listFiles(projectId);
    const files = await buildStoreSeedFiles(existing);

    reportSetupProgress('Uploading this device\'s bookmarks to the repository');
    const response = await store.writeFiles(projectId, files);
    if (!response.ok) {
      const body = await response.text();
      throw new Error(`Could not write to that project: ${response.status} - ${body}`);
    }

    return await adoptProjectStore(projectId, branch, files.length > 1);
  }

  /* [ZeroLabs] 2026-09-07 9:20 PM - added: record this device's bookmarks as its own */
  // Writes every local URL into the created-here list, which is what stops the
  // first reconcile after a connect from offering to delete bookmarks this device
  // holds and the cloud does not.
  async function claimLocalBookmarksAsOurs() {
    try {
      const firefoxTree = await browser.bookmarks.getTree();
      const snippetData = await firefoxBookmarksToSnippetFormat(firefoxTree);
      const entries = collectSnippetEntries(snippetData);

      const urls = [];
      entries.forEach(entry => {
        if (entry && entry.url) urls.push(entry.url);
      });

      if (urls.length === 0) return 0;

      await safeStorage.set({
        snippet_local_created: urls,
        snippet_local_deleted: [],
        snippet_local_edited: []
      });

      console.log(`[Setup] Claimed ${urls.length} local bookmark(s) as this device's own`);
      return urls.length;
    } catch (error) {
      // Not fatal. Without it the reconcile is merely more cautious than it needs
      // to be, which is exactly the behaviour that existed before this.
      console.error('[Setup] Could not record local bookmarks as ours:', error);
      return 0;
    }
  }

  /* [ZeroLabs] 2026-09-07 9:20 PM - added: take everything off the old store before leaving it */
  // Migration seeds the new repository from THIS device, so anything the snippet
  // holds that never reached here would be left behind. This pulls those in first.
  //
  // Additions only, and deliberately not pushed: the old snippet is usually being
  // left because it has stopped accepting writes, so any attempt to push would
  // fail and take the migration down with it.
  /* [ZeroLabs] 2026-09-23 10:50 PM - added: which cloud items are genuinely missing here (see also: Bookmark-Manager-Zero-Chrome/sidepanel.js) */
  // calculateBookmarkDiff keys a bookmark on its URL plus its full path, and the
  // path includes the bookmark's own title. So a bookmark that exists on BOTH
  // sides with any difference in title or folder - a trailing space, a rename, a
  // different folder - appears in `added` AND in `removed`. Creating everything
  // in `added` therefore creates a second copy of a bookmark this device already
  // has.
  //
  // The reconcile filtered that out. The join, the migration pull and the diff
  // dialog's merge did not, which is where the duplicates came from. All of them
  // now call this, so they cannot drift apart again.
  //
  // A URL on both lists is an edit, not an addition. A URL this device deleted
  // is not wanted back. A folder is created only when a wanted bookmark is going
  // into it, because attribution is URL-based and a folder has no URL.
  function safeAdditionsFromDiff(diff, deletedHere) {
    const removedUrls = new Set(diff.removed.filter(item => item.url).map(item => item.url));

    const wanted = (item) => item.url
      && !deletedHere.has(item.url)
      && !removedUrls.has(item.url);

    return diff.added.filter(item => {
      if (item.url) return wanted(item);
      return diff.added.some(other => other.path && item.path
        && other.path.startsWith(item.path + '/') && wanted(other));
    });
  }

  async function pullEverythingFromCurrentStore() {
    if (!snippetId) return { added: 0, deferred: false };

    reportSetupProgress('Reading your cloud bookmarks');
    const remoteData = await readBookmarksFromSnippet(snippetId);
    reportSetupProgress('Comparing this device with the cloud');
    const localTree = await browser.bookmarks.getTree();
    const remoteAsFirefox = snippetFormatToFirefoxBookmarks(remoteData);

    const diff = calculateBookmarkDiff(localTree[0], remoteAsFirefox[0]);

    /* [ZeroLabs] 2026-09-07 9:20 PM - added: report whether anything is still unresolved */
    // Anything removed or moved is something this pull will NOT settle, and the
    // caller needs to know before it writes the local tree back over the store.
    const deferred = (diff.removed.length + diff.moved.length + diff.modified.length) > 0;

    if (diff.added.length === 0) return { added: 0, deferred };

    /* [ZeroLabs] 2026-09-23 10:50 PM - fixed: the join created duplicates */
    // This handed the raw `diff.added` to bringSidesTogether, so every bookmark
    // held on both sides under a different title or folder was created a second
    // time. The same filter the reconcile uses now decides what is missing.
    const stored = await safeStorage.get('snippet_local_deleted');
    const deletedHere = new Set(stored.snippet_local_deleted || []);
    const toAdd = safeAdditionsFromDiff(diff, deletedHere);

    const skipped = diff.added.length - toAdd.length;
    if (skipped > 0) {
      console.log(`[Setup] ${skipped} cloud item(s) are already here under another title or folder, not copied again`);
    }
    if (toAdd.length === 0) return { added: 0, deferred };

    await bringSidesTogether(toAdd, true, false);

    /* [ZeroLabs] 2026-09-24 5:05 AM - fixed: a merge scrambled the order of what it created (see also: Bookmark-Manager-Zero-Chrome/sidepanel.js) */
    // bringSidesTogether creates every missing folder first, then every missing
    // bookmark, each added at the end of its parent. So a folder that sat
    // between two bookmarks in the cloud came out above both. The join then
    // writes this device's tree back, which published that order, and every
    // other device took it on its next sync. Putting what was just created
    // into the cloud's order here, before anything is written back, means a
    // merge can never publish a new order. Items only this device holds keep
    // their places.
    try {
      const moved = await applySnippetOrder(remoteData);
      if (moved > 0) console.log(`[Setup] Put ${moved} merged item(s) into the cloud's order`);
    } catch (error) {
      console.warn('[Setup] Could not apply the cloud order after merging:', error.message);
    }

    await loadBookmarks();
    return { added: toAdd.length, deferred };
  }

  /* [ZeroLabs] 2026-09-07 9:20 PM - added: join a repository that already holds bookmarks */
  // The other three paths seed the repository from this device. This one must not:
  // the bookmarks there belong to a device that set this up already, and writing
  // over them is how a second device would silently destroy the first one's data.
  // It only adopts the repository, then the caller runs the normal reconcile.
  /* [ZeroLabs] 2026-09-23 11:55 PM - added: setup reports what it is doing (see also: Bookmark-Manager-Zero-Chrome/sidepanel.js) */
  // Connecting to a repository can take a long time: joining one that holds
  // thousands of bookmarks creates every one of them on this device, one call at
  // a time. The dialog showed only "Connecting..." on a disabled button for all
  // of it, which reads as frozen.
  //
  // The setup dialog switches this reporter on when it starts a long action and
  // off when it ends. The slow steps call reportSetupProgress wherever they run,
  // including bringSidesTogether, which normal syncing also uses. With no
  // reporter switched on the call does nothing, so an ordinary sync is unaffected.
  //
  // `var`, not `let`, on purpose. This sits partway through setupEventListeners,
  // and bringSidesTogether can be reached before this line has run. A `let` read
  // then throws a ReferenceError; a `var` reads as undefined, which is "off".
  var setupProgressReporter = null;

  function reportSetupProgress(phase, done = 0, total = 0) {
    if (!setupProgressReporter) return;
    try {
      setupProgressReporter(phase, done, total);
    } catch (error) {
      // A progress display must never break the work it is describing
      console.warn('[Setup] Progress display failed:', error);
    }
  }

  /* [ZeroLabs] 2026-09-23 11:55 PM - added: the worker waits while a full replace runs */
  // A full replace removes every bookmark, then recreates the cloud's one call
  // at a time. If the background script ran in the middle it would see a
  // half-built tree, and the removals just recorded, and offer to delete the
  // "missing" bookmarks from the cloud. This stamp tells runSnippetPush to wait.
  // It carries a time, so a sidebar closed mid-replace cannot block syncing for
  // ever. Written with browser.storage.local directly, never safeStorage: in a
  // private window safeStorage keeps it in memory, where the background script
  // cannot see it.
  const BULK_REPLACE_KEY = 'bmz_bulk_replace_started';

  function countSnippetBookmarks(snippetData) {
    let count = 0;
    const walk = (node) => {
      if (!node) return;
      if (node.url) {
        count++;
        return;
      }
      (node.children || []).forEach(walk);
    };
    Object.values((snippetData && snippetData.roots) || {}).forEach(walk);
    return count;
  }

  /* [ZeroLabs] 2026-09-23 11:55 PM - added: read a repository's bookmarks, and refuse a stranger's */
  // The same checks joinProjectStore makes, so every option on the three-way
  // screen starts from bookmarks that are known to be BMZ's own.
  async function readProjectBookmarks(projectRef, branch = 'main') {
    const store = projectStore(branch);
    const projectId = encodeURIComponent(String(projectRef));
    const content = await store.readFile(projectId, 'bookmarks.json');

    let parsed = null;
    try {
      parsed = JSON.parse(content);
    } catch (error) {
      throw new Error('That repository has a bookmarks.json, but it is not readable as BMZ data. Pick a different repository.');
    }
    if (!parsed || !parsed.roots || typeof parsed.roots !== 'object') {
      throw new Error('That repository has a bookmarks.json, but it was not written by BMZ. Pick a different repository.');
    }
    return parsed;
  }

  /* [ZeroLabs] 2026-09-24 3:00 AM - added: are the two sides already the same */
  // When this device and the repository hold exactly the same bookmarks, the
  // three-way question has no answer worth asking: merging, keeping the cloud and
  // keeping this device all end in the same place. So the connect skips it.
  //
  // "The same" means every bookmark matches on URL, title and folder, with the
  // same number of copies of each. Titles are compared trimmed, as everywhere
  // else in sync, because a browser keeps a trailing space an HTML round trip
  // drops. Order inside a folder is NOT compared: it syncs separately, and the
  // repository's order is taken on the next sync.
  function snippetsMatch(localData, remoteData) {
    const countEntries = (data) => {
      const counts = new Map();
      const walk = (node, rootKey, segments) => {
        if (!node) return;
        if (node.url) {
          const key = [rootKey, segments.join('/'), String(node.title || '').trim(), node.url].join('\u0000');
          counts.set(key, (counts.get(key) || 0) + 1);
          return;
        }
        (node.children || []).forEach(child => {
          const nextSegments = child.url
            ? segments
            : segments.concat(String(child.title || child.name || '').trim());
          walk(child, rootKey, nextSegments);
        });
      };
      Object.keys((data && data.roots) || {}).forEach(rootKey => {
        walk(data.roots[rootKey], rootKey, []);
      });
      return counts;
    };

    const local = countEntries(localData);
    const remote = countEntries(remoteData);
    if (local.size !== remote.size) return false;
    for (const [key, count] of local) {
      if (remote.get(key) !== count) return false;
    }
    return true;
  }

  /* [ZeroLabs] 2026-09-23 11:55 PM - added: connect, keeping the cloud's bookmarks */
  // applyRemoteChangesToFirefox asks twice, saves a restorable snapshot to the
  // Event Log, and only then replaces. It runs BEFORE the repository is adopted,
  // so pressing Cancel on either question leaves this device exactly as it was
  // and not connected to anything new. Once the replace has happened both sides
  // match, so the attribution records are cleared on adoption.
  //
  // @returns {Promise<boolean>} false when the user cancelled
  async function replaceLocalFromProjectStore(projectRef, remoteData, branch = 'main') {
    const replaced = await applyRemoteChangesToFirefox(remoteData);
    if (!replaced) return false;

    reportSetupProgress('Connecting this device to the repository');
    const store = projectStore(branch);
    const projectId = encodeURIComponent(String(projectRef));
    const existing = await store.listFiles(projectId);
    const version = Number(remoteData.version) || 0;
    await adoptProjectStore(projectId, branch, existing.includes(META_FILE), version, true);
    return true;
  }

  async function joinProjectStore(projectRef, branch = 'main') {
    const store = projectStore(branch);
    const projectId = encodeURIComponent(String(projectRef));
    reportSetupProgress('Reading the repository');
    const existing = await store.listFiles(projectId);

    if (!existing.includes('bookmarks.json')) {
      throw new Error('That repository has no bookmarks.json in it yet. Use the empty repository option instead.');
    }

    /* [ZeroLabs] 2026-09-07 9:20 PM - added: check it is OUR bookmarks.json */
    // A repository can hold an unrelated file of the same name. Adopting one would
    // parse, find no roots, read as an empty cloud side, and ask the user to
    // approve removing every bookmark they own. Refusing up front is the only
    // decent answer, and it costs one read.
    const probe = await store.readFile(projectId, 'bookmarks.json');
    let parsed = null;
    try {
      parsed = JSON.parse(probe);
    } catch (error) {
      throw new Error('That repository has a bookmarks.json, but it is not readable as BMZ data. Pick a different repository.');
    }
    if (!parsed || !parsed.roots || typeof parsed.roots !== 'object') {
      throw new Error('That repository has a bookmarks.json, but it was not written by BMZ. Pick a different repository, or use the empty repository option to start fresh.');
    }

    await adoptProjectStore(projectId, branch, existing.includes(META_FILE), 0, false);

    /* [ZeroLabs] 2026-09-07 9:20 PM - added: on a first connect, everything here is yours */
    // The reconcile decides "here but not in the cloud" by asking whether this
    // device watched you add it. A device that has never synced has no such
    // records, so its own bookmarks read as things another device deleted and it
    // offers to remove them. On a first connect there is no shared history and no
    // deletion can have happened, so claiming the local tree is the honest reading.
    reportSetupProgress('Recording the bookmarks already on this device');
    await claimLocalBookmarksAsOurs();

    // Read, merge, then push what is only here. Adopting first is what points
    // readBookmarksFromSnippet at the new repository rather than the old store.
    const pulled = await pullEverythingFromCurrentStore();
    if (pulled.added > 0) {
      console.log(`[Setup] Brought ${pulled.added} item(s) down from the repository`);
    }

    /* [ZeroLabs] 2026-09-07 9:20 PM - added: a deferral stops the write back */
    // Writing the local tree back is only safe once local holds BOTH sides. A
    // deferral means the reconcile found something it would have to remove or
    // overwrite and stopped rather than doing it, so local is deliberately not
    // caught up. Pushing then would destroy exactly what the deferral protected.
    if (pulled.deferred) {
      console.warn('[Setup] Joined, but the merge needs your approval before anything is written back');
      return String(projectId);
    }

    // Local now holds both sides, so writing it back adds this device's extras
    // without removing anything that was already there.
    reportSetupProgress('Uploading the merged bookmarks to the repository');
    const merged = await buildStoreSeedFiles(existing);
    const response = await store.writeFiles(projectId, merged);
    if (!response.ok) {
      const body = await response.text();
      throw new Error(`Connected, but could not write back: ${response.status} - ${body}`);
    }

    return String(projectId);
  }

  /* [ZeroLabs] 2026-09-07 9:20 PM - added: read a project id out of whatever was pasted */
  // People paste the address bar, so accepting only "user/repo" would fail on the
  // most likely input. A bare number is already a project id and passes through.
  function parseProjectRef(input) {
    const trimmed = String(input || '').trim();
    if (!trimmed) return '';
    if (/^\d+$/.test(trimmed)) return trimmed;

    // Four shapes reach this in practice: the address bar, the HTTPS clone URL,
    // the SSH clone URL, and someone typing "user/repo" by hand. GitLab's clone
    // panel offers both clone forms, so both turn up.
    let ref = trimmed;
    ref = ref.replace(/^git@[^:]+:/i, '');        // git@gitlab.com:user/repo.git
    ref = ref.replace(/^ssh:\/\/[^/]+\//i, '');   // ssh://git@gitlab.com/user/repo.git
    ref = ref.replace(/^https?:\/\/[^/]+\//i, ''); // https://gitlab.com/user/repo

    // Slashes come off BEFORE ".git" and again after. Stripping ".git" first left
    // it attached on "user/repo.git/", because the anchor no longer matched the
    // end of the string. Both orders of typing happen, so both are handled.
    ref = ref.replace(/^\/+/, '').replace(/\/+$/, '');
    ref = ref.replace(/\.git$/i, '');
    ref = ref.replace(/\/+$/, '');

    // GitLab puts a /-/ segment in deep links, so a copied file or settings URL
    // still yields the project rather than a path that does not resolve.
    const dashIndex = ref.indexOf('/-/');
    if (dashIndex > 0) ref = ref.slice(0, dashIndex);

    return ref;
  }

  /* [ZeroLabs] 2026-09-07 9:20 PM - added: four ways in, chosen rather than guessed */
  // The old dialog listed snippets and offered to make another. Snippets turned out
  // to be the wrong store: GitLab never repacks them, so every push keeps a full
  // copy of bookmarks.json and the repository passes its allocation and goes
  // permanently read-only. Project repositories get housekeeping and draw on the
  // namespace allowance instead.
  //
  // Four options, and the user says which rather than BMZ inferring it. The
  // difference that matters is the last one: the first three write this device's
  // bookmarks INTO the repository, and the fourth must not, because the bookmarks
  // already there came from another device.
  // mode is 'setup' for a device with nothing connected, 'migrate' for one already
  // on a snippet, and 'stopped' for one whose snippet has begun refusing writes.
  //
  /* [ZeroLabs] 2026-09-07 10:40 PM - edited: migration shows the fourth option too */
  // It used to hide it, on the reasoning that someone migrating is moving their
  // own bookmarks rather than joining someone else's repository. That reasoning
  // only held for the FIRST device. Every device after it migrates to a
  // repository that already exists and already holds their bookmarks, and joining
  // is the only correct answer for them - so the one option they needed was the
  // one being hidden. The three that were left would each have done damage:
  // creating makes a second repository and splits the devices, and pointing at
  // the existing one as though it were empty writes this device's tree over what
  // the first device put there.
  //
  // This shadows the older top-level showSnippetSetup, which belongs to the
  // website-derived layer that the Firefox sidebar never reaches. Everything in
  // this scope resolves to the one below.
  async function showSnippetSetup(mode = 'setup') {
    const migrating = mode === 'migrate' || mode === 'stopped';

    const HEADINGS = {
      setup: 'Set Up Bookmark Sync',
      switch: 'Change repository',
      migrate: 'Move your bookmarks to a repository',
      stopped: 'Syncing has stopped'
    };

    const INTROS = {
      setup: `Your bookmarks are stored in a private GitLab repository, which is what keeps them in step across your devices.`,

      /* [ZeroLabs] 2026-09-08 1:10 AM - edited: the options describe themselves */
      // This named an order that no longer exists, and it was explaining what each
      // button already says on its own face.
      switch: `Point this device at a different GitLab repository.`,

      migrate: `Development of BMZ initially chose GitLab snippets for cloud sync and recent events have confirmed that was the wrong choice.
        <br><br>
        A snippet has a storage limit, and it counts every past version of your bookmarks rather than just the current one. A large collection reaches that limit eventually, and syncing then stops. BMZ would therefore like to migrate your bookmarks to a GitLab repository which does not share that same restriction.
        <br><br>
        Moving takes about a minute. Nothing is lost.`,

      stopped: `GitLab is refusing to save to this snippet. Its storage limit counts every past version of your bookmarks, and this one has reached that limit.
        <br><br>
        <strong>Your bookmarks are safe. Nothing has been lost.</strong>
        <br><br>
        This is our fault and we apologize for the inconvenience. BMZ picked the wrong kind of storage for this, however the solution is ready for you. Moving your cloud bookmarks from the snippet to a repository takes about a minute and does not have the same limit.`
    };

    const modal = document.createElement('div');
    modal.id = 'snippetSetupModal';
    modal.className = 'modal-overlay';
    modal.style.cssText = `
      position: fixed; top: 0; left: 0; right: 0; bottom: 0;
      background: rgba(0, 0, 0, 0.6); backdrop-filter: blur(4px);
      z-index: 10001; display: flex; align-items: center; justify-content: center;
    `;

    modal.innerHTML = `
      <div style="background: var(--md-sys-color-surface); border-radius: 16px; padding: 24px; max-width: 520px; width: 90%; max-height: 80vh; overflow-y: auto; box-shadow: 0 8px 32px rgba(0,0,0,0.3); border: 1px solid var(--md-sys-color-outline);">
        <h2 style="margin: 0 0 16px 0; color: var(--md-sys-color-primary); font-size: 20px; font-weight: 600; text-align: center;">${HEADINGS[mode]}</h2>
        <p style="margin-bottom: 20px; color: var(--md-sys-color-on-surface); line-height: 1.55;">
          ${INTROS[mode]}
        </p>
        <div id="snippetSetupContent"></div>
        <div id="snippetSetupError" style="display: none; margin-top: 16px; padding: 12px; background: var(--md-sys-color-error-container); color: var(--md-sys-color-on-error-container); border-radius: 8px; font-size: 14px;"></div>
      </div>
    `;

    document.body.appendChild(modal);

    const content = modal.querySelector('#snippetSetupContent');
    const errorDiv = modal.querySelector('#snippetSetupError');

    /* [ZeroLabs] 2026-09-23 11:55 PM - added: a progress panel for the slow actions */
    // Shown under the dialog's content while a connect, a create or a migration
    // runs, and fed by reportSetupProgress. A step with a count fills the bar. A
    // step that is only waiting on GitLab shows a moving stripe instead, so the
    // dialog never looks frozen.
    //
    // setupBusy also stops Escape and the backdrop from closing the dialog while
    // the work runs. Closing would not stop it; it would only hide the progress
    // of a merge that is still writing bookmarks.
    let setupBusy = false;

    const beginSetupProgress = () => {
      setupBusy = true;
      errorDiv.textContent = '';
      errorDiv.style.display = 'none';

      const panel = document.createElement('div');
      panel.style.cssText = 'margin-top: 16px;';
      panel.innerHTML = `
        <p class="setup-progress-phase" style="margin: 0 0 8px 0; font-size: 13px; color: var(--md-sys-color-on-surface);"></p>
        <div style="height: 8px; border-radius: 999px; background: var(--md-sys-color-surface-variant); overflow: hidden;">
          <div class="setup-progress-bar" style="width: 40%; height: 100%; border-radius: 999px; background: var(--md-sys-color-primary);"></div>
        </div>
        <p class="setup-progress-count" style="margin: 6px 0 0 0; font-size: 12px; color: var(--md-sys-color-on-surface-variant); min-height: 1em;"></p>
      `;
      errorDiv.insertAdjacentElement('beforebegin', panel);

      const phaseLine = panel.querySelector('.setup-progress-phase');
      const bar = panel.querySelector('.setup-progress-bar');
      const countLine = panel.querySelector('.setup-progress-count');

      // The waiting stripe. The Web Animations API needs no stylesheet, which
      // this dialog, built entirely in script, does not have.
      let stripe = null;
      const showWaiting = () => {
        if (stripe) return;
        bar.style.width = '40%';
        stripe = bar.animate(
          [{ transform: 'translateX(-100%)' }, { transform: 'translateX(250%)' }],
          { duration: 1200, iterations: Infinity, easing: 'ease-in-out' }
        );
      };
      const showCount = (done, total) => {
        if (stripe) {
          stripe.cancel();
          stripe = null;
        }
        bar.style.transform = '';
        bar.style.width = `${Math.round((done / total) * 100)}%`;
        countLine.textContent = `${done} of ${total}`;
      };

      const reporter = (phase, done, total) => {
        phaseLine.textContent = phase;
        if (total > 0) {
          showCount(done, total);
        } else {
          countLine.textContent = '';
          showWaiting();
        }
      };

      setupProgressReporter = reporter;
      reporter('Starting', 0, 0);

      return () => {
        setupBusy = false;
        if (stripe) stripe.cancel();
        if (setupProgressReporter === reporter) setupProgressReporter = null;
        panel.remove();
      };
    };

    /* [ZeroLabs] 2026-09-07 9:20 PM - added: a way out of every screen */
    // Escape, the backdrop, and a Close button on the chooser. Nothing here is so
    // important that it earns the right to trap someone in a dialog, including the
    // stopped-sync one: their bookmarks are safe either way and they can come back
    // to it from Cloud Sync Options whenever they want.
    const closeSetup = () => {
      document.removeEventListener('keydown', onEscape);
      modal.remove();
    };

    function onEscape(event) {
      /* [ZeroLabs] 2026-09-23 11:55 PM - edited: not while the work is running */
      if (setupBusy) return;
      if (event.key === 'Escape') closeSetup();
    }

    document.addEventListener('keydown', onEscape);

    modal.addEventListener('click', (event) => {
      if (setupBusy) return;
      if (event.target === modal) closeSetup();
    });

    const showSetupError = (message) => {
      errorDiv.textContent = message;
      errorDiv.style.display = 'block';
    };

    const clearSetupError = () => {
      errorDiv.textContent = '';
      errorDiv.style.display = 'none';
    };

    // adoptProjectStore has already saved the id and the kind by this point, so
    // this only has to bring the sidebar up on it.
    const finishSetup = async () => {
      closeSetup();
      startSnippetAutoSync();
      loadQuickAccessForSnippet(snippetId).catch(err => {
        console.error('[QuickAccess] Pin load after connect failed:', err);
      });
      await loadBookmarks();
      renderBookmarks();
    };

    const PRIMARY = 'background: var(--md-sys-color-primary); color: var(--md-sys-color-on-primary); border: none; padding: 12px 16px; border-radius: 8px; font-size: 14px; font-weight: 500; cursor: pointer;';
    const PLAIN = 'background: var(--md-sys-color-surface-variant); color: var(--md-sys-color-on-surface-variant); border: none; padding: 12px 16px; border-radius: 8px; font-size: 14px; cursor: pointer;';
    const CHOICE = 'display: block; width: 100%; text-align: left; background: var(--md-sys-color-surface-variant); color: var(--md-sys-color-on-surface); border: 2px solid transparent; padding: 14px 16px; border-radius: 10px; font-size: 14px; cursor: pointer; margin-bottom: 10px;';
    const FIELD = 'width: 100%; box-sizing: border-box; padding: 10px 12px; border-radius: 8px; border: 1px solid var(--md-sys-color-outline); background: var(--md-sys-color-surface); color: var(--md-sys-color-on-surface); font-size: 14px;';
    const HINT = 'font-size: 12px; color: var(--md-sys-color-on-surface-variant); margin-top: 6px; line-height: 1.5;';

    const choice = (id, title, detail) => `
      <button id="${id}" style="${CHOICE}">
        <div style="font-weight: 600; margin-bottom: 4px;">${title}</div>
        <div style="font-size: 12px; color: var(--md-sys-color-on-surface-variant); line-height: 1.45;">${detail}</div>
      </button>
    `;

    // Step one of a migration. The snippet is read one last time so anything on it
    // that never reached this device comes along, because the new repository is
    // seeded from here. The export is offered, never required.
    function renderMigrationStart() {
      clearSetupError();
      content.innerHTML = `
        <div style="padding: 4px 0;">
          <div style="display: flex; gap: 12px;">
            <button id="startMigration" style="flex: 1; ${PRIMARY}">Continue</button>
            <button id="exportFirst" style="${PLAIN}">Save a backup file first</button>
          </div>
          <div style="${HINT}">The backup is a bookmarks.html file you can open in any browser. It is optional.</div>
          <div style="margin-top: 16px; text-align: center;"><button id="notNow" style="${PLAIN}">Not now</button></div>
        </div>
      `;

      modal.querySelector('#exportFirst').addEventListener('click', async () => {
        try {
          await exportBookmarks();
        } catch (error) {
          console.error('[Setup] Export failed:', error);
          showSetupError('Could not save the backup file: ' + (error.message || ''));
        }
      });

      const notNow = modal.querySelector('#notNow');
      if (notNow) notNow.addEventListener('click', closeSetup);

      modal.querySelector('#startMigration').addEventListener('click', async () => {
        const button = modal.querySelector('#startMigration');
        button.disabled = true;
        button.textContent = 'Reading your cloud bookmarks...';
        /* [ZeroLabs] 2026-09-23 11:55 PM - added: show the pull as it happens */
        const endProgress = beginSetupProgress();
        try {
          const pulled = await pullEverythingFromCurrentStore();
          endProgress();
          if (pulled.added > 0) {
            console.log(`[Setup] Brought ${pulled.added} item(s) off the old store before migrating`);
          }
          /* [ZeroLabs] 2026-09-07 9:20 PM - added: say when the old store still wants a decision */
          // The new repository is seeded from this device, so a deferral here means
          // the old store holds something this device chose not to take. Migrating
          // anyway is allowed, it just leaves that behind, so it is said out loud
          // rather than discovered later by counting bookmarks.
          //
          // After the render, not before: renderChooser clears the error box.
          renderChooser();
          if (pulled.deferred) {
            showSetupError('Your snippet has changes still waiting for your approval. You can continue, but anything you have not approved will not come across.');
          }
        } catch (error) {
          endProgress();
          console.error('[Setup] Could not read the old store:', error);
          showSetupError('Could not read your cloud bookmarks: ' + (error.message || '') + ' You can still continue, but anything only on the snippet would be left behind.');
          button.disabled = false;
          button.textContent = 'Continue anyway';
          button.onclick = renderChooser;
        }
      });
    }

    function renderChooser() {
      clearSetupError();
      /* [ZeroLabs] 2026-09-08 1:10 AM - edited: most likely answer first */
      // Joining led the list because it is the right answer for every device
      // except the first one, and by the time anyone reaches this screen the first
      // device has usually already been set up. Creating a repository moved down
      // for the same reason: on a second device it is the choice that splits your
      // bookmarks across two stores.
      content.innerHTML = `
        <div style="padding: 4px 0;">
          ${choice('optJoin', 'Connect to a repository that already has my bookmarks',
            'Another device set this up. You then choose: merge both, keep the cloud\'s bookmarks, or keep this device\'s.')}
          ${choice('optEmpty', 'Use an empty repository I already made',
            'You made one yourself and it has nothing in it yet. This device\'s bookmarks go into it.')}
          ${choice('optCreate', 'Create a repository for me',
            'BMZ makes a new private repository on your GitLab account and puts this device\'s bookmarks in it.')}
          ${choice('optHowTo', 'Show me how to make one myself',
            'Step by step, then point BMZ at it.')}
          <div style="margin-top: 8px; text-align: center;">
            <button id="setupBottom" style="${PLAIN}">${chooserBottomLabel()}</button>
          </div>
        </div>
      `;

      modal.querySelector('#setupBottom').addEventListener('click', chooserBottomAction);
      modal.querySelector('#optCreate').addEventListener('click', renderCreate);
      modal.querySelector('#optEmpty').addEventListener('click', () => renderPointAt('seed'));
      modal.querySelector('#optHowTo').addEventListener('click', renderHowTo);
      modal.querySelector('#optJoin').addEventListener('click', () => renderPointAt('join'));
    }

    /* [ZeroLabs] 2026-09-08 1:10 AM - added: the bottom button depends on what is behind it */
    // The chooser is not always the first screen, so a single Close was wrong.
    // Migration arrives here from the backup-first screen, and Change Repository
    // arrives from the sync settings dialog, which was removed to get here. Both
    // have somewhere to go back to. Only first-run setup has nothing behind it.
    function chooserBottomLabel() {
      return mode === 'setup' ? 'Close' : 'Back';
    }

    function chooserBottomAction() {
      if (migrating) {
        renderMigrationStart();
        return;
      }
      if (mode === 'switch') {
        closeSetup();
        openSnippetSyncDialog();
        return;
      }
      closeSetup();
    }

    function backButton() {
      return `<button id="setupBack" style="${PLAIN}">Back</button>`;
    }

    function wireBack() {
      modal.querySelector('#setupBack').addEventListener('click', renderChooser);
    }

    /* [ZeroLabs] 2026-09-23 11:55 PM - added: the three answers for a repository that has bookmarks */
    // Merge first, because it is the only one that loses nothing, and the two
    // replaces spell out their numbers so the cost is visible before choosing.
    // Each replace still asks once more before it acts.
    async function renderExistingRepoChoice(ref, remoteData) {
      clearSetupError();

      const cloudCount = countSnippetBookmarks(remoteData);
      const localTree = await browser.bookmarks.getTree();
      const localCount = countBookmarks(localTree[0]);
      const plural = (count) => `${count} bookmark${count === 1 ? '' : 's'}`;

      content.innerHTML = `
        <div style="padding: 4px 0;">
          <p style="margin: 0 0 14px 0; font-size: 14px; line-height: 1.5; color: var(--md-sys-color-on-surface);">
            That repository already holds ${plural(cloudCount)}. This device has ${plural(localCount)}.
          </p>
          ${choice('optMergeBoth', 'Merge both (recommended)',
            'Keeps everything. Anything only in the cloud comes to this device, anything only here goes to the cloud, and nothing is removed from either.')}
          ${choice('optCloudWins', 'Replace this device\'s bookmarks with the cloud',
            `This device ends up with exactly the cloud's ${plural(cloudCount)}. Its own ${plural(localCount)} are removed. A snapshot is saved in the Event Log first, so this can be undone.`)}
          ${choice('optDeviceWins', 'Replace the cloud with this device\'s bookmarks',
            `The repository ends up with exactly this device's ${plural(localCount)}. Anything only in the cloud is removed, on every device that uses it.`)}
          <div style="margin-top: 8px; text-align: center;">${backButton()}</div>
        </div>
      `;
      wireBack();

      // One runner for all three, so each gets the progress panel, the same
      // error handling, and the same finish.
      const run = async (work) => {
        const buttons = content.querySelectorAll('button');
        buttons.forEach(button => { button.disabled = true; });
        const endProgress = beginSetupProgress();
        try {
          const finished = await work();
          endProgress();
          if (finished === false) {
            // The user said no to a confirmation. Nothing changed; stay here.
            buttons.forEach(button => { button.disabled = false; });
            return;
          }
          await finishSetup();
        } catch (error) {
          endProgress();
          console.error('[Setup] Could not connect to the repository:', error);
          showSetupError(error.message || 'Could not connect to that repository.');
          buttons.forEach(button => { button.disabled = false; });
        }
      };

      modal.querySelector('#optMergeBoth').addEventListener('click', () => {
        run(() => joinProjectStore(ref));
      });

      modal.querySelector('#optCloudWins').addEventListener('click', () => {
        // applyRemoteChangesToFirefox asks twice itself before it removes anything
        run(() => replaceLocalFromProjectStore(ref, remoteData));
      });

      modal.querySelector('#optDeviceWins').addEventListener('click', () => {
        run(async () => {
          const proceed = confirm(
            `Replace the repository's ${plural(cloudCount)} with this device's ${plural(localCount)}?\n\n` +
            'Anything only in the cloud is removed, on every device that uses this repository.'
          );
          if (!proceed) return false;
          await useProjectStore(ref);
          return true;
        });
      });
    }

    function renderCreate() {
      clearSetupError();
      content.innerHTML = `
        <div style="padding: 4px 0;">
          <label style="display: block; font-size: 13px; font-weight: 600; margin-bottom: 8px;">Repository name</label>
          <input id="newRepoName" type="text" value="bmz-bookmarks" style="${FIELD}">
          <div style="${HINT}">It is created as private. Only you can see it.</div>
          <div style="display: flex; gap: 12px; margin-top: 20px;">
            <button id="doCreate" style="flex: 1; ${PRIMARY}">Create and start syncing</button>
            ${backButton()}
          </div>
        </div>
      `;
      wireBack();

      modal.querySelector('#doCreate').addEventListener('click', async () => {
        const name = modal.querySelector('#newRepoName').value.trim();
        if (!name) {
          showSetupError('Give the repository a name.');
          return;
        }
        const button = modal.querySelector('#doCreate');
        button.disabled = true;
        button.textContent = 'Creating...';
        /* [ZeroLabs] 2026-09-23 11:55 PM - added: show the create as it happens */
        const endProgress = beginSetupProgress();
        try {
          await createProjectStore(name);
          endProgress();
          await finishSetup();
        } catch (error) {
          endProgress();
          console.error('[Setup] Could not create the repository:', error);
          showSetupError('Could not create it: ' + (error.message || ''));
          button.disabled = false;
          button.textContent = 'Create and start syncing';
        }
      });
    }

    /* [ZeroLabs] 2026-09-07 11:05 PM - added: pick a repository instead of typing one */
    // The token is already stored and the adapter already had a list() nobody
    // called, so asking someone to go and copy a URL out of their address bar was
    // work BMZ could do for them.
    //
    // The picker FILLS the paste field rather than replacing it. That keeps one
    // code path through parseProjectRef and wirePointAt, and leaves the field as
    // the way in for a repository the listing cannot show: past the 100 GitLab
    // returns, or on a token whose scope will not list projects at all.
    function repoPickerMarkup() {
      return `
        <label for="repoPicker" style="display: block; font-size: 13px; font-weight: 600; margin-bottom: 8px;">Your repositories</label>
        <select id="repoPicker" style="${FIELD}">
          <option value="">Loading your repositories...</option>
        </select>
        <div style="${HINT}">Or paste an address below.</div>
      `;
    }

    // Loads in the background. The screen is usable the moment it draws, because
    // the paste field never depended on this.
    function wireRepoPicker() {
      const picker = modal.querySelector('#repoPicker');
      const field = modal.querySelector('#repoRef');
      if (!picker || !field) return;

      picker.addEventListener('change', () => {
        if (picker.value) field.value = picker.value;
      });

      projectStore('main').list().then(projects => {
        if (!projects || projects.length === 0) {
          picker.innerHTML = '<option value="">No repositories found on your account</option>';
          picker.disabled = true;
          return;
        }

        const options = projects.map(project =>
          `<option value="${escapeHtml(project.title)}">${escapeHtml(project.title)}</option>`
        ).join('');
        picker.innerHTML = `<option value="">Choose a repository...</option>${options}`;
      }).catch(error => {
        // Not an error worth a red box. The paste field still works, so this only
        // has to stop promising a list that is not coming.
        console.warn('[Setup] Could not list your repositories:', error);
        picker.innerHTML = '<option value="">Could not load your repositories</option>';
        picker.disabled = true;
      });
    }

    function renderHowTo() {
      clearSetupError();
      content.innerHTML = `
        <div style="padding: 4px 0;">
          <ol style="margin: 0 0 16px 18px; padding: 0; font-size: 14px; line-height: 1.7; color: var(--md-sys-color-on-surface);">
            <li><a href="https://gitlab.com/users/sign_in" target="_blank" rel="noopener noreferrer" style="color: var(--md-sys-color-primary); text-decoration: underline;">Sign in to your GitLab account</a> first.</li>
            <li>Open <a href="https://gitlab.com/projects/new" target="_blank" rel="noopener noreferrer" style="color: var(--md-sys-color-primary); text-decoration: underline;">gitlab.com/projects/new</a> and choose "Create blank project".</li>
            <li>Give it any name you like.</li>
            <li>Set Visibility to <strong>Private</strong>.</li>
            <li>Leave <strong>Initialize repository with a README</strong> ticked. BMZ needs a branch to write to.</li>
            <li>Create it, then pick it from the list below. It will be at the top.</li>
          </ol>
          ${repoPickerMarkup()}
          <label for="repoRef" style="display: block; font-size: 13px; font-weight: 600; margin: 12px 0 8px 0;">Repository address</label>
          <input id="repoRef" type="text" placeholder="https://gitlab.com/you/bmz-bookmarks" style="${FIELD}">
          <div style="display: flex; gap: 12px; margin-top: 20px;">
            <button id="doPoint" style="flex: 1; ${PRIMARY}">Start syncing</button>
            ${backButton()}
          </div>
        </div>
      `;
      wireBack();
      wireRepoPicker();
      wirePointAt('seed');
    }

    function renderPointAt(mode) {
      clearSetupError();
      const joining = mode === 'join';
      content.innerHTML = `
        <div style="padding: 4px 0;">
          ${repoPickerMarkup()}
          <label for="repoRef" style="display: block; font-size: 13px; font-weight: 600; margin: 12px 0 8px 0;">Repository address</label>
          <input id="repoRef" type="text" placeholder="https://gitlab.com/you/bmz-bookmarks" style="${FIELD}">
          <div style="${HINT}">
            ${joining
              ? 'Its bookmarks are read first. You then choose to merge both, keep the cloud\'s, or keep this device\'s.'
              : 'This device\'s bookmarks are written into it. If it already holds bookmarks, you are asked what to do with them first.'}
          </div>
          <div style="display: flex; gap: 12px; margin-top: 20px;">
            <button id="doPoint" style="flex: 1; ${PRIMARY}">${joining ? 'Continue' : 'Start syncing'}</button>
            ${backButton()}
          </div>
        </div>
      `;
      wireBack();
      wireRepoPicker();
      wirePointAt(mode);
    }

    function wirePointAt(mode) {
      const button = modal.querySelector('#doPoint');
      const original = button.textContent;

      button.addEventListener('click', async () => {
        const typed = modal.querySelector('#repoRef').value;
        const ref = parseProjectRef(typed);
        if (!ref) {
          showSetupError('Paste the repository address.');
          return;
        }

        button.disabled = true;
        button.textContent = 'Connecting...';
        try {
          /* [ZeroLabs] 2026-09-07 11:05 PM - added: do not write over a repository that is in use */
          // useProjectStore seeds from THIS device, and its verbFor sends "update"
          // for a bookmarks.json that already exists, so this path silently
          // replaced whatever was there. Typing a full URL made that unlikely. A
          // dropdown of every repository on the account makes it a slip.
          //
          // The right answer is almost always the join option, so it is named.
          // One extra read on a path taken once is worth not overwriting a library.
          /* [ZeroLabs] 2026-09-24 3:00 AM - added: set below when both sides already match */
          let joinInstead = false;

          /* [ZeroLabs] 2026-09-23 11:55 PM - edited: a repository with bookmarks gets a real choice */
          // This probe used to run only for the empty-repository option, and its
          // one answer to "that repository already has bookmarks" was a confirm
          // that REPLACED them. The join option skipped it and always merged. So
          // there was no way to say "keep the cloud" and only a hidden way to say
          // "keep this device".
          //
          // Now any repository that already holds BMZ bookmarks, whichever option
          // led here, opens one screen with all three: merge both, replace this
          // device with the cloud, or replace the cloud with this device.
          {
            let entries = null;
            try {
              entries = await projectStore('main').listEntries(encodeURIComponent(ref));
            } catch (probeError) {
              // Could not look. Let the connect below report the real problem
              // rather than guessing at one here.
              console.warn('[Setup] Could not check the repository first:', probeError);
            }

            if (entries) {
              const alreadyHasBookmarks = entries.some(entry => entry.path === 'bookmarks.json');
              const otherContent = BMZGitLabStore.contentEntries(entries);

              /* [ZeroLabs] 2026-09-08 12:40 AM - added: two different wrong repositories */
              // Holds somebody's actual project is not destructive, but BMZ would
              // commit into it on every sync from then on, which nobody asked for.
              // That stays a confirmation rather than a refusal: a person may
              // genuinely want bookmarks living beside other files.
              if (alreadyHasBookmarks) {
                const remoteData = await readProjectBookmarks(ref);

                /* [ZeroLabs] 2026-09-24 3:00 AM - added: nothing to choose when both sides match */
                // Identical bookmarks on both sides make all three answers the
                // same, so connect straight away with the merge, which writes
                // nothing new to either side.
                const localAsSnippet = await firefoxBookmarksToSnippetFormat(await browser.bookmarks.getTree());
                if (snippetsMatch(localAsSnippet, remoteData)) {
                  console.log('[Setup] This device and the repository already match, connecting without asking');
                  joinInstead = true;
                } else {
                  button.disabled = false;
                  button.textContent = original;
                  renderExistingRepoChoice(ref, remoteData);
                  return;
                }
              } else if (mode !== 'join' && otherContent.length > 0) {
                // Naming a couple of them is what makes the repository recognisable.
                // A README on its own never reaches here: BMZ creates repositories
                // with one, and the how-to screen tells people to keep it.
                const sample = otherContent.slice(0, 3).map(entry => entry.path).join(', ');
                const more = otherContent.length > 3 ? `, and ${otherContent.length - 3} more` : '';
                const proceed = confirm(
                  'That repository is not empty. It already contains:\n\n' +
                  `  ${sample}${more}\n\n` +
                  'Nothing there will be deleted, but BMZ would add bookmarks.json to it ' +
                  'and commit to it on every sync from now on.\n\n' +
                  'Use it for your bookmarks anyway?'
                );
                if (!proceed) {
                  button.disabled = false;
                  button.textContent = original;
                  return;
                }
              }
            }
          }

          /* [ZeroLabs] 2026-09-23 11:55 PM - added: show the connect as it happens */
          // Started here, after the checks above, because those can still end in
          // the user pressing Cancel on a warning.
          const endProgress = beginSetupProgress();
          try {
            if (mode === 'join' || joinInstead) {
              await joinProjectStore(ref);
            } else {
              await useProjectStore(ref);
            }
          } finally {
            endProgress();
          }
          await finishSetup();
        } catch (error) {
          console.error('[Setup] Could not connect to the repository:', error);
          showSetupError(error.message || 'Could not connect to that repository.');
          button.disabled = false;
          button.textContent = original;
        }
      });
    }

    if (migrating) {
      renderMigrationStart();
    } else {
      renderChooser();
    }
  }

  /* [ZeroLabs] 2026-09-07 9:20 PM - added: the outer migration card needs a way in */
  // renderBookmarks and its cards live outside this scope, the same way
  // showHeldPushDialog is reached. Nothing else here is exposed.
  window.showSnippetSetup = showSnippetSetup;

  // Read bookmarks from the cloud store
  async function readBookmarksFromSnippet(id = null) {
    const useId = id || snippetId;
    if (!useId) {
      throw new Error('No cloud sync connected');
    }

    try {
      /* [ZeroLabs] 2026-09-07 9:20 PM - edited: read through the store adapter */
      // The two-step read and the raw endpoint fallback moved into the adapter,
      // because a project repository answers both in one call and a snippet does
      // not.
      const content = await currentStore().readFile(useId, 'bookmarks.json');

      if (content === null) {
        throw new Error('Remote store does not contain bookmarks.json');
      }

      // If content is empty or just whitespace, return empty structure
      if (!content || content.trim() === '') {
        console.log('Cloud bookmarks file is empty, returning empty bookmark structure');
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
      console.error('Failed to read bookmarks from cloud storage:', error);
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
      /* [ZeroLabs] 2026-09-07 9:20 PM - edited: ask the store which files exist */
      // metaFileExists decides whether the next push says create or update, and
      // getting it wrong makes GitLab refuse the whole write. Asking the adapter
      // for the file list keeps that answer correct on either backend.
      const store = currentStore();
      const filePaths = await store.listFiles(useId);

      // A store with no meta file means no pins yet, which is the normal state of
      // every snippet that existed before this feature. Not an error.
      if (!filePaths.includes(META_FILE)) {
        metaFileExists = false;
        return { pins: [], tombstones: [] };
      }
      metaFileExists = true;

      const content = await store.readFile(useId, META_FILE);
      if (!content || content.trim() === '') return { pins: [], tombstones: [] };

      const parsed = JSON.parse(content);
      return {
        pins: Array.isArray(parsed.quickAccess) ? parsed.quickAccess : [],
        tombstones: Array.isArray(parsed.quickAccessRemoved) ? parsed.quickAccessRemoved : []
      };
    } catch (error) {
      console.error('Failed to read quick access meta from cloud storage:', error);
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

  // Update bookmarks in the cloud store
  async function updateBookmarksInSnippet(bookmarkTree, version = null) {
    if (!snippetId) {
      throw new Error('No cloud sync connected');
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

      /* [ZeroLabs] 2026-09-07 9:20 PM - edited: write through the store adapter */
      const response = await currentStore().writeFiles(snippetId, files);

      if (!response.ok) {
        const errorText = await response.text();

        /* [ZeroLabs] 2026-09-07 9:20 PM - added: recognise a store that has filled up */
        // GitLab reports this as a bare 400 saying "Repository Error updating the
        // snippet", which names no cause and repeats forever. Every sync fails,
        // nothing explains why, and the only visible symptom is that other devices
        // quietly stop matching. Saying so is the difference between a user moving
        // and a user losing sync without ever learning it happened.
        if (isStoreFullError(response.status, errorText)) {
          noteStoreIsFull();
        }

        throw new Error(`Failed to update cloud storage: ${response.status} - ${errorText}`);
      }

      // A successful write means the file is there now, so later pushes update
      // rather than create.
      if (files.length > 1) metaFileExists = true;

      /* [ZeroLabs] 2026-09-07 10:05 PM - added: a working write clears the failure */
      // The card is driven entirely by this flag, so a manual sync that succeeds
      // has to take it down. Awaited: the render that follows reads it.
      syncFailure = { failed: false, reason: '', detail: '' };
      await browser.storage.local.set({
        snippet_sync_failed: false,
        snippet_sync_failed_reason: '',
        snippet_sync_failed_detail: ''
      });

      console.log('Updated bookmarks in cloud storage:', snippetId);
      return await response.json();
    } catch (error) {
      console.error('Failed to update bookmarks in cloud storage:', error);
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
      console.warn('[CloudAdd] No local root matches path segment:', segments[0]);
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

  /* [ZeroLabs] 2026-09-23 6:10 PM - edited: a renamed folder keeps its place */
  // A folder rename cannot travel as a rename. The snippet has no folder objects
  // at all - a folder exists only as segments on the bookmarks it holds - so the
  // receiving device sees every bookmark in that folder move from one path to
  // another. It then creates the new folder here and prunes the old one once it
  // is empty.
  //
  // `browser.bookmarks.create` with no index APPENDS, so the renamed folder
  // landed at the bottom of its parent on every other device while the original
  // sat wherever the user had put it.
  //
  // `options.placeLike` is the folder the bookmarks are leaving. When it is a
  // SIBLING of the folder being created, the new folder is created at its index
  // instead of at the end. The browser inserts before it, and the old folder is
  // pruned moments later, so the new one ends up in exactly the old one's slot.
  //
  // The sibling test is what keeps this narrow. A bookmark moved into a genuinely
  // new folder somewhere else still appends, because the folder it came from is
  // not a sibling of the new one.
  async function resolveOrCreateFolderUnder(parentId, segments, options = {}) {
    const placeLike = options.placeLike || null;
    let currentId = parentId;

    for (let i = 0; i < segments.length; i++) {
      const segment = segments[i];
      const children = await browser.bookmarks.getChildren(currentId);
      let match = children.find(child => !child.url && child.title === segment);

      if (!match) {
        const details = { parentId: currentId, title: segment };

        // Only the LAST segment is the folder the bookmarks are moving into.
        // A missing parent above it is a folder nobody had, so it appends.
        const isLastSegment = i === segments.length - 1;
        if (isLastSegment
            && placeLike
            && placeLike.parentId === currentId
            && typeof placeLike.index === 'number') {
          details.index = placeLike.index;
        }

        match = await browser.bookmarks.create(details);
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

  /* [ZeroLabs] 2026-09-07 10:05 PM - edited: never return silently on a click */
  // fromUser is true when a person pressed Review changes. Both guards below used
  // to return with no dialog and no message, so the button appeared broken. It was
  // reachable because the failure path raised the deferral card without ever
  // writing the held lists the dialog reads.
  //
  // The internal caller passes nothing, because it only calls this when a
  // reconcile has just reported a deferral and a toast there would be noise.
  async function showHeldPushDialog(fromUser = false) {
    const stored = await safeStorage.get([
      'snippet_push_held',
      'snippet_push_held_items',
      'snippet_pull_held_items',
      'snippet_overwrite_held_items',
      'snippet_added_here_items',
      'snippet_pending_push_items'
    ]);

    const fromSnippet = stored.snippet_push_held_items || [];
    const fromDevice = stored.snippet_pull_held_items || [];
    /* [ZeroLabs] 2026-08-27 2:02 PM - added: renames and moves wait here too */
    const overwrites = stored.snippet_overwrite_held_items || [];

    const nothingHeld = !stored.snippet_push_held ||
      (fromSnippet.length === 0 && fromDevice.length === 0 && overwrites.length === 0);

    if (nothingHeld) {
      if (fromUser) {
        // The card was standing on a stale flag, so it goes as well. Leaving it
        // up after saying there is nothing to review is its own small lie.
        showToast('Nothing is waiting for your approval.');
        await setSnippetNeedsReconcile(false);
        renderBookmarks();
      }
      return;
    }

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
        `Add ${plural(pendingPush.length, 'bookmark', 'bookmarks')} from this device to your cloud bookmarks.`,
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

    /* [ZeroLabs] 2026-09-22 6:54 PM - added: the apply runs in view, not behind a closed modal */
    // The dialog used to close on click and the work ran with no indicator at
    // all. An approved folder rename can carry thousands of bookmarks, and each
    // one is a search, an update, a move and a storage write. The dialog stays
    // open and becomes the progress surface, which also stops a second click
    // starting the same work twice.
    const startApplyProgress = () => {
      dialog.innerHTML = `
        <h2 style="margin: 0 0 16px 0; font-size: 18px; color: #ff9800; text-align: center;">Applying sync changes</h2>
        <p id="heldApplyCount" style="margin: 0 0 6px 0; font-size: 14px; font-weight: 600;"></p>
        <p id="heldApplyPhase" style="margin: 0 0 16px 0; font-size: 13px; color: var(--md-sys-color-on-surface-variant, #aaa);"></p>
        <div style="height: 8px; border-radius: 999px; background: var(--md-sys-color-surface-variant, #2a2a2a); overflow: hidden;">
          <div id="heldApplyBar" style="width: 0%; height: 100%; background: #f59e0b; transition: width 0.15s linear;"></div>
        </div>
      `;
      const countLine = dialog.querySelector('#heldApplyCount');
      const phaseLine = dialog.querySelector('#heldApplyPhase');
      const bar = dialog.querySelector('#heldApplyBar');

      return (done, total, phase) => {
        countLine.textContent = total > 0 ? `${done} of ${total}` : 'Finishing';
        phaseLine.textContent = phase;
        bar.style.width = total > 0 ? `${Math.round((done / total) * 100)}%` : '100%';
      };
    };

    dialog.querySelector('#heldPushConfirm').addEventListener('click', async () => {
      await clearHold();

      const totalOps = fromDevice.length + overwrites.length;
      const setProgress = startApplyProgress();
      let done = 0;
      setProgress(0, totalOps, 'Preparing the approved changes.');

      /* [ZeroLabs] 2026-09-22 6:54 PM - added: one changelog entry for the whole apply */
      // This used to write up to two entries per bookmark. MAX_CHANGELOG_ENTRIES
      // is 1000, so approving a large sync rolled the entire event log off the
      // end and took the fullData snapshots that make earlier deletions
      // restorable with it. One entry now holds every operation and is
      // restorable as a unit.
      const syncOps = { removed: [], renamed: [], moved: [], prunedFolders: [] };

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
              /* [ZeroLabs] 2026-09-22 6:54 PM - edited: collected, not written per bookmark */
              syncOps.removed.push({ title: node.title || 'Untitled', url: node.url || null, fullData });
            }
          } catch (error) {
            console.warn('[CloudSync] Could not remove locally:', item.url, error.message);
          }
          done++;
          setProgress(done, totalOps, 'Removing bookmarks from this device.');
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
              /* [ZeroLabs] 2026-09-22 6:54 PM - edited: collected, not written per bookmark */
              syncOps.renamed.push({ url: item.url || null, oldTitle, newTitle: item.remoteTitle });
            }

            if (item.localPath !== item.remotePath && Array.isArray(item.remoteSegments)) {
              const rootId = firefoxRootForSnippetKey(item.remoteRootKey);
              if (rootId) {
                /* [ZeroLabs] 2026-09-23 6:10 PM - added: keep a renamed folder where it was */
                // The folder this bookmark is leaving. When the move is a folder
                // rename, that folder is about to be emptied and pruned, and the
                // replacement should take its place rather than be appended.
                let placeLike = null;
                if (node.parentId) {
                  const [oldParent] = await browser.bookmarks.get(node.parentId);
                  if (oldParent && !oldParent.url) {
                    placeLike = {
                      id: oldParent.id,
                      parentId: oldParent.parentId,
                      index: oldParent.index
                    };
                  }
                }

                const parentId = await resolveOrCreateFolderUnder(
                  rootId, item.remoteSegments, { placeLike });
                // An approved move empties a folder just as a removal does
                if (node.parentId && node.parentId !== parentId) vacated.add(node.parentId);
                /* [ZeroLabs] 2026-09-22 6:54 PM - edited: record the parent id, not only the path */
                // The move restore used to resolve a path string back to a
                // folder. A bookmark title holding a slash makes that string
                // ambiguous, while the id is exact for as long as the folder
                // exists. The path is kept as the fallback and as what the user
                // reads.
                const fromParentId = node.parentId || null;
                await browser.bookmarks.move(node.id, { parentId });
                syncOps.moved.push({
                  url: item.url || null,
                  title: item.remoteTitle || oldTitle,
                  fromFolder: item.localPath,
                  toFolder: item.remotePath,
                  fromParentId
                });
              }
            }
          } catch (error) {
            console.warn('[CloudSync] Could not apply change to:', item.url, error.message);
          }
          done++;
          setProgress(done, totalOps, 'Renaming and moving bookmarks to match your cloud bookmarks.');
        }
        await loadBookmarks();
        renderBookmarks();
      }

      /* [ZeroLabs] 2026-08-28 - added: run the prune once everything has moved */
      // Deferred to here rather than done inline, because a folder emptied by a
      // removal can be refilled by a move later in the same resolution.
      if (vacated.size > 0) {
        setProgress(totalOps, totalOps, 'Removing folders left empty.');
        for (const parentId of vacated) {
          /* [ZeroLabs] 2026-09-22 6:54 PM - edited: the prune hands its folders back */
          const pruned = await pruneEmptyFolderChain(parentId);
          syncOps.prunedFolders.push(...pruned);
        }
        await loadBookmarks();
        renderBookmarks();
      }

      /* [ZeroLabs] 2026-09-22 6:54 PM - added: the whole apply is one event */
      const appliedCount = syncOps.removed.length + syncOps.renamed.length +
        syncOps.moved.length + syncOps.prunedFolders.length;
      if (appliedCount > 0) {
        await addChangelogEntry('sync-apply', 'sync', 'Approved sync changes', null, syncOps);
      }

      /* [ZeroLabs] 2026-09-22 6:54 PM - edited: the modal closes when the work ends */
      // It used to close on the click. Now that it carries the progress, a throw
      // would leave it on screen for ever, so both outcomes close it.
      try {
        setProgress(totalOps, totalOps, 'Saving to your cloud bookmarks.');
        await syncToSnippet(true);
        await setSnippetNeedsReconcile(false);
        modal.remove();
        /* [ZeroLabs] 2026-08-27 2:41 PM - edited: one result, not the push's pair */
        showToast('Sync approved and applied.');
      } catch (error) {
        modal.remove();
        showToast(`Sync failed: ${error.message}`, 'error');
      }
    });
    dialog.querySelector('#heldPushLater').addEventListener('click', () => modal.remove());
  }

  /* [ZeroLabs] 2026-08-27 - added: reachable from the notice card */
  // The card is rendered at module level, and in Firefox this function lives
  // inside setupEventListeners, so a direct call from the card would be a
  // ReferenceError - the same scope trap that broke the v4.5 announcement
  // card's button in v4.6. Exposed here so both browsers call it the same way.
  window.showHeldPushDialog = showHeldPushDialog;
  /* [ZeroLabs] 2026-09-07 10:05 PM - added: the failed-sync card retries through this */
  // Same reason as the line above: the cards are rendered outside this scope and
  // can only reach in through window.
  window.reconcileWithSnippet = reconcileWithSnippet;

  /* [ZeroLabs] 2026-08-27 12:20 PM - added: the sidebar's copy of the background's reconcile */
  // Same four outcomes and the same classification the background uses, so a
  // manual sync and an automatic one can never disagree about what is safe. The
  // difference is only what happens on a deferral: the background asks for
  // consent, while this returns the diff so the caller can offer every option.
  /* [ZeroLabs] 2026-09-23 7:15 PM - added: the order of a folder's contents syncs now */
  // Reordering was the one change that never travelled. The push already wrote it:
  // the snippet is serialised from the live tree, so its order is this device's
  // order, and onMoved already schedules a push. Nothing ever read it back, so
  // every other device kept its own order for ever.
  //
  // The comparison is per FOLDER, not per bookmark. Order is a property of a
  // folder's children list, so one drag is one difference, not one difference for
  // every bookmark that shifted below it.
  //
  // Items that are NOT in the snippet never move. They keep the exact slots they
  // hold, and the matched items are arranged among the slots that remain. That is
  // what makes Chrome's `Bookmarks Menu` and `Mobile Bookmarks` folders safe: they
  // live inside Other Bookmarks here and are promoted to roots of their own in the
  // snippet, so they are never matched, and the device cannot fight itself over
  // where they sit.
  //
  // There is no merge and no prompt. The last device to write the snippet decides
  // the order, which is the model this project already uses everywhere else.

  /**
   * The key that identifies a child inside one folder.
   * Two bookmarks can share a URL, so repeats are numbered.
   */
  function orderKeyFor(node, seen) {
    const base = node.url
      ? `b:${node.url}`
      : `f:${normalizeBookmarkTitle(node.title || node.name || '')}`;

    const count = seen.get(base) || 0;
    seen.set(base, count + 1);
    return count === 0 ? base : `${base}\u0000#${count}`;
  }

  function orderKeysOf(children) {
    const seen = new Map();
    return (children || []).map(child => orderKeyFor(child, seen));
  }

  /**
   * Put one folder's children into the order the snippet holds.
   *
   * @returns {number} how many items had to move
   */
  async function applyFolderOrder(parentId, remoteChildren) {
    const localChildren = await browser.bookmarks.getChildren(parentId);
    if (localChildren.length < 2) return 0;

    const desired = orderKeysOf(remoteChildren);
    const localKeys = orderKeysOf(localChildren);

    // Where each key sits in the snippet's list. A key the snippet does not have
    // is left out, and the item that carries it never moves.
    const rank = new Map();
    desired.forEach((key, index) => {
      if (!rank.has(key)) rank.set(key, index);
    });

    const matched = [];
    localChildren.forEach((child, index) => {
      if (rank.has(localKeys[index])) {
        matched.push({ id: child.id, index, rankValue: rank.get(localKeys[index]) });
      }
    });
    if (matched.length < 2) return 0;

    // The slots the matched items hold now. The unmatched items own every other
    // slot and keep it, so the matched items are dealt back into these.
    const slots = matched.map(entry => entry.index);
    const wanted = matched.slice().sort((a, b) => a.rankValue - b.rankValue);

    // The exact list this folder should end up as, built before anything moves
    const target = localChildren.map(child => child.id);
    wanted.forEach((entry, position) => {
      target[slots[position]] = entry.id;
    });

    const order = localChildren.map(child => child.id);
    if (order.every((id, index) => id === target[index])) return 0;

    let moves = 0;

    for (let index = 0; index < target.length; index++) {
      if (order[index] === target[index]) continue;

      const id = target[index];
      const currentIndex = order.indexOf(id);

      // Every slot before this one already holds the right item, so the item
      // wanted here is always LATER in the list. Chrome removes an item before it
      // inserts it, and a removal after the target cannot shift the target, so the
      // index needs no adjustment. A forward move would need one, and walking the
      // list from the front means one never happens.
      await browser.bookmarks.move(id, { index });

      order.splice(currentIndex, 1);
      order.splice(index, 0, id);
      moves++;
    }

    return moves;
  }

  /* [ZeroLabs] 2026-09-24 6:55 AM - fixed: start inside each root, not above them (see also: Bookmark-Manager-Zero-Chrome/sidepanel.js) */
  // This walked the Firefox-shaped copy of the cloud from ITS top node, so the
  // first thing it did was try to put Firefox's four root folders into the
  // copy's order (toolbar, menu, other, mobile) against Firefox's own (menu,
  // toolbar, other, mobile). Firefox refuses to move a root folder, so that
  // threw, and the sync button and the merge never ordered anything. It also
  // matched the roots by display title, which differs in another language.
  //
  // Now each root of the cloud file is mapped to its Firefox root by key with
  // firefoxRootForSnippetKey, the way the background script already does it.
  // The root folders themselves are never moved.
  /**
   * Walk the cloud file and put every Firefox folder that differs into its order.
   *
   * @returns {Promise<number>} how many items moved in total
   */
  async function applySnippetOrder(remoteData) {
    let moved = 0;

    const walk = async (remoteNode, localNode) => {
      if (!remoteNode || !localNode) return;
      const remoteChildren = remoteNode.children || [];
      const localChildren = localNode.children || [];
      if (remoteChildren.length === 0 || localChildren.length === 0) return;

      moved += await applyFolderOrder(localNode.id, remoteChildren);

      // Descend by title, which is how folders are identified everywhere in sync
      const remoteFolders = new Map();
      remoteChildren.forEach(child => {
        if (child.url) return;
        const title = normalizeBookmarkTitle(child.title || child.name || '');
        if (!remoteFolders.has(title)) remoteFolders.set(title, child);
      });

      for (const child of localChildren) {
        if (child.url) continue;
        const match = remoteFolders.get(normalizeBookmarkTitle(child.title || ''));
        if (!match) continue;
        // The children read above are stale after the moves, so read again
        const [fresh] = await browser.bookmarks.getSubTree(child.id);
        await walk(match, fresh);
      }
    };

    const remoteRoots = (remoteData && remoteData.roots) || {};
    for (const key of Object.keys(remoteRoots)) {
      const localId = firefoxRootForSnippetKey(key);
      if (!localId) continue;
      const [localNode] = await browser.bookmarks.getSubTree(localId);
      await walk(remoteRoots[key], localNode);
    }

    return moved;
  }

  /* [ZeroLabs] 2026-09-23 9:40 PM - added: the worker's order comparison, for the sync button (copied from: background.js) */
  // The same three functions the background worker uses, so the sync button and
  // the automatic sync can never judge an order differently. Both sides are in
  // snippet format here, and items only one side holds are ignored.
  function snippetOrderKeys(children) {
    const seen = new Map();
    return (children || []).map(child => {
      const title = String(child.title || child.name || '').trim();
      const base = child.url ? `b:${child.url}` : `f:${title}`;
      const count = seen.get(base) || 0;
      seen.set(base, count + 1);
      return count === 0 ? base : `${base}\u0000#${count}`;
    });
  }

  function folderOrderDiffers(localChildren, remoteChildren) {
    const remoteKeys = snippetOrderKeys(remoteChildren);
    const localKeys = snippetOrderKeys(localChildren);

    // Only the items both sides hold can disagree about order
    const inRemote = new Set(remoteKeys);
    const inLocal = new Set(localKeys);
    const localShared = localKeys.filter(key => inRemote.has(key));
    const remoteShared = remoteKeys.filter(key => inLocal.has(key));

    if (localShared.length !== remoteShared.length) return false;
    return localShared.some((key, index) => key !== remoteShared[index]);
  }

  function snippetOrderDiffers(localData, remoteData) {
    const walk = (localNode, remoteNode) => {
      if (!localNode || !remoteNode) return false;
      const localChildren = localNode.children || [];
      const remoteChildren = remoteNode.children || [];
      if (localChildren.length === 0 || remoteChildren.length === 0) return false;

      if (folderOrderDiffers(localChildren, remoteChildren)) return true;

      const remoteFolders = new Map();
      remoteChildren.forEach(child => {
        if (child.url) return;
        const title = String(child.title || child.name || '').trim();
        if (!remoteFolders.has(title)) remoteFolders.set(title, child);
      });

      return localChildren.some(child => {
        if (child.url) return false;
        const match = remoteFolders.get(String(child.title || child.name || '').trim());
        return match ? walk(child, match) : false;
      });
    };

    const localRoots = (localData && localData.roots) || {};
    const remoteRoots = (remoteData && remoteData.roots) || {};
    return Object.keys(localRoots).some(key => walk(localRoots[key], remoteRoots[key]));
  }

  async function reconcileWithSnippet() {
    const remoteData = await readBookmarksFromSnippet(snippetId);
    const localTree = await browser.bookmarks.getTree();
    const remoteAsFirefox = snippetFormatToFirefoxBookmarks(remoteData);

    /* [ZeroLabs] 2026-09-23 9:40 PM - edited: the sync button follows the worker's order rule exactly */
    // A different order means one of two things:
    //   - this device moved something and that change has not gone up yet
    //     (`snippet_push_pending` AND a record in `snippet_local_edited`): its
    //     order is the newer one, so the sync publishes it.
    //   - otherwise another device reordered: take the cloud order FIRST, so any
    //     push this sync makes carries it instead of this device's old order.
    // A pending change alone is not enough. Adding a bookmark here after a
    // reorder on another device leaves a change pending while this device still
    // holds the old order.
    //
    // This runs before the content comparison below, and deliberately outside
    // it: a reorder produces no added, removed or modified entries at all, so
    // the early return for "no changes" would skip it. The same rule runs in
    // background.js for the push alarm and the five minute poll, so a manual
    // sync and an automatic one can never disagree.
    let publishOrder = false;
    try {
      const orderState = await safeStorage.get(['snippet_push_pending', 'snippet_local_edited']);
      const localChangePending = orderState.snippet_push_pending === true;
      const movedHere = (orderState.snippet_local_edited || []).length > 0;

      const localAsSnippet = await firefoxBookmarksToSnippetFormat(localTree);
      if (snippetOrderDiffers(localAsSnippet, remoteData)) {
        if (localChangePending && movedHere) {
          publishOrder = true;
          console.log('[CloudSync] This device reordered, publishing its order');
        } else {
          const moved = await applySnippetOrder(remoteData);
          if (moved > 0) {
            console.log(`[CloudSync] Took the cloud order for ${moved} item(s)`);
            await loadBookmarks();
            renderBookmarks();
          }
        }
      }
    } catch (error) {
      // Order is cosmetic. It must never stop a sync that moves real data.
      console.warn('[CloudSync] Could not compare the cloud order:', error.message);
    }

    const diff = calculateBookmarkDiff(localTree[0], remoteAsFirefox[0]);

    const hasChanges = diff.added.length + diff.removed.length +
                       diff.moved.length + diff.modified.length > 0;

    if (!hasChanges) {
      /* [ZeroLabs] 2026-09-23 9:40 PM - added: a reorder alone is still worth a push */
      // Nothing was added, removed or renamed, but this device moved something.
      // Without this the sync button said "already in sync" and left the
      // reorder for the background push to carry up.
      if (publishOrder) {
        await syncToSnippet(true);
        return { changed: true, deferred: false, addedLocally: 0, pushed: true };
      }

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
    /* [ZeroLabs] 2026-09-23 10:50 PM - edited: one filter, shared with the join (see safeAdditionsFromDiff) */
    const toAdd = safeAdditionsFromDiff(diff, deletedHere);

    /* [ZeroLabs] 2026-08-27 - edited: removals use the consent dialog, like everywhere else */
    // This used to hand the raw diff back, and the caller showed the diff dialog:
    // "2 item(s) only in the cloud", with a Merge button. That is the same fact
    // told backwards. A bookmark you deleted here that the snippet still holds is
    // not something you are missing - it is your deletion waiting to travel, and
    // Merge would have put it straight back. The worker and the Website both use
    // the consent dialog for this; the panel was the odd one out.
    if (removesFromSnippet.length > 0 || removesFromDevice.length > 0) {
      // Safe additions still land - they are never what the deferral is about.
      await bringSidesTogether(toAdd, true, false);

      /* [ZeroLabs] 2026-09-22 6:54 PM - edited: store every item, cap only the display (see also: background.js) */
      // The dialog renders 50 rows and an "and N more" line, so cutting the
      // stored list at 200 only made the counts wrong and, on the approve path,
      // dropped the work itself.
      const strip = (items) => items
        .filter(item => item.url)
        .map(item => ({ url: item.url, title: item.title, path: item.path }));

      await safeStorage.set({
        snippet_push_held: true,
        snippet_push_held_items: strip(removesFromSnippet),
        snippet_pull_held_items: strip(removesFromDevice),
        snippet_overwrite_held_items: [],
        /* [ZeroLabs] 2026-08-27 - added: report the safe additions too */
        snippet_added_here_items: toAdd.filter(i => i.url)
          .map(i => ({ url: i.url, title: i.title, path: i.path })),
        snippet_pending_push_items: diff.removed
          .filter(item => item.url && createdHere.has(item.url))
          .map(i => ({ url: i.url, title: i.title, path: i.path }))
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

      /* [ZeroLabs] 2026-09-07 9:20 PM - edited: surrounding whitespace is not a rename */
      // Titles are compared trimmed. A browser will happily store "Sebtube " with a
      // trailing space, while an HTML export and re-import strips it, so the two
      // sides disagree over a character nobody can see. Only the comparison is
      // trimmed; neither copy is rewritten.
      const sameTitle = String(localEntry.title || '').trim() === String(remoteEntry.title || '').trim();
      const movedOrRenamed =
        !sameTitle ||
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
        /* [ZeroLabs] 2026-09-22 6:54 PM - edited: store every item, cap only the display */
        snippet_overwrite_held_items: overwritesOnDevice,
        /* [ZeroLabs] 2026-08-27 - added: report the safe additions too */
        snippet_added_here_items: toAdd.filter(i => i.url)
          .map(i => ({ url: i.url, title: i.title, path: i.path })),
        snippet_pending_push_items: diff.removed
          .filter(item => item.url && createdHere.has(item.url))
          .map(i => ({ url: i.url, title: i.title, path: i.path }))
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
        They are still in the cloud and on your other devices, so nothing has been lost.
      </p>
      <div style="margin-bottom: 20px;">${list}</div>
      <label style="display: block; font-size: 13px; color: var(--md-sys-color-on-surface-variant, #aaa); margin-bottom: 6px;">
        Save them to this folder instead:
      </label>
      <!-- [ZeroLabs] 2026-09-23 1:30 AM - edited: the shared folder tree, not a flat list -->
      <select id="unplaceableFolder" style="display: none;" aria-hidden="true"></select>
      <div id="unplaceableFolderTree" class="folder-tree-picker" role="tree" aria-label="Destination folder" style="margin-bottom: 12px;"></div>
      <div style="display: flex; flex-direction: column; gap: 12px;">
        <button id="unplaceableSave" style="width: 100%; padding: 12px; border-radius: 8px; border: none; background: var(--md-sys-color-primary, #90caf9); color: var(--md-sys-color-on-primary, #000); cursor: pointer; font-size: 14px; font-weight: 500;">
          Save them there and sync
        </button>
        <button id="unplaceableClose" style="width: 100%; padding: 12px; border-radius: 8px; border: none; background: var(--md-sys-color-surface-variant, #2a2a2a); color: var(--md-sys-color-on-surface-variant, #aaa); cursor: pointer; font-size: 14px;">
          Leave them in the cloud only
        </button>
      </div>
    `;

    modal.appendChild(dialog);
    document.body.appendChild(modal);

    /* [ZeroLabs] 2026-09-23 1:30 AM - edited: the shared folder tree */
    // The tree never offers Root, so the option that used to be stripped out
    // afterwards does not exist in the first place.
    const folderSelect = dialog.querySelector('#unplaceableFolder');
    const unplaceableTree = dialog.querySelector('#unplaceableFolderTree');
    renderFolderTree(folderSelect, unplaceableTree);

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

      /* [ZeroLabs] 2026-09-23 11:55 PM - added: count the slow part out loud */
      // This loop is what takes the time on a first connect: one browser call per
      // bookmark. It does nothing unless the setup dialog is listening.
      let processed = 0;

      for (const item of ordered) {
        processed++;
        reportSetupProgress('Adding bookmarks from the cloud to this device', processed, ordered.length);
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
          : 'Cloud updated.');
      }
    } catch (error) {
      console.error('[CloudAdd] Failed:', error);
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

    let content = '<h2 style="margin: 0 0 16px 0; font-size: 20px;">Cloud Sync Changes</h2>';

    if (!hasChanges) {
      content += '<p style="color: var(--md-sys-color-on-surface-variant, #aaa);">No changes detected. Your local bookmarks match the cloud.</p>';
    } else {
      // Summary
      content += '<div style="margin-bottom: 20px; padding: 16px; background: var(--md-sys-color-surface-variant, #2a2a2a); border-radius: 8px;">';
      content += '<h3 style="margin: 0 0 12px 0; font-size: 16px;">Summary</h3>';
      /* [ZeroLabs] 2026-08-27 2:33 AM - edited: say where each side's items are, not "remove" */
      // Both of these end up on both sides after a merge. Calling one "to
      // remove" in red read as a threat to bookmarks that were never in danger.
      if (diff.added.length > 0) content += `<div style="margin-bottom: 4px; color: #4caf50;">${diff.added.length} item(s) only in the cloud</div>`;
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
        content += '<div style="margin-bottom: 20px;"><h3 style="margin: 0 0 12px 0; font-size: 16px; color: #4caf50;">From Cloud</h3>';
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
            <!-- [ZeroLabs] 2026-09-07 9:20 PM - added: which way the data moves -->
            <!-- Same arrows as the pair in Cloud Sync Options. This pair is the
                 more dangerous of the two: side by side, no captions, and the
                 labels differ only in word order. -->
            <button id="pushLocalToRemote" style="flex: 1; padding: 12px; border-radius: 8px; border: none; background: var(--md-sys-color-primary, #90caf9); color: var(--md-sys-color-on-primary, #000); cursor: pointer; font-size: 14px; display: flex; align-items: center; justify-content: center; gap: 8px;">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor" style="flex-shrink:0;" aria-hidden="true">
                <path d="M13,20H11V8L5.5,13.5L4.08,12.08L12,4.16L19.92,12.08L18.5,13.5L13,8V20Z"/>
              </svg>
              <span>Overwrite Cloud with Local</span>
            </button>
            <button id="applyRemoteChanges" style="flex: 1; padding: 12px; border-radius: 8px; border: none; background: var(--md-sys-color-error, #f44336); color: var(--md-sys-color-on-error, #fff); cursor: pointer; font-size: 14px; display: flex; align-items: center; justify-content: center; gap: 8px;">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor" style="flex-shrink:0;" aria-hidden="true">
                <path d="M11,4H13V16L18.5,10.5L19.92,11.92L12,19.84L4.08,11.92L5.5,10.5L11,16V4Z"/>
              </svg>
              <span>Overwrite Local with Cloud</span>
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
      /* [ZeroLabs] 2026-09-23 10:50 PM - fixed: same duplicate fault as the join */
      // The raw `diff.added` includes every bookmark held on both sides under a
      // different title or folder, so merging created a second copy of each.
      const stored = await safeStorage.get('snippet_local_deleted');
      const deletedHere = new Set(stored.snippet_local_deleted || []);
      await bringSidesTogether(safeAdditionsFromDiff(diff, deletedHere));
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
        showToast('Cloud bookmarks overwritten with local.');
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
      showToast('No cloud sync connected', 'error');
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
      console.log('[CloudPull] Skipped: a held push is waiting for consent');
      return;
    }

    snippetIsSyncing = true;
    try {
      if (!silent) showToast('Checking for cloud updates...');

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
        console.log('[CloudPull] Differences found; leaving them to the background');
        return;
      }

      await showSyncDiffDialog(diff, remoteData);
    } catch (error) {
      console.error('Cloud sync failed:', error);
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
      showToast('No cloud sync connected', 'error');
      return;
    }
    if (snippetIsSyncing) {
      if (!silent) showToast('Sync already in progress, please wait.', 'error');
      return;
    }
    snippetIsSyncing = true;

    try {
      if (!silent) showToast('Syncing to the cloud...');

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

      if (!silent) showToast('Synced to the cloud successfully!');
    } catch (error) {
      console.error('Sync to cloud storage failed:', error);
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
      /* [ZeroLabs] 2026-09-07 9:20 PM - edited: the backend goes with the connection */
      // bmz_store_kind survived a disconnect, so connecting a SNIPPET afterwards
      // left the project backend pointed at a snippet id and every call failed.
      // Which store a device uses is part of the connection, not of the device.
      await browser.storage.local.remove([
        'bmz_snippet_id',
        'snippet_local_version',
        'bmz_store_kind',
        'bmz_store_branch',
        /* [ZeroLabs] 2026-09-07 11:40 PM - added: a failure belongs to the store that had it */
        // Same reasoning as the backend keys above. Carrying it past a disconnect
        // would report the old store's failure against whatever is connected next.
        'snippet_sync_failed',
        'snippet_sync_failed_reason',
        'snippet_sync_failed_detail'
      ]);
      syncFailure = { failed: false, reason: '', detail: '' };
      syncFailureDismissed = false;
      storeFullNoticeShown = false;
      await supabase.clearSession();
      await setTokenMode('local');
      snippetId = null;
      snippetLocalVersion = 0;
      storeKind = null;
      storeBranch = null;
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
        <p style="font-size:13px;color:var(--md-sys-color-on-surface-variant,#aaa);margin:0 0 12px 0;">This is the Personal Access Token currently saved in BMZ on this device. Keep it private. It grants access to your GitLab bookmark storage.</p>
        <div style="display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:16px;">
          <input type="password" readonly id="revealTokenInput" style="flex:1 1 100%;min-width:0;padding:10px;border-radius:8px;border:1px solid var(--md-sys-color-outline,#444);background:var(--md-sys-color-surface-variant,#2a2a2a);color:var(--md-sys-color-on-surface,#e0e0e0);font-size:12px;font-family:monospace;box-sizing:border-box;">
          <button id="toggleReveal" style="flex:1 1 auto;flex-shrink:0;padding:10px 12px;border-radius:8px;border:1px solid var(--md-sys-color-outline,#444);background:var(--md-sys-color-surface-variant,#2a2a2a);color:var(--md-sys-color-on-surface,#e0e0e0);font-size:12px;cursor:pointer;">Show</button>
          <button id="copyRevealToken" style="flex:1 1 auto;flex-shrink:0;padding:10px 14px;border-radius:8px;border:none;background:var(--md-sys-color-primary,#818cf8);color:var(--md-sys-color-on-primary,#fff);font-size:13px;cursor:pointer;">Copy</button>
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

    /* [ZeroLabs] 2026-09-07 9:20 PM - edited: write through the store adapter */
    const response = await currentStore().writeFiles(snippetId, [{
      action: metaFileExists ? 'update' : 'create',
      file_path: META_FILE,
      content: buildQuickAccessMetaContent()
    }]);

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

    /* [ZeroLabs] 2026-09-07 9:20 PM - added: which store controls this device gets */
    // Three states, not two, and the third is the one that mattered. A device
    // already on a project switches repositories. A device already on a snippet
    // keeps the snippet controls, because those still describe what it uses and
    // switching snippets was always available. A device connected to NOTHING gets
    // neither: it goes through the setup dialog, which only offers repositories.
    const REPO_BUTTON = `
            <!-- The repository equivalent of Select Existing Snippet. Without it a
                 project user could only change repository by disconnecting, which
                 throws the token away as well. -->
            <button id="changeRepository" style="padding: 12px; border-radius: 8px; border: none; background: var(--md-sys-color-secondary-container, #2a2a2a); color: var(--md-sys-color-on-secondary-container, #d0bcff); cursor: pointer; font-size: 14px;">
              Change Repository
            </button>`;

    const SNIPPET_BUTTONS = `
            <button id="createNewSnippet" style="padding: 12px; border-radius: 8px; border: none; background: var(--md-sys-color-secondary-container, #2a2a2a); color: var(--md-sys-color-on-secondary-container, #d0bcff); cursor: pointer; font-size: 14px;">
              Create New Snippet with Current Bookmarks
            </button>
            <button id="selectExistingSnippet" style="padding: 12px; border-radius: 8px; border: none; background: var(--md-sys-color-secondary-container, #2a2a2a); color: var(--md-sys-color-on-secondary-container, #d0bcff); cursor: pointer; font-size: 14px;">
              Select Existing Snippet
            </button>`;

    /* [ZeroLabs] 2026-09-07 9:20 PM - added: the third state needs a way in */
    // A device holding a token but connected to nothing had no button at all
    // here. The setup dialog opens by itself right after a token is entered, so
    // this was only reachable by dismissing that one, but from then on the
    // dialog offered Disconnect and Cancel and no route to a store.
    const SETUP_BUTTON = `
            <button id="openStoreSetup" style="padding: 12px; border-radius: 8px; border: none; background: var(--md-sys-color-primary, #90caf9); color: var(--md-sys-color-on-primary, #000); cursor: pointer; font-size: 14px; font-weight: 500;">
              Set Up Bookmark Sync
            </button>`;

    let storeChoiceButtons = '';
    if (storeKind === 'project') {
      storeChoiceButtons = REPO_BUTTON;
    } else if (snippetId) {
      storeChoiceButtons = SNIPPET_BUTTONS;
    } else {
      storeChoiceButtons = SETUP_BUTTON;
    }

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
              <button id="manualSyncNow" title="Sync your bookmarks" aria-label="Sync your bookmarks" style="position: relative; width: 128px; height: 128px; max-width: 100%; border-radius: 50%; border: none; background: var(--md-sys-color-surface-container, #2a2a2a); box-shadow: var(--md-elevation-1); cursor: pointer; padding: 0; display: flex; align-items: center; justify-content: center;">
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
          ` : ''}
          <!-- [ZeroLabs] 2026-09-08 3:35 AM - moved: out of the collapsed panel -->
          <!-- Which store you are connected to is the first thing you want when
               you open this dialog, and it was hidden behind the Cloud Sync
               Options toggle, which is collapsed whenever a store IS connected.
               It sits with the sync button now, above the divider, since both
               describe the current connection rather than offering an action.
               Rendered in both states, so a device connected to nothing says so
               here too. -->
          <div style="text-align: center; font-size: 13px; color: var(--md-sys-color-on-surface-variant, #aaa); line-height: 1.7; padding: 4px 0;">
            ${snippetId
              ? `Connected to ${storeKind === 'project' ? 'Repository' : 'Snippet'}:<br><code id="connectedStoreName" style="font-size: 12px; word-break: break-all;">${escapeHtml(String(snippetId))}</code>`
              : 'Not connected to any store'}
          </div>
          <hr style="border: none; border-top: 1px solid var(--md-sys-color-outline, #444); margin: 4px 0;">
          <button id="snippetOptionsToggle" aria-expanded="${snippetId ? 'false' : 'true'}" style="padding: 12px; border-radius: 8px; border: none; background: var(--md-sys-color-secondary-container, #2a2a2a); color: var(--md-sys-color-on-secondary-container, #d0bcff); cursor: pointer; font-size: 14px; display: flex; align-items: center; justify-content: space-between; gap: 8px;">
            <span>Cloud Sync Options</span>
            <svg id="snippetOptionsChevron" width="16" height="16" viewBox="0 0 24 24" fill="currentColor" style="flex-shrink:0;transition:transform 0.2s ease;transform:rotate(${snippetId ? '-90' : '0'}deg);"><path d="M7.41,8.58L12,13.17L16.59,8.58L18,10L12,16L6,10L7.41,8.58Z"/></svg>
          </button>
          <div id="snippetOptionsPanel" style="display: ${snippetId ? 'none' : 'flex'}; flex-direction: column; gap: 12px;">
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
            <!-- [ZeroLabs] 2026-09-07 9:20 PM - added: snippet-only actions, hidden once off snippets -->
            <!-- These two make and pick SNIPPETS. Offering them to someone already
                 syncing to a repository would quietly move them back onto the
                 storage they were migrated off. They keep their snippet wording
                 because that is exactly what they still do. -->
            ${storeChoiceButtons}
            ${snippetId ? `
              <!-- [ZeroLabs] 2026-08-27 12:20 PM - added: forcing, always reachable -->
              <!-- The sync button resolves everything it safely can, which means
                   a divergence in renames or moves never surfaces a choice, and a
                   wholesale recovery has no route. These stay available whatever
                   the current difference happens to look like. -->
              <!-- [ZeroLabs] 2026-09-07 9:20 PM - added: the way off snippets -->
              <!-- Offered before anything breaks. A snippet keeps every past
                   version of bookmarks.json, so a large collection eventually
                   passes its allocation and the store goes permanently read-only.
                   Only shown while this device is still on a snippet. -->
              ${storeKind === 'project' ? '' : `
              <hr style="border: none; border-top: 1px solid var(--md-sys-color-outline, #444); margin: 4px 0;">
              <button id="migrateToRepo" style="padding: 12px; border-radius: 8px; border: none; background: var(--md-sys-color-secondary-container, #2a2a2a); color: var(--md-sys-color-on-secondary-container, #d0bcff); cursor: pointer; font-size: 14px;">
                Move your bookmarks to a repository
              </button>`}
              <hr style="border: none; border-top: 1px solid var(--md-sys-color-outline, #444); margin: 4px 0;">
              <!-- [ZeroLabs] 2026-09-07 9:20 PM - added: which way the data moves -->
              <!-- Both buttons are destructive and their labels differ by word
                   order alone, which is exactly the kind of pair someone misreads
                   in a hurry. The arrow says the direction before the text does:
                   up is this device writing over the cloud, down is the cloud
                   writing over this device. -->
              <button id="forceOverwriteSnippet" style="padding: 12px; border-radius: 8px; border: none; background: var(--md-sys-color-error-container, #3b1a1a); color: var(--md-sys-color-on-error-container, #f9dedc); cursor: pointer; font-size: 14px; display: flex; align-items: center; justify-content: center; gap: 8px;">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor" style="flex-shrink:0;" aria-hidden="true">
                  <path d="M13,20H11V8L5.5,13.5L4.08,12.08L12,4.16L19.92,12.08L18.5,13.5L13,8V20Z"/>
                </svg>
                <span>Overwrite Cloud with Local</span>
              </button>
              <button id="forceOverwriteLocal" style="padding: 12px; border-radius: 8px; border: none; background: var(--md-sys-color-error-container, #3b1a1a); color: var(--md-sys-color-on-error-container, #f9dedc); cursor: pointer; font-size: 14px; display: flex; align-items: center; justify-content: center; gap: 8px;">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor" style="flex-shrink:0;" aria-hidden="true">
                  <path d="M11,4H13V16L18.5,10.5L19.92,11.92L12,19.84L4.08,11.92L5.5,10.5L11,16V4Z"/>
                </svg>
                <span>Overwrite Local with Cloud</span>
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
      /* [ZeroLabs] 2026-09-08 3:10 AM - added: fill in the store's real name */
      // Not awaited. The dialog is already usable, and a slow GitLab must not
      // hold it shut over a label. On failure the id simply stays, which is what
      // the dialog showed before this existed.
      if (snippetId) {
        currentStore().describe(snippetId).then(info => {
          const name = BMZGitLabStore.cleanStoreName(info && info.name);
          if (!name) return;
          const el = dialog.querySelector('#connectedStoreName');
          if (el) el.textContent = name;
        }).catch(error => {
          console.warn('[Store] Could not read the store name:', error);
        });
      }

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
            <span><span style="display:inline-flex;align-items:center;gap:5px;"><strong>Supabase</strong><span class="bmz-tooltip-wrap" style="position:relative;display:inline-flex;align-items:center;"><span style="display:inline-flex;align-items:center;justify-content:center;width:15px;height:15px;border-radius:50%;background:var(--md-sys-color-on-surface-variant,#aaa);color:var(--md-sys-color-surface,#1e1e1e);font-size:10px;font-weight:700;cursor:help;flex-shrink:0;line-height:1;">i</span><span class="bmz-tooltip" style="display:none;position:fixed;background:var(--md-sys-color-inverse-surface,#e0e0e0);color:var(--md-sys-color-inverse-on-surface,#1a1a1a);padding:8px 10px;border-radius:6px;font-size:12px;width:220px;z-index:10010;line-height:1.4;pointer-events:none;white-space:normal;">Your token is encrypted and stored in Supabase. When it renews, all your BMZ clients update silently, with no manual steps. Only your encrypted token is stored; it can only access your GitLab bookmark storage.</span></span></span><br><span style="color:var(--md-sys-color-on-surface-variant,#aaa);font-size:12px;">(auto-sync across devices)</span></span>
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
                ? `Synced. ${outcome.addedLocally} added here, cloud updated.`
                : 'Synced. Cloud updated.');
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
      /* [ZeroLabs] 2026-09-07 9:20 PM - added: open the migration from settings */
      const migrateBtn = dialog.querySelector('#migrateToRepo');
      if (migrateBtn) {
        migrateBtn.addEventListener('click', async () => {
          // The settings dialog would sit behind the migration one otherwise, and
          // finishing the move leaves it showing a snippet that is no longer used.
          modal.remove();
          await showSnippetSetup('migrate');
        });
      }

      /* [ZeroLabs] 2026-09-07 9:20 PM - added: reach setup from the settings dialog */
      const openSetupBtn = dialog.querySelector('#openStoreSetup');
      if (openSetupBtn) {
        openSetupBtn.addEventListener('click', async () => {
          modal.remove();
          await showSnippetSetup();
        });
      }

      /* [ZeroLabs] 2026-09-07 9:20 PM - added: switch to a different repository */
      const changeRepoBtn = dialog.querySelector('#changeRepository');
      if (changeRepoBtn) {
        changeRepoBtn.addEventListener('click', async () => {
          modal.remove();
          await showSnippetSetup('switch');
        });
      }

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
              ? `Warning: your cloud bookmarks will be replaced with this device's.\n\n${losing} item(s) currently in the cloud are not on this device and will be lost, on every device using it.\n\nContinue?`
              : 'Your cloud bookmarks will be replaced with this device\'s. Nothing in the cloud is missing here, so nothing will be lost.\n\nContinue?');
            if (!proceed) return;

            modal.remove();
            /* [ZeroLabs] 2026-08-27 2:41 PM - edited: one result, not the push's pair */
            await syncToSnippet(true);
            showToast('Cloud bookmarks overwritten with local.');
          } catch (error) {
            console.error('[ForceOverwrite] Cloud overwrite failed:', error);
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

          /* [ZeroLabs] 2026-09-07 9:20 PM - edited: first-run chooser instead of reopening settings */
          // Reopening the settings dialog left a brand new user to find their own
          // way onto a store, and the only routes it offered were snippet ones.
          // The setup dialog asks the four questions and only creates repositories.
          // A device that is already connected has nothing to choose, so the
          // settings dialog is still right for that one.
          if (snippetId) {
            await openSnippetSyncDialog();
          } else {
            await showSnippetSetup();
          }
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
        <p>You're about to replace your local bookmarks with the cloud data. Would you like to download a backup of your current bookmarks first?</p>
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
      /* [ZeroLabs] 2026-09-23 11:55 PM - edited: above the setup dialog */
      // Was 10000, under the setup dialog's 10001, so opening it from setup put
      // the warning behind the dialog that asked for it.
      modal.style.cssText = 'position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.8); z-index: 10002; display: flex; align-items: center; justify-content: center;';

      const dialog = document.createElement('div');
      dialog.style.cssText = 'background: var(--md-sys-color-error-container, #3b1a1a); padding: 24px; border-radius: 12px; max-width: 500px; width: 90%; color: var(--md-sys-color-on-error-container, #f9dedc); border: 2px solid var(--md-sys-color-error, #f44336);';

      dialog.innerHTML = `
        <h2 style="margin: 0 0 16px 0; font-size: 20px; color: var(--md-sys-color-error, #f44336);">
          ⚠️ WARNING: This Will Override Your Native Browser Bookmarks
        </h2>
        <p style="margin: 0 0 16px 0; font-size: 14px;">
          This action will <strong>permanently replace</strong> your current Firefox bookmarks with the data from the cloud.
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
          'FINAL CONFIRMATION: This will permanently delete all your current Firefox bookmarks and replace them with the cloud data. This cannot be undone. Click OK to proceed.'
        );

        if (!confirmed) {
          resolve(false);
          return;
        }

        try {
          showToast('Syncing from the cloud... This may take a moment.');
          await browser.storage.local.set({ [BULK_REPLACE_KEY]: Date.now() });

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
          reportSetupProgress('Removing this device\'s current bookmarks');
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
          /* [ZeroLabs] 2026-09-23 11:55 PM - added: count the recreate out loud */
          const replaceTotal = countSnippetBookmarks(remoteSnippetData);
          let replaceDone = 0;
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
                  replaceDone++;
                  reportSetupProgress('Copying the cloud\'s bookmarks to this device', replaceDone, replaceTotal);
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
          /* [ZeroLabs] 2026-09-23 11:55 PM - added: the wipe and recreate are not your edits */
          // Every removal and creation above was recorded as a change made here.
          // Both sides now match exactly, so those records describe nothing.
          await clearLocalBookmarkEvents();

          showToast('Bookmarks synced successfully!');
          resolve(true);

          // Reload the bookmark view
          await loadBookmarks();
          renderBookmarks();
        } catch (error) {
          console.error('Failed to apply remote changes:', error);
          showToast(`Error: ${error.message}`, 'error');
          resolve(false);
        } finally {
          await browser.storage.local.remove(BULK_REPLACE_KEY).catch(() => {});
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
            <div style="font-weight: 500;">Replace Cloud with Local</div>
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
            <div style="font-weight: 500;">Replace Local with Cloud</div>
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
              showToast('Cloud sync connected. Bookmarks are already in sync.');
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
                showToast('Cloud bookmarks replaced with local.');
              } catch (error) {
                console.error('Failed to replace cloud bookmarks:', error);
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
                console.error('Failed to replace bookmarks from cloud storage:', error);
                showToast(`Error: ${error.message}`, 'error');
              }
            }
          } else {
            // No local bookmarks, just connect
            snippetId = selectedSnippetId;
            await safeStorage.set({ bmz_snippet_id: snippetId });
            updateGitLabButtonIcon();
            showToast('Cloud sync connected: ' + snippetId);
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
      /* [ZeroLabs] 2026-09-07 9:20 PM - edited: load which KIND of store the id names */
      // Absent means snippet, so an install that predates the project backend keeps
      // working with no migration and no prompt.
      const snippetIdResult = await safeStorage.get(['bmz_snippet_id', 'bmz_store_kind', 'bmz_store_branch']);
      if (snippetIdResult.bmz_snippet_id) {
        snippetId = snippetIdResult.bmz_snippet_id;
      }
      storeKind = snippetIdResult.bmz_store_kind || null;
      storeBranch = snippetIdResult.bmz_store_branch || null;
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
  // Matches the bmzBulkBarOut animation in sidebar.html, so the bar retracts
  // while the boxes are sliding away
  const BULK_BAR_EXIT_MS = 220;

  // .content carries padding: 6px, and the headroom is added on top of it
  const LIST_BASE_PADDING_PX = 6;
  let bulkBarHeadroom = 0;

  function setBulkActionsBarVisible(visible) {
    const bar = document.getElementById('bulkActionsBar');
    if (!bar) return;

    /* [ZeroLabs] 2026-09-22 11:30 PM - edited: flush against the GUI, out of the list's way */
    // Both halves at once. It is pinned to the BOTTOM EDGE OF THE GUI above it,
    // so it continues that stack with no gap and reads as part of it. Pinning
    // to the list's top edge instead left the list's own 6px of padding showing
    // above the bar, which is the gap that made it look like a separate island.
    //
    // It is out of the flow, so the list keeps its size and position and no row
    // moves. The bar covers the first row or so while it is open.
    if (bar.nextElementSibling !== bookmarkList) {
      bookmarkList.before(bar);
    }

    if (!visible) {
      /* [ZeroLabs] 2026-09-23 12:24 AM - edited: let it retract before it disappears */
      // It slides back up under the GUI, and only then is it hidden and its
      // inline styles cleared. Hiding first would delete it mid-travel.
      if (bar.classList.contains('hidden')) return;

      /* [ZeroLabs] 2026-09-23 12:34 AM - added: give the headroom back the same way */
      // Taken away and the scroll pulled back by the same amount, so again
      // nothing on screen moves.
      if (bulkBarHeadroom > 0) {
        bookmarkList.style.paddingTop = '';
        bookmarkList.scrollTo({
          top: Math.max(0, bookmarkList.scrollTop - bulkBarHeadroom),
          behavior: 'instant'
        });
        bulkBarHeadroom = 0;
      }

      bar.classList.remove('bmz-bar-in');
      bar.classList.add('bmz-bar-out');

      setTimeout(() => {
        bar.classList.add('hidden');
        bar.classList.remove('bmz-bar-out');
        bar.style.position = '';
        bar.style.left = '';
        bar.style.right = '';
        bar.style.top = '';
        bar.style.bottom = '';
        bar.style.zIndex = '';
        bar.style.background = '';
        bar.style.borderRadius = '';
        bar.style.boxShadow = '';
      }, BULK_BAR_EXIT_MS);
      return;
    }

    // The nearest thing above it that is actually on screen. The filter and
    // display bars collapse to nothing when closed, so they have to be skipped.
    let anchorBottom = bookmarkList.getBoundingClientRect().top;
    let previous = bar.previousElementSibling;
    while (previous) {
      const rect = previous.getBoundingClientRect();
      if (rect.height > 0) {
        anchorBottom = rect.bottom;
        break;
      }
      previous = previous.previousElementSibling;
    }

    /* [ZeroLabs] 2026-09-23 12:16 AM - edited: back to the top, which read better */
    // Hangs from the bottom edge of the GUI above it, wears the theme surface,
    // rounds its bottom corners and throws its shadow down over the list. Out
    // of the flow, so the list keeps its size and no bookmark moves.
    bar.style.position = 'fixed';
    bar.style.left = '0';
    bar.style.right = '0';
    bar.style.top = `${Math.round(anchorBottom)}px`;
    bar.style.bottom = 'auto';
    bar.style.zIndex = '40';
    bar.style.background = 'var(--md-sys-color-surface)';
    bar.style.borderRadius = '0 0 14px 14px';
    bar.style.boxShadow = '0 6px 16px rgba(0, 0, 0, 0.35)';

    /* [ZeroLabs] 2026-09-23 12:24 AM - added: play the slide every time it opens */
    // The class is removed first, so re-opening restarts the animation instead
    // of finding it already applied and doing nothing.
    bar.classList.remove('bmz-bar-out', 'bmz-bar-in');
    bar.classList.remove('hidden');
    void bar.offsetWidth;
    bar.classList.add('bmz-bar-in');

    /* [ZeroLabs] 2026-09-23 12:34 AM - added: headroom above the first bookmark */
    // The bar floats over the top of the list, so the first item would sit
    // under it with no way to reach it. The list gains padding at the top equal
    // to the bar's height, which makes that headroom exist at the very top of
    // the scroll.
    //
    // The scroll is advanced by the same amount in the same breath, so what is
    // on screen does not move. The headroom is only found by scrolling up to
    // it, which is the point.
    const headroom = Math.round(bar.getBoundingClientRect().height);
    if (headroom > 0) {
      bulkBarHeadroom = headroom;
      bookmarkList.style.paddingTop = `${LIST_BASE_PADDING_PX + headroom}px`;
      bookmarkList.scrollTo({
        top: bookmarkList.scrollTop + headroom,
        behavior: 'instant'
      });
    }
  }

  // Matches the bmzCheckboxOut animation in sidebar.html
  const CHECKBOX_EXIT_MS = 220;

  const multiSelectToggle = document.getElementById('multiSelectToggle');
  multiSelectToggle.addEventListener('click', () => {
    multiSelectMode = !multiSelectMode;

    // Toggle button appearance and ARIA state
    if (multiSelectMode) {
      /* [ZeroLabs] 2026-09-23 3:10 PM - edited: red, because this button is the only way out */
      // The lit-up primary colour read as decoration. This button is the ONLY
      // way to leave multi-select, so it wears the same red as Delete while the
      // mode is on, which reads as a state to be ended.
      multiSelectToggle.style.background = 'var(--md-sys-color-error)';
      multiSelectToggle.style.color = '#ffffff';
      multiSelectToggle.setAttribute('aria-pressed', 'true');
    } else {
      multiSelectToggle.style.background = '';
      multiSelectToggle.style.color = '';
      multiSelectToggle.setAttribute('aria-pressed', 'false');
      selectedItems.clear();
    }

    // Show/hide bulk actions bar
    setBulkActionsBarVisible(multiSelectMode);

    /* [ZeroLabs] 2026-09-22 11:18 PM - edited: let the boxes leave before the rows lose them */
    // Turning the mode off re-renders the rows without their checkboxes, which
    // would delete them mid-frame and there would be nothing to animate. The
    // boxes are tagged, they slide out to the left, and the re-render happens
    // when they are gone. Turning the mode on needs none of this: the checkbox
    // animates itself in as the row that holds it is created.
    const leaving = multiSelectMode
      ? []
      : Array.from(bookmarkList.querySelectorAll('.item-checkbox'));

    if (leaving.length === 0) {
      renderBookmarks();
      return;
    }

    leaving.forEach(box => box.classList.add('item-checkbox-leaving'));
    setTimeout(() => renderBookmarks(), CHECKBOX_EXIT_MS);
  });

  // Long-press to enter multi-select mode
  let longPressTimer = null;
  let longPressStartX = 0;
  let longPressStartY = 0;
  const LONG_PRESS_MS = 750;
  const LONG_PRESS_DRIFT_PX = 8;

  /* [ZeroLabs] 2026-09-22 7:17 PM - added: which input raised the gesture (see also: Bookmark-Manager-Zero-Chrome/sidepanel.js, Bookmark-Manager-Zero-Website/js/sidebar-adapted.js) */
  // A pen counts as touch, by decision: it is held against the screen the same
  // way. Capture phase, so nothing that stops propagation can hide it.
  let lastPointerType = 'mouse';
  document.addEventListener('pointerdown', (e) => {
    lastPointerType = e.pointerType || 'mouse';
  }, true);
  window.isTouchPointer = () => lastPointerType === 'touch' || lastPointerType === 'pen';

  /* [ZeroLabs] 2026-09-22 7:17 PM - edited: select first, render second */
  // The checkbox is drawn from selectedItems, so adding to it after the render
  // left the pressed item unticked while the count said one. The tick was being
  // set on the element captured before the render, which the rebuild had
  // already detached. When multi-select is already on there is no render, so
  // that path still ticks the live checkbox itself.
  function enterMultiSelectFromLongPress(itemEl) {
    const container = itemEl.closest('.bookmark-item, .folder-item');
    const id = container && container.dataset.id;
    if (id) selectedItems.add(id);

    if (!multiSelectMode) {
      multiSelectMode = true;
      /* [ZeroLabs] 2026-09-23 3:10 PM - edited: same red as the toggle handler uses */
      multiSelectToggle.style.background = 'var(--md-sys-color-error)';
      multiSelectToggle.style.color = '#ffffff';
      multiSelectToggle.setAttribute('aria-pressed', 'true');
      setBulkActionsBarVisible(true);
      renderBookmarks();
    } else if (container) {
      const checkbox = container.querySelector('.item-checkbox');
      if (checkbox) checkbox.checked = true;
    }

    if (id) updateSelectedCount();
  }

  /* [ZeroLabs] 2026-09-22 7:17 PM - added: the row handlers reach this through window */
  // The row renderers are OUTSIDE setupEventListeners, so a direct call from
  // them would be a ReferenceError. Same scope trap as showHeldPushDialog.
  window.enterMultiSelectFromLongPress = enterMultiSelectFromLongPress;

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
  /* [ZeroLabs] 2026-09-08 4:05 AM - added: scale the status message, never clip it */
  // The status bar puts a fixed-width section on each side of the progress
  // message, so on a narrow sidebar a long message had nowhere to go and
  // overlapped the "Scan All Bookmarks" label to its left. The CSS now lets the
  // middle section shrink; this makes the text fit inside whatever it gets.
  //
  // Scaled rather than truncated: every one of these messages carries a count or
  // a stage that is the entire reason it is on screen, and an ellipsis would eat
  // exactly the numbers you are watching.
  function fitStatusText() {
    const center = document.querySelector('.scan-status-bar .status-center');
    const el = document.getElementById('scanProgress');
    if (!center || !el) return;

    /* [ZeroLabs] 2026-09-08 6:05 AM - edited: transform, with the layout width corrected */
    // font-size CANNOT work here. On the Fold 5 the Android WebView enforces a
    // minimum font size and ignores anything smaller, so a computed 5px still
    // renders at its clamped width. That is the documented reason fitHeaderText
    // uses transform: scale(), which is a compositor operation and immune to it.
    //
    // transform alone was not enough either, because it does not change layout:
    // the element kept reserving its full width and went on colliding with the
    // bookmark count. So the width is set explicitly to the SCALED width, which
    // makes the box the flex row reserves match the pixels actually painted.
    el.style.transform = '';
    el.style.width = '';
    el.style.fontSize = '';    // clear the font attempt from the previous build

    // The info icon shares the centre section, so its width is not available.
    const icon = center.querySelector('.info-icon');
    const iconWidth = icon ? icon.getBoundingClientRect().width + 6 : 0;
    const box = center.clientWidth - iconWidth;

    // Range rather than scrollWidth: it reports the true rendered text width even
    // while the element is being squeezed by its flex parent.
    const range = document.createRange();
    range.selectNodeContents(el);
    const natural = range.getBoundingClientRect().width;

    if (natural <= box || natural === 0) return;

    // Floor at 60%: below that the counts stop being readable.
    const ratio = Math.max(0.6, box > 0 ? box / natural : 0);
    el.style.transformOrigin = 'left center';
    el.style.transform = 'scale(' + ratio + ')';
    el.style.width = (natural * ratio).toFixed(2) + 'px';
  }

  const schedule = function () {
    requestAnimationFrame(function () {
      fitHeaderText();
      fitStatusText();
    });
  };
  function initHeaderFit() {
    schedule();

    /* [ZeroLabs] 2026-09-08 4:05 AM - added: the status text changes constantly */
    // Unlike the header, this one is rewritten on every scanned batch, so it has
    // to be re-fitted on content change rather than only on resize.
    const progress = document.getElementById('scanProgress');
    if (progress && window.MutationObserver && !progress.dataset.fitObserved) {
      progress.dataset.fitObserved = '1';
      new MutationObserver(schedule).observe(progress, { childList: true, characterData: true, subtree: true });
    }
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
