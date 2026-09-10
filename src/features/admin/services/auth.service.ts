import { securityConfig } from '../config/security.config';

// Types
export interface AdminUser {
  email: string;
  name: string;
  picture?: string;
  totpEnabled: boolean;
}

export interface AuthSession {
  user: AdminUser;
  accessToken: string;
  refreshToken?: string;
  expiresAt: number;
  lastActivity: number;
  totpVerified: boolean;
}

export interface RateLimitEntry {
  attempts: number;
  windowStart: number;
}

// Rate limiting storage
const rateLimitStore = new Map<string, RateLimitEntry>();

// Session storage (in production, use secure server-side storage)
const SESSION_KEY = 'admin_auth_session';

export class AuthService {
  private static instance: AuthService;
  private session: AuthSession | null = null;
  private activityTimer: NodeJS.Timeout | null = null;

  private constructor() {
    this.loadSession();
    this.startActivityMonitoring();
  }

  static getInstance(): AuthService {
    if (!AuthService.instance) {
      AuthService.instance = new AuthService();
    }
    return AuthService.instance;
  }

  private getApiBaseUrl(): string {
    return import.meta.env.VITE_API_URL || 'http://localhost:8000';
  }

  // OAuth2 Authentication
  async authenticateWithGoogle(code: string): Promise<{ success: boolean; user?: AdminUser; error?: string }> {
    try {
      // Send the OAuth code to the backend for token exchange and validation
      const response = await fetch(`${this.getApiBaseUrl()}/api/admin/auth/oauth/google`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ 
          code,
          redirect_uri: securityConfig.oauth2.redirectUri 
        }),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        this.logSecurityEvent('BACKEND_AUTH_ERROR', { error: errorData.detail || 'Authentication failed' });
        return { success: false, error: errorData.detail || 'Authentication failed' };
      }

      const authResult = await response.json();
      
      if (!authResult.access_token || !authResult.user) {
        return { success: false, error: 'Invalid authentication response from server' };
      }

      const adminUser: AdminUser = {
        email: authResult.user.email,
        name: authResult.user.name || authResult.user.email,
        picture: authResult.user.picture,
        // Whether this admin already has a TOTP secret is now decided
        // server-side (it's the server that stores secrets), not by
        // checking this browser's localStorage.
        totpEnabled: Boolean(authResult.totp_enabled),
      };

      this.createSession(adminUser, authResult.access_token, authResult.refresh_token);
      
      this.logSecurityEvent('OAUTH_SUCCESS', { email: adminUser.email });
      return { success: true, user: adminUser };
    } catch (error) {
      if (import.meta.env.DEV) {
        console.error('OAuth authentication error:', error);
      }
      return { success: false, error: 'Authentication failed. Please try again.' };
    }
  }

  // Legacy exchangeCodeForTokens and getUserInfo removed — OAuth token
  // exchange AND the userinfo fetch both MUST happen server-side only
  // (via /api/admin/auth/oauth/google) to protect client_secret; this
  // class never talks to Google directly.

  // TOTP Management — setup and verification both happen server-side now.
  // The secret is generated and stored by the backend (TOTPService); this
  // client only ever sees it long enough to render the QR code / manual
  // entry key during enrollment.
  async setupTotp(email: string): Promise<{ secret: string; qrCode: string } | null> {
    if (!this.session) {
      return null;
    }

    try {
      const response = await fetch(`${this.getApiBaseUrl()}/api/admin/auth/totp/setup`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${this.session.accessToken}`,
        },
      });

      if (!response.ok) {
        this.logSecurityEvent('TOTP_SETUP_FAILED', { email });
        return null;
      }

      const result = await response.json();
      return { secret: result.secret, qrCode: result.qrcode_url };
    } catch (error) {
      if (import.meta.env.DEV) {
        console.error('TOTP setup error:', error);
      }
      this.logSecurityEvent('TOTP_SETUP_ERROR', { email });
      return null;
    }
  }

  async verifyTotp(email: string, token: string): Promise<boolean> {
    if (!this.session || this.session.user.email !== email) {
      return false;
    }

    try {
      const response = await fetch(`${this.getApiBaseUrl()}/api/admin/auth/totp/verify`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.session.accessToken}`,
        },
        body: JSON.stringify({
          email,
          totp_code: token
        }),
      });

      if (response.ok) {
        const result = await response.json();
        if (result.verified && result.access_token) {
          // The pre-auth token used to get this far carries no admin
          // permissions — swap it for the fully-verified token the
          // backend just minted. Every subsequent admin API call needs
          // to use THIS token from here on.
          this.session.accessToken = result.access_token;
          this.session.refreshToken = result.refresh_token;
          this.session.totpVerified = true;
          this.session.user.totpEnabled = true;
          sessionStorage.setItem('admin_token', result.access_token);
          this.saveSession();
          this.logSecurityEvent('TOTP_VERIFIED', { email });
          return true;
        }
      }

      this.logSecurityEvent('TOTP_FAILED', { email });
      return false;
    } catch (error) {
      if (import.meta.env.DEV) {
        console.error('Backend TOTP verification failed:', error);
      }
      this.logSecurityEvent('TOTP_BACKEND_UNREACHABLE', { email });
      return false;
    }
  }

  // Session Management
  private createSession(user: AdminUser, accessToken: string, refreshToken?: string): void {
    const now = Date.now();
    
    // Store the backend JWT token in sessionStorage (not localStorage)
    // sessionStorage is cleared when the tab closes, reducing window of exposure
    sessionStorage.setItem('admin_token', accessToken);
    
    this.session = {
      user,
      accessToken,
      refreshToken,
      expiresAt: now + securityConfig.admin.sessionTimeout,
      lastActivity: now,
      totpVerified: false,
    };
    this.saveSession();
  }

  updateSessionActivity(): void {
    if (this.session) {
      const now = Date.now();
      this.session.lastActivity = now;
      this.session.expiresAt = now + securityConfig.admin.sessionTimeout;
      this.saveSession();
    }
  }

  isAuthenticated(): boolean {
    if (!this.session) {
      return false;
    }

    const now = Date.now();
    
    // Check if session has expired
    if (now > this.session.expiresAt) {
      this.logout();
      return false;
    }

    // Check if inactive for too long
    if (now - this.session.lastActivity > securityConfig.admin.sessionTimeout) {
      this.logout();
      return false;
    }

    return true;
  }

  isFullyAuthenticated(): boolean {
    return this.isAuthenticated() && (this.session?.totpVerified || !this.session?.user.totpEnabled);
  }

  getSession(): AuthSession | null {
    if (this.isAuthenticated()) {
      return this.session;
    }
    return null;
  }

  logout(): void {
    if (this.session) {
      this.logSecurityEvent('LOGOUT', { email: this.session.user.email });
    }
    
    // Clear admin token from sessionStorage
    sessionStorage.removeItem('admin_token');
    // Also clear from localStorage in case of legacy sessions
    localStorage.removeItem('admin_token');
    
    this.session = null;
    this.clearSession();
    
    if (this.activityTimer) {
      clearInterval(this.activityTimer);
      this.activityTimer = null;
    }
  }

  // Authorization — admin email validation is enforced server-side.
  // If the backend issued a valid session, the user is authorized.
  private isAuthorizedAdmin(_email: string): boolean {
    return this.session !== null;
  }

  // Rate Limiting
  private checkRateLimit(identifier: string): boolean {
    const now = Date.now();
    const entry = rateLimitStore.get(identifier);
    
    if (!entry || now - entry.windowStart > securityConfig.rateLimit.windowMs) {
      // New window
      rateLimitStore.set(identifier, { attempts: 1, windowStart: now });
      return true;
    }
    
    if (entry.attempts >= securityConfig.rateLimit.maxAttempts) {
      return false;
    }
    
    entry.attempts++;
    return true;
  }

  // Storage helpers
  private saveSession(): void {
    if (this.session) {
      try {
        const encrypted = this.encrypt(JSON.stringify(this.session));
        sessionStorage.setItem(SESSION_KEY, encrypted);
      } catch (error) {
        if (import.meta.env.DEV) {
          console.error('Failed to save session:', error);
        }
      }
    }
  }

  private loadSession(): void {
    try {
      const encrypted = sessionStorage.getItem(SESSION_KEY);
      if (encrypted) {
        const decrypted = this.decrypt(encrypted);
        this.session = JSON.parse(decrypted);
      }
    } catch (error) {
      if (import.meta.env.DEV) {
        console.error('Failed to load session:', error);
      }
      this.clearSession();
    }
  }

  private clearSession(): void {
    sessionStorage.removeItem(SESSION_KEY);
  }

  // Storage obfuscation helpers for sessionStorage.
  //
  // This is NOT encryption — it's a base64 transform with a random,
  // unused IV prepended, despite what an earlier version of this
  // comment claimed. It never called the Web Crypto API. Real crypto
  // here would need `saveSession`/`loadSession` to go async (this class
  // calls `loadSession()` synchronously from its constructor), for
  // protection that wouldn't meaningfully help anyway: anything that can
  // run JS in this origin can call `authService.getSession()` directly,
  // encrypted-at-rest or not. The actual fix for the secret this used to
  // guard — the TOTP secret — is that it no longer touches the browser
  // at all; see setupTotp()/verifyTotp() above.
  private encrypt(data: string): string {
    try {
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const encoder = new TextEncoder();
      const encoded = encoder.encode(data);
      const ivHex = Array.from(iv, b => b.toString(16).padStart(2, '0')).join('');
      const dataB64 = btoa(String.fromCharCode(...encoded));
      return ivHex + ':' + dataB64;
    } catch {
      // Fallback: at minimum, don't store plaintext
      return btoa(encodeURIComponent(data));
    }
  }

  private decrypt(data: string): string {
    try {
      if (data.includes(':')) {
        // New format: ivHex:base64Data
        const parts = data.split(':');
        const dataB64 = parts[1];
        const bytes = atob(dataB64);
        return new TextDecoder().decode(Uint8Array.from(bytes, c => c.charCodeAt(0)));
      }
      // Legacy base64 format (backwards-compatible)
      return decodeURIComponent(atob(data));
    } catch {
      // Last resort: try plain atob
      try { return atob(data); } catch { return data; }
    }
  }

  // Activity monitoring
  private startActivityMonitoring(): void {
    // Check session expiry every minute
    this.activityTimer = setInterval(() => {
      if (this.session && !this.isAuthenticated()) {
        this.logout();
      }
    }, 60000);

    // Listen for user activity
    if (typeof window !== 'undefined') {
      ['mousedown', 'keydown', 'scroll', 'touchstart'].forEach(event => {
        window.addEventListener(event, () => this.updateSessionActivity(), { passive: true });
      });
    }
  }

  // Security logging
  private logSecurityEvent(event: string, details: Record<string, unknown>): void {
    const logEntry = {
      timestamp: new Date().toISOString(),
      event,
      details,
      userAgent: navigator.userAgent,
      ip: 'client-side', // In production, get from server
    };
    
    if (import.meta.env.DEV) {
      console.log('[SECURITY]', logEntry);
    }
    
    // In production, security logs are sent to the backend
  }
}

export const authService = AuthService.getInstance();
