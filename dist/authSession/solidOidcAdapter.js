/**
 * Adapter to make solid-oidc compatible with @inrupt/solid-client-authn-browser API
 *
 * This provides a drop-in replacement for the Inrupt Session class using the minimal
 * solid-oidc library from JavaScriptSolidServer.
 *
 * @see https://github.com/JavaScriptSolidServer/solid-oidc
 */
import { Session as SolidOidcSession, SessionDatabase } from 'solid-oidc';
/**
 * Event names compatible with @inrupt/solid-client-authn-browser
 */
export const EVENTS = {
    SESSION_RESTORED: 'sessionRestore',
    LOGIN: 'login',
    LOGOUT: 'logout',
    SESSION_EXPIRED: 'sessionExpired',
    ERROR: 'error'
};
/**
 * Simple event emitter for compatibility with Inrupt's session.events API
 */
class EventEmitter {
    constructor() {
        this.listeners = new Map();
    }
    on(event, callback) {
        if (!this.listeners.has(event)) {
            this.listeners.set(event, new Set());
        }
        this.listeners.get(event).add(callback);
    }
    off(event, callback) {
        var _a;
        (_a = this.listeners.get(event)) === null || _a === void 0 ? void 0 : _a.delete(callback);
    }
    emit(event, ...args) {
        var _a;
        (_a = this.listeners.get(event)) === null || _a === void 0 ? void 0 : _a.forEach(cb => cb(...args));
    }
}
/**
 * Session class that wraps solid-oidc to provide @inrupt/solid-client-authn-browser compatible API
 */
export class Session {
    constructor(options) {
        this._session = new SolidOidcSession({
            clientId: options === null || options === void 0 ? void 0 : options.clientId,
            database: new SessionDatabase(),
            onStateChange: (event) => {
                const detail = event.detail;
                if (detail === null || detail === void 0 ? void 0 : detail.isActive) {
                    this._events.emit(EVENTS.LOGIN);
                    this._events.emit(EVENTS.SESSION_RESTORED, window.location.href);
                }
                else {
                    this._events.emit(EVENTS.LOGOUT);
                }
            },
            onExpiration: () => {
                this._events.emit(EVENTS.SESSION_EXPIRED);
            }
        });
        this._events = new EventEmitter();
        this._sessionId = crypto.randomUUID();
    }
    /**
     * Event emitter for session events
     */
    get events() {
        return this._events;
    }
    /**
     * Session information
     */
    get info() {
        var _a;
        return {
            isLoggedIn: this._session.isActive,
            webId: (_a = this._session.webId) !== null && _a !== void 0 ? _a : undefined,
            sessionId: this._sessionId,
            expirationDate: this._session.isActive
                ? Date.now() + (this._session.getExpiresIn() * 1000)
                : undefined
        };
    }
    /**
     * Handle incoming redirect from identity provider
     */
    async handleIncomingRedirect(options) {
        // Handle string URL (legacy API)
        const opts = typeof options === 'string'
            ? { url: options }
            : options !== null && options !== void 0 ? options : {};
        try {
            // First handle any redirect from login
            await this._session.handleRedirectFromLogin();
            // If not logged in and restorePreviousSession is true, try to restore
            if (!this._session.isActive && opts.restorePreviousSession !== false) {
                try {
                    await this._session.restore();
                }
                catch {
                    // No session to restore, that's okay
                }
            }
            return this.info;
        }
        catch (error) {
            this._events.emit(EVENTS.ERROR, error);
            return undefined;
        }
    }
    /**
     * Initiate login flow
     */
    async login(options) {
        const redirectUrl = options.redirectUrl || window.location.href;
        await this._session.login(options.oidcIssuer, redirectUrl);
    }
    /**
     * Log out and clear session
     */
    async logout() {
        await this._session.logout();
    }
    /**
     * Make authenticated fetch request
     */
    async fetch(url, init) {
        return this._session.authFetch(url, init);
    }
}
export default Session;
//# sourceMappingURL=solidOidcAdapter.js.map