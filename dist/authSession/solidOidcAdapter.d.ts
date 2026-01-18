/**
 * Adapter to make solid-oidc compatible with @inrupt/solid-client-authn-browser API
 *
 * This provides a drop-in replacement for the Inrupt Session class using the minimal
 * solid-oidc library from JavaScriptSolidServer.
 *
 * @see https://github.com/JavaScriptSolidServer/solid-oidc
 */
/**
 * Event names compatible with @inrupt/solid-client-authn-browser
 */
export declare const EVENTS: {
    readonly SESSION_RESTORED: "sessionRestore";
    readonly LOGIN: "login";
    readonly LOGOUT: "logout";
    readonly SESSION_EXPIRED: "sessionExpired";
    readonly ERROR: "error";
};
/**
 * Callback type for event listeners
 */
type EventCallback = (...args: any[]) => void;
/**
 * Simple event emitter for compatibility with Inrupt's session.events API
 */
declare class EventEmitter {
    private listeners;
    on(event: string, callback: EventCallback): void;
    off(event: string, callback: EventCallback): void;
    emit(event: string, ...args: unknown[]): void;
}
/**
 * Session info interface compatible with Inrupt
 */
export interface SessionInfo {
    isLoggedIn: boolean;
    webId?: string;
    sessionId?: string;
    expirationDate?: number;
}
/**
 * Options for handleIncomingRedirect
 */
export interface HandleRedirectOptions {
    restorePreviousSession?: boolean;
    url?: string;
}
/**
 * Options for login
 */
export interface LoginOptions {
    oidcIssuer: string;
    redirectUrl: string;
    clientId?: string;
    clientName?: string;
    tokenType?: string;
}
/**
 * Session class that wraps solid-oidc to provide @inrupt/solid-client-authn-browser compatible API
 */
export declare class Session {
    private _session;
    private _events;
    private _sessionId;
    constructor(options?: {
        clientId?: string;
    });
    /**
     * Event emitter for session events
     */
    get events(): EventEmitter;
    /**
     * Session information
     */
    get info(): SessionInfo;
    /**
     * Handle incoming redirect from identity provider
     */
    handleIncomingRedirect(options?: HandleRedirectOptions | string): Promise<SessionInfo | undefined>;
    /**
     * Initiate login flow
     */
    login(options: LoginOptions): Promise<void>;
    /**
     * Log out and clear session
     */
    logout(): Promise<void>;
    /**
     * Make authenticated fetch request
     */
    fetch(url: RequestInfo | URL, init?: RequestInit): Promise<Response>;
}
export default Session;
//# sourceMappingURL=solidOidcAdapter.d.ts.map