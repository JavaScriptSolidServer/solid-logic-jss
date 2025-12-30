/**
 * Adapter to make solid-oidc compatible with @inrupt/solid-client-authn-browser API
 *
 * This provides a drop-in replacement for the Inrupt Session class using the minimal
 * solid-oidc library from JavaScriptSolidServer.
 *
 * @see https://github.com/JavaScriptSolidServer/solid-oidc
 */

import {
  Session as SolidOidcSession,
  SessionDatabase
} from 'solid-oidc'

/**
 * Event names compatible with @inrupt/solid-client-authn-browser
 */
export const EVENTS = {
  SESSION_RESTORED: 'sessionRestore',
  LOGIN: 'login',
  LOGOUT: 'logout',
  SESSION_EXPIRED: 'sessionExpired',
  ERROR: 'error'
} as const

/**
 * Callback type for event listeners
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type EventCallback = (...args: any[]) => void

/**
 * Simple event emitter for compatibility with Inrupt's session.events API
 */
class EventEmitter {
  private listeners: Map<string, Set<EventCallback>> = new Map()

  on(event: string, callback: EventCallback): void {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, new Set())
    }
    this.listeners.get(event)!.add(callback)
  }

  off(event: string, callback: EventCallback): void {
    this.listeners.get(event)?.delete(callback)
  }

  emit(event: string, ...args: unknown[]): void {
    this.listeners.get(event)?.forEach(cb => cb(...args))
  }
}

/**
 * Session info interface compatible with Inrupt
 */
export interface SessionInfo {
  isLoggedIn: boolean
  webId?: string
  sessionId?: string
  expirationDate?: number
}

/**
 * Options for handleIncomingRedirect
 */
export interface HandleRedirectOptions {
  restorePreviousSession?: boolean
  url?: string
}

/**
 * Options for login
 */
export interface LoginOptions {
  oidcIssuer: string
  redirectUrl: string
  clientId?: string
  clientName?: string
  tokenType?: string
}

/**
 * Session class that wraps solid-oidc to provide @inrupt/solid-client-authn-browser compatible API
 */
export class Session {
  private _session: SolidOidcSession
  private _events: EventEmitter
  private _sessionId: string

  constructor(options?: { clientId?: string }) {
    this._session = new SolidOidcSession({
      clientId: options?.clientId,
      database: new SessionDatabase(),
      onStateChange: (event) => {
        const detail = (event as CustomEvent).detail
        if (detail?.isActive) {
          this._events.emit(EVENTS.LOGIN)
          this._events.emit(EVENTS.SESSION_RESTORED, window.location.href)
        } else {
          this._events.emit(EVENTS.LOGOUT)
        }
      },
      onExpiration: () => {
        this._events.emit(EVENTS.SESSION_EXPIRED)
      }
    })
    this._events = new EventEmitter()
    this._sessionId = crypto.randomUUID()
  }

  /**
   * Event emitter for session events
   */
  get events(): EventEmitter {
    return this._events
  }

  /**
   * Session information
   */
  get info(): SessionInfo {
    return {
      isLoggedIn: this._session.isActive,
      webId: this._session.webId ?? undefined,
      sessionId: this._sessionId,
      expirationDate: this._session.isActive
        ? Date.now() + (this._session.getExpiresIn() * 1000)
        : undefined
    }
  }

  /**
   * Handle incoming redirect from identity provider
   */
  async handleIncomingRedirect(options?: HandleRedirectOptions | string): Promise<SessionInfo | undefined> {
    // Handle string URL (legacy API)
    const opts: HandleRedirectOptions = typeof options === 'string'
      ? { url: options }
      : options ?? {}

    try {
      // First handle any redirect from login
      await this._session.handleRedirectFromLogin()

      // If not logged in and restorePreviousSession is true, try to restore
      if (!this._session.isActive && opts.restorePreviousSession !== false) {
        try {
          await this._session.restore()
        } catch {
          // No session to restore, that's okay
        }
      }

      return this.info
    } catch (error) {
      this._events.emit(EVENTS.ERROR, error)
      return undefined
    }
  }

  /**
   * Initiate login flow
   */
  async login(options: LoginOptions): Promise<void> {
    const redirectUrl = options.redirectUrl || window.location.href
    await this._session.login(options.oidcIssuer, redirectUrl)
  }

  /**
   * Log out and clear session
   */
  async logout(): Promise<void> {
    await this._session.logout()
  }

  /**
   * Make authenticated fetch request
   */
  async fetch(url: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    return this._session.authFetch(url as string, init)
  }
}

export default Session
