import { namedNode, sym } from 'rdflib';
import { appContext, offlineTestID } from './authUtil';
import * as debug from '../util/debug';
import { EVENTS } from '../authSession/solidOidcAdapter';
export class SolidAuthnLogic {
    constructor(solidAuthSession) {
        this.session = solidAuthSession;
    }
    // we created authSession getter because we want to access it as authn.authSession externally
    get authSession() { return this.session; }
    currentUser() {
        const app = appContext();
        if (app.viewingNoAuthPage) {
            return sym(app.webId);
        }
        if (this && this.session && this.session.info && this.session.info.webId && this.session.info.isLoggedIn) {
            return sym(this.session.info.webId);
        }
        return offlineTestID(); // null unless testing
    }
    /**
     * Retrieves currently logged in webId from either
     * defaultTestUser or SolidAuth
     * Also activates a session after login
     * @param [setUserCallback] Optional callback
     * @returns Resolves with webId uri, if no callback provided
     */
    async checkUser(setUserCallback) {
        // Save hash for "restorePreviousSession"
        const preLoginRedirectHash = new URL(window.location.href).hash;
        if (preLoginRedirectHash) {
            window.localStorage.setItem('preLoginRedirectHash', preLoginRedirectHash);
        }
        this.session.events.on(EVENTS.SESSION_RESTORED, (url) => {
            debug.log(`Session restored to ${url}`);
            if (document.location.toString() !== url)
                history.replaceState(null, '', url);
        });
        /**
         * Handle a successful authentication redirect
         */
        const redirectUrl = new URL(window.location.href);
        redirectUrl.hash = '';
        await this.session
            .handleIncomingRedirect({
            restorePreviousSession: true,
            url: redirectUrl.href
        });
        // Check to see if a hash was stored in local storage
        const postLoginRedirectHash = window.localStorage.getItem('preLoginRedirectHash');
        if (postLoginRedirectHash) {
            const curUrl = new URL(window.location.href);
            if (curUrl.hash !== postLoginRedirectHash) {
                if (history.pushState) {
                    // debug.log('Setting window.location.has using pushState')
                    history.pushState(null, document.title, postLoginRedirectHash);
                }
                else {
                    // debug.warn('Setting window.location.has using location.hash')
                    location.hash = postLoginRedirectHash;
                }
                curUrl.hash = postLoginRedirectHash;
            }
            // See https://stackoverflow.com/questions/3870057/how-can-i-update-window-location-hash-without-jumping-the-document
            // window.location.href = curUrl.toString()// @@ See https://developer.mozilla.org/en-US/docs/Web/API/Window/location
            window.localStorage.setItem('preLoginRedirectHash', '');
        }
        // Check to see if already logged in / have the WebID
        let me = offlineTestID();
        if (me) {
            return Promise.resolve(setUserCallback ? setUserCallback(me) : me);
        }
        const webId = this.webIdFromSession(this.session.info);
        if (webId) {
            me = this.saveUser(webId);
        }
        if (me) {
            debug.log(`(Logged in as ${me} by authentication)`);
        }
        return Promise.resolve(setUserCallback ? setUserCallback(me) : me);
    }
    /**
     * Saves `webId` in `context.me`
     * @param webId
     * @param context
     *
     * @returns Returns the WebID, after setting it
     */
    saveUser(webId, context) {
        let webIdUri;
        if (webId) {
            webIdUri = (typeof webId === 'string') ? webId : webId.uri;
            const me = namedNode(webIdUri);
            if (context) {
                context.me = me;
            }
            return me;
        }
        return null;
    }
    /**
     * @returns {Promise<string|null>} Resolves with WebID URI or null
     */
    webIdFromSession(session) {
        const webId = (session === null || session === void 0 ? void 0 : session.webId) && session.isLoggedIn ? session.webId : null;
        return webId;
    }
}
//# sourceMappingURL=SolidAuthnLogic.js.map