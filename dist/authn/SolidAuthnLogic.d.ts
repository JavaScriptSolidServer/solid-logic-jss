import { NamedNode } from 'rdflib';
import { Session } from '../authSession/solidOidcAdapter';
import { AuthenticationContext, AuthnLogic } from '../types';
export declare class SolidAuthnLogic implements AuthnLogic {
    private session;
    constructor(solidAuthSession: Session);
    get authSession(): Session;
    currentUser(): NamedNode | null;
    /**
     * Retrieves currently logged in webId from either
     * defaultTestUser or SolidAuth
     * Also activates a session after login
     * @param [setUserCallback] Optional callback
     * @returns Resolves with webId uri, if no callback provided
     */
    checkUser<T>(setUserCallback?: (me: NamedNode | null) => T): Promise<NamedNode | T | null>;
    /**
     * Saves `webId` in `context.me`
     * @param webId
     * @param context
     *
     * @returns Returns the WebID, after setting it
     */
    saveUser(webId: NamedNode | string | null, context?: AuthenticationContext): NamedNode | null;
    /**
     * @returns {Promise<string|null>} Resolves with WebID URI or null
     */
    webIdFromSession(session?: {
        webId?: string;
        isLoggedIn: boolean;
    }): string | null;
}
//# sourceMappingURL=SolidAuthnLogic.d.ts.map