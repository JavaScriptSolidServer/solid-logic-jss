import { NamedNode } from 'rdflib';
/**
 * find a user or app's context as set in window.SolidAppContext
 * this is a const, not a function, because we have problems to jest mock it otherwise
 * see: https://github.com/facebook/jest/issues/936#issuecomment-545080082 for more
 * @return {any} - an appContext object
 */
export declare const appContext: () => any;
/**
 * Returns `sym($SolidTestEnvironment.username)` if
 * `$SolidTestEnvironment.username` is defined as a global
 * or
 * returns testID defined in the HTML page
 * @returns {NamedNode|null}
 */
export declare function offlineTestID(): NamedNode | null;
//# sourceMappingURL=authUtil.d.ts.map