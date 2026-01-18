import { solidLogicSingleton } from './logic/solidLogicSingleton';
declare const authn: import("./types").AuthnLogic;
declare const authSession: import("./authSession/solidOidcAdapter").Session;
declare const store: import("rdflib").LiveStore;
export { ACL_LINK } from './acl/aclLogic';
export { offlineTestID, appContext } from './authn/authUtil';
export { getSuggestedIssuers } from './issuer/issuerLogic';
export { createTypeIndexLogic } from './typeIndex/typeIndexLogic';
export type { AppDetails, SolidNamespace, AuthenticationContext, SolidLogic, ChatLogic } from './types';
export { UnauthorizedError, CrossOriginForbiddenError, SameOriginForbiddenError, NotFoundError, FetchError, NotEditableError, WebOperationError } from './logic/CustomError';
export { solidLogicSingleton, // solidLogicSingleton is exported entirely because it is used in solid-panes
store, authn, authSession };
//# sourceMappingURL=index.d.ts.map