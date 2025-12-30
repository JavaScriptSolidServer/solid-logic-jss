# solid-logic-jss

[![MIT license](https://img.shields.io/github/license/JavaScriptSolidServer/solid-logic-jss)](LICENSE)

**Core Solid logic with minimal solid-oidc authentication (JSS variant)**

A fork of [solid-logic](https://github.com/solidos/solid-logic) that replaces `@inrupt/solid-client-authn-browser` with the minimal [solid-oidc](https://github.com/JavaScriptSolidServer/solid-oidc) library.

## Why This Fork?

| Aspect | solid-logic (original) | solid-logic-jss |
|--------|------------------------|-----------------|
| Auth library | @inrupt/solid-client-authn-browser (~150KB) | solid-oidc (~20KB) |
| Auth code | Compiled/minified | 584 lines, readable |
| Dependencies | Many | Minimal |

## Installation

```sh
npm install solid-logic-jss rdflib
```

> **Note**: `rdflib` is a peer dependency.

## Usage

```js
import { solidLogicSingleton, store, authn, authSession } from 'solid-logic-jss'

// Check current user
console.log('Current user:', authn.currentUser())

// Login
await authSession.login({
  oidcIssuer: 'https://solidcommunity.net',
  redirectUrl: window.location.href
})

// Make authenticated requests
const response = await authSession.fetch('https://pod.example/private/data.ttl')
```

## Browser Usage (ESM)

```html
<script type="module">
  import * as $rdf from 'https://esm.sh/rdflib'
  import { solidLogicSingleton, authn, authSession } from 'https://esm.sh/solid-logic-jss'

  // Handle login redirect
  await authSession.handleIncomingRedirect({ restorePreviousSession: true })

  console.log('Current user:', authn.currentUser())
</script>
```

## API Compatibility

This fork maintains API compatibility with solid-logic. The `authSession` object provides the same interface as `@inrupt/solid-client-authn-browser`:

- `authSession.info.webId` - Current user's WebID
- `authSession.info.isLoggedIn` - Login status
- `authSession.login(options)` - Initiate login
- `authSession.logout()` - Log out
- `authSession.fetch(url, init)` - Authenticated fetch
- `authSession.handleIncomingRedirect(options)` - Handle OIDC redirect
- `authSession.events.on(event, callback)` - Session events

## Common Exports

```js
import {
  solidLogicSingleton,  // Complete singleton instance
  store,                // RDF store
  authn,                // Authentication logic
  authSession,          // Authentication session
  ACL_LINK,             // ACL constants
  // Error classes
  UnauthorizedError,
  NotFoundError,
  FetchError
} from 'solid-logic-jss'
```

## Related

- [solid-oidc](https://github.com/JavaScriptSolidServer/solid-oidc) - Minimal OIDC client
- [solid-logic](https://github.com/solidos/solid-logic) - Original library
- [JavaScriptSolidServer](https://github.com/JavaScriptSolidServer) - JSS ecosystem

## Credits

- Original [solid-logic](https://github.com/solidos/solid-logic) by SolidOS team
- [solid-oidc](https://github.com/JavaScriptSolidServer/solid-oidc) based on work by [uvdsl](https://github.com/uvdsl)

## License

MIT
