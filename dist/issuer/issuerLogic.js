const DEFAULT_ISSUERS = [
    {
        name: 'Solid Community',
        uri: 'https://solidcommunity.net'
    },
    {
        name: 'Solid Web',
        uri: 'https://solidweb.org'
    },
    {
        name: 'Solid Web ME',
        uri: 'https://solidweb.me'
    },
    {
        name: 'Inrupt.com',
        uri: 'https://login.inrupt.com'
    }
];
/**
 * @returns - A list of suggested OIDC issuers
 */
export function getSuggestedIssuers() {
    // Suggest a default list of OIDC issuers
    const issuers = [...DEFAULT_ISSUERS];
    // Suggest the current host if not already included
    const { host, origin } = new URL(location.href);
    const hosts = issuers.map(({ uri }) => new URL(uri).host);
    if (!hosts.includes(host) && !hosts.some(existing => isSubdomainOf(host, existing))) {
        issuers.unshift({ name: host, uri: origin });
    }
    return issuers;
}
function isSubdomainOf(subdomain, domain) {
    const dot = subdomain.length - domain.length - 1;
    return dot > 0 && subdomain[dot] === '.' && subdomain.endsWith(domain);
}
//# sourceMappingURL=issuerLogic.js.map