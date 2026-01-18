import { NamedNode } from 'rdflib';
export declare function createUtilityLogic(store: any, aclLogic: any, containerLogic: any): {
    recursiveDelete: (containerNode: NamedNode) => Promise<any>;
    setSinglePeerAccess: (options: {
        ownerWebId: string;
        peerWebId: string;
        accessToModes?: string;
        defaultModes?: string;
        target: string;
    }) => Promise<any>;
    createEmptyRdfDoc: (doc: NamedNode, comment: string) => Promise<void>;
    followOrCreateLink: (subject: NamedNode, predicate: NamedNode, object: NamedNode, doc: NamedNode) => Promise<NamedNode | null>;
    loadOrCreateIfNotExists: (doc: NamedNode) => Promise<any>;
};
//# sourceMappingURL=utilityLogic.d.ts.map