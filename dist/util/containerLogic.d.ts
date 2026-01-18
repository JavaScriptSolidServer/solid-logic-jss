import { NamedNode } from 'rdflib';
/**
 * Container-related class
 */
export declare function createContainerLogic(store: any): {
    isContainer: (url: NamedNode) => boolean;
    createContainer: (url: string) => Promise<void>;
    getContainerElements: (containerNode: NamedNode) => NamedNode[];
    getContainerMembers: (containerUrl: NamedNode) => Promise<NamedNode[]>;
};
//# sourceMappingURL=containerLogic.d.ts.map