import { NamedNode } from 'rdflib';
export declare function newThing(doc: NamedNode): NamedNode;
export declare function uniqueNodes(arr: NamedNode[]): NamedNode[];
export declare function getArchiveUrl(baseUrl: string, date: Date): string;
export declare function differentOrigin(doc: any): boolean;
export declare function suggestPreferencesFile(me: NamedNode): NamedNode;
export declare function determineChatContainer(invitee: NamedNode, podRoot: NamedNode): NamedNode;
//# sourceMappingURL=utils.d.ts.map