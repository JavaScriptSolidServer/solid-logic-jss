declare class CustomError extends Error {
    constructor(message?: string);
}
export declare class UnauthorizedError extends CustomError {
}
export declare class CrossOriginForbiddenError extends CustomError {
}
export declare class SameOriginForbiddenError extends CustomError {
}
export declare class NotFoundError extends CustomError {
}
export declare class NotEditableError extends CustomError {
}
export declare class WebOperationError extends CustomError {
}
export declare class FetchError extends CustomError {
    status: number;
    constructor(status: number, message?: string);
}
export {};
//# sourceMappingURL=CustomError.d.ts.map