export interface EmailAuthOptions {
    privateAppKey: string;
    AppSecret: string;
    AppKey: string;
    AppName: string;
}
export interface BearerPayload {
    index: number | string;
}
export interface CallbackJwtPayload {
    index_id: number | string;
    to: string;
    job_id?: string;
    iat?: number;
}
export declare class EmailAuthSdk {
    private privateAppKey;
    private appSecret;
    private appName;
    private appKey;
    constructor(options: EmailAuthOptions);
    /**
     * Generates the x-app-key using a SHA256 hash.
     */
    generateAppKey(indexId: number | string): string;
    /**
     * Generates a Bearer JWT token.
     */
    generateBearerToken(payload: BearerPayload): string;
    /**
     * Returns all required authentication headers.
     */
    getAuthHeaders(indexId: number | string): {
        "x-app-key": string;
        "x-app-name": string;
        Authorization: string;
    };
    /**
     * Validates the app_key received from the callback cookie.
     *
     * @param incomingHashedAppKey Hashed app_key value received in the cookie
     * @param indexId Database record index ID
     * @param to Recipient email address
     */
    verifyCallbackAppKey(incomingHashedAppKey: string, indexId: number | string, to: string): boolean;
    /**
     * Validates the JWT access_key received from the callback cookie
     * and returns the decoded payload.
     *
     * @param token JWT token from the cookie (supports both raw token and Bearer token formats)
     */
    verifyCallbackJwt(token: string): CallbackJwtPayload | null;
    /**
     * Performs complete callback validation using both cookies.
     *
     * @param cookies Request cookies containing access_key and app_key
     * @param indexId Expected database record index ID
     * @param to Expected recipient email address
     */
    validateCallback(cookies: {
        access_key?: string;
        app_key?: string;
    }, indexId: number | string, to: string): {
        isValid: boolean;
        payload: CallbackJwtPayload | null;
    };
}
