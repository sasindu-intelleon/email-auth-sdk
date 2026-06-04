"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.EmailAuthSdk = void 0;
const crypto = __importStar(require("crypto"));
const jwt = __importStar(require("jsonwebtoken"));
class EmailAuthSdk {
    constructor(options) {
        if (!options.privateAppKey ||
            !options.AppSecret ||
            !options.AppKey ||
            !options.AppName) {
            throw new Error("EmailAuthSdk: All parameters are required.");
        }
        this.privateAppKey = options.privateAppKey;
        this.appSecret = options.AppSecret;
        this.appName = options.AppName;
        this.appKey = options.AppKey;
    }
    /**
     * Generates the x-app-key using a SHA256 hash.
     */
    generateAppKey(indexId) {
        const rawString = `id:${indexId}:ak:${this.privateAppKey}`;
        return crypto.createHash("sha256").update(rawString).digest("hex");
    }
    /**
     * Generates a Bearer JWT token.
     */
    generateBearerToken(payload) {
        const jwtPayload = {
            index: payload.index,
        };
        const token = jwt.sign(jwtPayload, this.privateAppKey, {
            algorithm: "HS256",
            expiresIn: "5m",
        });
        return `Bearer ${token}`;
    }
    /**
     * Returns all required authentication headers.
     */
    getAuthHeaders(indexId) {
        return {
            "x-app-key": this.generateAppKey(indexId),
            "x-app-name": this.appName,
            Authorization: this.generateBearerToken({ index: indexId }),
        };
    }
    // =========================================================================
    // CALLBACK VALIDATION METHODS
    // =========================================================================
    /**
     * Validates the app_key received from the callback cookie.
     *
     * @param incomingHashedAppKey Hashed app_key value received in the cookie
     * @param indexId Database record index ID
     * @param to Recipient email address
     */
    verifyCallbackAppKey(incomingHashedAppKey, indexId, to) {
        // Recreate the original string using the same pattern
        const rawString = `app:${this.appKey}-${indexId}-m:${to}`;
        // Generate the expected SHA256 hash
        const expectedHash = crypto
            .createHash("sha256")
            .update(rawString)
            .digest("hex");
        // Compare the received hash with the expected hash
        return incomingHashedAppKey === expectedHash;
    }
    /**
     * Validates the JWT access_key received from the callback cookie
     * and returns the decoded payload.
     *
     * @param token JWT token from the cookie (supports both raw token and Bearer token formats)
     */
    verifyCallbackJwt(token) {
        try {
            // Remove Bearer prefix if present
            const actualToken = token.startsWith("Bearer ")
                ? token.split(" ")[1]
                : token;
            const decoded = jwt.verify(actualToken, this.appSecret, {
                algorithms: ["HS256"],
            });
            return decoded;
        }
        catch (error) {
            // Return null if the token is invalid or expired
            return null;
        }
    }
    /**
     * Performs complete callback validation using both cookies.
     *
     * @param cookies Request cookies containing access_key and app_key
     * @param indexId Expected database record index ID
     * @param to Expected recipient email address
     */
    validateCallback(cookies, indexId, to) {
        const { access_key, app_key } = cookies;
        if (!access_key || !app_key) {
            return { isValid: false, payload: null };
        }
        // Step 1: Validate app_key hash
        const isAppKeyValid = this.verifyCallbackAppKey(app_key, indexId, to);
        if (!isAppKeyValid) {
            return { isValid: false, payload: null };
        }
        // Step 2: Validate JWT token
        const jwtPayload = this.verifyCallbackJwt(access_key);
        if (!jwtPayload) {
            return { isValid: false, payload: null };
        }
        // Step 3: Verify payload values match expected values
        if (String(jwtPayload.index_id) !== String(indexId) ||
            jwtPayload.to !== to) {
            return { isValid: false, payload: null };
        }
        return {
            isValid: true,
            payload: jwtPayload,
        };
    }
}
exports.EmailAuthSdk = EmailAuthSdk;
