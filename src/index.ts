import * as crypto from "crypto";
import * as jwt from "jsonwebtoken";

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

export class EmailAuthSdk {
  private privateAppKey: string;
  private appSecret: string;
  private appName: string;
  private appKey: string;

  constructor(options: EmailAuthOptions) {
    if (
      !options.privateAppKey ||
      !options.AppSecret ||
      !options.AppKey ||
      !options.AppName
    ) {
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
  public generateAppKey(indexId: number | string): string {
    const rawString = `id:${indexId}:ak:${this.privateAppKey}`;
    return crypto.createHash("sha256").update(rawString).digest("hex");
  }

  /**
   * Generates a Bearer JWT token.
   */
  public generateBearerToken(payload: BearerPayload): string {
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
  public getAuthHeaders(indexId: number | string) {
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
  public verifyCallbackAppKey(
    incomingHashedAppKey: string,
    indexId: number | string,
    to: string
  ): boolean {
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
  public verifyCallbackJwt(token: string): CallbackJwtPayload | null {
    try {
      // Remove Bearer prefix if present
      const actualToken = token.startsWith("Bearer ")
        ? token.split(" ")[1]
        : token;

      const decoded = jwt.verify(actualToken, this.appSecret, {
        algorithms: ["HS256"],
      });

      return decoded as CallbackJwtPayload;
    } catch (error) {
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
  public validateCallback(
    cookies: { access_key?: string; app_key?: string },
    indexId: number | string,
    to: string
  ): { isValid: boolean; payload: CallbackJwtPayload | null } {
    const { access_key, app_key } = cookies;

    if (!access_key || !app_key) {
      return { isValid: false, payload: null };
    }

    // Step 1: Validate app_key hash
    const isAppKeyValid = this.verifyCallbackAppKey(
      app_key,
      indexId,
      to
    );

    if (!isAppKeyValid) {
      return { isValid: false, payload: null };
    }

    // Step 2: Validate JWT token
    const jwtPayload = this.verifyCallbackJwt(access_key);

    if (!jwtPayload) {
      return { isValid: false, payload: null };
    }

    // Step 3: Verify payload values match expected values
    if (
      String(jwtPayload.index_id) !== String(indexId) ||
      jwtPayload.to !== to
    ) {
      return { isValid: false, payload: null };
    }

    return {
      isValid: true,
      payload: jwtPayload,
    };
  }
}