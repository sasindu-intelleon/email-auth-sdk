
# Email Authentication SDK

A lightweight, secure TypeScript SDK designed to manage API authentication headers and seamlessly validate secure webhook cookies for the Email Service ecosystem.

---

## Features

* **Header Generation**: Securely generate `x-app-key`, `x-app-name`, and `Authorization` Bearer tokens.
* **Callback & Webhook Validation**: Robust dual-layer validation for incoming server webhooks using securely hashed app keys and JWT validation.
* **TypeScript Native**: Fully typed exports with zero configuration required to get auto-completion out of the box.

---

## Installation

Since this is a private package hosted via GitHub, you can install it directly using your repository link:

  ```bash
    npm install git+[https://github.com/sasindu-intelleon/email-auth-sdk.git](https://github.com/sasindu-intelleon/email-auth-sdk.git)
  
  ```



## Configuration

Initialize the SDK by providing the required environment credentials from your centralized configuration module:

```typescript
import { EmailAuthSdk } from '@sasindu-intelleon/email-auth-sdk';

const authSdk = new EmailAuthSdk({
  privateAppKey: process.env.PRIVATE_APP_KEY,   // Secret key used to generate outward signatures
  AppSecret: process.env.APP_SECRET_KEY,        // Secret key used to sign/verify callback JWTs
  AppKey: process.env.APP_KEY,                  // Public app identifier string
  AppName: process.env.APP_NAME,                // Descriptive application name
});

```

---

## Usage Guide

### 1. Generating Outbound Request Headers

Use this configuration when your main client application needs to issue requests safely into the email distribution microservice.

```typescript
import axios from 'axios';

const indexId = 1042; // Database record identifier

// Generate the fully assembled auth header bundle
const authHeaders = authSdk.getAuthHeaders(indexId);

/*
Returns:
{
  "x-app-key": "a591a6d40bf420404a011733cfb7b190d62c65...",
  "x-app-name": "FINANCIAL_PLANNER",
  "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
*/

// Dispatch request securely
await axios.post('[https://api.email-service.local/v1/send](https://api.email-service.local/v1/send)', emailPayload, {
  headers: {
    'Content-Type': 'application/json',
    ...authHeaders
  }
});

```

### 2. Validating Inbound Callback Requests (Webhooks)

When the internal pipeline transitions states, it returns signed transactional data securely payloaded inside HTTP Cookies (`access_key` and `app_key`). Use the SDK to verify the state integrity of the sender before processing updates.

```typescript
import { Request, Response } from 'express';

export const handleEmailCallback = async (req: Request, res: Response) => {
  const { index_id, data } = req.body;
  const targetRecipient = data.to;

  // Extract cookies (Requires cookie-parser middleware configured in your Express app)
  const incomingCookies = {
    access_key: req.cookies?.access_key, // Contains the JWT token
    app_key: req.cookies?.app_key,       // Contains the hashed application metadata
  };

  // Perform full cryptographic dual-layer structure verification
  const validation = authSdk.validateCallback(incomingCookies, index_id, targetRecipient);

  if (!validation.isValid) {
    return res.status(401).json({ 
      status: "error", 
      message: "Unauthorized callback request. Signature mismatch or expired token." 
    });
  }

  // At this stage, data authenticity is guaranteed.
  console.log("Verified Job ID:", validation.payload?.job_id);

  // Safely proceed with internal business logic or database commits
  return res.status(200).json({ status: "success" });
};

```

---

## API Reference

### `new EmailAuthSdk(options: EmailAuthOptions)`

Instantiates the authentication interface. Throws a generic runtime error if any configuration option is missing.

### `.getAuthHeaders(indexId: number | string)`

Generates matching SHA256 hashed keys and structured JWT access payloads synchronized to clear request context keys.

### `.validateCallback(cookies, indexId, to)`

Validates incoming cookie payloads. Returns a structural validation object: `{ isValid: boolean; payload: CallbackJwtPayload | null }`.

---

## License

Internal Proprietary Software - All Rights Reserved.

