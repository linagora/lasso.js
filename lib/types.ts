/**
 * HTTP methods for SAML message binding
 */
export enum HttpMethod {
  NONE = 0,
  GET = 1,
  POST = 2,
  REDIRECT = 3,
  SOAP = 4,
  ARTIFACT_GET = 5,
  ARTIFACT_POST = 6,
}

/**
 * Signature methods for SAML messages
 */
export enum SignatureMethod {
  RSA_SHA1 = 1,
  RSA_SHA256 = 2,
  RSA_SHA384 = 3,
  RSA_SHA512 = 4,
}

/**
 * SAML 2.0 Name ID formats
 */
export const NameIdFormat = {
  UNSPECIFIED: "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
  EMAIL: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
  PERSISTENT: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
  TRANSIENT: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
  ENCRYPTED: "urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted",
  KERBEROS: "urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos",
} as const;

export type NameIdFormatType = (typeof NameIdFormat)[keyof typeof NameIdFormat];

/**
 * SAML 2.0 Authentication context classes
 */
export const AuthnContext = {
  PASSWORD:
    "urn:oasis:names:tc:SAML:2.0:ac:classes:Password",
  PASSWORD_PROTECTED_TRANSPORT:
    "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
  TLS_CLIENT: "urn:oasis:names:tc:SAML:2.0:ac:classes:TLSClient",
  X509: "urn:oasis:names:tc:SAML:2.0:ac:classes:X509",
  SMARTCARD: "urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard",
  KERBEROS: "urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos",
} as const;

export type AuthnContextType = (typeof AuthnContext)[keyof typeof AuthnContext];

/**
 * Options for adding a provider to the server
 */
export interface ProviderOptions {
  /** Metadata XML as string or Buffer */
  metadata: string | Buffer;
  /** Public key PEM (optional) */
  publicKey?: string | Buffer;
  /** CA certificate PEM (optional) */
  caCert?: string | Buffer;
}

/**
 * Options for creating a server
 */
export interface ServerOptions {
  /** Metadata XML as string or Buffer */
  metadata: string | Buffer;
  /** Private key PEM as string or Buffer */
  privateKey: string | Buffer;
  /** Private key password (optional) */
  privateKeyPassword?: string;
  /** Certificate PEM as string or Buffer */
  certificate: string | Buffer;
}

/**
 * Result from building a SAML message
 */
export interface MessageResult {
  /** URL to redirect/post to */
  responseUrl: string;
  /** Message body (for POST binding) */
  responseBody?: string;
  /** HTTP method used */
  httpMethod: HttpMethod;
  /** RelayState value */
  relayState?: string;
}

/**
 * Provider information returned by Server.getProvider()
 */
export interface ProviderInfo {
  /** Entity ID of the provider */
  entityId: string;
  /** Provider metadata XML (if available) */
  metadata?: string;
}

/**
 * SAML attribute to include in assertion
 */
export interface SamlAttribute {
  /** Attribute name */
  name: string;
  /** Attribute name format (optional) */
  nameFormat?: string;
  /** Attribute values */
  values: string[];
}
