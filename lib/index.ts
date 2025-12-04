/**
 * lasso.js - Node.js N-API binding for Lasso SAML library
 *
 * @packageDocumentation
 */

import path from "path";

// Types
export * from "./types";

interface NativeBinding {
  init(): boolean;
  shutdown(): boolean;
  checkVersion(): string;
  isInitialized(): boolean;
  Server: ServerConstructor;
  Login: LoginConstructor;
  Logout: LogoutConstructor;
  Identity: IdentityConstructor;
  Session: SessionConstructor;
  HttpMethod: Record<string, number>;
  SignatureMethod: Record<string, number>;
  NameIdFormat: Record<string, string>;
}

// Load native binding
let binding: NativeBinding;
try {
  // Load the locally built binary
  binding = require(path.join(__dirname, "..", "build", "Release", "lasso.node"));
} catch (e) {
  throw new Error(
    `Failed to load lasso.js native binding: ${e instanceof Error ? e.message : String(e)}\n` +
      "Make sure liblasso is installed and the native module is built.",
  );
}

/**
 * Initialize Lasso library
 * Must be called before any other Lasso function
 */
export function init(): boolean {
  return binding.init();
}

/**
 * Shutdown Lasso library
 * Should be called when done using Lasso
 */
export function shutdown(): boolean {
  return binding.shutdown();
}

/**
 * Get Lasso library version
 */
export function checkVersion(): string {
  return binding.checkVersion();
}

/**
 * Check if Lasso is initialized
 */
export function isInitialized(): boolean {
  return binding.isInitialized();
}

// Re-export native classes with TypeScript interfaces

import type {
  HttpMethod,
  MessageResult,
  NameIdFormatType,
  ProviderInfo,
  SamlAttribute,
} from "./types";

// Server class interface
interface ServerConstructor {
  new (): Server;
  fromBuffers(
    metadata: string | Buffer,
    privateKey: string | Buffer,
    certificate: string | Buffer,
    privateKeyPassword?: string,
  ): Server;
  fromDump(dump: string): Server;
}

/**
 * Lasso Server - represents an IdP or SP
 */
export interface Server {
  /** Entity ID of this server */
  readonly entityId: string;

  /**
   * Add a provider from metadata file
   * @param providerId - Entity ID of the provider
   * @param metadataPath - Path to metadata file
   * @param publicKeyPath - Path to public key file (optional)
   * @param caCertPath - Path to CA certificate file (optional)
   */
  addProvider(
    providerId: string,
    metadataPath: string,
    publicKeyPath?: string,
    caCertPath?: string,
  ): void;

  /**
   * Add a provider from metadata buffer
   * @param providerId - Entity ID of the provider
   * @param metadata - Metadata XML as string or Buffer
   * @param publicKey - Public key PEM as string (optional)
   */
  addProviderFromBuffer(
    providerId: string,
    metadata: string | Buffer,
    publicKey?: string,
  ): void;

  /**
   * Get a provider by entity ID
   * @param providerId - Entity ID of the provider
   * @returns Provider info or null if not found
   */
  getProvider(providerId: string): ProviderInfo | null;

  /**
   * Dump server configuration to string
   * Can be used to restore server later with Server.fromDump()
   */
  dump(): string;
}

export const Server: ServerConstructor = binding.Server;

// Login class interface
interface LoginConstructor {
  new (server: Server): Login;
}

/**
 * Lasso Login - handles SSO operations
 */
export interface Login {
  /** Identity object */
  identity: Identity | null;
  /** Session object */
  session: Session | null;
  /** Remote provider entity ID */
  readonly remoteProviderId: string | null;
  /** Name ID from assertion */
  readonly nameId: string | null;
  /** Name ID format */
  readonly nameIdFormat: string | null;
  /** RelayState value */
  relayState: string | null;
  /** Message URL after building */
  readonly msgUrl: string | null;
  /** Message body after building */
  readonly msgBody: string | null;

  // IdP methods

  /**
   * Process an incoming AuthnRequest (IdP)
   * @param message - The SAML AuthnRequest (base64 or URL-encoded)
   * @param method - HTTP method used (optional, defaults to REDIRECT)
   */
  processAuthnRequestMsg(message: string, method?: HttpMethod): void;

  /**
   * Validate the AuthnRequest (IdP)
   */
  validateRequestMsg(): void;

  /**
   * Build a SAML assertion for the authenticated user (IdP)
   * @param authenticationMethod - Authentication context class URI
   * @param authenticationInstant - When authentication occurred (ISO string, optional)
   */
  buildAssertion(authenticationMethod?: string, authenticationInstant?: string): void;

  /**
   * Set the NameID for the assertion (IdP)
   * @param nameId - The name identifier value
   * @param format - The name ID format (optional)
   */
  setNameId(nameId: string, format?: NameIdFormatType): void;

  /**
   * Set user attributes in the assertion (IdP)
   * @param attributes - Array of attributes
   */
  setAttributes(attributes: SamlAttribute[]): void;

  /**
   * Build the SAML Response message (IdP)
   */
  buildResponseMsg(): MessageResult;

  // SP methods

  /**
   * Initialize an AuthnRequest (SP)
   * @param providerId - Target IdP entity ID (optional)
   * @param method - HTTP method to use (optional)
   */
  initAuthnRequest(providerId?: string, method?: HttpMethod): void;

  /**
   * Build the AuthnRequest message (SP)
   */
  buildAuthnRequestMsg(): MessageResult;

  /**
   * Process a SAML Response (SP)
   * @param message - The SAML Response
   */
  processResponseMsg(message: string): void;

  /**
   * Accept the SSO (SP)
   */
  acceptSso(): void;
}

export const Login: LoginConstructor = binding.Login;

// Logout class interface
interface LogoutConstructor {
  new (server: Server): Logout;
}

/**
 * Lasso Logout - handles SLO operations
 */
export interface Logout {
  /** Identity object */
  identity: Identity | null;
  /** Session object */
  session: Session | null;
  /** Message URL after building */
  readonly msgUrl: string | null;
  /** Message body after building */
  readonly msgBody: string | null;

  /**
   * Initialize a logout request
   * @param providerId - Target provider to notify (optional)
   * @param method - HTTP method to use (optional)
   */
  initRequest(providerId?: string, method?: HttpMethod): void;

  /**
   * Build the LogoutRequest message
   */
  buildRequestMsg(): MessageResult;

  /**
   * Process an incoming LogoutRequest
   * @param message - The SAML LogoutRequest
   * @param method - HTTP method used (optional)
   */
  processRequestMsg(message: string, method?: HttpMethod): void;

  /**
   * Validate the logout request
   */
  validateRequest(): void;

  /**
   * Build the LogoutResponse message
   */
  buildResponseMsg(): MessageResult;

  /**
   * Process an incoming LogoutResponse
   * @param message - The SAML LogoutResponse
   */
  processResponseMsg(message: string): void;

  /**
   * Get the next provider to notify (for IdP-initiated SLO)
   * @returns Provider ID or null if no more providers
   */
  getNextProviderId(): string | null;
}

export const Logout: LogoutConstructor = binding.Logout;

// Identity class interface
interface IdentityConstructor {
  new (): Identity;
  fromDump(dump: string): Identity;
}

/**
 * Lasso Identity - stores federation information
 */
export interface Identity {
  /** Check if identity is empty */
  readonly isEmpty: boolean;

  /**
   * Dump identity to string
   */
  dump(): string | null;
}

export const Identity: IdentityConstructor = binding.Identity;

// Session class interface
interface SessionConstructor {
  new (): Session;
  fromDump(dump: string): Session;
}

/**
 * Lasso Session - stores session information
 */
export interface Session {
  /** Check if session is empty */
  readonly isEmpty: boolean;
  /** Check if session is dirty (modified) */
  readonly isDirty: boolean;

  /**
   * Dump session to string
   */
  dump(): string | null;

  /**
   * Get assertions for a provider
   * @param providerId - Provider entity ID
   * @returns Array of assertion XML strings
   */
  getAssertions(providerId: string): string[];

  /**
   * Get session index for a provider
   * @param providerId - Provider entity ID
   * @returns Session index or null
   */
  getProviderIndex(providerId: string): string | null;
}

export const Session: SessionConstructor = binding.Session;
