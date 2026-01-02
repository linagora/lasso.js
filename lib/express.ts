/**
 * Express middleware for SAML Service Provider
 *
 * Copyright (c) LINAGORA <https://linagora.com>
 * License: GPL-2.0-or-later
 */

import * as lasso from "./index";
import type { Request, Response, NextFunction, Router } from "express";
import * as crypto from "crypto";

/**
 * Escape HTML special characters to prevent XSS
 */
function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;");
}

/**
 * Validate redirect URL to prevent open redirect attacks
 */
function isValidRedirectUrl(url: string, allowedHosts?: string[]): boolean {
  // Allow relative URLs (but not protocol-relative)
  if (url.startsWith("/") && !url.startsWith("//")) {
    return true;
  }
  // If allowed hosts are configured, check against them
  if (allowedHosts?.length) {
    try {
      const parsed = new URL(url);
      return allowedHosts.includes(parsed.host);
    } catch {
      return false;
    }
  }
  // By default, reject absolute URLs
  return false;
}

/**
 * SAML SP middleware configuration
 */
export interface SamlSpConfig {
  /** SP metadata XML string or path to file */
  spMetadata: string;
  /** SP private key PEM string or path to file */
  spKey: string;
  /** SP certificate PEM string or path to file */
  spCert: string;
  /** IdP metadata XML string or path to file */
  idpMetadata: string;
  /** IdP entity ID (extracted from metadata if not provided) */
  idpEntityId?: string;

  /**
   * Called when user is authenticated successfully
   * @param user - User information from SAML assertion
   * @param req - Express request
   * @returns User object to store in session, or Promise
   */
  onAuth: (
    user: SamlUser,
    req: Request
  ) => unknown | Promise<unknown>;

  /**
   * Called when logout is completed
   * @param req - Express request
   */
  onLogout?: (req: Request) => void | Promise<void>;

  /**
   * Get the current user's name ID for logout
   * @param req - Express request
   * @returns NameID string or null if not logged in
   */
  getNameId?: (req: Request) => string | null;

  /**
   * Get the current user's session index for logout
   * @param req - Express request
   * @returns Session index string or null
   */
  getSessionIndex?: (req: Request) => string | null;

  /** Base path for SAML routes (default: '/saml') */
  basePath?: string;

  /** Session property name to store user (default: 'user') */
  sessionProperty?: string;

  /** NameID format to request (default: EMAIL) */
  nameIdFormat?: string;

  /** Authentication context class (default: PasswordProtectedTransport) */
  authnContext?: string;

  /** Force authentication even if already logged in at IdP */
  forceAuthn?: boolean;

  /** Request passive authentication (no user interaction) */
  isPassive?: boolean;

  /** Default redirect URL after login (default: '/') */
  defaultRedirectUrl?: string;

  /** Default redirect URL after logout (default: '/') */
  logoutRedirectUrl?: string;

  // Security options

  /** Allowed hosts for redirects (default: none, only relative URLs allowed) */
  allowedRedirectHosts?: string[];
  /** Maximum age of SAML state in ms (default: 300000 = 5 minutes) */
  stateMaxAge?: number;
  /** Regenerate session after authentication (default: true) */
  regenerateSession?: boolean;
}

/**
 * User information extracted from SAML assertion
 */
export interface SamlUser {
  /** NameID value */
  nameId: string;
  /** NameID format */
  nameIdFormat: string;
  /** Session index from IdP */
  sessionIndex?: string;
  /** Additional attributes from assertion */
  attributes: Record<string, string | string[]>;
  /** Raw assertion XML (if available) */
  assertionXml?: string;
}

/**
 * Extended Express Request with SAML data
 */
export interface SamlRequest extends Request {
  samlUser?: SamlUser;
  samlLogoutRequest?: {
    nameId: string;
    sessionIndex?: string;
  };
}

// Helper to read file or return string as-is
async function readFileOrString(value: string): Promise<string> {
  // If it looks like content (not a path), return as-is
  if (value.includes("-----BEGIN") || value.includes("<?xml") || value.includes("<")) {
    return value;
  }

  const fs = await import("fs");
  const pathModule = await import("path");

  // Resolve and normalize the path
  const resolved = pathModule.resolve(value);

  // Security: Ensure the path doesn't traverse outside cwd
  const cwd = process.cwd();
  if (!resolved.startsWith(cwd)) {
    throw new Error("Path traversal detected: path must be within working directory");
  }

  return fs.promises.readFile(resolved, "utf-8");
}

// Extract entity ID from metadata
function extractEntityId(metadata: string): string | null {
  const match = metadata.match(/entityID="([^"]+)"/);
  return match ? match[1] : null;
}

/**
 * Create Express router with SAML SP endpoints
 *
 * @example
 * ```typescript
 * import express from 'express';
 * import session from 'express-session';
 * import { createSamlSp } from 'lasso.js/express';
 *
 * const app = express();
 * app.use(session({ secret: 'secret', resave: false, saveUninitialized: true }));
 *
 * app.use('/saml', createSamlSp({
 *   spMetadata: './sp-metadata.xml',
 *   spKey: './sp-key.pem',
 *   spCert: './sp-cert.pem',
 *   idpMetadata: './idp-metadata.xml',
 *   onAuth: (user, req) => {
 *     return { id: user.nameId, email: user.attributes.email };
 *   }
 * }));
 *
 * // Routes created:
 * // GET  /saml/metadata - SP metadata
 * // GET  /saml/login    - Initiate login
 * // POST /saml/acs      - Assertion Consumer Service
 * // GET  /saml/logout   - Initiate logout
 * // POST /saml/slo      - Single Logout Service
 * ```
 */
export function createSamlSp(config: SamlSpConfig): Router {
  // Lazy import express to avoid requiring it as a dependency
   
  const express = require("express");
  const router: Router = express.Router();

  const sessionProperty = config.sessionProperty || "user";
  const defaultRedirectUrl = config.defaultRedirectUrl || "/";
  const logoutRedirectUrl = config.logoutRedirectUrl || "/";

  // Security settings
  const allowedRedirectHosts = config.allowedRedirectHosts;
  const stateMaxAge = config.stateMaxAge ?? 300000; // 5 minutes default
  const regenerateSession = config.regenerateSession !== false; // true by default

  // Server instance (initialized lazily)
  let server: lasso.Server | null = null;
  let spMetadataXml: string | null = null;
  let initPromise: Promise<void> | null = null;

  // Initialize server
  async function initServer(): Promise<void> {
    if (server) {return;}

    if (!lasso.isInitialized()) {
      lasso.init();
    }

    const [spMeta, spKeyPem, spCertPem, idpMeta] = await Promise.all([
      readFileOrString(config.spMetadata),
      readFileOrString(config.spKey),
      readFileOrString(config.spCert),
      readFileOrString(config.idpMetadata),
    ]);

    spMetadataXml = spMeta;
    server = lasso.Server.fromBuffers(spMeta, spKeyPem, spCertPem);

    // Add IdP as provider
    const idpEntityId = config.idpEntityId || extractEntityId(idpMeta);
    if (!idpEntityId) {
      throw new Error("Could not extract IdP entity ID from metadata");
    }
    server.addProviderFromBuffer(idpEntityId, idpMeta);
  }

  // Ensure server is initialized
  async function ensureInit(): Promise<void> {
    if (!initPromise) {
      initPromise = initServer();
    }
    await initPromise;
  }

  // Middleware to ensure initialization
  const initMiddleware = async (
    _req: Request,
    _res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      await ensureInit();
      next();
    } catch (err) {
      next(err);
    }
  };

  router.use(initMiddleware);

  // GET /metadata - Return SP metadata
  router.get("/metadata", (_req: Request, res: Response) => {
    res.type("application/xml").send(spMetadataXml);
  });

  // GET /login - Initiate SAML login
  router.get("/login", async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!server) {throw new Error("Server not initialized");}

      const login = new lasso.Login(server);

      // Store RelayState (where to redirect after login)
      let relayState = (req.query.returnTo as string) || defaultRedirectUrl;

      // Security: Validate redirect URL to prevent open redirect
      if (!isValidRedirectUrl(relayState, allowedRedirectHosts)) {
        relayState = defaultRedirectUrl;
      }

      // Initialize authentication request
      login.initAuthnRequest();

      // Set options
      if (config.forceAuthn) {
        // Would set forceAuthn flag if supported
      }

      // Build the request message
      const result = login.buildAuthnRequestMsg();

      // Store login state in session for later validation (CSRF protection)
      const session = (req as any).session;
      if (session) {
        session.samlLoginState = {
          relayState,
          nonce: crypto.randomUUID(),
          timestamp: Date.now(),
        };
      }

      // Redirect to IdP
      if (result.responseUrl) {
        const separator = result.responseUrl.includes("?") ? "&" : "?";
        const url = relayState
          ? `${result.responseUrl}${separator}RelayState=${encodeURIComponent(relayState)}`
          : result.responseUrl;
        res.redirect(url);
      } else {
        // POST binding - return auto-submit form (with HTML escaping for XSS prevention)
        res.send(`
          <!DOCTYPE html>
          <html>
          <head><title>SAML Login</title></head>
          <body onload="document.forms[0].submit()">
            <noscript><p>JavaScript is disabled. Click the button to continue.</p></noscript>
            <form method="POST" action="${escapeHtml(result.responseUrl || "")}">
              <input type="hidden" name="SAMLRequest" value="${escapeHtml(result.responseBody || "")}" />
              ${relayState ? `<input type="hidden" name="RelayState" value="${escapeHtml(relayState)}" />` : ""}
              <noscript><input type="submit" value="Continue" /></noscript>
            </form>
          </body>
          </html>
        `);
      }
    } catch (err) {
      next(err);
    }
  });

  // POST /acs - Assertion Consumer Service (receive SAML response)
  router.post("/acs", express.urlencoded({ extended: false }), async (
    req: Request,
    res: Response,
    next: NextFunction
  ) => {
    try {
      if (!server) {throw new Error("Server not initialized");}

      const samlResponse = req.body.SAMLResponse;
      const session = (req as any).session;

      if (!samlResponse) {
        res.status(400).send("Missing SAMLResponse");
        return;
      }

      // Security: Validate SAML state (CSRF protection)
      const storedState = session?.samlLoginState;
      if (!storedState || Date.now() - storedState.timestamp > stateMaxAge) {
        res.status(400).send("SAML state expired or missing");
        return;
      }

      // Security: Validate redirect URL from stored state (not from request)
      let relayState = storedState.relayState || defaultRedirectUrl;
      if (!isValidRedirectUrl(relayState, allowedRedirectHosts)) {
        relayState = defaultRedirectUrl;
      }

      const login = new lasso.Login(server);

      // Process the SAML response
      login.processResponseMsg(samlResponse);

      // Security: Accept the SSO to complete validation
      login.acceptSso();

      // Extract user information
      const nameId = login.nameId;
      const nameIdFormat = login.nameIdFormat || lasso.NameIdFormat.UNSPECIFIED;

      if (!nameId) {
        throw new Error("No NameID in SAML response");
      }

      // Build user object
      const samlUser: SamlUser = {
        nameId,
        nameIdFormat,
        sessionIndex: undefined, // Would extract from assertion if available
        attributes: {},
      };

      // Call onAuth callback
      const user = await config.onAuth(samlUser, req);

      // Security: Regenerate session to prevent session fixation
      if (regenerateSession && session?.regenerate) {
        await new Promise<void>((resolve, reject) => {
          const savedState = {
            [sessionProperty]: user,
            samlNameId: nameId,
            samlNameIdFormat: nameIdFormat,
          };
          session.regenerate((err: Error | null) => {
            if (err) {
              reject(err);
            } else {
              // Restore user data after regeneration
              Object.assign(session, savedState);
              resolve();
            }
          });
        });
      } else if (session) {
        session[sessionProperty] = user;
        session.samlNameId = nameId;
        session.samlNameIdFormat = nameIdFormat;
        delete session.samlLoginState;
      }

      // Redirect to original destination
      res.redirect(relayState);
    } catch (err) {
      next(err);
    }
  });

  // GET /logout - Initiate SAML logout
  router.get("/logout", async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!server) {throw new Error("Server not initialized");}

      const session = (req as any).session;
      const nameId = config.getNameId
        ? config.getNameId(req)
        : session?.samlNameId;

      if (!nameId) {
        // Not logged in via SAML, just redirect
        if (config.onLogout) {
          await config.onLogout(req);
        }
        if (session) {
          delete session[sessionProperty];
        }
        res.redirect(logoutRedirectUrl);
        return;
      }

      const logout = new lasso.Logout(server);

      // Set the identity for logout
      logout.setNameId(nameId, session?.samlNameIdFormat || lasso.NameIdFormat.UNSPECIFIED);

      // Initialize logout request
      logout.initRequest();

      // Build the request message
      const result = logout.buildRequestMsg();

      // Redirect to IdP for logout
      if (result.responseUrl) {
        res.redirect(result.responseUrl);
      } else {
        // POST binding with HTML escaping for XSS prevention
        res.send(`
          <!DOCTYPE html>
          <html>
          <head><title>SAML Logout</title></head>
          <body onload="document.forms[0].submit()">
            <noscript><p>JavaScript is disabled. Click the button to continue.</p></noscript>
            <form method="POST" action="${escapeHtml(result.responseUrl || "")}">
              <input type="hidden" name="SAMLRequest" value="${escapeHtml(result.responseBody || "")}" />
              <noscript><input type="submit" value="Continue" /></noscript>
            </form>
          </body>
          </html>
        `);
      }
    } catch (err) {
      next(err);
    }
  });

  // POST /slo - Single Logout Service (receive logout request/response)
  router.post("/slo", express.urlencoded({ extended: false }), async (
    req: Request,
    res: Response,
    next: NextFunction
  ) => {
    try {
      if (!server) {throw new Error("Server not initialized");}

      const samlRequest = req.body.SAMLRequest;
      const samlResponse = req.body.SAMLResponse;
      const session = (req as any).session;

      if (samlResponse) {
        // This is a logout response from IdP
        const logout = new lasso.Logout(server);
        logout.processResponseMsg(samlResponse);

        // Clear session
        if (config.onLogout) {
          await config.onLogout(req);
        }
        if (session) {
          delete session[sessionProperty];
          delete session.samlNameId;
          delete session.samlNameIdFormat;
        }

        res.redirect(logoutRedirectUrl);
      } else if (samlRequest) {
        // This is a logout request from IdP (IdP-initiated logout)
        const logout = new lasso.Logout(server);
        logout.processRequestMsg(samlRequest);

        // Clear session
        if (config.onLogout) {
          await config.onLogout(req);
        }
        if (session) {
          delete session[sessionProperty];
          delete session.samlNameId;
          delete session.samlNameIdFormat;
        }

        // Build and send logout response
        const result = logout.buildResponseMsg();

        if (result.responseUrl) {
          res.redirect(result.responseUrl);
        } else {
          // POST binding with HTML escaping for XSS prevention
          res.send(`
            <!DOCTYPE html>
            <html>
            <head><title>SAML Logout</title></head>
            <body onload="document.forms[0].submit()">
              <form method="POST" action="${escapeHtml(result.responseUrl || "")}">
                <input type="hidden" name="SAMLResponse" value="${escapeHtml(result.responseBody || "")}" />
                <noscript><input type="submit" value="Continue" /></noscript>
              </form>
            </body>
            </html>
          `);
        }
      } else {
        res.status(400).send("Missing SAMLRequest or SAMLResponse");
      }
    } catch (err) {
      next(err);
    }
  });

  // GET /slo - Single Logout Service (HTTP-Redirect binding)
  router.get("/slo", async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!server) {throw new Error("Server not initialized");}

      const samlRequest = req.query.SAMLRequest as string;
      const samlResponse = req.query.SAMLResponse as string;
      const session = (req as any).session;

      if (samlResponse) {
        // Logout response from IdP
        const logout = new lasso.Logout(server);
        logout.processResponseMsg(samlResponse);

        if (config.onLogout) {
          await config.onLogout(req);
        }
        if (session) {
          delete session[sessionProperty];
          delete session.samlNameId;
          delete session.samlNameIdFormat;
        }

        res.redirect(logoutRedirectUrl);
      } else if (samlRequest) {
        // Logout request from IdP
        const logout = new lasso.Logout(server);
        logout.processRequestMsg(samlRequest);

        if (config.onLogout) {
          await config.onLogout(req);
        }
        if (session) {
          delete session[sessionProperty];
          delete session.samlNameId;
          delete session.samlNameIdFormat;
        }

        const result = logout.buildResponseMsg();
        res.redirect(result.responseUrl || logoutRedirectUrl);
      } else {
        res.status(400).send("Missing SAMLRequest or SAMLResponse");
      }
    } catch (err) {
      next(err);
    }
  });

  return router;
}

/**
 * Middleware to require SAML authentication
 *
 * @example
 * ```typescript
 * app.get('/protected', requireAuth(), (req, res) => {
 *   res.send(`Hello ${req.session.user.name}`);
 * });
 * ```
 */
export function requireAuth(options?: {
  /** Session property name (default: 'user') */
  sessionProperty?: string;
  /** Login URL (default: '/saml/login') */
  loginUrl?: string;
}): (req: Request, res: Response, next: NextFunction) => void {
  const sessionProperty = options?.sessionProperty || "user";
  const loginUrl = options?.loginUrl || "/saml/login";

  return (req: Request, res: Response, next: NextFunction): void => {
    const session = (req as any).session;
    if (session && session[sessionProperty]) {
      next();
    } else {
      const returnTo = encodeURIComponent(req.originalUrl);
      res.redirect(`${loginUrl}?returnTo=${returnTo}`);
    }
  };
}
