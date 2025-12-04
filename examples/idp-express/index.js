#!/usr/bin/env node
/**
 * Example SAML Identity Provider using lasso.js and Express
 *
 * This is a minimal IdP implementation for demonstration purposes.
 * In production, you would add proper user authentication, session management,
 * and security measures.
 */

const express = require("express");
const session = require("express-session");
const bodyParser = require("body-parser");
const fs = require("fs");
const path = require("path");

// Load lasso.js from parent directory (in real app, use: require('lasso.js'))
const lasso = require("../../dist");

const app = express();
const PORT = process.env.PORT || 3000;
const dataDir = path.join(__dirname, "data");

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(
  session({
    secret: "example-idp-secret-change-in-production",
    resave: false,
    saveUninitialized: true,
  })
);

// Initialize Lasso
lasso.init();
console.log("Lasso version:", lasso.checkVersion());

// Load IdP configuration
let server;
try {
  const idpMetadata = fs.readFileSync(
    path.join(dataDir, "idp-metadata.xml"),
    "utf-8"
  );
  const idpKey = fs.readFileSync(path.join(dataDir, "idp-key.pem"), "utf-8");
  const idpCert = fs.readFileSync(path.join(dataDir, "idp-cert.pem"), "utf-8");

  server = lasso.Server.fromBuffers(idpMetadata, idpKey, idpCert);
  console.log("IdP loaded:", server.entityId);

  // Load SP metadata if available
  const spMetadataPath = path.join(dataDir, "sp-metadata.xml");
  if (fs.existsSync(spMetadataPath)) {
    const spMetadata = fs.readFileSync(spMetadataPath, "utf-8");
    // Extract entity ID from metadata
    const match = spMetadata.match(/entityID="([^"]+)"/);
    if (match) {
      server.addProviderFromBuffer(match[1], spMetadata);
      console.log("SP loaded:", match[1]);
    }
  }
} catch (err) {
  console.error("Failed to load IdP configuration:", err.message);
  console.error("\\nRun 'npm run setup' first to generate certificates.");
  process.exit(1);
}

// Demo users (in production, use a real user database)
const users = {
  admin: { password: "admin", email: "admin@example.com", name: "Admin User" },
  user: { password: "user", email: "user@example.com", name: "Test User" },
};

// Home page
app.get("/", (req, res) => {
  res.send(`
    <h1>SAML Identity Provider</h1>
    <p>Entity ID: ${server.entityId}</p>
    <ul>
      <li><a href="/saml/metadata">IdP Metadata</a></li>
      <li><a href="/login">Login Page</a></li>
    </ul>
    <h2>Demo Users</h2>
    <ul>
      <li>admin / admin</li>
      <li>user / user</li>
    </ul>
  `);
});

// IdP Metadata endpoint
app.get("/saml/metadata", (req, res) => {
  const metadata = fs.readFileSync(
    path.join(dataDir, "idp-metadata.xml"),
    "utf-8"
  );
  res.type("application/xml").send(metadata);
});

// Login page
app.get("/login", (req, res) => {
  const error = req.query.error || "";
  res.send(`
    <h1>Login</h1>
    ${error ? `<p style="color:red">${error}</p>` : ""}
    <form method="POST" action="/login">
      <p>
        <label>Username: <input type="text" name="username" required></label>
      </p>
      <p>
        <label>Password: <input type="password" name="password" required></label>
      </p>
      <p><button type="submit">Login</button></p>
    </form>
  `);
});

// Login POST handler
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  const user = users[username];

  if (!user || user.password !== password) {
    return res.redirect("/login?error=Invalid+credentials");
  }

  // Store user in session
  req.session.user = {
    username,
    email: user.email,
    name: user.name,
  };

  // If there's a pending SAML request, complete it
  if (req.session.samlRequest) {
    return res.redirect("/saml/respond");
  }

  res.send(`
    <h1>Logged in as ${user.name}</h1>
    <p>Email: ${user.email}</p>
    <p><a href="/logout">Logout</a></p>
  `);
});

// Logout
app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

// SSO endpoint (receives AuthnRequest)
app.get("/saml/sso", (req, res) => {
  try {
    const samlRequest = req.query.SAMLRequest;
    const relayState = req.query.RelayState;

    if (!samlRequest) {
      return res.status(400).send("Missing SAMLRequest parameter");
    }

    // Create login object and process the request
    const login = new lasso.Login(server);
    login.processAuthnRequestMsg(samlRequest);
    login.validateRequestMsg();

    // Store SAML context in session
    req.session.samlRequest = {
      remoteProviderId: login.remoteProviderId,
      relayState: relayState || "",
    };

    // If user is already logged in, send response
    if (req.session.user) {
      return res.redirect("/saml/respond");
    }

    // Otherwise, redirect to login
    res.redirect("/login");
  } catch (err) {
    console.error("SSO error:", err);
    res.status(500).send(`SSO Error: ${err.message}`);
  }
});

// POST binding for SSO
app.post("/saml/sso", (req, res) => {
  try {
    const samlRequest = req.body.SAMLRequest;
    const relayState = req.body.RelayState;

    if (!samlRequest) {
      return res.status(400).send("Missing SAMLRequest parameter");
    }

    const login = new lasso.Login(server);
    login.processAuthnRequestMsg(samlRequest);
    login.validateRequestMsg();

    req.session.samlRequest = {
      remoteProviderId: login.remoteProviderId,
      relayState: relayState || "",
    };

    if (req.session.user) {
      return res.redirect("/saml/respond");
    }

    res.redirect("/login");
  } catch (err) {
    console.error("SSO POST error:", err);
    res.status(500).send(`SSO Error: ${err.message}`);
  }
});

// Send SAML Response
app.get("/saml/respond", (req, res) => {
  try {
    if (!req.session.user || !req.session.samlRequest) {
      return res.redirect("/login");
    }

    const { user } = req.session;
    const { relayState } = req.session.samlRequest;

    // Create a new login for the response
    const login = new lasso.Login(server);

    // We need to re-process the original request to get the context
    // In a real implementation, you'd store the login object dump in the session
    // For this example, we'll initiate a response directly

    // Set the NameID
    login.setNameId(user.email, lasso.NameIdFormat.EMAIL);

    // Build the assertion
    login.buildAssertion(
      "urn:oasis:names:tc:SAML:2.0:ac:classes:Password"
    );

    // Set relay state if present
    if (relayState) {
      login.relayState = relayState;
    }

    // Build response message
    const result = login.buildResponseMsg();

    // Clear SAML request from session
    delete req.session.samlRequest;

    // Send POST binding response
    res.send(`
      <!DOCTYPE html>
      <html>
      <head><title>SAML Response</title></head>
      <body onload="document.forms[0].submit()">
        <noscript>
          <p>JavaScript is disabled. Click the button to continue.</p>
        </noscript>
        <form method="POST" action="${result.responseUrl}">
          <input type="hidden" name="SAMLResponse" value="${result.responseBody || ""}" />
          ${relayState ? `<input type="hidden" name="RelayState" value="${relayState}" />` : ""}
          <noscript><input type="submit" value="Continue" /></noscript>
        </form>
      </body>
      </html>
    `);
  } catch (err) {
    console.error("Response error:", err);
    res.status(500).send(`Response Error: ${err.message}`);
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`\\nIdP running at http://localhost:${PORT}`);
  console.log(`Metadata available at http://localhost:${PORT}/saml/metadata`);
});

// Cleanup on exit
process.on("SIGINT", () => {
  console.log("\\nShutting down...");
  lasso.shutdown();
  process.exit(0);
});
