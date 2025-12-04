#!/usr/bin/env node
/**
 * Setup script for the IdP example
 * Generates self-signed certificates and metadata
 */

const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const dataDir = path.join(__dirname, "data");

// Create data directory
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir);
}

// Generate IdP certificate
console.log("Generating IdP certificate...");
execSync(
  `openssl req -x509 -newkey rsa:2048 -keyout "${path.join(dataDir, "idp-key.pem")}" -out "${path.join(dataDir, "idp-cert.pem")}" -days 365 -nodes -subj "/CN=localhost"`,
  { stdio: "inherit" }
);

// Read certificate for metadata
const cert = fs
  .readFileSync(path.join(dataDir, "idp-cert.pem"), "utf-8")
  .replace(/-----BEGIN CERTIFICATE-----/, "")
  .replace(/-----END CERTIFICATE-----/, "")
  .replace(/\n/g, "");

// Generate IdP metadata
const idpMetadata = `<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
                  xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                  entityID="http://localhost:3000/saml/metadata">
  <IDPSSODescriptor WantAuthnRequestsSigned="false"
                    protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>${cert}</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </KeyDescriptor>
    <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                         Location="http://localhost:3000/saml/slo"/>
    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
    <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</NameIDFormat>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                         Location="http://localhost:3000/saml/sso"/>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                         Location="http://localhost:3000/saml/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`;

fs.writeFileSync(path.join(dataDir, "idp-metadata.xml"), idpMetadata);

console.log("\\nSetup complete!");
console.log("\\nGenerated files:");
console.log("  - data/idp-key.pem");
console.log("  - data/idp-cert.pem");
console.log("  - data/idp-metadata.xml");
console.log("\\nTo add a Service Provider, copy its metadata to data/sp-metadata.xml");
console.log("Then start the IdP with: npm start");
