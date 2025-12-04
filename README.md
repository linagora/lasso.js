# lasso.js

Node.js N-API binding for the [Lasso](https://lasso-project.org/) SAML library.

Provides complete SAML 2.0 Identity Provider (IdP) and Service Provider (SP) functionality for Node.js applications.

## Features

- Full SAML 2.0 SSO (Single Sign-On) support
- Full SAML 2.0 SLO (Single Logout) support
- IdP and SP roles
- Multiple bindings: HTTP-Redirect, HTTP-POST, SOAP
- Signature and encryption support
- TypeScript definitions included

## Prerequisites

### System Dependencies

**Debian/Ubuntu:**
```bash
sudo apt-get install -y \
  liblasso3-dev \
  libxml2-dev \
  libxmlsec1-dev \
  libglib2.0-dev
```

**Fedora/RHEL:**
```bash
sudo dnf install -y \
  lasso-devel \
  libxml2-devel \
  xmlsec1-devel \
  glib2-devel
```

**macOS (Homebrew):**
```bash
brew install lasso libxml2 xmlsec1 glib
```

## Installation

```bash
npm install lasso.js
```

## Quick Start

### Initialize Lasso

```typescript
import { init, shutdown, Server, Login, HttpMethod, NameIdFormat } from 'lasso.js';

// Initialize Lasso library (call once at startup)
init();

// ... use Lasso ...

// Shutdown when done (call once at exit)
shutdown();
```

### IdP: Process AuthnRequest and Build Response

```typescript
import { init, Server, Login, NameIdFormat, AuthnContext } from 'lasso.js';
import fs from 'fs';

init();

// Load IdP configuration
const server = Server.fromBuffers(
  fs.readFileSync('idp-metadata.xml'),
  fs.readFileSync('idp-key.pem'),
  fs.readFileSync('idp-cert.pem')
);

// Add known Service Providers
server.addProviderFromBuffer(
  'https://sp.example.com',
  fs.readFileSync('sp-metadata.xml')
);

// Process AuthnRequest
function handleSsoRequest(samlRequest: string, relayState?: string) {
  const login = new Login(server);

  // Process the AuthnRequest
  login.processAuthnRequestMsg(samlRequest);
  login.validateRequestMsg();

  // After user authenticates, build the response
  login.setNameId('user@example.com', NameIdFormat.EMAIL);
  login.buildAssertion(AuthnContext.PASSWORD);

  if (relayState) {
    login.relayState = relayState;
  }

  const result = login.buildResponseMsg();

  return {
    url: result.responseUrl,
    body: result.responseBody,
    relayState: result.relayState
  };
}
```

### SP: Initiate SSO and Process Response

```typescript
import { init, Server, Login, HttpMethod } from 'lasso.js';
import fs from 'fs';

init();

// Load SP configuration
const server = Server.fromBuffers(
  fs.readFileSync('sp-metadata.xml'),
  fs.readFileSync('sp-key.pem'),
  fs.readFileSync('sp-cert.pem')
);

// Add the IdP
server.addProviderFromBuffer(
  'https://idp.example.com',
  fs.readFileSync('idp-metadata.xml')
);

// Initiate SSO
function initiateSso(returnUrl: string) {
  const login = new Login(server);
  login.initAuthnRequest('https://idp.example.com', HttpMethod.REDIRECT);
  login.relayState = returnUrl;

  const result = login.buildAuthnRequestMsg();
  return result.responseUrl; // Redirect user here
}

// Process SAML Response
function processSsoResponse(samlResponse: string) {
  const login = new Login(server);
  login.processResponseMsg(samlResponse);
  login.acceptSso();

  return {
    nameId: login.nameId,
    relayState: login.relayState
  };
}
```

## API Reference

### Core Functions

- `init()` - Initialize Lasso library (must be called first)
- `shutdown()` - Shutdown Lasso library
- `checkVersion()` - Get Lasso version string
- `isInitialized()` - Check if Lasso is initialized

### Server Class

```typescript
// Create from buffers
const server = Server.fromBuffers(metadata, privateKey, certificate, password?);

// Restore from dump
const server = Server.fromDump(dumpString);

// Add providers
server.addProvider(providerId, metadataPath, publicKeyPath?, caCertPath?);
server.addProviderFromBuffer(providerId, metadata, publicKey?);

// Get provider info
const provider = server.getProvider(providerId);

// Serialize
const dump = server.dump();
```

### Login Class (SSO)

```typescript
const login = new Login(server);

// IdP methods
login.processAuthnRequestMsg(message, method?);
login.validateRequestMsg();
login.setNameId(nameId, format?);
login.setAttributes(attributes);
login.buildAssertion(authMethod?, authInstant?);
const result = login.buildResponseMsg();

// SP methods
login.initAuthnRequest(providerId?, method?);
const result = login.buildAuthnRequestMsg();
login.processResponseMsg(message);
login.acceptSso();

// Properties
login.identity;      // Identity object
login.session;       // Session object
login.remoteProviderId;
login.nameId;
login.nameIdFormat;
login.relayState;
```

### Logout Class (SLO)

```typescript
const logout = new Logout(server);

logout.identity = identity;
logout.session = session;

logout.initRequest(providerId?, method?);
const result = logout.buildRequestMsg();

logout.processRequestMsg(message, method?);
logout.validateRequest();
const result = logout.buildResponseMsg();

logout.processResponseMsg(message);
const nextProvider = logout.getNextProviderId();
```

### Identity & Session Classes

```typescript
// Identity
const identity = new Identity();
const identity = Identity.fromDump(dump);
const dump = identity.dump();
const isEmpty = identity.isEmpty;

// Session
const session = new Session();
const session = Session.fromDump(dump);
const dump = session.dump();
const isEmpty = session.isEmpty;
const isDirty = session.isDirty;
const assertions = session.getAssertions(providerId);
const index = session.getProviderIndex(providerId);
```

## Building from Source

```bash
# Clone the repository
git clone https://github.com/linagora/lasso.js.git
cd lasso.js

# Install dependencies
npm install

# Build
npm run build

# Test
npm test
```

## Express Middleware

lasso.js includes an Express middleware for easy SP integration:

```typescript
import express from 'express';
import session from 'express-session';
import { createSamlSp, requireAuth } from 'lasso.js';

const app = express();
app.use(session({ secret: 'secret', resave: false, saveUninitialized: true }));

// Mount SAML SP endpoints
app.use('/saml', createSamlSp({
  spMetadata: './sp-metadata.xml',
  spKey: './sp-key.pem',
  spCert: './sp-cert.pem',
  idpMetadata: './idp-metadata.xml',
  onAuth: (user, req) => {
    // Called when user authenticates successfully
    return { id: user.nameId, email: user.attributes.email };
  },
  onLogout: (req) => {
    // Called when user logs out
  }
}));

// Protect routes
app.get('/protected', requireAuth(), (req, res) => {
  res.send(`Hello ${req.session.user.id}`);
});

app.listen(3000);
```

### Endpoints Created

- `GET /saml/metadata` - SP metadata XML
- `GET /saml/login` - Initiate SAML login
- `POST /saml/acs` - Assertion Consumer Service
- `GET /saml/logout` - Initiate SAML logout
- `GET|POST /saml/slo` - Single Logout Service

## License

GPL-2.0-or-later (same as Lasso library)

## Copyright

Copyright (c) [LINAGORA](https://linagora.com)

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## Related Projects

- [Lasso](https://lasso-project.org/) - The underlying C library
- [LemonLDAP::NG](https://lemonldap-ng.org/) - Web SSO solution using Lasso
