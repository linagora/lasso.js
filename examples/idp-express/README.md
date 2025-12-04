# Express SAML IdP Example

A minimal SAML 2.0 Identity Provider using lasso.js and Express.

## Setup

```bash
# Install dependencies
npm install

# Generate certificates and metadata
npm run setup

# Start the IdP
npm start
```

## Usage

1. The IdP will start at http://localhost:3000
2. Download the IdP metadata from http://localhost:3000/saml/metadata
3. Configure your Service Provider with this metadata
4. Copy your SP's metadata to `data/sp-metadata.xml`
5. Restart the IdP

## Demo Users

- `admin` / `admin` - admin@example.com
- `user` / `user` - user@example.com

## Endpoints

- `GET /` - Home page
- `GET /saml/metadata` - IdP metadata (XML)
- `GET /saml/sso` - SSO endpoint (HTTP-Redirect binding)
- `POST /saml/sso` - SSO endpoint (HTTP-POST binding)
- `GET /login` - Login page
- `POST /login` - Login handler

## Notes

This is a demonstration IdP. For production use:

- Use a real user database
- Implement proper session management
- Add HTTPS
- Validate and sign all SAML messages
- Implement Single Logout (SLO)
