# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.1] - 2026-01-17

### Changed

- Bump node-gyp from 10.0.0 to 12.1.0

## [0.2.0] - 2026-01-02

### Security

- **CSRF Protection**: Added nonce-based state validation with round-trip via RelayState
- **XSS Prevention**: HTML escaping in all POST binding forms (`escapeHtml()`)
- **Open Redirect Prevention**: URL validation blocks absolute URLs by default (`isValidRedirectUrl()`)
- **XXE Protection**: Disabled external entity loading in libxml2 (`xmlSubstituteEntitiesDefault(0)`)
- **Session Fixation**: Session regeneration after successful authentication
- **Path Traversal Prevention**: Improved validation using `path.relative()` and `isAbsolute()`
- **Memory Safety**: Use `explicit_bzero()` for secure erasure of private keys (POSIX/Windows)
- **Input Validation**: Metadata size limit (10 MB) to prevent DoS
- **Error Handling**: Throw errors on session/identity restoration failure instead of silent fallback

### Added

- Configuration options: `allowedRedirectHosts`, `stateMaxAge`, `regenerateSession`

### Fixed

- POST binding forms now use `msgUrl` instead of `responseUrl` for logout/SLO
- Proper `acceptSso()` call after processing SAML response

### Changed

- Prebuilds: Removed darwin-x64 (macos-13 unavailable in GitHub Actions)

## [0.1.1] - 2026-01-02

### Fixed

- CI/CD workflow for npm publishing
- ARM64 Dockerfile multi-stage build
- Prebuild generation for linux-arm64 via QEMU

## [0.1.0] - 2025-12-04

### Added

- Initial release
- Node.js N-API binding for Lasso SAML library
- Express middleware for SAML Service Provider (`createSamlSp`)
- Support for SAML 2.0 SSO and SLO
- Classes: `Server`, `Login`, `Logout`, `Identity`, `Session`
- Prebuilds for linux-x64, linux-arm64, darwin-arm64
