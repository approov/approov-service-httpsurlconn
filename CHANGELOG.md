# Changelog

All notable changes to this package will be documented in this file.

The format is based on Keep a Changelog and this project adheres to Semantic Versioning.

## [3.5.4] - 2026-05-15

### Added
- `ApproovService.addApproov(HttpsURLConnection, byte[])` overload to support message signing body digests (`Content-Digest`) for repeatable payloads.
- `ApproovServiceMutator` protocol with default behavior to centralize decision points in the service flow.
- Mutator hooks for precheck, token fetch, secure string fetch, custom JWT fetch, header substitutions, and pinning.
- Configurable HTTP message signing via `ApproovDefaultMessageSigning` and `SignatureParametersFactory` supporting both Install and Account message signatures.
- Added `setUseApproovStatusIfNoToken` to allow using status as the token value when the token is missing.
- Added `getAccountMessageSignature` and `getInstallMessageSignature` to the public API.
- Added comprehensive documentation files: `REFERENCE.md`, `CHANGELOG.md`, and `USAGE.md`.

### Changed
- `ApproovService` now routes decision logic through the service mutator and exposes set/get APIs (`setServiceMutator` / `getServiceMutator`).
- `ApproovService.addApproov(connection)` now returns the configured `HttpsURLConnection` object instead of `void`.
- Updated documentation in `USAGE.md` and `REFERENCE.md` to demonstrate how to perform manual query parameter substitution using `fetchSecureString`.

### Removed
- Automated query parameter substitution (`substituteQueryParams` and related methods) has been removed to resolve mutation metadata tracking limitations caused by Java `URL` immutability (Issue #14).

### Deprecated
- `setProceedOnNetworkFail()` and `getProceedOnNetworkFail()` in favor of `ApproovServiceMutator` policies.
- `getMessageSignature(message)` in favor of the specialized `getAccountMessageSignature` and `getInstallMessageSignature` methods.

### Fixed
- Prevented `NullPointerException` in `SignatureParametersFactory` by safely initializing optional headers (Issue #8).
- Ensured `addApproov` immediately returns the connection object when processing is skipped (Issue #9).
- Removed static global pinning verifier in favor of safe dynamic per-request wrapping (Issue #10).
- Wrapped native SDK calls in request paths to correctly translate unchecked SDK exceptions into `ApproovException` (Issue #11).
- Explicitly clear token binding state when the configured binding header is absent from a request, preventing stale `pay` claims (Issue #12).
- Emptied the implementation of the deprecated `getMessageSignature` method (Issue #13).
- Gracefully return `false` from `PinningHostnameVerifier` on `SSLException` instead of throwing a `RuntimeException` (Issue #16).
- Aligned `compileSdk` to 34 and safely conditioned test dependencies on the presence of the mini-SDK environment (Issue #17).
