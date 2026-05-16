# Changelog

All notable changes to this package will be documented in this file.

The format is based on Keep a Changelog and this project adheres to Semantic Versioning.


## [3.5.4] - 2026-05-15

### Added
- `ApproovService.addApproov(HttpsURLConnection, byte[])` overload to support message signing body digests (`Content-Digest`) for repeatable payloads.
- `ApproovServiceMutator` protocol with default behavior to centralize decision points in the service flow.
- Mutator hooks for precheck, token fetch, secure string fetch, custom JWT fetch, header/query substitutions, and pinning.
- Configurable HTTP message signing via `ApproovDefaultMessageSigning` and `SignatureParametersFactory` supporting both Install and Account message signatures.
- Added `setUseApproovStatusIfNoToken` to allow using status as the token value when the token is missing.
- Added `getAccountMessageSignature` and `getInstallMessageSignature` to the public API.
- Added comprehensive documentation files: `REFERENCE.md`, `CHANGELOG.md`, and `USAGE.md`.

### Changed
- `ApproovService` now routes decision logic through the service mutator and exposes set/get APIs (`setServiceMutator` / `getServiceMutator`).
- `ApproovService.addApproov(connection)` now returns the configured `HttpsURLConnection` object instead of `void`.

### Deprecated
- `setProceedOnNetworkFail()` and `getProceedOnNetworkFail()` in favor of `ApproovServiceMutator` policies.
- `getMessageSignature(message)` in favor of the specialized `getAccountMessageSignature` and `getInstallMessageSignature` methods.
