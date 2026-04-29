# Changelog

All notable changes to this package will be documented in this file.

The format is based on Keep a Changelog and this project adheres to Semantic Versioning.

## [Unreleased]

### Added
- `ApproovServiceMutator` support to centralize decision points in the `HttpsURLConnection` service flow.
- `USAGE.md`, `REFERENCE.md`, and `CHANGELOG.md` at the repository root.
- `setUseApproovStatusIfNoToken` support for propagating fetch status in the Approov token header when no token is available.
- `Approov-TraceID` configuration helpers.
- Configurable query parameter substitution APIs.
- `addApproovToConnection(HttpsURLConnection)` for flows that need to continue with a wrapped connection.

### Changed
- `ApproovService` now routes request-preparation decisions through the service mutator.
- `addApproov(HttpsURLConnection)` preserves the original in-place API, while `addApproovToConnection(HttpsURLConnection)` supports mutator-driven signing, optional URL substitution, and deferred body-aware processing.
- Message signing now supports the `HttpsURLConnection` request path, including optional body digest generation when request buffering is used.

### Deprecated
- `ApproovInterceptorExtensions` in favor of `ApproovServiceMutator`.
- `setProceedOnNetworkFail()` and `getProceedOnNetworkFail()` in favor of `ApproovServiceMutator`.
- `getMessageSignature()` in favor of `getAccountMessageSignature()`.
