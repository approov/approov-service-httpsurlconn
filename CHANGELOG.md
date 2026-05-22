# Changelog

All notable changes to this package will be documented in this file.

The format is based on Keep a Changelog and this project adheres to Semantic Versioning.

## [3.5.5] - 2026-05-22

### Added
- Public visibility getter methods `isInitialized()` and `isApproovEnabled()`.
- Overhauled and restructured `README.md` based on the standard `3.5.3` quickstart template, with original reference links migrated to the bottom.
- Overloaded `initialize(Context, String, String)` support to allow passing custom initialization options and reinitialization comments.

### Fixed
- Corrected parameter mapping in `initialize(Context, String, String)` to map the `comment` argument correctly to the 4th parameter of the native SDK instead of the 3rd (`updateConfig`) parameter.
- Added safety checks for `null` and empty config strings during initialization to normalize parameters and prevent native initialization conflicts.
- Aligned default `initialize` method to pass `null` comment instead of `""` to prevent initialization mismatches.
- Added strict gating to all native API calls to prevent `IllegalStateException` crashes when called before initialization or during bypass mode.
- Cleaned up static state between unit tests using a new `@VisibleForTesting` static `reset()` method.

## [3.5.4] - 2026-05-21

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
