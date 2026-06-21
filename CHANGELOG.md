# Changelog

All notable changes to this package will be documented in this file.

The format is based on Keep a Changelog and this project adheres to Semantic Versioning.

## [3.5.7] - 2026-06-21

### Added
- Mini-SDK integration test suite (`ApproovServiceMiniSdkTest`, `ApproovNativeSdkTest`) wired against `core-service-layers-testing/mini-sdk`, exercising the TESTING_REQUIREMENTS scenarios.
- CHANGELOG-vs-tag validation in the publish workflow: a release fails fast if the top `## [x.y.z]` CHANGELOG entry does not match the pushed git tag.

### Changed
- **`NO_APPROOV_SERVICE`**: the request now proceeds with an **empty** `Approov-Token` header (and a trace ID if the SDK provides one) as evidence that Approov processing occurred, instead of omitting the headers (root §2 Missing Artifacts Fallback).

### Removed
- **Automated query parameter substitution** (`addSubstitutionQueryParam`, `removeSubstitutionQueryParam`, `getSubstitutionQueryParams`, `substituteQueryParams`, `substituteQueryParam`) — Issue #14. `java.net.URL` is immutable once the connection is opened, and the automated path broke the request-mutation tracking that message signing relies on. Fetch secure-string query values with `fetchSecureString()` and build the URL before `openConnection()` (see USAGE.md / REFERENCE.md).

### Fixed
- A **required** body digest that cannot be generated now fails closed via `ApproovException` (the documented `addApproov` contract) rather than a raw `IllegalStateException`.

## [3.5.6] - 2026-05-30

### Added
- `addApproov(HttpsURLConnection, byte[])` overload that computes the message-signing `Content-Digest` over the supplied repeatable body bytes and covers it with the signature (TESTING_REQUIREMENTS supp §4). The legacy `addApproov(HttpsURLConnection)` still gracefully skips the body digest when no body is available.

### Improved
- Tightened SDK initialization: service-layer state is now only reset and committed after the native SDK confirms success, preserving the prior operating mode (protected or bypass) if initialization fails.
- `null` config now throws `IllegalArgumentException` instead of being silently coerced to bypass mode; pass `""` explicitly for bypass.

### Changed
- **Dependency isolation** (TESTING_REQUIREMENTS §9): BouncyCastle is now shaded and relocated into `io.approov.internal.httpsurlconn.bouncycastle` (via the Shadow plugin) so it is no longer an exposed/transitive dependency and cannot clash with an app's own copy. Added consumer ProGuard/R8 rules (`consumer-rules.pro`) preserving the `com.criticalblue.approovsdk` SDK and its native methods. BouncyCastle bumped to `bcprov-jdk15to18:1.84`.

### Fixed
- **Message-signing fail-open conformance** (core issue #564): the account-signature branch, base64 decode, and ASN.1/DER ES256 decode now **fail open** (proceed unsigned, logged at error level) instead of aborting the request. Only a required body digest that cannot be generated and an unsupported signing algorithm still fail closed. The backend remains the enforcement point for signatures.

---

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
