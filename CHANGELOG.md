# Changelog

All notable changes to this package will be documented in this file.

The format is based on Keep a Changelog and this project adheres to Semantic Versioning.

## [3.7.0] - YYYY-MM-DD

Entries marked **Breaking** need a source change.

### Changed
- **Breaking:** `initialize` passes every non-empty account ID and comment to the Approov SDK and the SDK decides, so the layer no longer compares account IDs itself. It resets the configuration each time, so make your configuration calls after it. It throws `IllegalArgumentException` for a null context, also in bypass mode (`""`).
- **Breaking:** The message signing helper classes moved from `io.approov.util.http.sfv` and `io.approov.util.sig` to `io.approov.util.httpsurlconn.http.sfv` and `io.approov.util.httpsurlconn.sig`. Update imports of classes such as `SignatureParameters` and `ComponentProvider`.
- Google Tink 1.23.0 replaces BouncyCastle. The AAR bundles Tink in a relocated package, so it cannot clash with your own dependencies. The published POM adds none.
- The package depends on Approov SDK 3.7.0, where 3.5.x depended on 3.5.3.
- A failed secure string fetch no longer fails the request under the standard mutators. The package skips the substitution and the request proceeds.
- `getLastARC()` makes no token fetch of its own. It returns the ARC of the most recent token, secure string or custom JWT fetch, or an empty string.

### Deprecated
- `getMessageSignature(message)`. Use `getAccountMessageSignature`.
- `setApproovHeader`, `setApproovTraceIDHeader`, `getApproovTokenHeader`, `getApproovTokenPrefix` and `getApproovTraceIDHeader`. Use `setTokenHeader(header, prefix)`, `setTraceIDHeader(header)`, `getTokenHeader()`, `getTokenPrefix()` and `getTraceIDHeader()`.

### Added
- `ApproovServiceMutator.CLOSE_FAILURE`, the default, which keeps the 3.5.x token decisions, and `ALWAYS_PROCEED`, which never aborts a request on a token fetch failure.
- The names shared by all Approov packages: `isApproovServiceEnabled()`, `isApproovProtectionEnabled()`, `setInstallAttributes(String)`, `getTokenHeader()`, `getTokenPrefix()`, `getTraceIDHeader()`, `setTokenHeader(header, prefix)` and `setTraceIDHeader(header)`.
- `ApproovService.setLoggingLevel(ApproovLogLevel)`, `INFO` by default. `OFF` silences the layer, and debug logging for the `ApproovService` tag raises any other level to `DEBUG`. The package logs the loggable token at `DEBUG` only, with the URL without its query, user info or fragment.

### Removed
- **Breaking:** `prefetch()`. The SDK manages prefetching itself.
- BouncyCastle, which the package no longer bundles.

## [3.5.7] - 2026-11-27

### Added
- Integration tests that run the package against a test Approov SDK.
- CHANGELOG-vs-tag validation in the publish workflow: a release fails fast if the top `## [x.y.z]` CHANGELOG entry does not match the pushed git tag.
- The runtime Approov user-property now reports the service-layer version (`approov-service-httpsurlconn/<version>`): a `BuildConfig.APPROOV_SERVICE_VERSION` field (default `dev`) is baked from `-PapproovServiceVersion`, the Maven publish workflow passes the release tag (`-PapproovServiceVersion=${{ github.ref_name }}`), and `setUserProperty` appends it. Previously a bare, version-less string was reported.
- Full `build_and_test.yml` CI (builds the AAR and runs the unit and integration tests on push to `main` and on PRs), plus automatic release tagging gated behind it (`tag-release` job): once tests pass, the top CHANGELOG entry drives a matching git tag, which triggers the Maven publish workflow. Skipped if the tag already exists.

### Changed
- Android build migrated from the unmaintained `com.github.johnrengelman.shadow` 8.1.1 plugin to the maintained fork `com.gradleup.shadow` 8.3.11 for Gradle 9 compatibility (Gradle 9 removed `FileCopyDetails.mode`, making the old plugin fail with a `MissingPropertyException`). Shaded BouncyCastle jar verified byte-identical; minimum supported Gradle remains 8.3.
- Removed the defunct `jcenter()` repository from the root build — JCenter is shut down and the `jcenter()` method is removed in Gradle 9.
- **`NO_APPROOV_SERVICE`**: the request now proceeds with an **empty** `Approov-Token` header (and a trace ID if the SDK provides one) as evidence that Approov processing occurred, instead of omitting the headers.

### Removed
- **Automated query parameter substitution** (`addSubstitutionQueryParam`, `removeSubstitutionQueryParam`, `getSubstitutionQueryParams`, `substituteQueryParams`, `substituteQueryParam`) — Issue #14. `java.net.URL` is immutable once the connection is opened, and the automated path broke the request-mutation tracking that message signing relies on. Fetch secure-string query values with `fetchSecureString()` and build the URL before `openConnection()` (see USAGE.md / REFERENCE.md).

### Fixed
- Message signing: a signature-base build failure and a `Signature`/`Signature-Input` serialization failure now fail open (log at error, proceed unsigned) to match the fail-open policy of the other Approov service layers; a required body digest and an unsupported algorithm remain fail-closed.
- A **required** body digest that cannot be generated now fails closed via `ApproovException` (the documented `addApproov` contract) rather than a raw `IllegalStateException`.
- **Empty config after a valid config is now ignored** — it no longer resets state / downgrades a protected layer to bypass. Approov protection remains active under the original config and the empty call is not forwarded to the SDK.
- `setApproovHeader(header, null)` no longer prepends the literal string `"null"` to the token — a `null` prefix is treated as no prefix.
- Bypass-mode hostname verification now delegates to the default/OS verifier instead of accepting unconditionally, so OS certificate/hostname trust validation is never skipped.
- An empty trace ID returned by the SDK is now emitted as an empty header value rather than omitted.

## [3.5.6] - 2026-05-30

### Added
- `addApproov(HttpsURLConnection, byte[])` overload that computes the message-signing `Content-Digest` over the supplied repeatable body bytes and covers it with the signature. The legacy `addApproov(HttpsURLConnection)` still gracefully skips the body digest when no body is available.

### Improved
- Tightened SDK initialization: service-layer state is now only reset and committed after the native SDK confirms success, preserving the prior operating mode (protected or bypass) if initialization fails.
- `null` config now throws `IllegalArgumentException` instead of being silently coerced to bypass mode; pass `""` explicitly for bypass.

### Changed
- **Dependency isolation**: BouncyCastle is now shaded and relocated into `io.approov.internal.httpsurlconn.bouncycastle` (via the Shadow plugin) so it is no longer an exposed/transitive dependency and cannot clash with an app's own copy. Added consumer ProGuard/R8 rules (`consumer-rules.pro`) preserving the `com.criticalblue.approovsdk` SDK and its native methods. BouncyCastle bumped to `bcprov-jdk15to18:1.84`.

### Fixed
- **Message-signing fail-open conformance**: the account-signature branch, base64 decode, and ASN.1/DER ES256 decode now **fail open** (proceed unsigned, logged at error level) instead of aborting the request. Only a required body digest that cannot be generated and an unsupported signing algorithm still fail closed. The backend remains the enforcement point for signatures.

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
