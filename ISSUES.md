# Approov Service HttpsURLConnection Implementation Issues

Reviewed on 2026-05-16 against:

- `/Users/ivol/Github/approov-service-okhttp`
- `/Users/ivol/Github/core-service-layers-testing/TESTING_REQUIREMENTS.md`
- the current `README.md`, `USAGE.md`, and `REFERENCE.md` documents in this repository

This document de-duplicates the previous findings, removes issues that have been fixed by the current local changes, and keeps the remaining findings grounded in the current `approov-service-httpsurlconn` working tree.

## Status Summary

### Fixed or stale findings

- **Body digest is no longer completely unsupported.** The previous issue claiming that HttpsURLConnection could never generate a body digest is now stale. The current working tree adds `ApproovService.addApproov(HttpsURLConnection, byte[])`, stores those bytes in `ApproovRequestMutations`, and uses them to generate `Content-Digest` during message signing.
- **Streaming body digest remains impossible without buffering.** This is not a bug in the new overload. It is a fundamental HttpsURLConnection limitation unless the service owns/buffers/spools the body. This matches OkHttp's limitation for one-shot/streaming request bodies.
- **Failure caching is a parity/performance gap, not a stated requirement.** OkHttp caches short-lived SDK failure results; HttpsURLConnection does not. Track this as an optimization unless performance testing shows user-visible impact.
- **Initialization State Machine.** Issue #3 has been fully implemented, porting the robust state-machine logic from OkHttp to HttpsURLConnection. This includes `initialize(context, config, comment)` overloading, `isInitialized`, `isApproovEnabled`, empty-config bypass gating, and initialization failure surfacing.

### Confirmed active findings





#### 4. `setProceedOnNetworkFail` Appears Commented Out

**Severity: P1. Status: Confirmed compile/API risk.**

The deprecated `setProceedOnNetworkFail` method appears inside an unterminated Javadoc block. It is documented in `REFERENCE.md`, but likely absent from the compiled API.

Evidence:

- `ApproovService.java:121-126`
- `REFERENCE.md:67-72`

This should be fixed even though the method is obsolete, because published documentation still lists it and existing callers may compile against it.

#### 5. Trace ID Header Support Is Missing

**Severity: P1. Status: Confirmed.**

The HttpsURLConnection layer has no trace ID header constant, no `setApproovTraceIDHeader` or equivalent API, and no request mutation that adds `approovResults.getTraceID()`.

Evidence:

- `ApproovRequestMutations.java:31` has `traceIDHeaderKey`.
- `ApproovDefaultMessageSigning.java:540-541` can include the trace ID header if present.
- `ApproovService.addApproov()` never sets it.
- OkHttp injects trace IDs at `ApproovService.java:1264-1269` in the OkHttp repo.

This fails the protected-request and custom-header requirements in `TESTING_REQUIREMENTS.md:28-33`.

#### 6. Token Fetch Uses Host Instead Of Full URL

**Severity: P1. Status: Confirmed.**

`addApproov()` fetches the Approov token using only `request.getURL().getHost()`.

Evidence:

- `ApproovService.java:797-800`
- OkHttp uses `url.toString()` at `ApproovService.java:1229-1230` in the OkHttp repo.

Impact:

- Path-specific protected/unprotected URL decisions can be wrong.
- A request that should be `UNPROTECTED_URL` may be treated as host-level protected.
- Message signing and mutation decisions can become inconsistent with the exact URL sent.

#### 7. Empty Token And Header Replacement Semantics Are Wrong

**Severity: P1. Status: Confirmed.**

When token processing continues, `addApproov()` always adds a token header and uses `addRequestProperty`.

Evidence:

- `ApproovService.java:807-814`
- OkHttp uses `builder.header(...)`, which replaces the header, at `ApproovService.java:1331-1333` in the OkHttp repo.
- `TESTING_REQUIREMENTS.md:30`

Impact:

- If the SDK returns an empty token and `setUseApproovStatusIfNoToken(false)`, an empty token header may still be emitted.
- If the caller already set the token header, `addRequestProperty` can append another value instead of replacing it.
- Multiple values or empty values can break backend validation and message signing.

#### 8. Dynamic Pinning Updates Are Not Acted Upon

**Severity: P1. Status: Confirmed.**

OkHttp checks `approovResults.isConfigChanged()`, calls `Approov.fetchConfig()`, and rebuilds pins. The HttpsURLConnection layer does not check `isConfigChanged()` after token fetch.

Evidence:

- OkHttp: `ApproovService.java:1242-1247`
- HttpsURLConnection token flow: `ApproovService.java:797-842`
- `TESTING_REQUIREMENTS.md:41-48`

`PinningHostnameVerifier` does call `Approov.getPins(...)` during TLS verification, but the service never triggers fetching updated dynamic config after the token result reports a configuration change.

#### 9. Query Parameter Substitution Does Not Match The Common Interface

**Severity: P2. Status: Confirmed, with HttpsURLConnection-specific nuance.**

The current API only exposes manual URL substitution:

```java
URL substituteQueryParam(URL url, String queryParameter)
```

It does not expose or document the common required APIs:

- `addSubstitutionQueryParam(String key)`
- `removeSubstitutionQueryParam(String key)`
- `getSubstitutionQueryParams()` if matching OkHttp parity

Evidence:

- `ApproovService.java:860-897`
- OkHttp exposes query substitution registration and applies it inside the interceptor.
- `TESTING_REQUIREMENTS.md:105-114`

Because an `HttpsURLConnection` URL cannot be replaced after opening the connection, a manual pre-open helper may be necessary for this platform. However, the current public API still does not satisfy the common interface requirements.

#### 10. Mutator Hooks Are Defined But Not Fully Used

**Severity: P2. Status: Confirmed.**

`ApproovServiceMutator` defines request and pinning decision hooks that are not wired into the HttpsURLConnection flow.

Evidence:

- `ApproovServiceMutator.java:191-206` defines `handleInterceptorShouldProcessConnection`.
- `ApproovServiceMutator.java:347-350` defines `handlePinningShouldProcessRequest`.
- `ApproovService.addApproov()` never calls `handleInterceptorShouldProcessConnection`.
- `PinningHostnameVerifier.verify(hostname, session)` has no access to the original `HttpURLConnection`, so it cannot call `handlePinningShouldProcessRequest`.

Impact:

- Users cannot apply documented per-request skip policy through the mutator.
- Users cannot apply documented per-request pinning policy through the mutator.
- Custom mutator behavior differs from the OkHttp service layer and from the requirements.

#### 11. Direct API Calls Do Not Use Mutator Decision Methods

**Severity: P2. Status: Confirmed.**

The HttpsURLConnection mutator defines decision methods for direct APIs, but the direct APIs manually inspect statuses instead of delegating to those hooks.

Evidence:

- `ApproovServiceMutator.java:65-178`
- `ApproovService.precheck`, `fetchToken`, `fetchSecureString`, and `fetchCustomJWT` manually process statuses.
- OkHttp delegates these outcomes to `getServiceMutator()` in the corresponding methods.

Impact:

- Custom status policy is inconsistent between automatic request processing and direct APIs.
- Shared behavior such as empty-config bypass cannot be centralized.
- The service does not meet the mutator/decision override requirements in `TESTING_REQUIREMENTS.md:36-39`.

#### 12. Body Digest Overload Needs Reference Docs And Tests

**Severity: P2. Status: Confirmed.**

The body digest implementation has been added, but public API documentation and tests have not caught up.

Evidence:

- `ApproovService.java:746-768` exposes both `addApproov` overloads.
- `ApproovDefaultMessageSigning.java:491-510` computes `Content-Digest` from `bodyBytes`.
- `USAGE.md:199-231` documents the overload and the required call ordering.
- `REFERENCE.md:25-30` still documents only `addApproov(HttpsURLConnection)`.
- There is no `approov-service/src/test` tree in this repo.

Notes:

- The old "body digest unavailable" issue should stay removed.
- The remaining requirement gap is documentation/test coverage and the trust-based nature of the overload.
- If `bodyDigestRequired=true`, calling the legacy overload without bytes should fail closed, which matches `TESTING_REQUIREMENTS.md:69-72`.

#### 13. Secure String Empty-Value Fallback Is Missing

**Severity: P2. Status: Confirmed against requirements; appears shared with OkHttp.**

The requirements say that if secure string substitution yields an empty value, the original placeholder should remain in place.

Evidence:

- `ApproovService.java:824-835` replaces a header whenever the substitution result is accepted.
- `ApproovService.java:884-888` replaces a query parameter whenever the substitution result is accepted.
- `TESTING_REQUIREMENTS.md:30`

Neither path checks for an empty secure string before replacing the original placeholder.

#### 14. Message-Signing Failure Fallback Is Incomplete

**Severity: P2. Status: Confirmed against requirements; partially shared with OkHttp.**

The requirements say any message-signature generation failure should proceed with the request without signature headers.

Evidence:

- Install signing catches `ApproovException` from `getInstallMessageSignature` and skips signing.
- Account signing calls `getAccountMessageSignature` without the same fallback.
- DER/base64 decode failures and unsupported algorithm failures throw runtime exceptions.
- Required body digest failure throws `IllegalStateException`, which is expected only when strict digest mode is explicitly configured.
- `TESTING_REQUIREMENTS.md:51-57`

The install-signing fallback is correct. The account-signing and unexpected runtime-failure paths should be made consistently fail-open for optional signing.

#### 15. Public API And Documentation Drift

**Severity: P2. Status: Confirmed.**

The repository docs describe behavior or APIs that the implementation does not currently provide.

Examples:

- `REFERENCE.md` does not document `addApproov(HttpsURLConnection, byte[])`.
- `USAGE.md` says the standard `addApproov(connection)` cannot compute a `Signature-Base-Digest` over the body. The body payload header is `Content-Digest`; `Signature-Base-Digest` is the optional debug digest of the signature base.
- Empty-config no-op behavior is described but not implemented.
- Mutator request-skipping and pinning-skipping hooks are described but not wired.
- The common required methods `initialize(context, config, comment)`, `isInitialized`, `isApproovEnabled`, `setApproovTraceIDHeader`, `addSubstitutionQueryParam`, and `removeSubstitutionQueryParam` are absent.

#### 16. Test Coverage Is Missing

**Severity: P2. Status: Fixed.**

OkHttp has requirement-oriented Robolectric/minisdk tests covering initialization, protected/unprotected processing, token binding, substitution, pinning, message signing, body digest, and direct APIs. HttpsURLConnection currently has no equivalent test tree.

Evidence:

- OkHttp: `approov-service/src/test/java/io/approov/service/okhttp/ApproovServiceMiniSdkTest.java`
- HttpsURLConnection: no `approov-service/src/test` directory.
- HttpsURLConnection `build.gradle` has no test dependencies comparable to OkHttp.

*Resolution: Ported `ApproovServiceMiniSdkTest.java` and integrated the `mini-sdk` testing framework. Tests pass correctly under Robolectric.*

#### 17. Java 9 `Map.of` Usage With minSdk 23 Needs Verification

**Severity: P2. Status: Likely issue; shared with OkHttp.**

Message signing uses `Map.of(...)` while the Android library targets `minSdkVersion 23` and does not enable core library desugaring in `build.gradle`.

Evidence:

- `ApproovDefaultMessageSigning.java:278-280`
- `ApproovDefaultMessageSigning.java:298-300`
- `approov-service/build.gradle:17-31`

On older Android runtimes, Java 9 collection factory methods can fail unless desugared. Because OkHttp uses the same pattern, this should be checked across both service layers rather than treated as HttpsURLConnection-only.

## Recommended Fix Order

1. Fix initialization state tracking, empty-config bypass, and the commented-out deprecated method.
2. Fetch tokens for the full URL, add trace ID support, replace token headers instead of appending, and omit empty token artifacts unless status fallback is enabled.
3. Decide whether the current mutable `addApproov` API is acceptable as documented manual mode, or add a safer wrapper/open-connection API for enforced signing order.
4. Clear or explicitly handle token binding state when the binding header is absent.
5. Wire mutator decision hooks consistently for request processing and direct APIs.
6. Add query substitution registration APIs or document a HttpsURLConnection-specific alternative that still satisfies the common outcomes.
7. Handle dynamic configuration updates for pinning.
8. Update `REFERENCE.md`, fix `USAGE.md` body-digest terminology, and add requirement-based tests equivalent to the OkHttp suite.

