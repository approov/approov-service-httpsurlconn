# Approov Service HttpsURLConnection Issues

Reviewed on 2026-05-16 against:

- `approov-service-httpsurlconn` current working tree
- `approov-service-okhttp` current working tree
- `/Users/ivol/Github/core-service-layers-testing/TESTING_REQUIREMENTS.md`
- local `README.md`, `USAGE.md`, and `REFERENCE.md` files in both service-layer repositories

This report intentionally separates active findings from items that appear to have
been fixed or are design constraints. The HttpsURLConnection service layer is not
an interceptor in the OkHttp sense: `ApproovService.addApproov(connection)` mutates
and returns the same live `HttpsURLConnection`. That makes some outcomes inherently
different from OkHttp's immutable request/interceptor model.

## Recently Fixed Or Stale Items

These were previously suspected issues but are no longer active in the current
tree, or are acceptable when documented as HttpsURLConnection limitations.

1. Body digest support has been added for in-memory payloads.
   `ApproovService.addApproov(HttpsURLConnection, byte[])` now exists and stores
   the supplied payload bytes in `ApproovRequestMutations`. The default message
   signing factory can compute `Content-Digest` from those bytes. This matches the
   current requirements for HttpsURLConnection: digest is possible only when the
   caller supplies a repeatable payload, while streaming/one-shot uploads cannot be
   pre-digested without buffering or changing the API.

2. Missing body bytes for optional digest is no longer necessarily a defect.
   The requirement explicitly allows `addApproov(connection)` to skip
   `Content-Digest` when body bytes are not available, provided the digest policy is
   not strict. Strict digest mode should fail when bytes are missing.

3. Trace ID header support has been added.
   The implementation now has an `approovTraceIDHeader`, setter support, and
   request mutation metadata for the trace header.

4. Token fetch now uses the full request URL in the protected request path.
   `ApproovService.addApproov` calls `Approov.fetchApproovTokenAndWait(url)` where
   `url` is `request.getURL().toString()`.

5. Token header replacement is no longer the old duplicate-header problem.
   The current implementation uses `setRequestProperty` for token, trace, digest,
   and signature headers. That replaces the current value on the connection rather
   than appending duplicate values.

6. Query parameter substitution APIs have been added.
   `addSubstitutionQueryParam`, `removeSubstitutionQueryParam`,
   `getSubstitutionQueryParams`, `substituteQueryParams`, and
   `substituteQueryParam` are present. There are still lower-severity issues with
   substitution semantics, described below.

7. Dynamic configuration fetch is present.
   When token fetch reports `isConfigChanged()`, the request path calls
   `Approov.fetchConfig()`.

8. `Map.of` is no longer an active Java 8 compatibility issue in this repo.
   The current code uses Java 8-compatible collection construction in the message
   signing header path.

9. The mutable connection after signing is a documented design limitation, not a
   defect by itself.
   `README.md` and `USAGE.md` now warn that `addApproov` must be called as the
   final step before connecting or writing the body, and that later mutation of
   headers, method, or body invalidates message signatures. This does not provide
   OkHttp-equivalent immutability, but it is a practical integration model for
   HttpsURLConnection if customers follow the documented sequence.

## Active Findings

### 1. `isApproovEnabled()` is documented but not public

Severity: P1

`REFERENCE.md:42` documents:

```java
boolean isApproovEnabled()
```

`TESTING_REQUIREMENTS.md:20` and `TESTING_REQUIREMENTS.md:91-93` require the
service layer to expose state methods for initialized and SDK-active/protected
states.

The implementation is package-private:

- `approov-service/src/main/java/io/approov/service/httpsurlconn/ApproovService.java:182`

```java
static synchronized boolean isApproovEnabled()
```

External customers cannot call the documented API. This is a real issue, not an
HttpsURLConnection limitation. The same issue appears in the OkHttp service layer
at `ApproovService.java:225`, so it is a shared service-layer parity issue.

Recommended fix: make `isApproovEnabled()` public in both service layers and add
API/documentation tests where practical.

### 2. Failed enable-after-empty initialization does not preserve disabled state

Severity: P1

`TESTING_REQUIREMENTS.md:19` requires that if the service was initialized with an
empty config and later enabling with a valid config fails, the service remains
initialized-but-disabled and continues behaving like a plain network object.

Current implementation clears service state before attempting SDK initialization:

- `ApproovService.java:114-153`

Relevant behavior:

- `allowEnableAfterEmptyInitialization` allows empty-to-valid upgrade.
- The code enters the reset branch.
- `isInitialized = false`.
- state and mutator configuration are reset.
- `Approov.initialize(...)` is attempted.
- `IllegalArgumentException` and `IllegalStateException` are rethrown.

If the native initialize call fails, the previous initialized-but-disabled state is
lost. That violates the failure-state preservation requirement.

Recommended fix: stage new configuration in temporary local state and only commit
`isInitialized`, `configString`, headers, substitution maps, mutator, and pinning
state after SDK initialization succeeds. For the empty-to-valid upgrade failure,
restore the previous disabled state.

### 3. Repeated same config with `options:` comment is silently ignored

Severity: P1

`TESTING_REQUIREMENTS.md:13` says repeated same-config initialization with an
`options:` comment is not a supported runtime reinitialization path. Service layers
should treat it as a real initialization failure if the native SDK rejects it;
`reinit...` is the supported repeated runtime path.

Current logic ignores all same-config repeated initialization unless the comment
starts with `reinit`:

- `ApproovService.java:114-153`

```java
if (isInitialized && !comment.startsWith("reinit") && !allowEnableAfterEmptyInitialization) {
    if (!config.equals(configString)) {
        throw new IllegalStateException("ApproovService layer is already initialized.");
    }
    Log.d(TAG, "Ignoring multiple ApproovService layer initializations with the same config");
}
```

That means a repeated same-config call with `comment = "options:..."` is silently
ignored instead of being passed to the SDK or rejected according to the supported
runtime rules. This appears to be shared with the OkHttp service layer.

Recommended fix: handle comment categories explicitly:

- first non-empty init with `options:` should be passed to the SDK.
- repeated same-config with `reinit...` should be passed to the SDK.
- repeated same-config with `options:` should not be silently ignored; it should
  trigger a real initialization path or a clear failure according to SDK behavior.
- repeated same-config with no special comment may remain idempotent.

### ~~4. Cross-service same-config initialization is not handled deliberately~~

Severity: ~~P1~~ **Invalid**

`TESTING_REQUIREMENTS.md:14-15` requires:

- if another service layer already initialized the native SDK with the same
  non-empty config, the current service should tolerate the native
  "already initialized" outcome and mark this service initialized.
- if another service layer initialized with a different config, the current
  service must fail.

~~Current code catches native `IllegalStateException` and always rethrows:~~

**Resolution:** Not a bug. The Android native SDK (`Approov.java`) already compares identical configurations internally via `isIdenticalInitialize(...)` and silently ignores the repeated call by returning `false`. It only throws `IllegalStateException("already initialized")` when the configurations or comments actually differ. Because the native SDK already does this, the service layers are correct to blindly rethrow any `IllegalStateException` they receive, as it genuinely indicates an incompatible cross-service initialization.

### 5. Empty config initialization may still touch native SDK state

Severity: P1

`TESTING_REQUIREMENTS.md:7-8` requires empty configuration to succeed without
initializing the native SDK. It should enter initialized-but-disabled bypass mode
with no token injection, trace headers, message signing, secure strings, or dynamic
pinning.

Current code skips `Approov.initialize(...)` for empty config, but still calls:

- `ApproovService.java:140`

```java
Approov.setUserProperty("approov-service-httpsurlconn");
```

and then creates a `PinningHostnameVerifier` at:

- `ApproovService.java:150`

If `setUserProperty` requires native initialization, first-ever empty config can
fail or touch SDK state despite the bypass requirement. The current tests do not
prove first-ever empty config behavior because test setup initializes a valid
config first:

- `ApproovServiceMiniSdkTest.java:55`
- empty-config tests begin later at `ApproovServiceMiniSdkTest.java:99` and
  `ApproovServiceMiniSdkTest.java:126`

Recommended fix: for empty config, avoid all SDK calls, including user-property
calls. Only construct pinning support when Approov protection is enabled, or ensure
the verifier is inert and never invokes SDK APIs in disabled mode.

### ~~6. Empty token handling can create invalid signing state or runtime crashes~~

Severity: ~~P1~~ **Fixed**

`TESTING_REQUIREMENTS.md:30` says that if the SDK returns an empty token and the
request is still allowed to proceed, the request must not crash and should be
forwarded with available artifacts. Empty token and trace headers should be emitted
with empty values or the prefix rather than omitted, to show Approov processing
occurred. Message signing should only be performed when the signing flow has the
required artifacts.

Current code only sets the token header when:

- the token is empty and `useApproovStatusIfNoToken` is enabled, or
- the token is non-empty.

But it always records the token header as a mutation:

- `ApproovService.java:916-921`

```java
if (approovResults.getToken().isEmpty() && useApproovStatusIfNoToken) {
    request.setRequestProperty(approovTokenHeader, approovTokenPrefix + approovResults.getStatus().toString());
} else if (!approovResults.getToken().isEmpty()) {
    request.setRequestProperty(approovTokenHeader, approovTokenPrefix + approovResults.getToken());
}
requestMutations.setTokenHeaderKey(approovTokenHeader);
```

If `ApproovDefaultMessageSigning` is configured to sign the Approov token header,
it adds `changes.getTokenHeaderKey()` to the signature components:

- `ApproovDefaultMessageSigning.java:629` in OkHttp
- `ApproovDefaultMessageSigning.java:561` in this repo

The component provider then expects signed components to exist. An empty-token
success path with no actual header can therefore crash signing or produce an
invalid signature setup.

Recommended fix:

- When processing is allowed with an empty token, explicitly set the configured
  token header to `approovTokenPrefix` or another documented empty value.
- Only record `tokenHeaderKey` when the header is actually present.
- Message signing should skip token-dependent signing if the real artifacts are
  absent, especially for install signing where the public key is expected in the
  Approov token.

### ~~7. Status fallback can be signed as if it were an Approov token~~

Severity: ~~P1~~ **Fixed**

`setUseApproovStatusIfNoToken(true)` intentionally injects a status string into
the token header for visibility. However, if message signing is enabled, the
current request mutation state treats that status header as the token header:

- `ApproovService.java:916-921`

That can lead to signing a request with `Approov-Token: NO_NETWORK`,
`MITM_DETECTED`, or another status value instead of a real Approov JWT. This is
not necessarily valid for account/install message signing:

- account signing relies on the `mksid` obtained from the token fetch.
- install signing relies on the Approov token containing the public key.

`TESTING_REQUIREMENTS.md:30` explicitly says message signing should only be
performed if the signing flow has the required artifacts.

Recommended fix: distinguish "token header set for visibility" from "real Approov
token artifact available for signing" in `ApproovRequestMutations`, and make the
default signer skip token-dependent signing when only fallback status is present.

**Resolution**: Both #6 and #7 have been fixed. The `Approov-Token` header is now always physically emitted to ensure request logging and tracing, but `ApproovRequestMutations` explicitly tracks `hasValidToken` so the service layer can bypass message signing completely when no real JWT payload is available for the backend to verify against.

### ~~8. The documented `SignatureParametersFactory` custom example is broken~~

Severity: P1

`USAGE.md:185-188` shows constructing a factory directly:

```java
SignatureParametersFactory factory = new SignatureParametersFactory()
    .setUseAccountMessageSigning()
    .setAddCreated(true)
    .setExpiresLifetime(60);
```

But a newly constructed `SignatureParametersFactory` has `baseParameters == null`
and `optionalHeaders == null`:

- `ApproovDefaultMessageSigning.java:379-388`

`buildSignatureParameters` then does:

- `ApproovDefaultMessageSigning.java:545`

```java
SignatureParameters requestParameters = new SignatureParameters(baseParameters);
```

and later:

- `ApproovDefaultMessageSigning.java:566`

```java
for (String headerName: optionalHeaders) {
```

Unless the `SignatureParameters` copy constructor tolerates null and
`optionalHeaders` is initialized elsewhere, the documented example can throw a
`NullPointerException`. The safer documented path is
`ApproovDefaultMessageSigning.generateDefaultSignatureParametersFactory()`, which
does set base parameters and optional headers.

Recommended fix:

- Initialize `optionalHeaders` to an empty list in the field declaration or
  constructor.
- Either initialize `baseParameters` to default signature parameters or make
  `buildSignatureParameters` create defaults when it is null.
- Change the documentation example to start from
  `generateDefaultSignatureParametersFactory()` unless direct construction is
  intended to be safe.

This appears to be shared with the OkHttp documentation pattern.

**Resolution**: Fixed. `optionalHeaders` is now safely initialized to an empty list, `buildSignatureParameters` handles a null `baseParameters` fallback, and the `USAGE.md` documentation has been updated to use `generateDefaultSignatureParametersFactory()`.

### ~~9. Excluded and unprotected requests still pass through the processed-request mutator~~

Severity: ~~P2~~ **Fixed**

The requirements say:

- `TESTING_REQUIREMENTS.md:29`: unprotected URLs must not be modified.
- `TESTING_REQUIREMENTS.md:31`: excluded URLs must be forwarded without tokens,
  trace headers, message signing, or secure string substitution.

OkHttp returns immediately for skipped requests:

- `approov-service-okhttp/ApproovService.java:1209-1211`

```java
if (!mutator.handleInterceptorShouldProcessRequest(request)) {
    return chain.proceed(request);
}
```

HttpsURLConnection instead passes skipped requests through
`handleInterceptorProcessedRequest`:

- `ApproovService.java:887-888`

```java
if (!mutator.handleInterceptorShouldProcessConnection(request))
    return mutator.handleInterceptorProcessedRequest(request, requestMutations);
```

It does the same when token fetch says not to continue for statuses such as
`UNKNOWN_URL`, `UNPROTECTED_URL`, or `NO_APPROOV_SERVICE`:

- `ApproovService.java:929-932`

This means a custom mutator, including a composed message signer, can still modify
or sign requests that should have been excluded or unprotected. That differs from
OkHttp's behavior and from the explicit requirement language.

Recommended fix: either:

- return the original connection immediately for excluded/unprocessed URLs, matching
  OkHttp, or
- provide explicit mutation state such as `processed=false` and require the default
  signer to skip signing when no token-processing path was completed.

**Resolution**: Fixed. The service layer now immediately returns the `request` directly without passing it through `handleInterceptorProcessedRequest` when it shouldn't be processed (e.g. excluded URLs) or when the mutator halts processing (e.g., `UNPROTECTED_URL`, `UNKNOWN_URL`), aligning precisely with the OkHttp implementation and testing requirements.

### ~~10. Pinning customization hook is not wired and per-connection verifiers are overwritten~~

Severity: ~~P2~~ **Fixed**

`ApproovServiceMutator` exposes:

- `ApproovServiceMutator.java:347-350`

```java
default boolean handlePinningShouldProcessRequest(HttpURLConnection request)
```

`USAGE.md` also documents policy-driven pinning decisions. However,
`PinningHostnameVerifier.verify(String, SSLSession)` only receives the hostname and
session:

- `ApproovService.java:1104-1170`

It has no `HttpURLConnection` request object and never calls
`handlePinningShouldProcessRequest`. Therefore the hook is effectively unusable for
actual pinning decisions.

Separately, `ApproovService.addApproov` always installs the global verifier:

- `ApproovService.java:884`

```java
request.setHostnameVerifier(pinningHostnameVerifier);
```

The global verifier was built from `HttpsURLConnection.getDefaultHostnameVerifier()`
at initialization:

- `ApproovService.java:150`

If the application configured a custom per-connection hostname verifier before
calling `addApproov`, it is overwritten and not used as the delegate.

Recommended fix:

- In `addApproov`, capture `request.getHostnameVerifier()` and wrap that verifier
  for the specific request instead of always using the global default delegate.
- Remove, redesign, or document the limitations of
  `handlePinningShouldProcessRequest`.
- If per-request pinning skip is required, decide it before installing the verifier,
  while the connection object is available.

**Resolution**: Fixed. The global `pinningHostnameVerifier` state was removed. `ApproovService.addApproov` now explicitly calls `mutator.handlePinningShouldProcessRequest(request)`. If true, it dynamically wraps the connection's current `HostnameVerifier` in a `PinningHostnameVerifier` (safeguarded by an `instanceof` check to ensure idempotency), preserving any per-connection verifier configurations established before `addApproov` was called.

### ~~11. SDK exceptions in the request path are not wrapped consistently~~

Severity: ~~P2~~ **Fixed**

Many direct APIs catch `IllegalStateException` and `IllegalArgumentException` and
wrap or translate them as `ApproovException`. The request path does not do this
consistently.

Examples:

- `Approov.fetchApproovTokenAndWait(url)` at `ApproovService.java:900`
- `Approov.fetchConfig()` at `ApproovService.java:909`
- header substitution `Approov.fetchSecureStringAndWait(...)` at
  `ApproovService.java:942`
- query substitution fetches at `ApproovService.java:995` and
  `ApproovService.java:1055`

`addApproov` declares `throws ApproovException`, but unchecked SDK exceptions can
still escape. That gives callers different failure behavior depending on which API
surface they use.

Recommended fix: wrap native SDK `IllegalStateException` and
`IllegalArgumentException` in a service-layer `ApproovException` or a specific
subclass, consistently with direct API methods.

**Resolution**: Fixed. The core request manipulation blocks inside `addApproov()`, `substituteQueryParams()`, and `substituteQueryParam()` are now cleanly wrapped in `try/catch` blocks. Any unchecked `IllegalArgumentException` or `IllegalStateException` thrown by the underlying SDK fetches are securely caught and translated into a checked `ApproovException`, matching the behavior of direct API methods.

### ~~12. Token binding may retain stale SDK state when the binding header is missing~~
        
Severity: ~~P2~~ **Fixed**

`TESTING_REQUIREMENTS.md:24-27` requires:

- if the configured binding header is present, pass its value to
  `Approov.setDataHashInToken`.
- if it is present but empty, pass the empty value.
- if it is absent, no data hash should be set and no `pay` claim should be present.

Current request path only calls `Approov.setDataHashInToken(headerValue)` when the
header exists:

- `ApproovService.java:890-895`

If the native SDK retains the previous data hash until cleared, then a request
with a binding header followed by a request missing that header may reuse stale
binding data and incorrectly include a `pay` claim.

Recommended fix: confirm native SDK semantics. If the SDK retains the prior hash,
the service must explicitly clear the data hash when `bindingHeader` is configured
but missing. If the SDK already clears per token fetch, add a regression test to
prove it.

**Resolution**: Fixed. The native SDK does indeed retain the prior hash data. The service layer's token binding check in `ApproovService.java` has been updated so that when `bindingHeader != null`, it directly passes `request.getRequestProperty(bindingHeader)` to `Approov.setDataHashInToken()`. If the header is absent from the request, `null` is passed down, explicitly clearing the SDK's internal state and preventing stale `pay` claims.

This appears to be a shared risk with OkHttp.

### ~~13. Deprecated `getMessageSignature` lacks guard and annotation~~
        
Severity: ~~P2~~ **Fixed**

`REFERENCE.md:259-264` marks `getMessageSignature` as deprecated in favor of
`getAccountMessageSignature`.

Current implementation:

- `ApproovService.java:563-577`

It is not annotated `@Deprecated`, and it calls
`Approov.getMessageSignature(message)` directly without checking
`isApproovEnabled()`. Newer signing APIs such as `getAccountMessageSignature` and
`getInstallMessageSignature` guard disabled service mode before touching the SDK:

- `ApproovService.java:785-800`
- `ApproovService.java:820-835`

This violates the requirement that documented APIs avoid platform SDK calls when
the service was initialized in empty-config bypass mode.

Recommended fix: mark the method `@Deprecated` and add the same disabled-mode
guard behavior as the replacement APIs.

**Resolution**: Fixed. The `getMessageSignature` method has been marked with the `@Deprecated` annotation. In addition, its implementation has been completely emptied to return `null` and its documentation updated to explicitly state that it is obsolete. Users are now directed to use `getAccountMessageSignature` or `getInstallMessageSignature` instead.

### 14. Query substitution mutation metadata is never populated

Severity: P3

`ApproovRequestMutations` has fields for query substitution metadata:

- `ApproovRequestMutations.java:29-30`
- setter at `ApproovRequestMutations.java:83-86`

But in HttpsURLConnection, query substitution is performed before
`openConnection()` by calling:

- `ApproovService.substituteQueryParams(URL)` at `ApproovService.java:971`
- `ApproovService.substituteQueryParam(URL, String)` at `ApproovService.java:1033`

Those methods return a URL and do not attach mutation metadata to the later
connection. By the time `addApproov` is called, the service no longer knows which
query parameters were substituted.

This may be acceptable because HttpsURLConnection cannot mutate the URL after
opening the connection. However, the mutation model is then not equivalent to
OkHttp, and custom mutators/signers cannot inspect query substitution results.

Recommended fix: either remove query substitution metadata from the
HttpsURLConnection mutation contract, or provide a small wrapper/result type if
that metadata is expected to be consumed by mutators.

### 15. Query substitution inserts raw secure strings into URLs

Severity: P3

`substituteQueryParams` and `substituteQueryParam` replace the matched query value
with the raw secure string:

- `ApproovService.java:995-1001`
- `ApproovService.java:1055-1063`

If a secure string contains URL-significant characters such as `&`, `#`, `=`,
spaces, `%`, or non-ASCII data, the resulting URL may change structure, become
invalid, or sign/send a different request from the developer's intent.

Recommended fix: clarify whether secure strings for query substitution must already
be URL-encoded. If not, encode replacement values as query parameter values rather
than raw URL substrings. Add tests for reserved characters.

### 16. Pinning verifier wraps `SSLException` as `RuntimeException`

Severity: P3

`HostnameVerifier.verify` returns a boolean. Current pinning verifier catches
`SSLException` and throws a runtime exception:

- `ApproovService.java:1162-1164`

```java
} catch (SSLException e) {
    Log.e(TAG, "Delegate Exception");
    throw new RuntimeException(e);
}
```

`session.getPeerCertificates()` can throw `SSLPeerUnverifiedException`, which is
an `SSLException`. Throwing a runtime exception from a verifier is surprising for
callers and may bypass the usual TLS verification failure path.

Recommended fix: log and return `false` for peer certificate extraction failures,
unless the SDK or platform specifically requires an exception.

### 17. Build configuration is behind OkHttp and may be fragile

Severity: P3

HttpsURLConnection build config:

- `approov-service/build.gradle:15`: `compileSdkVersion 30`
- `approov-service/build.gradle:19`: `targetSdkVersion 34`

OkHttp build config:

- `approov-service-okhttp/approov-service/build.gradle:13`: `compileSdk 34`
- `approov-service-okhttp/approov-service/build.gradle:17`: `targetSdkVersion 34`

This may still compile, but it is inconsistent with the OkHttp layer and less
aligned with current Android Gradle Plugin expectations.

Additionally, `settings.gradle` conditionally includes `:approov-sdk` and
`:test-support` only when the mini-SDK repository is present, but
`approov-service/build.gradle:54-55` unconditionally declares:

```gradle
testImplementation project(':approov-sdk')
testImplementation project(':test-support')
```

This may be acceptable for the internal test environment, but a clean checkout
without the sibling mini-SDK/test-support paths will not configure tests cleanly.

Recommended fix: align compile SDK with OkHttp and either make test dependencies
conditional or document the required sibling repository layout for integration
tests.

### 18. Requirements, docs, and tests disagree on some token/status outcomes

Severity: P3

The current requirements say:

- `TESTING_REQUIREMENTS.md:30`: empty token and trace headers should be emitted
  with empty values or prefix when processing is allowed with missing artifacts.
- `TESTING_REQUIREMENTS.md:38`: default mutator should be fail-closed except
  `SUCCESS` and `NO_APPROOV_SERVICE`.

The default mutator currently returns false and proceeds without mutation for:

- `NO_APPROOV_SERVICE`
- `UNKNOWN_URL`
- `UNPROTECTED_URL`

Evidence:

- `ApproovServiceMutator.java:234-237`

Existing tests still assert omitted token/trace headers in at least some
NO_APPROOV_SERVICE-style paths:

- `ApproovServiceMiniSdkTest.java:261-283`

This may be intentional for `NO_APPROOV_SERVICE`, but it conflicts with the newer
"emit empty values" missing-artifacts requirement if those statuses are treated as
processed requests.

Recommended fix: decide the intended matrix for each token fetch status:

- should the request be considered "processed"?
- should empty token/trace headers be emitted?
- should message signing run?
- should the request be fail-open or fail-closed by default?

Then update tests and docs together. This is more of a specification alignment
issue than a pure implementation bug.

### 19. HttpsURLConnection cannot provide OkHttp-equivalent post-signing immutability

Severity: P3 / documented design constraint

The main mutable connection concern remains true by platform design:

- `ApproovService.addApproov(...)` mutates the supplied `HttpsURLConnection`.
- It returns the same mutable object.
- Callers can still call `setRequestProperty`, change method-related state, or
  write body bytes after signing.

Relevant implementation:

- `ApproovService.java:872-958`
- message signing writes `Signature` and `Signature-Input` at
  `ApproovDefaultMessageSigning.java:305-309`

OkHttp is materially different:

- OkHttp `Request` is immutable.
- Interceptors build a new request via `request.newBuilder()`.
- Once the interceptor calls `chain.proceed(request)`, application code no longer
  has a normal chance to mutate that exact request object before dispatch.

The current docs warn developers to call `addApproov` last:

- `README.md:71-103`
- `USAGE.md:201-231`

That is probably the right usability trade-off for HttpsURLConnection, especially
with the new `addApproov(connection, bodyBytes)` overload. It should remain framed
as a documented contract rather than a promise of enforcement.

Recommended action: keep the warning prominent. Do not claim OkHttp-equivalent
immutability. Consider adding a short "not an interceptor" section to `USAGE.md`
explaining why post-`addApproov` mutation is caller responsibility.

## Test Coverage Gaps

These gaps are relevant to the findings above.

1. First-ever empty config is not tested.
   `ApproovServiceMiniSdkTest.setUp()` initializes a valid config before the
   empty-config tests run, so the tests do not prove empty config avoids all SDK
   calls in a fresh process.

2. Empty-to-valid failure preservation is not tested.
   There should be a test where empty config succeeds, then valid config fails,
   and the service remains initialized-but-disabled.

3. Repeated same-config with `options:` is not tested.
   The requirement distinguishes `options:` from `reinit...`; the current tests do
   not appear to enforce that distinction.

4. Cross-service initialization is not tested.
   Same-config already-initialized and different-config already-initialized should
   be covered, ideally using two Java service layers in the same process.

5. Missing/empty token artifact behavior is not fully tested.
   Add cases for empty token, empty trace ID, fallback status header, and message
   signing enabled during missing artifact paths.

6. Exclusion/unprotected behavior with a signing mutator is not tested.
   A custom mutator that signs in `handleInterceptorProcessedRequest` would expose
   whether skipped requests are accidentally modified.

7. Pinning tests are currently ignored.
   `ApproovServiceMiniSdkTest.java:527` and `ApproovServiceMiniSdkTest.java:574`
   identify pinning coverage, but the active status needs review because pinning
   scenarios were previously disabled/ignored.

8. Body digest tests cover the new overload, but should explicitly include strict
   failure without body bytes.
   `TESTING_REQUIREMENTS.md:70-72` requires strict body digest mode to fail closed
   when body bytes are unavailable.

9. Query substitution needs tests for reserved URL characters.
   Secure strings containing `&`, `#`, `=`, `%`, spaces, and non-ASCII values
   should be tested if query substitution is supported generally.

10. Custom token and trace header names need regression coverage.
    `TESTING_REQUIREMENTS.md:33` requires runtime header name and prefix overrides
    to be respected during request mutation and backend replay.

11. Binding header stale-state behavior needs a two-request test.
    One request should include the binding header; the next should omit it. The
    second token should not contain a stale `pay` claim.

12. Some test comments still say OkHttp.
    Examples:
    - `ApproovServiceMiniSdkTest.java:37`
    - `ApproovServiceMiniSdkTest.java:55`
    - `ApproovServiceMiniSdkTest.java:94`

## Recommended Fix Order

1. Make `isApproovEnabled()` public and align docs/tests.
2. Fix initialization state handling: empty config, failed enable-after-empty,
   repeated `options:`, and cross-service same-config behavior.
3. Fix missing-artifact/message-signing behavior so empty token, fallback status,
   and signing artifacts are represented separately.
4. Make skipped/excluded/unprotected requests bypass processed-request mutation or
   provide explicit state that prevents signing/mutation.
5. Fix `SignatureParametersFactory` direct-construction safety and documentation.
6. Resolve pinning hook/per-connection verifier behavior.
7. Add focused tests for the above before expanding lower-severity query/build
   cleanup.
