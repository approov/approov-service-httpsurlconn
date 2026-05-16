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

### ~~18. Requirements, docs, and tests disagree on some token/status outcomes~~

Severity: ~~P3~~ **Fixed**

The current requirements say:

- `TESTING_REQUIREMENTS.md:30`: empty token and trace headers should be emitted
  with empty values or prefix when processing is allowed with missing artifacts.
- `TESTING_REQUIREMENTS.md:38`: default mutator should be fail-closed except
  `SUCCESS` and `NO_APPROOV_SERVICE`.

The default mutator currently returns false and proceeds without mutation for:

- `NO_APPROOV_SERVICE`
- `UNKNOWN_URL`
- `UNPROTECTED_URL`
- `MITM_DETECTED` (and other network errors, when `useApproovStatusIfNoToken` is enabled)

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

**Resolution**: Fixed in both `httpsurlconn` and `okhttp` repositories. The `NO_APPROOV_SERVICE` state in `ApproovServiceMutator` now explicitly returns `true` (instead of `false`). This guarantees that the service layer correctly emits the empty token header and empty trace header to the backend to formally prove that Approov interception was attempted, fully satisfying the missing-artifacts requirements. The `ApproovServiceMiniSdkTest.java` suite was simultaneously updated to strictly assert `assertNotNull` and `assertEquals("...", getHeader(reply, "Approov-Token"))` instead of expecting a null omission.

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
2. Fix initialization state handling: empty config, failed enable-after-empty, and
   repeated `options:` behavior.
3. Address query substitution mutation metadata and URL encoding for secure strings (Issues 14 & 15).
