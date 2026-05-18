# Approov Service HttpsURLConnection Issues

Reviewed on 2026-05-17 against:

- `approov-service-httpsurlconn` current working tree
- `approov-service-okhttp` current working tree
- `/Users/ivol/Github/core-service-layers-testing/TESTING_REQUIREMENTS.md`
- local `README.md`, `USAGE.md`, `REFERENCE.md`, and `CHANGELOG.md`

## Status

No active implementation issues remain from the previous report.

The last release-build failure was real: `PinningHostnameVerifier.verify` could
fall through without returning `false` when the delegated `HostnameVerifier`
rejected the host. This has been fixed.

The remaining query-substitution metadata issue was also real in the intermediate
tree. Automated query parameter substitution has now been removed from the
HttpsURLConnection service layer, along with the stale query-substitution mutation
metadata and mutator hook. Query secure strings are now documented as a manual
`fetchSecureString` plus URL construction step.

## Resolved Items

1. Body digest support is present through
   `ApproovService.addApproov(HttpsURLConnection, byte[])`.

2. Optional body digests are skipped when body bytes are unavailable; strict body
   digest mode fails closed.

3. `isApproovEnabled()` is public and documents the enabled-vs-bypass distinction.

4. Empty config initialization avoids native SDK initialization and allows later
   enablement with a non-empty config.

5. Initialization state is preserved when enabling after empty bootstrap fails,
   because service-layer state is only reset after SDK initialization succeeds.

6. Same-config `options:` reinitialization is no longer silently ignored; it is
   allowed through to the SDK so unsupported repeated options are surfaced as real
   SDK failures.

7. Cross-service same-config initialization is tolerated by the native Android SDK
   when the initial config, update config, and comment are identical.

8. Token fetch uses the full request URL.

9. Token, trace, digest, and signature headers use `setRequestProperty`, avoiding
   duplicate header accumulation.

10. Empty-token allowed paths emit token and trace headers with empty values or
    prefix-equivalent values, satisfying the missing-artifacts requirement.

11. Message signing skips empty-token and status-fallback paths by using
    `ApproovRequestMutations.hasValidToken()`.

12. Excluded, unprocessed, unknown, and unprotected requests return immediately
    without running the processed-request mutator or signer.

13. `SignatureParametersFactory` direct construction is null-safe for base
    parameters and optional headers.

14. Request-path SDK `IllegalStateException` and `IllegalArgumentException` are
    wrapped as `ApproovException`.

15. Missing binding headers explicitly clear SDK token-binding state to prevent
    stale `pay` claims.

16. Deprecated `getMessageSignature` is annotated and inert.

17. Pinning now wraps the per-connection `HostnameVerifier` rather than replacing
    custom verifiers with a static global delegate.

18. `PinningHostnameVerifier` returns `false` on `SSLException` and on delegate
    rejection, instead of throwing or falling through.

19. `compileSdk` is aligned to 34 and test project dependencies are conditional on
    the mini-SDK/test-support projects being present.

20. HttpsURLConnection post-signing mutability is documented as a caller contract:
    `addApproov` must be called after method/header setup and before connecting or
    writing the body.

## Remaining Test Coverage Gaps

These are not currently known implementation defects, but they are still useful
coverage gaps against `TESTING_REQUIREMENTS.md`.

21. First-ever empty config is now tested directly using reflection to isolate the SDK state (`testFirstEverEmptyConfig`).
22. Empty-to-valid failure preservation is covered with a direct negative test (`testEmptyToValidFailurePreservation`).
23. Repeated same-config with `options:` has a direct test asserting that the SDK failure is surfaced (`testRepeatedSameConfigWithOptionsSurfacesFailure`).
24. Cross-service initialization is covered by emulating two Java service layers initializing sequentially (`testCrossServiceInitialization`).
25. Strict body digest mode includes a negative test for signed requests that omit the `bodyBytes` overload (`testStrictBodyDigestOmission`).
26. PATCH body digest behavior has test coverage, accounting for standard JDK limitations (`testPatchBodyDigestBehavior`).
27. Custom token and trace header names/prefixes replay coverage has been added (`testCustomTokenAndTraceHeaders`).

## Remaining Test Coverage Gaps

1. Pinning rejection and dynamic pin update tests remain limited by Robolectric `HttpsURLConnection` verifier behavior.
