# Reference

This provides a reference for the public static methods of `ApproovService`, and for the extension classes. These are available if you import:

**Java:**
```java
import io.approov.service.httpsurlconn.ApproovService;
```

[USAGE.md](USAGE.md) explains how to use these methods together.

# Exceptions

Many methods throw an `ApproovException` if there is a problem. It is an `IOException`, and `getMessage()` gives a description. It has these subclasses:

* `ApproovFetchStatusException` gives the SDK fetch status in `getTokenFetchStatus()`.
* `ApproovNetworkException` means that a network problem caused the failure (`NO_NETWORK`, `POOR_NETWORK` or `MITM_DETECTED`). Let the user retry. `getTokenFetchStatus()` gives the status.
* `ApproovRejectionException` is an `ApproovFetchStatusException` with the status `REJECTED`. It means that the app failed attestation. `getARC()` gives the [Attestation Response Code](https://approov.io/docs/latest/approov-usage-documentation/#attestation-response-code), and `getRejectionReasons()` gives the [rejection reasons](https://approov.io/docs/latest/approov-usage-documentation/#rejection-reasons) as a comma separated list, if this feature is on.

Each method that calls the Approov SDK throws `ApproovException` with the message `<method>: SDK not initialized` before `initialize` and in bypass mode. It does not call the SDK.

# ApproovService

## initialize

Initializes the Approov SDK and turns on the Approov features. The `config` is your Approov account ID. It is in your onboarding email, and `approov sdk -getConfigString` gives it.

**Java:**
```java
void initialize(Context context, String config)
```

**Kotlin:**
```kotlin
fun initialize(context: Context, config: String)
```

Pass the application context as `context`.

The package passes every non-empty `config`, and the comment unchanged, to the Approov SDK, and the SDK decides. A repeat call with the same `config` and comment returns at once. Each `initialize` that the package does not ignore resets the configuration to its defaults, so make your configuration calls after it. The logging level is not reset. See [initialize, then configure](USAGE.md#initialize-then-configure).

An empty `config` starts the package in bypass mode, with no Approov protection. Once protection is on, the package ignores an empty `config`. See [bypass mode](USAGE.md#bypass-mode).

**Throws** (unchecked, with the package state unchanged):
- `IllegalArgumentException` if `context` or `config` is `null`. Pass `""` for bypass mode.
- the exception of the SDK, unchanged, if the SDK rejects the call. For example, the SDK throws `IllegalStateException` for a second call with a different `config` or comment.

The extended form passes a `comment` to the Approov SDK. Use it for `options:` startup flags. `null` means no comment. See the [Approov SDK documentation](https://approov.io/docs/latest/approov-direct-sdk-integration/#sdk-initialization-options).

**Java:**
```java
void initialize(Context context, String config, String comment)
```

**Kotlin:**
```kotlin
fun initialize(context: Context, config: String, comment: String?)
```

## isApproovServiceEnabled

Returns `true` after any `initialize` succeeds, bypass mode included.

```java
boolean isApproovServiceEnabled()
```

`isInitialized()` returns the same value.

## isApproovProtectionEnabled

Returns `true` after an `initialize` with an account ID succeeds. It returns `false` before `initialize` and in bypass mode.

```java
boolean isApproovProtectionEnabled()
```

`isApproovEnabled()` returns the same value.

## setLoggingLevel

Sets the level of the package logging, with an `ApproovLogLevel`. The default is `INFO`. Each level includes the levels before it:

* `OFF` writes nothing.
* `ERROR` writes errors only.
* `WARNING` adds warnings.
* `INFO` adds information, such as the result of `initialize`.
* `DEBUG` adds the debug lines, which include the loggable form of the token for each request.

```java
void setLoggingLevel(ApproovLogLevel level)
```

You can call it at any time, also before `initialize`, and `initialize` does not reset it. A `null` level throws `IllegalArgumentException`. Debug logging for the `ApproovService` tag (`adb shell setprop log.tag.ApproovService DEBUG`) raises every level except `OFF` to `DEBUG`. The logging of the Approov SDK does not change.

## setServiceMutator

Installs the `ApproovServiceMutator` that makes the decisions of the package. See [service mutators](USAGE.md#service-mutators).

```java
void setServiceMutator(ApproovServiceMutator mutator)
```

Passing `null` installs `ApproovServiceMutator.DEFAULT`. Each `initialize` also installs `DEFAULT`, so call this after `initialize`.

## getServiceMutator

Returns the installed mutator. It never returns `null`.

```java
ApproovServiceMutator getServiceMutator()
```

## setApproovInterceptorExtensions

Deprecated: use `setServiceMutator`.

```java
void setApproovInterceptorExtensions(ApproovServiceMutator mutator)
```

## getApproovInterceptorExtensions

Deprecated: use `getServiceMutator`.

```java
ApproovServiceMutator getApproovInterceptorExtensions()
```

## setProceedOnNetworkFail

If `proceed` is `true`, the default decisions let a request proceed with no Approov headers when the token fetch fails with `NO_NETWORK`, `POOR_NETWORK` or `MITM_DETECTED`. The default is `false`, and `initialize` puts it back. If `setUseApproovStatusIfNoToken` is on, the request proceeds with the status instead.

```java
void setProceedOnNetworkFail(boolean proceed)
```

Use this with caution. A request can then connect before the app has the dynamic pins from Approov.

## getProceedOnNetworkFail

Deprecated: use `setServiceMutator` to control this behavior. Returns the value that `setProceedOnNetworkFail` set.

```java
boolean getProceedOnNetworkFail()
```

## setUseApproovStatusIfNoToken

If `shouldUse` is `true`, a request that proceeds without a token carries the token fetch status name, such as `NO_NETWORK`, in the token header after any prefix. Otherwise the token header is empty after any prefix. Under the default decisions, this also lets `NO_NETWORK`, `POOR_NETWORK` and `MITM_DETECTED` proceed. The default is `false`, and `initialize` puts it back.

```java
void setUseApproovStatusIfNoToken(boolean shouldUse)
```

## getUseApproovStatusIfNoToken

Returns the value that `setUseApproovStatusIfNoToken` set.

```java
boolean getUseApproovStatusIfNoToken()
```

## setDevKey

Sets a [development key](https://approov.io/docs/latest/approov-usage-documentation/#using-a-development-key), which makes the app pass attestation in a test environment.

```java
void setDevKey(String devKey) throws ApproovException
```

## setTokenHeader

Sets the header that carries the Approov token, and an optional prefix, such as `Bearer `. The default is `Approov-Token` with no prefix, and `initialize` puts it back. A `null` prefix means no prefix.

```java
void setTokenHeader(String header, String prefix)
```

## getTokenHeader

Returns the header that carries the Approov token.

```java
String getTokenHeader()
```

## getTokenPrefix

Returns the prefix that goes before the Approov token.

```java
String getTokenPrefix()
```

## setTraceIDHeader

Sets the header that carries the optional Approov TraceID debug value. The default is `Approov-TraceID`, and `initialize` puts it back. Passing `null` turns the TraceID header off.

```java
void setTraceIDHeader(String header)
```

## getTraceIDHeader

Returns the header that carries the Approov TraceID, or `null` if it is off.

```java
String getTraceIDHeader()
```

## Deprecated header methods

These methods still work. Use the replacement for each one:

| Deprecated | Replacement |
| :--- | :--- |
| `void setApproovHeader(String header, String prefix)` | `setTokenHeader(header, prefix)` |
| `void setApproovTraceIDHeader(String header)` | `setTraceIDHeader(header)` |
| `String getApproovTokenHeader()` | `getTokenHeader()` |
| `String getApproovTokenPrefix()` | `getTokenPrefix()` |
| `String getApproovTraceIDHeader()` | `getTraceIDHeader()` |

## setBindingHeader

Sets the header for [token binding](https://approov.io/docs/latest/approov-usage-documentation/#token-binding). If a request has this header, the SDK puts a hash of its value in the Approov token. `initialize` removes the binding header.

```java
void setBindingHeader(String header)
```

## addSubstitutionHeader

Adds a header whose value is a [secure string](https://approov.io/docs/latest/approov-usage-documentation/#secure-strings) key. The package replaces the value with the secure string. `requiredPrefix` is a prefix, such as `Bearer `, that goes before the key, or `null` for none.

```java
void addSubstitutionHeader(String header, String requiredPrefix)
```

It does nothing before an `initialize` with an account ID, and in bypass mode. `initialize` removes every substitution header. A secure string that the package cannot fetch leaves the header value unchanged, and the request goes ahead.

## removeSubstitutionHeader

Removes a header that you added with `addSubstitutionHeader`.

```java
void removeSubstitutionHeader(String header)
```

## getSubstitutionHeaders

Returns a copy of the substitution headers, each mapped to its required prefix. Call it after `initialize`.

```java
Map<String, String> getSubstitutionHeaders()
```

## addExclusionURLRegex

Adds a regular expression for URLs to exclude. The package does not process a request whose URL contains a match, but it still pins the connection. This method does nothing before an `initialize` with an account ID, and in bypass mode. The package logs an invalid expression as an error and does not add it.

```java
void addExclusionURLRegex(String urlRegex)
```

Use this with *EXTREME CAUTION*. An excluded request does not update the pins. Make sure that your app can always call a URL that is not excluded.

## removeExclusionURLRegex

Removes an expression that you added with `addExclusionURLRegex`.

```java
void removeExclusionURLRegex(String urlRegex)
```

## precheck

Checks if the app will pass attestation. This needs secure strings to be on for your account, but you do not need to define a secure string.

```java
void precheck() throws ApproovException
```

It throws `ApproovException` if the check fails. See [Exceptions](#exceptions). It can need network access, so do not call it from the UI thread.

## getDeviceID

Returns the device ID that Approov uses to identify this installation of the app.

```java
String getDeviceID() throws ApproovException
```

## getServerAdjustedCurrentTimeMS

Returns the current time in milliseconds since the epoch, corrected to the clock of the Approov servers. Before the first attestation, it is the device clock. Message signatures take their `created` and `expires` times from it.

```java
long getServerAdjustedCurrentTimeMS() throws ApproovException
```

## setDataHashInToken

Sets the data hash to put in the Approov tokens that the app fetches after this call. The SDK hashes the data on the device.

```java
void setDataHashInToken(String data) throws ApproovException
```

This is an alternative to `setBindingHeader`. Do not use both.

## fetchToken

Fetches an Approov token for the given URL. Use it when you cannot use `addApproov`. Do not cache the token.

```java
String fetchToken(String url) throws ApproovException
```

It throws `ApproovException` if the fetch does not succeed. See [Exceptions](#exceptions). It can need network access, so do not call it from the UI thread.

## getMessageSignature

Deprecated: use `getAccountMessageSignature`. The first call logs a warning.

```java
String getMessageSignature(String message) throws ApproovException
```

## getAccountMessageSignature

Returns the [account message signature](https://approov.io/docs/latest/approov-usage-documentation/#account-message-signing) for the message, as base64.

```java
String getAccountMessageSignature(String message) throws ApproovException
```

It throws `ApproovException` if no signature is available.

## getInstallMessageSignature

Returns the [install message signature](https://approov.io/docs/latest/approov-usage-documentation/#installation-message-signing) for the message, as base64 of the ASN.1 DER signature.

```java
String getInstallMessageSignature(String message) throws ApproovException
```

It throws `ApproovException` if no signature is available.

## fetchSecureString

Fetches the secure string for `key`. If `newDef` is not `null`, it defines the secure string for this installation of the app and returns the new value. An empty `newDef` removes the definition.

```java
String fetchSecureString(String key, String newDef) throws ApproovException
```

It returns `null` if `key` is not defined. It throws `ApproovException` if the fetch does not succeed. See [Exceptions](#exceptions). It can need network access, so do not call it from the UI thread. Do not cache the secure string.

## fetchCustomJWT

Fetches a custom JWT with the given marshaled JSON payload.

```java
String fetchCustomJWT(String payload) throws ApproovException
```

## getLastARC

Returns the Attestation Response Code of the most recent token, secure string or custom JWT fetch, from a request or from a direct method. It does not fetch.

```java
String getLastARC()
```

It returns an empty string if no fetch occurred after `initialize`. It also returns an empty string if the last fetch had no ARC, or if ARC is off for your account.

## setInstallAttributes

Sets an install attributes token, which the SDK sends with the next token fetch. The token must be signed, in its expiry time and bound to the device ID.

```java
void setInstallAttributes(String attrs) throws ApproovException
```

`setInstallAttrsInToken` is the same method with its 3.5.x name.

```java
void setInstallAttrsInToken(String attrs) throws ApproovException
```

## addApproov

Adds Approov to the connection, in place. For a request that the mutator lets proceed, it adds the token header and any trace header. It also substitutes the secure string headers, and signs the request if you installed message signing. It also pins the connection. Call it just before the request.

```java
void addApproov(HttpsURLConnection request) throws ApproovException
```

Before `initialize`, it throws `ApproovException`. In bypass mode, it changes nothing.

## addApproov (with body bytes)

As `addApproov(request)`, but it also gives the request body to message signing. The signature then covers a `Content-Digest` header of `body`. Write the same bytes to the connection.

```java
void addApproov(HttpsURLConnection request, byte[] body) throws ApproovException
```

If the factory requires a body digest and the package cannot make it, this throws `ApproovException` with a `RequiredBodyDigestException` cause.

## addApproovToConnection

As `addApproov(request)`, but it returns the connection to use for the request.

```java
HttpsURLConnection addApproovToConnection(HttpsURLConnection request) throws ApproovException
```

For a `POST`, `PUT` or `PATCH` request, or one with `setDoOutput(true)`, it returns a new connection. Write the body to the returned connection and read the response from it. That connection holds the body in memory, and signs the request just before it sends it. A signing failure then comes from a method such as `getResponseCode` as an `IOException` with an `ApproovException` cause. For any other request, it returns the connection that you passed in.

# ApproovLogLevel

The levels for `setLoggingLevel`, in order: `OFF`, `ERROR`, `WARNING`, `INFO` and `DEBUG`.

# ApproovServiceMutator

An interface whose methods all have defaults. Install it with `setServiceMutator`. A hook fails a request when it throws an `ApproovException`.

| Hook | Default decision |
| :--- | :--- |
| `boolean handleInterceptorShouldProcessConnection(HttpsURLConnection request) throws ApproovException` | `false` if the URL matches an exclusion expression, else `true` |
| `boolean handleInterceptorFetchTokenResult(Approov.TokenFetchResult approovResults, String url) throws ApproovException` | `true` (proceed with the Approov headers) for `SUCCESS` and `NO_APPROOV_SERVICE`. `false` (proceed with no Approov headers) for `UNKNOWN_URL` and `UNPROTECTED_URL`. For `NO_NETWORK`, `POOR_NETWORK` and `MITM_DETECTED`: `true` if `setUseApproovStatusIfNoToken` is on, `false` if `setProceedOnNetworkFail` is on, else throws `ApproovNetworkException`. Throws `ApproovFetchStatusException` for any other status |
| `boolean handleInterceptorHeaderSubstitutionResult(Approov.TokenFetchResult approovResults, String header) throws ApproovException` | `true` (substitute) for `SUCCESS`, else `false` (keep the header value). It never throws |
| `HttpsURLConnection handleInterceptorProcessedRequest(HttpsURLConnection request, ApproovRequestMutations changes) throws ApproovException` | returns `request` unchanged. The message signer signs here. The package puts back the token and trace headers that it set |
| `boolean handlePinningShouldProcessRequest(HttpURLConnection request)` | `true` (pin the connection) |
| `void handlePrecheckResult(Approov.TokenFetchResult approovResults) throws ApproovException` | throws for every status except `SUCCESS` and `UNKNOWN_KEY` |
| `void handleFetchTokenResult(Approov.TokenFetchResult approovResults) throws ApproovException` | throws for every status except `SUCCESS` |
| `void handleFetchSecureStringResult(Approov.TokenFetchResult approovResults, String operation, String key) throws ApproovException` | throws for every status except `SUCCESS` and `UNKNOWN_KEY` |
| `void handleFetchCustomJWTResult(Approov.TokenFetchResult approovResults) throws ApproovException` | throws for every status except `SUCCESS` |

| Constant | Meaning |
| :--- | :--- |
| `CLOSE_FAILURE` | a mutator with the default decisions above |
| `ALWAYS_PROCEED` | never fails a request. `handleInterceptorFetchTokenResult` returns `false` for `UNKNOWN_URL` and `UNPROTECTED_URL`, and `true` for every other status. All other hooks are the defaults |
| `DEFAULT` | the mutator that `setServiceMutator(null)` and `initialize` install. It is `CLOSE_FAILURE` |

`ApproovInterceptorExtensions` is a deprecated interface. Implement `ApproovServiceMutator` and rename `processedRequest` to `handleInterceptorProcessedRequest`.

# ApproovDefaultMessageSigning

The message signer, a service mutator that adds RFC 9421 `Signature` and `Signature-Input` headers to each request that carries the token header. See [message signing](USAGE.md#message-signing).

| Member | Meaning |
| :--- | :--- |
| `ApproovDefaultMessageSigning()` | a signer with the default decisions and no factory. It signs nothing until you set a factory |
| `static ApproovDefaultMessageSigning combined()` | a signer with the `DEFAULT` decisions, and a default factory that makes the install and the account signatures |
| `static ApproovDefaultMessageSigning combined(ApproovServiceMutator decisions)` | as `combined()`, with the decisions of `decisions`. It calls `handleInterceptorProcessedRequest` of `decisions` before it signs. A `null` value throws `IllegalArgumentException` |
| `ApproovDefaultMessageSigning setDefaultFactory(SignatureParametersFactory factory)` | the factory for each host that has no factory of its own. `null` signs nothing for such hosts. Returns the signer |
| `ApproovDefaultMessageSigning putHostFactory(String hostName, SignatureParametersFactory factory)` | the factory for one host, matched without regard to case and without a port. `null` removes it. Returns the signer |
| `static SignatureParametersFactory generateDefaultSignatureParametersFactory()` | a factory for the install signature. It covers `@method`, `@target-uri`, the token and trace headers, and `Authorization`, `Content-Length` and `Content-Type` when present. It adds `created`, an `expires` time 15 seconds later, and a SHA-256 body digest that is not required |
| `static SignatureParametersFactory generateDefaultSignatureParametersFactory(SignatureParameters baseParametersOverride)` | as above, with your base components. `null` uses the default base |
| `protected SignatureParameters buildSignatureParameters(HttpsURLConnectionComponentProvider provider, ApproovRequestMutations changes)` | override it to choose the parameters for each request. `null` leaves the request unsigned |
| `DIGEST_SHA256`, `DIGEST_SHA512` | the body digest algorithms, `sha-256` and `sha-512` |
| `ALG_ES256`, `ALG_HS256` | the signature algorithms, `ecdsa-p256-sha256` (install) and `hmac-sha256` (account) |
| `SIG_ID_INSTALL`, `SIG_ID_ACCOUNT` | the signature names in the headers, `install` and `account` |

If the package cannot make a signature, it sends the request with the other signature or unsigned, and logs it. Two errors fail the request with an `ApproovException`: an unsupported algorithm, and a required body digest that the package cannot make.

## SignatureParametersFactory

`ApproovDefaultMessageSigning.SignatureParametersFactory` builds the signature parameters for each request. Each setter returns the factory.

| Method | Meaning |
| :--- | :--- |
| `setBaseParameters(SignatureParameters baseParameters)` | the components that each signature covers |
| `setUseInstallMessageSigning()` | make the install signature only. This is the default |
| `setUseAccountMessageSigning()` | make the account signature only |
| `setUseInstallAndAccountMessageSigning()` | make both signatures |
| `List<String> getAlgs()` | the algorithms of the factory. Throws `IllegalStateException` if there are none |
| `setAddCreated(boolean addCreated)` | add the `created` parameter |
| `setExpiresLifetime(long expiresLifetime)` | add `expires`, this number of seconds after the signing time. `0` or less adds no `expires` |
| `setAddApproovTokenHeader(boolean addApproovTokenHeader)` | cover the token header |
| `setAddApproovTraceIDHeader(boolean addApproovTraceIDHeader)` | cover the trace header when present |
| `addOptionalHeaders(String... headers)` | cover these headers when present |
| `setBodyDigestConfig(String bodyDigestAlgorithm, boolean required)` | add a `Content-Digest` header with `DIGEST_SHA256` or `DIGEST_SHA512`, or `null` for none. If `required` is `true`, the request fails when the package cannot make the digest. Another algorithm throws `IllegalArgumentException` |

## RequiredBodyDigestException

`ApproovDefaultMessageSigning.RequiredBodyDigestException` is an `IllegalStateException`. A factory throws it when it cannot make a required body digest. The request then fails with an `ApproovException` that has it as its cause.
