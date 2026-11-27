# Reference

This provides a reference for the main static methods defined on `ApproovService`. These are available if you import:

**Java**
```java
import io.approov.service.httpsurlconn.ApproovService;
```

Various methods may throw an `ApproovException` if there is a problem. The method `getMessage()` provides a descriptive message.

If a method throws an `ApproovNetworkException`, a user-initiated retry should be allowed.

If a method throws an `ApproovRejectionException`, the app failed attestation. Additional methods `getARC()` and `getRejectionReasons()` provide more detail when available.

## initialize

Initializes the Approov SDK and enables the Approov features. The `config` will have been provided in the initial onboarding or email or can be obtained using the approov CLI. A second attempt to initialize with a different `config` (without using the reinitialization comment) is forwarded to the native SDK, which throws an `IllegalStateException` that this method surfaces unchanged.

**Java:**
```java
void initialize(Context context, String config)
```

**Kotlin:**
```kotlin
fun initialize(context: Context, config: String)
```

The application context must be provided using the `context` parameter.

It is possible to pass an empty `config` string to indicate that no initialization of the underlying native Approov SDK is required. This initializes the service layer in a bypass mode, allowing you to obtain standard, non-Approov protected connections. If you attempt to use any direct native Approov SDK functions (such as `fetchToken` or `precheck`) while bypassed, an `ApproovException` will be thrown. You may later call `initialize` again with a valid `config` string to enable Approov protection for connections obtained after that point.

An alternative initialization function allows you to provide further options or trigger reinitialization in the `comment` parameter. Please refer to the [Approov SDK documentation](https://approov.io/docs/latest/approov-direct-sdk-integration/#sdk-initialization-options) for details.

**Throws** (both are unchecked and propagate directly; the service-layer state is left unchanged on failure):
- `IllegalArgumentException` — if `config` is `null`. Pass `""` for bypass mode.
- `IllegalStateException` — if the native SDK rejects the configuration, e.g. a different non-empty `config` than the one already initialized (an empty `config` after a valid one is ignored, not an error).

**Java:**
```java
void initialize(Context context, String config, String comment)
```

**Kotlin:**
```kotlin
fun initialize(context: Context, config: String, comment: String)
```

For example, options like `options:no-install-key` or reinitialization via `reinit` can be supplied via the `comment` parameter.

## setServiceMutator

Sets the `ApproovServiceMutator` instance used to customize request preparation and attestation handling.

```java
void setServiceMutator(ApproovServiceMutator mutator)
```

Passing `null` restores the default behavior.

## getServiceMutator

Gets the currently active mutator.

```java
ApproovServiceMutator getServiceMutator()
```

## setApproovInterceptorExtensions

Deprecated compatibility alias for `setServiceMutator`.

```java
void setApproovInterceptorExtensions(ApproovServiceMutator mutator)
```

## getApproovInterceptorExtensions

Deprecated compatibility alias for `getServiceMutator`.

```java
ApproovServiceMutator getApproovInterceptorExtensions()
```

## setProceedOnNetworkFail

If `proceed` is `true` then request preparation may continue when it is not possible to obtain an Approov token due to a networking failure.

```java
void setProceedOnNetworkFail(boolean proceed)
```

Deprecated: use `setServiceMutator` instead to control this behavior.

## getProceedOnNetworkFail

Gets the legacy proceed-on-network-failure flag.

```java
boolean getProceedOnNetworkFail()
```

Deprecated: use `setServiceMutator` instead to control this behavior.

## setUseApproovStatusIfNoToken

If `shouldUse` is `true` then the Approov fetch status, for example `NO_NETWORK`, is used as the token header value if the actual token fetch fails or returns an empty token.

```java
void setUseApproovStatusIfNoToken(boolean shouldUse)
```

## getUseApproovStatusIfNoToken

Gets the current status-as-token behavior flag.

```java
boolean getUseApproovStatusIfNoToken()
```

## setDevKey

Sets a development key in order to force the app to pass attestation in a test environment.

```java
void setDevKey(String devKey) throws ApproovException
```

## setApproovHeader

Sets the header that carries the Approov token and an optional prefix string such as `Bearer `.

```java
void setApproovHeader(String header, String prefix)
```

## getApproovTokenHeader

Gets the header currently used for the Approov token.

```java
String getApproovTokenHeader()
```

## getApproovTokenPrefix

Gets the prefix currently used before the Approov token value.

```java
String getApproovTokenPrefix()
```

## setApproovTraceIDHeader

Sets the header used to transmit any optional Approov TraceID debug value.

```java
void setApproovTraceIDHeader(String header)
```

Passing `null` disables the TraceID header.

## getApproovTraceIDHeader

Gets the header currently used for the optional Approov TraceID.

```java
String getApproovTraceIDHeader()
```

## setBindingHeader

Sets a binding header used for [token binding](https://approov.io/docs/latest/approov-usage-documentation/#token-binding).

```java
void setBindingHeader(String header)
```

## addSubstitutionHeader

Adds a header that should be subject to secure string substitution.

```java
void addSubstitutionHeader(String header, String requiredPrefix)
```

## removeSubstitutionHeader

Removes a header previously added using `addSubstitutionHeader`.

```java
void removeSubstitutionHeader(String header)
```

## getSubstitutionHeaders

Gets the currently configured substitution headers.

```java
Map<String, String> getSubstitutionHeaders()
```

## Query parameter substitution (removed in 3.5.7)

Automated query parameter substitution — `addSubstitutionQueryParam`, `removeSubstitutionQueryParam`, `getSubstitutionQueryParams`, `substituteQueryParams`, and `substituteQueryParam` — was **removed** (Issue #14). `java.net.URL` is immutable once the connection is opened, and the automated path broke the request-mutation tracking that message signing relies on. To use an Approov secure string as a query value, fetch it with `fetchSecureString()` and build the URL before `openConnection()` — see USAGE.md.

## addExclusionURLRegex

Adds an exclusion URL regular expression. Matching URLs are not subject to Approov protection.

```java
void addExclusionURLRegex(String urlRegex)
```

## removeExclusionURLRegex

Removes an exclusion URL regular expression previously added using `addExclusionURLRegex`.

```java
void removeExclusionURLRegex(String urlRegex)
```

## prefetch

Starts a background Approov fetch operation early so a later token or secure string fetch may use cached data.

```java
void prefetch()
```

## precheck

Performs a precheck to determine if the app will pass attestation.

```java
void precheck() throws ApproovException
```

This may require network access and should not be called from the UI thread.

## getDeviceID

Gets the device ID used by Approov to identify the current app installation.

```java
String getDeviceID() throws ApproovException
```

## setDataHashInToken

Directly sets the data hash to be included in subsequently fetched Approov tokens.

```java
void setDataHashInToken(String data) throws ApproovException
```

This is an alternative to using `setBindingHeader`; you should not use both at the same time.

## fetchToken

Performs an Approov token fetch for the given URL.

```java
String fetchToken(String url) throws ApproovException
```

Use this when it is not possible to use `addApproov(...)` or `addApproovToConnection(...)` to prepare the request automatically.

## getMessageSignature

Deprecated alias for `getAccountMessageSignature`.

```java
String getMessageSignature(String message) throws ApproovException
```

## getAccountMessageSignature

Gets the account message signature for the given message.

```java
String getAccountMessageSignature(String message) throws ApproovException
```

## getInstallMessageSignature

Gets the install message signature for the given message.

```java
String getInstallMessageSignature(String message) throws ApproovException
```

## fetchSecureString

Fetches a secure string with the given `key`. If `newDef` is not `null` then the string definition is updated for the current app installation.

```java
String fetchSecureString(String key, String newDef) throws ApproovException
```

## fetchCustomJWT

Fetches a custom JWT with the given marshaled JSON payload.

```java
String fetchCustomJWT(String payload) throws ApproovException
```

## getLastARC

Obtains the last Attestation Response Code, provided a network request to the Approov servers has succeeded.

```java
String getLastARC()
```

This returns an empty string if no suitable ARC is available.

## setInstallAttrsInToken

Sets an install attributes token to be sent to the server and associated with this app installation for future token fetches.

```java
void setInstallAttrsInToken(String attrs) throws ApproovException
```

## addApproov

Prepares an `HttpsURLConnection` request in place by adding the Approov token header, applying header substitutions, applying pinning, and invoking the configured mutator when a wrapper is not required.

```java
void addApproov(HttpsURLConnection request) throws ApproovException
```

This preserves the original binary-compatible API. Use `addApproovToConnection(...)` when deferred body-aware processing may be required (a message-signing body digest on a body-bearing request).

## addApproov (with body bytes)

Prepares the request and additionally supplies the request body so a message-signing `Content-Digest` can be computed over it. Use this when message signing is configured with a body digest and the body is available as a repeatable byte array. The SHA-256 (or SHA-512) digest of `body` is set in the `Content-Digest` header and covered by the signature.

```java
void addApproov(HttpsURLConnection request, byte[] body) throws ApproovException
```

If a body digest is configured as **required** and cannot be generated, this fails closed with an `ApproovException`.

## addApproovToConnection

Prepares an `HttpsURLConnection` request and returns the connection reference that should be used for the network call.

```java
HttpsURLConnection addApproovToConnection(HttpsURLConnection request) throws ApproovException
```

In the common case this is the same instance that was passed in. A wrapped connection is returned only when deferred body-aware processing is required (a message-signing body digest on a body-bearing request).
