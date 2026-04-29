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

Initializes the Approov SDK and enables the Approov features.

```java
void initialize(Context context, String config)
```

The application context must be provided using the `context` parameter. It is possible to pass an empty `config` string to indicate that no initialization is required. Only do this if you are also using a different Approov service layer in your app and that layer initializes the shared SDK first.

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

## addSubstitutionQueryParam

Adds a query parameter key that should be subject to secure string substitution.

```java
void addSubstitutionQueryParam(String key)
```

## removeSubstitutionQueryParam

Removes a query parameter key previously added using `addSubstitutionQueryParam`.

```java
void removeSubstitutionQueryParam(String key)
```

## getSubstitutionQueryParams

Gets the currently configured substitution query parameters.

```java
Map<String, Pattern> getSubstitutionQueryParams()
```

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

This preserves the original binary-compatible API. Use `addApproovToConnection(...)` for query parameter substitution or deferred body-aware processing.

## addApproovToConnection

Prepares an `HttpsURLConnection` request and returns the connection reference that should be used for the network call.

```java
HttpsURLConnection addApproovToConnection(HttpsURLConnection request) throws ApproovException
```

In the common case this is the same instance that was passed in. If configured query substitutions change the effective URL, or if deferred body-aware processing is required, then a wrapped connection is returned instead.

## substituteQueryParams

Applies all configured query parameter substitutions to the supplied URL.

```java
URL substituteQueryParams(URL url) throws ApproovException
```

Since this modifies the URL itself, it must be done before opening the `HttpsURLConnection`.

## substituteQueryParam

Substitutes a single query parameter in the supplied URL.

```java
URL substituteQueryParam(URL url, String queryParameter) throws ApproovException
```

Since this modifies the URL itself, it must be done before opening the `HttpsURLConnection`.
