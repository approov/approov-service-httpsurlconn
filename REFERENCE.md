# Reference
This page lists every static method of `ApproovService`, the entry point of the Approov Package for HttpsURLConnection. To use them, import:

**Java:**
```java
import io.approov.service.httpsurlconn.ApproovService;
```

The rest of this introduction explains what happens to requests that you pass to `addApproov`, and which exceptions your app can see. The methods follow it.

A request that you pass to `addApproov` sometimes cannot be protected, for example because no token could be fetched. The installed [service mutator](ADVANCED.md#service-mutators), an `ApproovServiceMutator`, decides whether it still goes ahead. See [setServiceMutator](#setservicemutator) and [what happens by default](ADVANCED.md#what-happens-by-default).

* The default, `ApproovServiceMutator.DEFAULT`, is `CLOSE_FAILURE`. It makes the same decisions as 3.5.x. A request goes ahead on `SUCCESS`, and on `NO_APPROOV_SERVICE` with an empty token header. Otherwise `addApproov` throws one of the `ApproovException` subclasses listed below.
* With `ApproovServiceMutator.ALWAYS_PROCEED` the request always goes ahead. If the package could not protect it, it carries the `Approov-Token` header with an empty token after any prefix. It also carries the trace header whenever the SDK gives one.
* With [setUseApproovStatusIfNoToken](#setuseapproovstatusifnotoken) turned on, such a request carries the fetch status name in the token header instead of an empty token. Under `CLOSE_FAILURE` this also lets `NO_NETWORK`, `POOR_NETWORK` and `MITM_DETECTED` go ahead with the status instead of failing.

Some requests are never failed by a token fetch:

* A request to an API you added with `-noApproovToken` (status `UNPROTECTED_URL`) receives its secure strings and its pins, but no Approov header.
* A request to a host you have not added to Approov (status `UNKNOWN_URL`) goes ahead with no Approov headers.
* A request to an [excluded URL](ADVANCED.md#excluding-urls) receives no token fetch. The package still pins it.

Whatever mutator you install, these other exceptions can reach your code from a request:

* Your app's own configuration errors. A required body digest that cannot be generated, and an unsupported signing algorithm, fail every request they apply to with an `ApproovException`, an `IOException`. For the body digest, its cause is `ApproovDefaultMessageSigning.RequiredBodyDigestException`.
* Pinning failures on your API domains throw `javax.net.ssl.SSLPeerUnverifiedException` when the connection opens.
* An abort that your app opted in to through a service mutator throws the `ApproovException` that your hook threw.

From the connection that [addApproovToConnection](#addapproovtoconnection) returns for a request with a body, the package signs the request when it sends it. A signing failure then comes from a method such as `getResponseCode` or `getInputStream`, as an `IOException` with the `ApproovException` as its cause.

A secure string that the package cannot fetch never fails a request under either standard mutator. The header keeps the value that your app set. A debug line names the header and the status.

A request to one of your Approov API domains that goes ahead after a failed token fetch carries the token header. So if you installed message signing, the signer also signs it, over the empty token or the status.

The direct methods (`precheck`, `fetchToken`, `fetchSecureString`, `fetchCustomJWT` and so on) return a value to your code. They report a failure with the exceptions described below.

In [bypass mode](ADVANCED.md#bypass-initialization), `addApproov` returns the connection without any Approov processing and without Approov pinning. Before any `initialize`, `addApproov` throws `ApproovException` with the message `Approov not initialized`.

Many methods throw an `ApproovException` when there is a problem. It is an `IOException`, so it is a checked exception, and `getMessage()` gives a description. `ApproovException(String message, Throwable cause)` and `ApproovException(Throwable cause)` keep the original exception as the cause. It has these subclasses:

* `ApproovFetchStatusException`, a subclass of `ApproovException`, carries the SDK fetch status in `getTokenFetchStatus()`.
* `ApproovNetworkException`, a subclass of `ApproovException`, means a network problem caused the failure (`NO_NETWORK`, `POOR_NETWORK` or `MITM_DETECTED`). Your app should let the user retry. `getTokenFetchStatus()` gives the status.
* `ApproovRejectionException`, a subclass of `ApproovFetchStatusException` with the status `REJECTED`, means the app failed attestation. `getARC()` returns the [Attestation Response Code](https://approov.io/docs/latest/approov-usage-documentation/#attestation-response-code). Your user can give it to your app support, who can then find the reason for the failure. The user does not see the reason. `getRejectionReasons()` returns the [Rejection Reasons](https://approov.io/docs/latest/approov-usage-documentation/#rejection-reasons) as a comma separated list, if you turned on the feature.

Every method that calls the Approov SDK first checks [isApproovProtectionEnabled](#isapproovprotectionenabled). While it is `false`, the method throws `ApproovException` with the message `<method>: SDK not initialized`, without calling the SDK. These methods are `setDevKey`, `precheck`, `getDeviceID`, `getServerAdjustedCurrentTimeMS`, `setDataHashInToken`, `fetchToken`, `getMessageSignature`, `getAccountMessageSignature`, `getInstallMessageSignature`, `fetchSecureString`, `fetchCustomJWT`, `setInstallAttributes` and `setInstallAttrsInToken`. `getMessageSignature` uses the message of `getAccountMessageSignature`, and `setInstallAttributes` uses the message of `setInstallAttrsInToken`.

## initialize
Initializes the Approov SDK, which turns on the Approov features.

The `config` parameter is your Approov account ID. It is in your onboarding email, and the Approov CLI gives it with `approov sdk -getConfigString` (the CLI and the SDK call it the SDK config string). It identifies your account to the SDK. It is not a secret, and it is the same for every app in your account.

The package passes every non-empty account ID to the Approov SDK, with the comment exactly as you passed it, and the SDK decides. The package does not store or compare the account ID.

* The first initialization succeeds.
* For a repeat call with the same account ID and comment, the SDK reports that it is already initialized, and `initialize` returns at once. So every part of your app that uses Approov may call it.
* A `null` context throws `IllegalArgumentException` with the message `initialize: null context`. A `null` account ID throws `IllegalArgumentException` with the message `config must not be null; pass "" for bypass mode`.
* Anything else the SDK rejects throws the SDK's own `IllegalStateException` or `IllegalArgumentException`, unchanged. That includes a different account ID or comment. The package state stays as it was.

Every `initialize` that is not ignored resets the configuration to its defaults. A repeat call with the same account ID resets it too. The reset covers:
* the token header and prefix, and the trace header
* `setUseApproovStatusIfNoToken` and `setProceedOnNetworkFail`
* the binding header
* the service mutator, and so any message signing
* substitution headers and exclusions
* the value of `getLastARC()`

The reset keeps the logging level. While protection is on, the package ignores an empty account ID, and resets nothing. So initialize first, then make your configuration calls. See [initialize, then configure](ADVANCED.md#initialize-then-configure).

This is the standard form, and the one most apps should use. The `comment` parameter defaults to `null`.

**Java:**
```java
void initialize(Context context, String config)
```

Pass the [application context](https://developer.android.com/reference/android/content/Context#getApplicationContext()) as the `context` parameter.

You can pass an empty string instead of the account ID to skip initializing the Approov SDK. This is bypass mode:

* `isApproovServiceEnabled()` returns `true` and `isApproovProtectionEnabled()` returns `false`.
* The SDK is not called.
* `addApproov` returns the connection with no Approov token, message signing, secure strings or Approov pinning. The operating system's trust alone checks the connections.

Bypass mode is a starting state for advanced integrations. The package passes a later `initialize` with the account ID to the SDK, which turns on Approov protection if it accepts the call. Like any `initialize`, it resets the configuration. If the SDK rejects it, the package stays in bypass mode. After protection is on, the package ignores an empty string and does not pass it to the SDK. See [bypass initialization](ADVANCED.md#bypass-initialization).

To pass a `comment` to the native SDK, use the extended form. You might do this to pass `options:...` startup flags.

**Java:**
```java
void initialize(Context context, String config, String comment)
```

The package passes the `comment` parameter directly to the native Approov SDK. `null`, or the two-argument form, means no comment. This is the default. See the [Approov SDK documentation](https://approov.io/docs/latest/approov-direct-sdk-integration/#sdk-initialization-options) for the comment values.

## isApproovServiceEnabled
Returns whether the package is on, that is, whether `addApproov` accepts requests.

**Java:**
```java
boolean isApproovServiceEnabled()
```

Returns `true` after any `initialize` succeeds, including in bypass mode (an empty string instead of the account ID). Returns `false` only if no `initialize` succeeded.

A later call that the SDK rejects, for example one with a different account ID, throws and leaves the previous state in place. So this method keeps returning `true`. Use `isApproovProtectionEnabled()` to tell bypass mode from protected mode.

`isInitialized()` is the same method under its 3.5.x name:

**Java:**
```java
boolean isInitialized()
```

## isApproovProtectionEnabled
Returns whether Approov protection is on.

**Java:**
```java
boolean isApproovProtectionEnabled()
```

Returns `true` after an `initialize` with the account ID succeeds and Approov protection is active. Returns `false` before initialization and in bypass mode (an empty string).

While this returns `false`, the methods that call the Approov SDK, such as `fetchToken`, `precheck` and `fetchSecureString`, throw `ApproovException` without calling the SDK.

After a successful `initialize`, check `isApproovServiceEnabled()` and then this method. This one is `false` only in deliberate bypass mode.

`isApproovEnabled()` is the same method under its 3.5.x name:

**Java:**
```java
boolean isApproovEnabled()
```

## addApproov
Adds Approov protection to a connection, in place. Call it after you set the request method and headers, and before you connect. Call it again for each new connection, also in a retry loop.

For a request that the mutator lets go ahead, it:
* adds the token header and any trace header
* substitutes the secure string headers
* signs the request, if you installed message signing
* pins the connection (see [connection validation](ADVANCED.md#connection-validation)), and sets `Connection: close` unless the request has a `Connection` header

A request that carries a header that the package added does not follow redirects by itself. See [redirects](ADVANCED.md#redirects).

**Java:**
```java
void addApproov(HttpsURLConnection request) throws ApproovException
```

It throws `ApproovException` if the mutator fails the request. Before `initialize`, it throws `ApproovException` with the message `Approov not initialized`. In bypass mode, it changes nothing.

To give the request body to message signing, pass the body bytes too. The signature then covers a `Content-Digest` header of `body`. Write the same bytes to the connection. See [body digest](ADVANCED.md#body-digest).

**Java:**
```java
void addApproov(HttpsURLConnection request, byte[] body) throws ApproovException
```

If the factory requires a body digest and the package cannot make it, this throws `ApproovException` with a `RequiredBodyDigestException` cause.

## addApproovToConnection
Adds Approov protection as `addApproov(request)` does, but returns the connection to use for the request.

**Java:**
```java
HttpsURLConnection addApproovToConnection(HttpsURLConnection request) throws ApproovException
```

For a `POST`, `PUT` or `PATCH` request, or one with `setDoOutput(true)`, it returns a new connection. Set the request method before the call. Write the body to the returned connection and read the response from it. That connection holds the body in memory, and signs the request just before it sends it. A signing failure then comes from a method such as `getResponseCode` as an `IOException` with an `ApproovException` cause. For any other request, it returns the connection that you passed in.

## setServiceMutator
Installs an `ApproovServiceMutator`, which receives callbacks from `ApproovService`. A service mutator lets you customize what the package does at key points in the configuration and attestation flows. See [service mutators](ADVANCED.md#service-mutators) for the hooks and examples.

**Java:**
```java
void setServiceMutator(ApproovServiceMutator mutator)
```

The standard mutator is `ApproovServiceMutator.DEFAULT`, and passing `null` puts it back. Every `initialize` puts it back too, so install your mutator after `initialize`.

Message signing is a mutator too, [ApproovDefaultMessageSigning](#approovdefaultmessagesigning). Installing another mutator removes it.

A request keeps the mutator that you installed before `addApproov` processed it. A new mutator applies to requests processed after the call.

The package provides three standard mutators:

| Mutator | Decisions |
| :--- | :--- |
| `ApproovServiceMutator.CLOSE_FAILURE` | The 3.5.x token decisions, which are also the interface defaults. A token fetch goes ahead on `SUCCESS` (token and trace headers) and on `NO_APPROOV_SERVICE` (an empty token header, or the status with `setUseApproovStatusIfNoToken`, and any trace header). `UNKNOWN_URL` and `UNPROTECTED_URL` send the request with no Approov headers (`UNPROTECTED_URL` with its secure strings). `NO_NETWORK`, `POOR_NETWORK` and `MITM_DETECTED` throw `ApproovNetworkException`, unless `setUseApproovStatusIfNoToken` is on, when they go ahead with the status. Every other status throws `ApproovFetchStatusException`, `REJECTED` included. The package substitutes a secure string on `SUCCESS`. For every other secure string status, the header keeps the value that your app set. |
| `ApproovServiceMutator.ALWAYS_PROCEED` | Never aborts. Every token fetch status except `UNKNOWN_URL` and `UNPROTECTED_URL` goes ahead with the token header. On a failure status that is the token header with an empty token (or the status with `setUseApproovStatusIfNoToken`) and any trace header. The package substitutes a secure string on `SUCCESS`, as for `CLOSE_FAILURE`. |
| `ApproovServiceMutator.DEFAULT` | Points to the release's default behaviour: `CLOSE_FAILURE`. If your app wants a fixed behaviour, name `CLOSE_FAILURE` or `ALWAYS_PROCEED` explicitly. |

**Java:**
```java
ApproovService.setServiceMutator(ApproovServiceMutator.ALWAYS_PROCEED);
```

A custom mutator has the `CLOSE_FAILURE` decisions for every hook it does not override. To make one that never aborts, delegate the token decision to `ALWAYS_PROCEED` (see [service mutators](ADVANCED.md#service-mutators)).

A custom mutator may choose to abort a request from any interceptor hook. To do so it throws an `ApproovException`, which `addApproov` throws to your code. That is an explicit decision for you to make.

The aborts that `CLOSE_FAILURE` makes keep the 3.5.x Approov exception types, which are all subclasses of `IOException`. So an existing app catches the same exceptions as before.

## getServiceMutator
Returns the service mutator that is currently installed. It never returns `null`.

**Java:**
```java
ApproovServiceMutator getServiceMutator()
```

## Deprecated mutator aliases
These older, deprecated names still work:

* `setApproovInterceptorExtensions(mutator)` calls `setServiceMutator`
* `getApproovInterceptorExtensions()` calls `getServiceMutator`

## setDevKey
[Sets a development key](https://approov.io/docs/latest/approov-usage-documentation/#using-a-development-key) that makes your app pass attestation. Use it when the app has to be re-signed for a test environment, and would otherwise fail attestation.

**Java:**
```java
void setDevKey(String devKey) throws ApproovException
```

It throws `ApproovException` if the SDK rejects the development key. Before `initialize` and in bypass mode it throws `ApproovException` with the message `setDevKey: SDK not initialized`, without calling the SDK.

## setTokenHeader
Sets the `header` that carries the Approov token, and an optional `prefix` such as "`Bearer `".

* By default the token goes on `Approov-Token` with no prefix.
* Pass `null` or an empty string as `prefix` if you don't need one. `null` never adds the literal text "null".
* The header carries a token only on a request whose token fetch succeeded. The mutator can let a request go ahead without a token. The package then sends the header with an empty token after the prefix. If [setUseApproovStatusIfNoToken](#setuseapproovstatusifnotoken) is on, it sends the fetch status name instead.
* `initialize` puts back the default header and prefix, so call this after it.
* With message signing installed, the signature covers a token header only once, also when it is a covered optional header (`Authorization` in the default factory).

**Java:**
```java
void setTokenHeader(String header, String prefix)
```

## getTokenHeader
Returns the name of the header that carries the Approov token.

**Java:**
```java
String getTokenHeader()
```

## getTokenPrefix
Returns the prefix, such as "Bearer ", that the package adds before the Approov token in its header.

**Java:**
```java
String getTokenPrefix()
```

## setTraceIDHeader
Sets the name of the header that carries the optional Approov TraceID debug value. The default is `Approov-TraceID`, and `initialize` puts it back. Passing `null` turns the TraceID header off.

**Java:**
```java
void setTraceIDHeader(String header)
```

## getTraceIDHeader
Returns the name of the header used for the Approov TraceID. Returns `null` if the TraceID header is off.

**Java:**
```java
String getTraceIDHeader()
```

## setUseApproovStatusIfNoToken
Sets whether a request that goes ahead without a token carries the token fetch status in the token header. See [what happens by default](ADVANCED.md#what-happens-by-default).

* Off by default. A request that goes ahead after a failed token fetch then carries the token header with an empty token after any prefix.
* With the flag on, the token header carries the SDK fetch status name after any prefix, unchanged, such as `NO_NETWORK`, `POOR_NETWORK`, `MITM_DETECTED`, `NO_APPROOV_SERVICE` or `REJECTED`. It always describes the token fetch, never a secure string fetch.
* Under `CLOSE_FAILURE`, the flag also lets `NO_NETWORK`, `POOR_NETWORK` and `MITM_DETECTED` go ahead with the status, instead of throwing `ApproovNetworkException`. Every other failure still throws.
* The token header is never sent to a host you have not added (`UNKNOWN_URL`), or to a secrets-only API added with `-noApproovToken` (`UNPROTECTED_URL`).
* `initialize` turns the flag off again, so call this after it.

**Java:**
```java
void setUseApproovStatusIfNoToken(boolean shouldUse)
```

## getUseApproovStatusIfNoToken
Returns whether the package sends the token fetch status in the token header when no token is available.

**Java:**
```java
boolean getUseApproovStatusIfNoToken()
```

## setProceedOnNetworkFail
Deprecated: use `ApproovServiceMutator.ALWAYS_PROCEED`, or `setUseApproovStatusIfNoToken(true)`. It still works.

If `proceed` is `true`, the `CLOSE_FAILURE` decisions let a request go ahead with no Approov headers when the token fetch fails with `NO_NETWORK`, `POOR_NETWORK` or `MITM_DETECTED`. If `setUseApproovStatusIfNoToken` is also on, the request carries the status instead. The default is `false`, and `initialize` puts it back.

**Java:**
```java
void setProceedOnNetworkFail(boolean proceed)
```

Use this with caution. A request can then connect before the app has the dynamic pins from Approov.

## getProceedOnNetworkFail
Deprecated: use `setServiceMutator` to control this behaviour. Returns the value that `setProceedOnNetworkFail` set.

**Java:**
```java
boolean getProceedOnNetworkFail()
```

## Deprecated header aliases
These older, deprecated names still work. Each one calls the method with the name that every Approov package now uses:

* `setApproovHeader(header, prefix)` calls `setTokenHeader`
* `setApproovTraceIDHeader(header)` calls `setTraceIDHeader`
* `getApproovTokenHeader()` calls `getTokenHeader`
* `getApproovTokenPrefix()` calls `getTokenPrefix`
* `getApproovTraceIDHeader()` calls `getTraceIDHeader`

## setLoggingLevel
Sets the level of the package's own logging. The levels are: `io.approov.service.httpsurlconn.ApproovLogLevel.OFF`, `ERROR`, `WARNING`, `INFO` (the default) and `DEBUG`.

Each level includes the ones before it:
* `ERROR` writes errors only.
* `WARNING` adds warnings.
* `INFO` adds information lines, such as the result of initialization.
* `DEBUG` adds the debug lines. These include the [loggable form](https://approov.io/docs/latest/approov-usage-documentation/#loggable-tokens) of each request's token, whose claims include the device ID, and the device ID from `getDeviceID`.
* `OFF` writes nothing, not even errors.

You can set the level at any time, including before `initialize`, and `initialize` does not reset it. Passing `null` throws `IllegalArgumentException` and leaves the level unchanged. The Approov SDK's own logging is not affected.

You can also turn on debug logging for the `ApproovService` tag with `adb shell setprop log.tag.ApproovService DEBUG`. This raises any level except `OFF` to `DEBUG`, for every tag of the package. It lets support read the debug lines of an installed build, release builds included, without a rebuild. Run `adb shell setprop log.tag.ApproovService INFO`, or reboot, to end it. `OFF` is final: if your app turned the package's logging off, this does not override it.

**Java:**
```java
void setLoggingLevel(ApproovLogLevel level)
```

## setBindingHeader
Sets a binding `header` for the [token binding](https://approov.io/docs/latest/approov-usage-documentation/#token-binding) feature (see also [token binding](ADVANCED.md#token-binding)). Choose a header whose value stays the same for most requests, such as an Authorization header.

If the `header` is present on a request, `addApproov` gives its value to the SDK, which puts a hash of it in the Approov token. The issued token can then carry the matching `pay` claim, and so be bound to that value. Your backend integration can then check it. `initialize` clears the binding header, so call this after it.

**Java:**
```java
void setBindingHeader(String header)
```

## addSubstitutionHeader
Adds a `header` whose value the package replaces with a [secure string](https://approov.io/docs/latest/approov-usage-documentation/#secure-strings). If the header is present on a request, the package uses its value as a key to look up a secure string. The secure string then replaces the header value. This makes it easy to move existing code to secure strings. See [secure strings](ADVANCED.md#secure-strings).

* `requiredPrefix` handles values with a fixed start, such as "`Bearer `" in an authorization header. Set it to `null` if you don't need one.
* The package substitutes the header on requests to your token-protected API domains and to your secrets-only API domains.
* If the secure string fetch returns any other status than `SUCCESS`, the header keeps the value that your app set, and the request goes ahead.
* It applies to requests that you pass to `addApproov` after the call.
* It does nothing before an `initialize` with an account ID, and in bypass mode. `initialize` removes every substitution header, so call this after it.

**Java:**
```java
void addSubstitutionHeader(String header, String requiredPrefix)
```

The package does not substitute query parameters. Fetch the secure string with [fetchSecureString](#fetchsecurestring) and build the URL before you open the connection. See [secure strings](ADVANCED.md#secure-strings).

## removeSubstitutionHeader
Removes a `header` you added with `addSubstitutionHeader`. It does nothing before an `initialize` with an account ID, and in bypass mode.

**Java:**
```java
void removeSubstitutionHeader(String header)
```

## getSubstitutionHeaders
Returns the headers currently subject to secure string substitution, each mapped to its required prefix. It returns a copy.

**Java:**
```java
Map<String, String> getSubstitutionHeaders()
```

## addExclusionURLRegex
Adds a [regular expression](https://regex101.com/), the `urlRegex` parameter, for URLs to exclude. A request whose URL contains a match receives no token fetch, no Approov headers and no secure strings. The package still pins its connection. See [excluding URLs](ADVANCED.md#excluding-urls).

**Java:**
```java
void addExclusionURLRegex(String urlRegex)
```

The package logs an invalid regular expression as an error and adds nothing. It throws no exception. It keeps the exclusions you already added. It does nothing before an `initialize` with an account ID, and in bypass mode. `initialize` removes every exclusion, so call this after it.

Use this with *EXTREME CAUTION*, because of the way dynamic pinning works. Pinning may apply to every domain you added to Approov, and pin updates arrive when the SDK makes an Approov fetch. If you exclude some URLs on a domain protected by Approov, those URLs still use the Approov pins. But they give the pins no way to update until your app calls a URL that is not excluded.

So you must make sure your app can always call a URL that is not excluded, with `addApproov`.

Excluding URLs can also let the app open a connection before any dynamic pins arrive from Approov. That may open the connection to a man-in-the-middle (MitM) attack.

## removeExclusionURLRegex
Removes an exclusion regular expression (`urlRegex`) you added with `addExclusionURLRegex`. It does nothing before an `initialize` with an account ID, and in bypass mode.

**Java:**
```java
void removeExclusionURLRegex(String urlRegex)
```

## precheck
Checks whether your app will pass attestation. This needs [secure strings](https://approov.io/docs/latest/approov-usage-documentation/#secure-strings) to be enabled for your account, although you don't need to set up any strings.

**Java:**
```java
void precheck() throws ApproovException
```

It throws `ApproovException` if the precheck fails. For `NO_NETWORK`, `POOR_NETWORK` and `MITM_DETECTED` it is an `ApproovNetworkException`. For `REJECTED` it is an `ApproovRejectionException` with the message `precheck: REJECTED: <arc> <reasons>`. For any other failure it is an `ApproovFetchStatusException`, with the status in `getTokenFetchStatus()`.

It will probably need network access, so it may take some time. Don't call it from the UI thread.

Before `initialize` and in bypass mode it throws `ApproovException` with the message `precheck: SDK not initialized`, without calling the SDK.

## getDeviceID
Returns the [device ID](https://approov.io/docs/latest/approov-usage-documentation/#extracting-the-device-id) that Approov uses to identify the device the SDK is running on. Different Approov apps on the same device have different IDs. The ID may also change if the user uninstalls and reinstalls the app.

**Java:**
```java
String getDeviceID() throws ApproovException
```

It throws `ApproovException` if there was a problem reading the device ID. Before `initialize` and in bypass mode it throws `ApproovException` with the message `getDeviceID: SDK not initialized`, without calling the SDK.

## getServerAdjustedCurrentTimeMS
Returns the current time in milliseconds since the epoch, adjusted to the Approov servers' clock. The SDK learns the offset between the device clock and the Approov servers' clock at each attestation. Before the installation's first attestation the value is the device clock. Message signatures take their `created` and `expires` times from it, so a device whose clock is wrong still signs within the window your backend accepts. Use it for timestamps of your own that your backend compares with its clock.

**Java:**
```java
long getServerAdjustedCurrentTimeMS() throws ApproovException
```

If the server time is not available, it returns the device clock. It throws `ApproovException` if the SDK call fails. Before `initialize` and in bypass mode it throws `ApproovException` with the message `getServerAdjustedCurrentTimeMS: SDK not initialized`, without calling the SDK.

## setDataHashInToken
Sets the [token binding](https://approov.io/docs/latest/approov-usage-documentation/#token-binding) hash directly, for the Approov tokens fetched after it.

If the hash differs from any value set before, the next token fetch returns a new token with the new payload data hash. The token then carries the `pay` claim, a base64 encoded string of the SHA256 hash of the data. The SDK hashes the data on the device and never sends it to the Approov cloud service.

This is an alternative to `setBindingHeader`. Don't use both at the same time.

**Java:**
```java
void setDataHashInToken(String data) throws ApproovException
```

It throws `ApproovException` if there was a problem changing the data hash. Before `initialize` and in bypass mode it throws `ApproovException` with the message `setDataHashInToken: SDK not initialized`, without calling the SDK.

## fetchToken
Fetches an Approov token for the given `url`. Use it where you cannot use `addApproov`. Never cache the returned token in your app. Call this method each time you need one.

**Java:**
```java
String fetchToken(String url) throws ApproovException
```

It throws `ApproovException` if there was a problem fetching a token. For `NO_NETWORK`, `POOR_NETWORK` and `MITM_DETECTED` it is an `ApproovNetworkException`. For any other failure it is an `ApproovFetchStatusException`, with the status in `getTokenFetchStatus()`.

It may need network access, so it may take some time. Don't call it from the UI thread.

Before `initialize` and in bypass mode it throws `ApproovException` with the message `fetchToken: SDK not initialized`, without calling the SDK.

## getMessageSignature
Deprecated: use `getAccountMessageSignature` instead. It returns the same value as `getAccountMessageSignature`. The first call in your app's process logs a deprecation warning that names `getAccountMessageSignature`.

**Java:**
```java
String getMessageSignature(String message) throws ApproovException
```

## getAccountMessageSignature
Returns the [account message signature](https://approov.io/docs/latest/approov-usage-documentation/#account-message-signing) for the given message, as a base64 encoded string.

It uses a signing key specific to your account. The SDK receives this key after a successful fetch, if your account has the feature. If attestation failed, the key it receives is random, so the signature will be wrong. Always include an Approov token in the message you sign, and send the token alongside the signature, to prevent replay attacks.

**Java:**
```java
String getAccountMessageSignature(String message) throws ApproovException
```

It throws `ApproovException` with the message `no account signature available` if no signature is available, because no fetch occurred yet or your account does not have the feature. Before `initialize` and in bypass mode it throws `ApproovException` with the message `getAccountMessageSignature: SDK not initialized`, without calling the SDK.

## getInstallMessageSignature
Returns the [install message signature](https://approov.io/docs/latest/approov-usage-documentation/#installation-message-signing) for the given message. It returns the base64 encoding of the signature in ASN.1 DER format.

It uses a signing key specific to this installation of the app, which the SDK generates the first time the app starts. The key is an ECC key pair. The device's secure element or trusted execution environment holds its private key. Where it can, Approov uses attested key pairs for this signing. Always include an Approov token in the message you sign, and send the token alongside the signature, to prevent replay attacks.

**Java:**
```java
String getInstallMessageSignature(String message) throws ApproovException
```

It throws `ApproovException` with the message `no device signature available` if no signature is available, because no fetch occurred yet or your account does not have the feature. Before `initialize` and in bypass mode it throws `ApproovException` with the message `getInstallMessageSignature: SDK not initialized`, without calling the SDK.

## fetchSecureString
Fetches the [secure string](https://approov.io/docs/latest/approov-usage-documentation/#secure-strings) with the given `key`, or defines a new one.

* With `newDef` set to `null`, it looks up the secure string. It returns `null` if your account defines no secure string for `key`.
* With `newDef` not `null`, it may define a secure string for this particular app instance. It then returns the new value as the secure string.
* An empty string as `newDef` removes the entry.

Never cache the returned string in your app. Call this method each time you need it.

**Java:**
```java
String fetchSecureString(String key, String newDef) throws ApproovException
```

It throws `ApproovException` if there was a problem fetching the secure string. For `NO_NETWORK`, `POOR_NETWORK` and `MITM_DETECTED` it is an `ApproovNetworkException`. For `REJECTED` it is an `ApproovRejectionException`, with the ARC and rejection reasons, and the message `fetchSecureString <lookup|definition> for <key>: REJECTED: <arc> <reasons>`. For any other failure it is an `ApproovFetchStatusException`, with the status in `getTokenFetchStatus()`.

It may need network access, so it may take some time. Don't call it from the UI thread.

Before `initialize` and in bypass mode it throws `ApproovException` with the message `fetchSecureString: SDK not initialized`, without calling the SDK.

## fetchCustomJWT
Fetches a [custom JWT](https://approov.io/docs/latest/approov-usage-documentation/#custom-jwts) with the given `payload`, which is a marshaled JSON string.

**Java:**
```java
String fetchCustomJWT(String payload) throws ApproovException
```

It throws `ApproovException` if there was a problem fetching the custom JWT. For `NO_NETWORK`, `POOR_NETWORK` and `MITM_DETECTED` it is an `ApproovNetworkException`. For `REJECTED` it is an `ApproovRejectionException`, with the ARC and rejection reasons, and the message `fetchCustomJWT: REJECTED: <arc> <reasons>`. For any other failure it is an `ApproovFetchStatusException`, with the status in `getTokenFetchStatus()`.

It may need network access, so it may take some time. Don't call it from the UI thread.

Before `initialize` and in bypass mode it throws `ApproovException` with the message `fetchCustomJWT: SDK not initialized`, without calling the SDK.

## getLastARC
Returns the [Attestation Response Code](https://approov.io/docs/latest/approov-usage-documentation/#attestation-response-code) (ARC) from the most recent fetch this package made. The ARC is a code that tells Approov support why attestation gave its result.

The fetch can be a token, secure string or custom JWT fetch. It can come from `addApproov` (including secure string substitutions) or from a direct method (`fetchToken`, `fetchSecureString`, `fetchCustomJWT`, `precheck`).

It returns an empty string if:
* no fetch occurred after the last `initialize`, which clears it
* the last fetch produced no ARC
* ARC is not enabled for your account
* the last fetch failed without a result (an SDK exception in a direct method)

It makes no SDK call and does no fetch. It returns the value the app already received, so you can read it after a rejected request and match it up with your backend. Where possible, prefer logging the ARC your backend saw.

**Java:**
```java
String getLastARC()
```

## setInstallAttributes
Sets an [install attributes token](https://approov.io/docs/latest/approov-usage-documentation/#application-installation-attributes), which the SDK sends to the server. The server then associates it with this app installation for future Approov token fetches. The token must be signed, within its expiry time, and bound to the device ID of this installation. The package passes it to the SDK's `Approov.setInstallAttrsInToken`.

**Java:**
```java
void setInstallAttributes(String attrs) throws ApproovException
```

It throws `ApproovException` if the SDK refuses the attributes. Before `initialize` and in bypass mode it throws `ApproovException` with the message `setInstallAttrsInToken: SDK not initialized`, without calling the SDK.

`setInstallAttrsInToken(attrs)` does the same under its 3.5.x name.

**Java:**
```java
void setInstallAttrsInToken(String attrs) throws ApproovException
```

# Extension classes

The classes below complete the public API of the package. A standard integration never uses them. See [ADVANCED.md](ADVANCED.md) for when you need them.

## ApproovServiceMutator

An interface with default methods, which you install with `setServiceMutator`. Its interceptor defaults are the `CLOSE_FAILURE` decisions, the same as in 3.5.x. See [service mutators](ADVANCED.md#service-mutators).

Every `handleInterceptor...` hook declares `ApproovException`, and a mutator aborts a request by throwing one. `addApproov` then throws that exception to your code.

The `CLOSE_FAILURE` token decisions keep their 3.5.x exception types, whether a custom mutator inherits them or calls them. The standard substitution decisions never throw.

| Method | Default decision |
| :--- | :--- |
| `boolean handleInterceptorShouldProcessConnection(HttpsURLConnection request) throws ApproovException` | `false` if the URL matches an exclusion regex, else `true` |
| `boolean handleInterceptorFetchTokenResult(Approov.TokenFetchResult approovResults, String url) throws ApproovException` | `true` for `SUCCESS` (token and trace headers) and `NO_APPROOV_SERVICE` (an empty token header, or the status, and any trace header). `false` for `UNKNOWN_URL` and `UNPROTECTED_URL` (no Approov headers). For `NO_NETWORK`, `POOR_NETWORK` and `MITM_DETECTED`: `true` when `setUseApproovStatusIfNoToken` is on, `false` (no Approov headers) when the deprecated `setProceedOnNetworkFail` is on, else throws `ApproovNetworkException`. Throws `ApproovFetchStatusException` for every other status, with the message `Approov token fetch for <url>: <status>`. The package substitutes secure strings only when this returns `true`, or on `UNPROTECTED_URL` |
| `boolean handleInterceptorHeaderSubstitutionResult(Approov.TokenFetchResult approovResults, String header) throws ApproovException` | `true` for `SUCCESS`. `false` for every other status, so the header keeps the value that your app set. Never throws. An override may throw an `ApproovException` to abort |
| `HttpsURLConnection handleInterceptorProcessedRequest(HttpsURLConnection request, ApproovRequestMutations changes) throws ApproovException` | returns the request unchanged. `ApproovDefaultMessageSigning` signs here. The package puts back the token and trace headers that it set |
| `boolean handlePinningShouldProcessRequest(HttpURLConnection request)` | `true` |
| `void handlePrecheckResult(Approov.TokenFetchResult approovResults) throws ApproovException` | throws for every status except `SUCCESS` and `UNKNOWN_KEY` |
| `void handleFetchTokenResult(Approov.TokenFetchResult approovResults) throws ApproovException` | throws for every status except `SUCCESS` |
| `void handleFetchSecureStringResult(Approov.TokenFetchResult approovResults, String operation, String key) throws ApproovException` | throws for every status except `SUCCESS` and `UNKNOWN_KEY` |
| `void handleFetchCustomJWTResult(Approov.TokenFetchResult approovResults) throws ApproovException` | throws for every status except `SUCCESS` |
| `static boolean isNetworkFailure(Approov.TokenFetchStatus status)` | `true` for `NO_NETWORK`, `POOR_NETWORK`, `MITM_DETECTED` |
| `static boolean closeFailureSubstitution(Approov.TokenFetchResult approovResults)` | The substitution decision of both standard mutators: `true` for `SUCCESS`, `false` otherwise. Never throws |

| Constant | Meaning |
| :--- | :--- |
| `CLOSE_FAILURE` | an instance with these defaults |
| `ALWAYS_PROCEED` | Never aborts. `handleInterceptorFetchTokenResult` returns `false` for `UNKNOWN_URL` and `UNPROTECTED_URL`, and `true` for every other status. All other hooks are the defaults |
| `DEFAULT` | Declared as `ApproovServiceMutator`. It points to the release's default behaviour: `CLOSE_FAILURE`. If your app wants a fixed behaviour, name `CLOSE_FAILURE` or `ALWAYS_PROCEED` explicitly |

The standard mutators do not sign. [ApproovDefaultMessageSigning](#approovdefaultmessagesigning) is the mutator that signs.

`ApproovInterceptorExtensions` is a deprecated interface. Implement `ApproovServiceMutator` and rename `processedRequest` to `handleInterceptorProcessedRequest`.

## ApproovRequestMutations

Passed to `handleInterceptorProcessedRequest`. It describes what `addApproov` did to the request.

| Method | Meaning |
| :--- | :--- |
| `String getTokenHeaderKey()` | name of the token header added, or `null` if none |
| `String getTraceIDHeaderKey()` | name of the trace header added, or `null` |
| `List<String> getSubstitutionHeaderKeys()` | headers whose values the package replaced with secure strings, or `null` |
| `byte[] getBodyBytes()` | a copy of the body bytes from `addApproov(request, body)`, or `null` |
| `void setTokenHeaderKey(String tokenHeaderKey)` | sets the token header name |
| `void setTraceIDHeaderKey(String traceIDHeaderKey)` | sets the trace header name |
| `void setSubstitutionHeaderKeys(List<String> substitutionHeaderKeys)` | sets the substituted header names |
| `void setBodyBytes(byte[] bodyBytes)` | sets the body bytes for the body digest |

The package uses the setters. Tests that build a mutations object for a custom mutator also use them. A mutator that receives the object only needs to read it, not call the setters.

## SignatureParameters

`io.approov.util.httpsurlconn.sig.SignatureParameters` holds the covered components and the signature parameters of one signature (RFC 9421 section 2.3). Three places use it: `SignatureParametersFactory.setBaseParameters` takes it, `generateDefaultSignatureParametersFactory(SignatureParameters)` accepts it, and a subclass of `ApproovDefaultMessageSigning` returns it from `buildSignatureParameters`.

| Method | Meaning |
| :--- | :--- |
| `SignatureParameters()` | empty parameter set |
| `SignatureParameters(SignatureParameters base)` | copy of the components, parameters and debug flag of another set |
| `SignatureParameters addComponentIdentifier(String)` / `(StringItem)` | covers a component. That is a derived component such as `ComponentProvider.DC_METHOD` (`@method`) or `DC_TARGET_URI` (`@target-uri`), or a header name. A component already covered, with the same name and parameters, is not added again (RFC 9421 section 2) |
| `boolean containsComponentIdentifier(String)` / `(StringItem)` | whether the set covers a component |
| `String getAlg()` / `SignatureParameters setAlg(String)` | signature algorithm. The default factory leaves it unset, so that the signer produces one signature per configured algorithm. Set it to produce a single signature |
| `Long getCreated()` / `setCreated(Long)` | the `created` parameter, in seconds since the epoch |
| `Long getExpires()` / `setExpires(Long)` | the `expires` parameter |
| `String getKeyid()` / `setKeyid(String)` | the `keyid` parameter, not used by Approov signatures |
| `String getNonce()` / `setNonce(String)` | the `nonce` parameter |
| `String getTag()` / `setTag(String)` | the `tag` parameter |
| `Object getCustomParameter(String)` / `setCustomParameter(String, Object)` | any other signature parameter |
| `SignatureParameters setParameters(Map<String, Object>)` | replaces all signature parameters |
| `boolean isDebugMode()` / `void setDebugMode(boolean)` | when `true`, the signer adds `Signature-Base-Digest`, a SHA-256 of each signature base, to help you debug a verifier |
| `StringItem toComponentIdentifier()` | the `@signature-params` identifier |
| `InnerList toComponentValue()` | the `Signature-Input` member value for this set |
| `static SignatureParameters fromDictionaryEntry(Dictionary, String sigId)` | parses a `Signature-Input` member back into a parameter set |

## Supporting signing classes

The packages `io.approov.util.httpsurlconn.sig` (`ComponentProvider`, `SignatureBaseBuilder` and `SignatureParameters`) and `io.approov.util.httpsurlconn.http.sfv` (the RFC 8941 structured field values, such as `StringItem`, `Dictionary` and `InnerList`) are public because the signing extension points use them. `ComponentProvider` names the derived components of RFC 9421 section 2.2, such as `DC_METHOD` and `DC_TARGET_URI`, and `SignatureBaseBuilder` builds the signature base that `ApproovDefaultMessageSigning` signs. Your app needs them only in a subclass of the signer or in a custom factory.

## ApproovDefaultMessageSigning

The message signing service mutator. Install it with `setServiceMutator` to sign requests (RFC 9421). See [message signing](ADVANCED.md#message-signing).

**Java:**
```java
ApproovService.setServiceMutator(new ApproovDefaultMessageSigning().setDefaultFactory(
        ApproovDefaultMessageSigning.generateDefaultSignatureParametersFactory()));
```

The signer signs every request that carries the Approov token header. It signs after all the other changes the package makes, so the signature covers what the package sends. That includes a request to one of your Approov API domains that goes ahead after a failed token fetch. Its token header holds an empty token or the status.

Signing is off unless you install it. The signer makes the interface default decisions, the same as `CLOSE_FAILURE`. Installing another mutator, passing `null` to `setServiceMutator` or calling `initialize` removes it. To sign under other decisions, use `combined(decisions)`, or call the signer from your own mutator (see [sign with other decisions](ADVANCED.md#sign-with-other-decisions)).

If the signer cannot produce a signature, it leaves it out, and the request goes ahead with the other one, or unsigned. If a signature covers a header that the request does not send, the request goes ahead unsigned. Only configuration errors fail the request. They are a required body digest that cannot be generated (an `ApproovException` whose cause is `RequiredBodyDigestException`), or an unsupported signature algorithm (`ApproovException` with the message `Message signing: unsupported algorithm identifier: <alg>`).

| Member | Meaning |
| :--- | :--- |
| `ApproovDefaultMessageSigning()` | a signer with no factory, which signs nothing until you set one |
| `ApproovDefaultMessageSigning setDefaultFactory(SignatureParametersFactory factory)` | the factory for every host without one of its own, or `null` to sign nothing for such hosts. Returns the signer |
| `ApproovDefaultMessageSigning putHostFactory(String hostName, SignatureParametersFactory factory)` | the factory for one host, matched without regard to case and without the port. `null` removes it, so the default applies again. A `null` `hostName` throws `IllegalArgumentException`. Returns the signer |
| `protected SignatureParameters buildSignatureParameters(HttpsURLConnectionComponentProvider provider, ApproovRequestMutations changes)` | The override point for choosing parameters per request. The default builds them with the factory for the request's host. Returning `null` leaves the request unsigned. Let a `RequiredBodyDigestException` from `super` propagate |
| `HttpsURLConnection handleInterceptorProcessedRequest(HttpsURLConnection request, ApproovRequestMutations changes) throws ApproovException` | signs the request. A mutator that calls it from its own `handleInterceptorProcessedRequest` makes its changes first. A subclass that overrides it makes its changes, then calls `super` |
| `static SignatureParametersFactory generateDefaultSignatureParametersFactory()` | The default factory. It produces the install signature only. It covers `@method`, `@target-uri`, and the token and trace headers. It also covers `Authorization`, `Content-Length` and `Content-Type` when present. When the package has the body, it adds a SHA-256 body digest that is not required. It adds `created` and a 15 second `expires` |
| `static SignatureParametersFactory generateDefaultSignatureParametersFactory(SignatureParameters baseParametersOverride)` | as above, over a custom base set of components. `null` uses the default base |
| `static ApproovDefaultMessageSigning combined()` | a signer whose default factory adds both the install and the account signature. It makes the `ApproovServiceMutator.DEFAULT` decisions. Install it with `setServiceMutator` |
| `static ApproovDefaultMessageSigning combined(ApproovServiceMutator decisions)` | as `combined()`, but it makes the decisions of `decisions`, for example `ApproovServiceMutator.CLOSE_FAILURE` or `ALWAYS_PROCEED`. It calls `handleInterceptorProcessedRequest` of `decisions` before it signs. Each call returns a new signer. Throws `IllegalArgumentException` if `decisions` is `null` |
| `DIGEST_SHA256`, `DIGEST_SHA512` | body digest algorithms, `sha-256` and `sha-512` |
| `ALG_ES256`, `ALG_HS256` | signature algorithms (`ecdsa-p256-sha256`, `hmac-sha256`) |
| `SIG_ID_INSTALL`, `SIG_ID_ACCOUNT` | dictionary member names `install` and `account` |
| `RequiredBodyDigestException` | An `IllegalStateException` thrown by `buildSignatureParameters` when a required body digest cannot be generated. The request then fails with an `ApproovException` (an `IOException`) that has it as its cause, with the message `Message signing: required body digest not generated` |
| `protected HttpsURLConnectionComponentProvider` | the view of the request passed to `buildSignatureParameters` (`getMethod()`, `getPath()`, `hasField(name)`, `getField(name)`, ...). Only a subclass of `ApproovDefaultMessageSigning` can use it |

## ApproovDefaultMessageSigning.SignatureParametersFactory

Builds the signature parameters for each request. All setters return the factory, so you can chain them. Every request that a factory applies to shares it. So configure it fully before you pass it to `setDefaultFactory` or `putHostFactory`, and use a separate instance for each distinct configuration.

| Method | Meaning |
| :--- | :--- |
| `setBaseParameters(SignatureParameters baseParameters)` | components that are always covered |
| `setUseInstallMessageSigning()` | produce the install signature only. A newly constructed factory, and the default factory, start in this state |
| `setUseAccountMessageSigning()` | produce the account signature only |
| `setUseInstallAndAccountMessageSigning()` | produce both, as the members `install` and `account` of the same headers |
| `List<String> getAlgs()` | the configured algorithms, in the order of the signatures in the headers. Throws `IllegalStateException` if there are none. The package then sends a request that such a factory applies to unsigned |
| `setAddCreated(boolean addCreated)` | add the `created` parameter, the signing time from [getServerAdjustedCurrentTimeMS](#getserveradjustedcurrenttimems) |
| `setExpiresLifetime(long expiresLifetime)` | add `expires` this many seconds after `created`. `0` or less leaves it out |
| `setAddApproovTokenHeader(boolean addApproovTokenHeader)` | cover the token header |
| `setAddApproovTraceIDHeader(boolean addApproovTraceIDHeader)` | cover the trace header when present |
| `addOptionalHeaders(String... headers)` | cover these headers when present |
| `setBodyDigestConfig(String bodyDigestAlgorithm, boolean required)` | compute `Content-Digest` with `DIGEST_SHA256` or `DIGEST_SHA512`, or pass `null` for none. With `required` set, the request fails when the digest cannot be generated. Another algorithm throws `IllegalArgumentException` |
| `protected SignatureParameters buildSignatureParameters(HttpsURLConnectionComponentProvider provider, ApproovRequestMutations changes)` | Builds the parameters for one request. The signer calls it. If the returned parameter set has an explicit `alg`, the signer produces that single signature. Otherwise the algorithms come from the factory (`getAlgs()`). To choose parameters per request, override `buildSignatureParameters` on `ApproovDefaultMessageSigning` instead |
