# Usage

This document describes the features of the Approov Service for `HttpsURLConnection`, and how to change its default behavior. For a basic integration, see the [README](README.md) and the [Quickstart guide](https://github.com/approov/quickstart-android-java-httpsurlconn/blob/master/README.md). [REFERENCE.md](REFERENCE.md) describes every method.

## Initialize, then configure

Call `initialize` once when your app starts, then make every configuration call that your app needs:

```java
ApproovService.initialize(getApplicationContext(), "<your-approov-account-id>");
ApproovService.setServiceMutator(ApproovServiceMutator.ALWAYS_PROCEED);
```

Each `initialize` resets these settings to their defaults:

* the token, trace and binding headers, and `setUseApproovStatusIfNoToken`
* the substitution headers and the exclusions
* the service mutator, and so any message signing
* the value of `getLastARC()`

It keeps the logging level. So a setting that you make before `initialize` is lost.

The package passes every non-empty account ID and comment to the Approov SDK, and the SDK decides. A repeat call with the same account ID and comment returns at once, but it also resets the configuration. The SDK rejects a different account ID or comment, and its exception reaches your code with the package state unchanged.

### Bypass mode

Initialize with an empty account ID, `""`, to start the package in bypass mode. In bypass mode, `isApproovServiceEnabled()` is `true` and `isApproovProtectionEnabled()` is `false`:

* `addApproov` returns the connection unchanged. There is no token, secure string, signature or Approov pinning, only OS trust.
* The methods that call the SDK, such as `fetchToken`, throw `ApproovException`.
* `addSubstitutionHeader` and `addExclusionURLRegex` do nothing.

A later `initialize` with the account ID turns on Approov protection, if the SDK accepts it. Once protection is on, the package ignores an `initialize` with `""`.

Before any `initialize`, `addApproov` throws `ApproovException`.

## Adding Approov to a request

Call one of these methods on each connection, after you set its method and headers and before you connect:

| Method | Use it for |
| :--- | :--- |
| `addApproov(connection)` | a request with no body to sign, such as a `GET` |
| `addApproov(connection, body)` | a request whose body you have as a `byte[]`, so that a message signature covers the body |
| `addApproovToConnection(connection)` | a `POST`, `PUT` or `PATCH` request, or one with `setDoOutput(true)`, when you write the body to the output stream |

`addApproov(connection)` and `addApproov(connection, body)` change the connection in place. They make the message signature immediately, so set every header that you want signed before the call.

`addApproovToConnection` returns the connection to use for the request. For a request with a body, it returns a new connection. This connection holds the body in memory, and signs the request just before it sends it. Write the body to the returned connection, and read the response from it:

```java
HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
connection.setRequestMethod("POST");
connection.setRequestProperty("Content-Type", "application/json");
connection = ApproovService.addApproovToConnection(connection);
try (OutputStream out = connection.getOutputStream()) {
    out.write(body);
}
int status = connection.getResponseCode();
```

Set the request method before you call `addApproovToConnection`. For any other request, it returns the connection that you passed in.

An `HttpsURLConnection` sends one request only. For a retry, open a new connection and call the method again, so that the request has a current token.

## What happens by default

For each request, the package fetches an Approov token for the request URL. It does not process a request to an [excluded URL](#excluding-urls). The installed service mutator then decides what the request carries, or if it fails. The package gives two standard mutators:

* `ApproovServiceMutator.CLOSE_FAILURE` is the default. It keeps the 3.5.x token decisions.
* `ApproovServiceMutator.ALWAYS_PROCEED` never fails a request because of its token fetch. Your backend then decides.

`ApproovServiceMutator.DEFAULT` is `CLOSE_FAILURE`. `setServiceMutator(null)` and each `initialize` put it back. To always proceed:

```java
ApproovService.setServiceMutator(ApproovServiceMutator.ALWAYS_PROCEED);
```

| Token fetch status | `CLOSE_FAILURE` (default) | `ALWAYS_PROCEED` |
| :--- | :--- | :--- |
| `SUCCESS` | proceeds with the token and any trace ID | same |
| `UNKNOWN_URL`, `UNPROTECTED_URL` | proceeds with no Approov headers | same |
| `NO_APPROOV_SERVICE` | proceeds with an empty token header (or the status) and any trace ID | same |
| `NO_NETWORK`, `POOR_NETWORK`, `MITM_DETECTED` | throws `ApproovNetworkException`, which your app can let the user retry | proceeds with an empty token header (or the status) and any trace ID |
| any other status | throws `ApproovFetchStatusException` | proceeds with an empty token header (or the status) and any trace ID |

"The status" means the fetch status name, such as `NO_NETWORK`, in the token header after any prefix. Turn this on with `setUseApproovStatusIfNoToken(true)`. Under `CLOSE_FAILURE`, this also lets the network failures proceed with the status in the token header. `setProceedOnNetworkFail(true)` lets them proceed with no Approov headers.

Under both standard mutators, a secure string that the package cannot fetch does not fail the request. The header keeps the value that your app set, and the request goes ahead.

## Service mutators

A service mutator, an `ApproovServiceMutator`, holds the decisions of the package. Install your own with `setServiceMutator` after `initialize`. Every hook has a default, which is the `CLOSE_FAILURE` decision, so override only the hooks that you need:

| Hook | Decides |
| :--- | :--- |
| `handleInterceptorShouldProcessConnection` | if the package processes a request. The default applies the exclusions |
| `handleInterceptorFetchTokenResult` | from the token fetch result, if the request proceeds with the Approov headers, proceeds without them, or fails |
| `handleInterceptorHeaderSubstitutionResult` | if a secure string replaces a header value |
| `handleInterceptorProcessedRequest` | final changes to the request. The message signer signs here |
| `handlePinningShouldProcessRequest` | if Approov pinning applies to a request |
| `handlePrecheckResult`, `handleFetchTokenResult`, `handleFetchSecureStringResult`, `handleFetchCustomJWTResult` | how the direct methods, such as `fetchToken`, change a result into an exception |

A hook fails a request when it throws an `ApproovException`. This mutator fails a request when the app cannot reach the Approov service, and keeps the default decisions for all other statuses:

```java
import com.criticalblue.approovsdk.Approov;

import io.approov.service.httpsurlconn.ApproovException;
import io.approov.service.httpsurlconn.ApproovNetworkException;
import io.approov.service.httpsurlconn.ApproovServiceMutator;

public class EnforceTokenMutator implements ApproovServiceMutator {
    @Override
    public boolean handleInterceptorFetchTokenResult(Approov.TokenFetchResult approovResults, String url)
            throws ApproovException {
        if (approovResults.getStatus() == Approov.TokenFetchStatus.NO_APPROOV_SERVICE)
            throw new ApproovNetworkException(approovResults.getStatus(), "Approov service not available");
        return ApproovServiceMutator.CLOSE_FAILURE.handleInterceptorFetchTokenResult(approovResults, url);
    }
}
```

`handleInterceptorProcessedRequest` cannot change or remove the token header or the trace header that the package set. The package puts them back and logs a warning.

## Message signing

The message signer, `ApproovDefaultMessageSigning`, adds RFC 9421 message signatures to each request that carries the Approov token header. Message signing is off until you install the signer. The signer is a service mutator, so install it after `initialize`. Another `setServiceMutator` call or `initialize` removes it.

The simplest signer adds both the [install signature](https://approov.io/docs/latest/approov-usage-documentation/#installation-message-signing) and the [account signature](https://approov.io/docs/latest/approov-usage-documentation/#account-message-signing):

```java
ApproovService.setServiceMutator(ApproovDefaultMessageSigning.combined());
```

`combined()` makes the `CLOSE_FAILURE` decisions. To sign with other decisions, pass them, for example `combined(ApproovServiceMutator.ALWAYS_PROCEED)` or `combined(new EnforceTokenMutator())`. The signer calls `handleInterceptorProcessedRequest` of that mutator first, so the signature covers its changes.

To choose what the signature covers, give the signer a factory. A signer with no factory signs nothing:

```java
ApproovDefaultMessageSigning.SignatureParametersFactory factory =
        ApproovDefaultMessageSigning.generateDefaultSignatureParametersFactory()
                .setUseInstallAndAccountMessageSigning()
                .setExpiresLifetime(60);
ApproovService.setServiceMutator(new ApproovDefaultMessageSigning().setDefaultFactory(factory));
```

The default factory makes the install signature only. It covers the method, the target URI, the token and trace headers, and `Authorization`, `Content-Length` and `Content-Type` when the request has them. It adds `created` and an `expires` time 15 seconds later, from `getServerAdjustedCurrentTimeMS()`. Use `putHostFactory(host, factory)` to give one host a different factory.

Your backend can check the install signature only if the Approov token carries the install public key, which is a setting of your account. See [installation message signing](https://approov.io/docs/latest/approov-usage-documentation/#installation-message-signing).

If the package cannot make a signature, it sends the request with the other signature, or unsigned, and logs it under the `ApproovMsgSign` tag. An unsupported signature algorithm fails the request with an `ApproovException`.

### Body digest

The default factory adds a SHA-256 `Content-Digest` header, and covers it, when the package has the body. It has the body only from `addApproov(connection, body)`, or from the connection that `addApproovToConnection` returns. Write the same bytes that you pass:

```java
byte[] body = json.getBytes(StandardCharsets.UTF_8);
HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
connection.setRequestMethod("POST");
connection.setDoOutput(true);
ApproovService.addApproov(connection, body);
try (OutputStream out = connection.getOutputStream()) {
    out.write(body);
}
```

Use `setBodyDigestConfig(algorithm, required)` on the factory to change the digest. The algorithm is `DIGEST_SHA256`, `DIGEST_SHA512`, or `null` for no digest.

Only a required body digest fails closed. If `required` is `true` and the package cannot make the digest, the request fails with an `ApproovException` whose cause is a `RequiredBodyDigestException`. From the connection that `addApproovToConnection` returns, this failure is an `IOException` from `getResponseCode` or `getInputStream`, with the `ApproovException` as its cause. Any other failure to build the signature sends the request unsigned, and logs an error.

## Header names

By default, the token goes in `Approov-Token` with no prefix, and the trace ID goes in `Approov-TraceID`. To change them, for example when your backend expects the token in `Authorization`:

```java
ApproovService.setTokenHeader("Authorization", "Bearer ");
ApproovService.setTraceIDHeader(null); // null turns the trace header off
```

The `Approov-TraceID` header is an optional debug header. Your backend can ignore it.

## Token binding

[Token binding](https://approov.io/docs/latest/approov-usage-documentation/#token-binding) binds the Approov token to the value of a request header, such as an OAuth `Authorization` header. The SDK hashes the value on the device. It never sends the value to the Approov cloud service.

```java
ApproovService.setBindingHeader("Authorization");
```

When the value of the binding header changes, the SDK fetches a new token with the new binding.

## Secure strings

[Secure strings](https://approov.io/docs/latest/approov-usage-documentation/#secure-strings) let you remove API keys and other secrets from your app. Approov gives them only to an app that passes attestation.

### Secure strings in headers

Register each header whose value is a secure string key. The package then replaces the value with the secure string:

```java
ApproovService.addSubstitutionHeader("Api-Key", null);              // the whole value is the key
ApproovService.addSubstitutionHeader("Authorization", "Bearer ");   // the value after the prefix is the key
```

Call `addSubstitutionHeader` after an `initialize` with your account ID. Before that, and in bypass mode, it does nothing.

### Secure strings in query parameters

The package does not substitute query parameters, because the URL of an `HttpsURLConnection` cannot change after `openConnection`. Fetch the secure string yourself, and build the URL before you open the connection:

```java
String apiKey = ApproovService.fetchSecureString("api_key", null);
URL url = new URL("https://api.example.com/shapes?api_key=" + URLEncoder.encode(apiKey, "UTF-8"));
HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
ApproovService.addApproov(connection);
```

`fetchSecureString` returns `null` if the key is not defined. It throws an `ApproovException` if it cannot fetch the secure string. It can need network access, so do not call it from the UI thread. Do not cache the secure string in your app.

## Excluding URLs

The package does not process a request whose URL matches an exclusion regular expression. The expression is not anchored, so use `^` and `$` to match the full URL:

```java
ApproovService.addExclusionURLRegex("^https://api\\.example\\.com/health.*");
```

Pinning still applies to an excluded request. Use exclusions with caution. A request to an excluded URL does not update the pins.

## Pinning

`addApproov` pins each connection to a domain that you added to Approov. It sets a `HostnameVerifier` on the connection, so do not set another one after the call. The verifier first runs the default verifier, then checks that a pin of the host matches a certificate in the chain that the platform accepted. It ignores any other certificate that the server sends. A failed check makes the connection throw `SSLPeerUnverifiedException`, and logs an error under the `ApproovPinVerifier` tag.

A domain with no pins of its own uses the [Managed Trust Roots](https://docs.approov.io/security-configuration/dynamic-pinning/#managed-trust-roots). If there are none, the domain uses OS trust only, and the package logs a warning. If the SDK cannot supply the pins, the connection continues on OS trust and the package logs one error. Before `initialize` and in bypass mode, the package does not pin.

To turn off Approov pinning for some requests, override `handlePinningShouldProcessRequest` in your mutator:

```java
@Override
public boolean handlePinningShouldProcessRequest(HttpURLConnection request) {
    return !request.getURL().getHost().equals("cdn.example.com");
}
```

## Logging and diagnostics

`setLoggingLevel` sets the level of the package logging: `ApproovLogLevel.OFF`, `ERROR`, `WARNING`, `INFO` (the default) or `DEBUG`. At `DEBUG`, the package logs the [loggable form](https://approov.io/docs/latest/approov-usage-documentation/#loggable-tokens) of the token for each request, under the `ApproovService` tag. The URL in the line has no query, user info or fragment.

```java
ApproovService.setLoggingLevel(ApproovLogLevel.DEBUG);
```

To see the debug lines of an installed build without a rebuild, turn on debug logging for the `ApproovService` tag. This raises every level except `OFF` to `DEBUG`:

```sh
adb shell setprop log.tag.ApproovService DEBUG
```

`getLastARC()` returns the [Attestation Response Code](https://approov.io/docs/latest/approov-usage-documentation/#attestation-response-code) of the most recent token, secure string or custom JWT fetch. It does not fetch. It returns an empty string if there is no ARC.

`getServerAdjustedCurrentTimeMS()` returns the current time, corrected to the clock of the Approov servers. Message signatures use it for their `created` and `expires` times. Use it for your own timestamps that your backend compares with its clock.
