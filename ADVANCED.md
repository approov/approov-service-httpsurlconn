# Advanced Options

The `approov-service-httpsurlconn` package works through the `addApproov` methods of `ApproovService`. After you call `initialize` with your account ID, a call to `addApproov` adds an Approov token to each request to your API domains. The token is a signed JWT that provides proof of attestation, which your backend can check.

A standard integration of the Approov Package for HttpsURLConnection needs nothing from this document. You add the dependency, initialize, and call `addApproov` on each connection, as the [README](README.md) shows. The options below change the defaults, suitable for applications with specific needs. You can find every method used in this document in [REFERENCE.md](REFERENCE.md).

| What you need | Read |
| :--- | :--- |
| Understand what reaches your backend | [What each request carries](#what-each-request-carries), then [What happens by default](#what-happens-by-default) |
| Change what happens on a network failure | [What happens by default](#what-happens-by-default), then [Service mutators](#service-mutators) |
| Protect request contents with signatures | [Message signing](#message-signing), then [Account Message Signing](https://docs.approov.io/operations/message-signing/account/) |
| Replace an embedded API secret | [Secure strings](#secure-strings) |
| Configure startup or runtime activation | [Initialize, then configure](#initialize-then-configure), then [Bypass initialization](#bypass-initialization) |
| Follow a redirect | [Redirects](#redirects) |
| Investigate an unexpected result | [Diagnostics](#diagnostics), then [What happens by default](#what-happens-by-default) |

## What each request carries

What the package adds to a request depends on two things:

* the kind of host: a token-protected API domain, a secrets-only API domain, or a host not protected by Approov (one you have not added)
* the outcome of the attestation attempt for the request

Based on the attestation outcome and the kind of host, the package and its [service mutator](#service-mutators) decide what to add to the request. They also decide whether the request goes ahead at all.

| Request goes to | Outcome | What the package adds |
| :--- | :--- | :--- |
| a token-protected domain: an API domain you added to Approov | `SUCCESS` | the token header, and the trace header when the SDK gives a trace ID. Your [secure strings](#secure-strings). The signatures, once you install [message signing](#message-signing). A pinned connection. |
| a secrets-only domain: an API domain you added with `approov api -add <domain> -noApproovToken` | `UNPROTECTED_URL` | your secure strings. A pinned connection. No token or trace header, and no signatures. |
| a host not protected by Approov | `UNKNOWN_URL` | nothing. The connection relies on the device's trust store. |
| any host | a failure status | depends on the service mutator (see below) |

A failure status means the app could not complete the attestation. For example, there was no network, or the Approov service could not be reached. The [service mutator](#what-happens-by-default) then decides whether `addApproov` throws or the request goes ahead. A request that goes ahead carries the `Approov-Token` header with an empty token after any prefix. If you turned on [setUseApproovStatusIfNoToken](REFERENCE.md#setuseapproovstatusifnotoken), it carries the status name instead. It also carries the trace header when the SDK gives a trace ID.

A secure string that the package cannot fetch never fails the request under the standard mutators. The header keeps the value that your app set, and the request goes ahead.

The headers your backend may receive:

* `Approov-Token` carries the Approov token, or is empty (or holds the [status](REFERENCE.md#setuseapproovstatusifnotoken)) when no token could be fetched. Only your backend can tell from the token whether the app passed. See [Approov tokens](https://docs.approov.io/core-concepts/approov-tokens/architecture-and-security/).
* `Signature` and `Signature-Input` carry the signatures, once you install [message signing](#message-signing).
* `Approov-TraceID` is an optional debug header. Your backend passes it through unchanged.

Whatever the attestation outcome, the package pins the connection to each domain you added, token-protected or secrets-only (see [Connection validation](#connection-validation)).

## What happens by default

For every request it processes, `addApproov` fetches an Approov token for the request URL. It then applies the decisions of the installed [service mutator](#service-mutators). It does not process a request in [bypass mode](#bypass-initialization), or a request to an [excluded URL](#excluding-urls). Before any `initialize`, `addApproov` throws `ApproovException`. The package provides three standard mutators:

* `ApproovServiceMutator.CLOSE_FAILURE` keeps the 3.5.x token decisions. A failed token fetch makes `addApproov` throw, with the same `ApproovException` types as 3.5.x.
* `ApproovServiceMutator.ALWAYS_PROCEED` never fails a request because of its token fetch. Whatever the token fetch outcome, the request goes ahead, and your backend decides. Your backend is then the enforcement point.
* `ApproovServiceMutator.DEFAULT` is the mutator installed out of the box. `setServiceMutator(null)` puts it back, and so does each `initialize` that succeeds. `DEFAULT` points to whatever the release considers default behaviour, which is currently `CLOSE_FAILURE`.

To opt in to always proceeding:

```java
ApproovService.setServiceMutator(ApproovServiceMutator.ALWAYS_PROCEED);
```

| Approov token fetch status | `CLOSE_FAILURE` (default) | `ALWAYS_PROCEED` |
| :--- | :--- | :--- |
| `SUCCESS` | proceeds with the token, any trace header, the secure strings and, with message signing installed, the signatures | same |
| `UNPROTECTED_URL` (secrets-only API) | proceeds with the secure strings only, no Approov headers | same |
| `UNKNOWN_URL` (host not protected by Approov) | proceeds with no Approov headers | same |
| `NO_APPROOV_SERVICE` | proceeds with an empty token header (or the status) and any trace header | same |
| `NO_NETWORK`, `POOR_NETWORK`, `MITM_DETECTED` | throws `ApproovNetworkException`, which can be retried. With `setUseApproovStatusIfNoToken(true)` it proceeds with the status in the token header instead | proceeds with an empty token header (or the status) and any trace header |
| any other status (`INTERNAL_ERROR`, `BAD_URL`, ...) | throws `ApproovFetchStatusException` | proceeds with an empty token header (or the status) and any trace header |

"The status" in this table means the status name in the token header, after any prefix, when you turn on [setUseApproovStatusIfNoToken](REFERENCE.md#setuseapproovstatusifnotoken). If you installed [message signing](#message-signing), the signer also signs a request that goes ahead after a failed token fetch.

`NO_APPROOV_SERVICE` means the app could not reach the Approov service or its failover. Requests to your API domains then go out with an empty token header (or the status) under either standard mutator.

The deprecated `setProceedOnNetworkFail(true)` still works. Under `CLOSE_FAILURE`, it lets `NO_NETWORK`, `POOR_NETWORK` and `MITM_DETECTED` proceed with no Approov headers. If `setUseApproovStatusIfNoToken` is also on, the request carries the status instead. Use `ALWAYS_PROCEED` or `setUseApproovStatusIfNoToken(true)` in new code.

These are the token fetch decisions only. Under either mutator, these still fail the request:

* a TLS connection that fails the pin check
* a required body digest that the package cannot make (see [Body digest](#body-digest))
* an abort that your own hooks ask for

## Message signing

The signer, `ApproovDefaultMessageSigning`, adds RFC 9421 message signatures to every request that carries the Approov token header.

Message signing is **off unless you install it**. If you do not need signatures, keep the default and install nothing.

The signer is a service mutator, so installing another mutator, passing `null` to `setServiceMutator` or a successful `initialize` removes it. The signer makes the standard decisions, the same as `CLOSE_FAILURE`. If those suit you, give it a default factory and install it right after `initialize`, as in the example. To sign under other decisions, such as `ALWAYS_PROCEED`, use [`combined`](#sign-with-other-decisions).

```java
ApproovService.setServiceMutator(new ApproovDefaultMessageSigning().setDefaultFactory(
        ApproovDefaultMessageSigning.generateDefaultSignatureParametersFactory()));
```

After you install the signer, it signs every request that carries the Approov token header with the install signature, `ecdsa-p256-sha256`. It uses a key unique to the app installation. Its dictionary member is `install`.

You can add the account signature, `hmac-sha256`, with `setUseInstallAndAccountMessageSigning()` on the factory. It uses a shared account key, delivered to the app when it passes attestation. Its member is `account`. Both are members of the same `Signature` and `Signature-Input` headers, over the same covered components. If one signature cannot be produced, the request goes ahead with the other, or unsigned.

The default factory covers the method, the target URI, the token and trace headers, and `Authorization`, `Content-Length` and `Content-Type` when the request has them. It adds `created` and an `expires` time 15 seconds later. Both times come from [getServerAdjustedCurrentTimeMS](REFERENCE.md#getserveradjustedcurrenttimems), the current time corrected to the clock of the Approov servers. Use `putHostFactory(host, factory)` to give one host a different factory.

The signed target URI, and the authority if you cover it, leave out a default port: `:443` for `https` and `:80` for `http`. So `https://api.example.com:443/v1` and `https://api.example.com/v1` give the same signature base.

`addApproov(connection)` and `addApproov(connection, body)` sign the request during the call, so set every header that you want signed before the call. The connection that `addApproovToConnection` returns for a request with a body signs the request just before it sends it.

A request to a secrets-only API that the SDK reports as `UNPROTECTED_URL` carries no token header and is not signed. A request to an Approov protected host can go ahead after a failed token fetch. It then still carries the token header, empty or with the status. So the signer signs it too, over that value.

If a signature covers a header that the request does not send, the package sends the request unsigned and logs an error.

Each `initialize` that succeeds puts back the `DEFAULT` mutator, which removes the signer. So install it again after each `initialize`.

To sign under decisions that `combined` does not offer, combine them with the signer in a mutator of your own. Your mutator makes its decisions and calls the signer from its `handleInterceptorProcessedRequest`. This mutator makes the `ALWAYS_PROCEED` token decisions and signs:

```java
class ProceedAndSign implements ApproovServiceMutator {
    private final ApproovDefaultMessageSigning signer = new ApproovDefaultMessageSigning().setDefaultFactory(
            ApproovDefaultMessageSigning.generateDefaultSignatureParametersFactory());

    @Override
    public boolean handleInterceptorFetchTokenResult(Approov.TokenFetchResult result, String url)
            throws ApproovException {
        return ApproovServiceMutator.ALWAYS_PROCEED.handleInterceptorFetchTokenResult(result, url);
    }

    @Override
    public HttpsURLConnection handleInterceptorProcessedRequest(HttpsURLConnection request,
            ApproovRequestMutations changes) throws ApproovException {
        return signer.handleInterceptorProcessedRequest(request, changes);
    }
}

ApproovService.setServiceMutator(new ProceedAndSign());
```

When you write such a mutator:

* To change the request before the signer signs it, make your change first and then call the signer.
* Let an exception from the signer propagate unchanged. A required body digest that cannot be generated then fails the request, as it does when you install the signer on its own.

Your backend receives `Signature` and `Signature-Input` headers whose members include `install`, `account` or both. When a signature cannot be produced, the request goes ahead with the other signature or unsigned. The package logs under the `ApproovMsgSign` tag. It logs a missing install or account signature as a warning once per process, and a request sent unsigned as an error once per process. It logs later occurrences at debug level. Only a configuration error fails the request with an `ApproovException`. The configuration errors are a required body digest that cannot be generated, and an unsupported signature algorithm.

Your backend verifies the signatures as [Installation Message Signing](https://docs.approov.io/operations/message-signing/installation/) and [Account Message Signing](https://docs.approov.io/operations/message-signing/account/) describe.

### Sign with other decisions

`ApproovDefaultMessageSigning.combined(decisions)` returns a signer that adds both the install and the account signature. It makes the decisions of `decisions`: `ApproovServiceMutator.CLOSE_FAILURE`, `ALWAYS_PROCEED`, `DEFAULT` or a mutator of your own. The signer calls `handleInterceptorProcessedRequest` of that mutator first, so the signature covers its changes. `combined()` uses `ApproovServiceMutator.DEFAULT`, the same as `CLOSE_FAILURE`. If `decisions` is `null`, the call throws `IllegalArgumentException`. If the signer cannot produce a signature, it leaves it out, and the request goes ahead with the other signature or unsigned. Your backend can check the install signature only if the Approov token carries the install public key. Turn that on for your account with `approov policy -setInstallPubKey on` (see [installation message signing](https://docs.approov.io/operations/message-signing/installation/)). Each call returns a new `ApproovDefaultMessageSigning`, so `setDefaultFactory` and `putHostFactory` on it change only that signer.

```java
ApproovService.setServiceMutator(
        ApproovDefaultMessageSigning.combined(ApproovServiceMutator.CLOSE_FAILURE));

ApproovService.setServiceMutator(
        ApproovDefaultMessageSigning.combined(ApproovServiceMutator.ALWAYS_PROCEED));
```

### Body digest

The default factory adds a SHA-256 `Content-Digest` header, and covers it, when the package has the body. The package has the body only from `addApproov(connection, body)`, or from the connection that `addApproovToConnection` returns. Write the same bytes that you pass:

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

Only a required body digest fails closed. If `required` is `true` and the package cannot make the digest, the request fails with an `ApproovException` whose cause is a `RequiredBodyDigestException`. From `addApproov`, the call throws this exception. From the connection that `addApproovToConnection` returns, `getResponseCode` or `getInputStream` throws an `IOException` with the `ApproovException` as its cause. Any other failure to build the signature sends the request unsigned, and logs an error.

## Header names

You can change the name of the token header and the trace header, and the prefix in front of the token. By default, the token goes in `Approov-Token` with no prefix, and the trace ID in `Approov-TraceID`.

Change them when your backend expects the token in another header, such as `Authorization` with a `Bearer ` prefix, or does not want the trace header. Passing `null` turns the trace header off.

```java
ApproovService.setTokenHeader("Authorization", "Bearer ");   // default "Approov-Token", no prefix
ApproovService.setTraceIDHeader(null);                       // default "Approov-TraceID"; null disables
```

Each `initialize` that succeeds puts these back to their defaults, so set them after it.

## Bypass initialization

Initialize with an empty string instead of the account ID to start the package in bypass mode. In bypass mode the package accepts requests but protects nothing: `isApproovServiceEnabled()` is `true` and `isApproovProtectionEnabled()` is `false`. In this mode:

* `addApproov` returns the connection unchanged. There is no token, signing, secure strings or Approov pinning, only OS trust.
* the methods that call the SDK throw `ApproovException` without calling it.
* `addSubstitutionHeader` and `addExclusionURLRegex` do nothing.

Before any `initialize`, `addApproov` throws `ApproovException`.

Bypass mode is a starting or fallback state. Use it, for example, while your app fetches the account ID remotely. The README example also uses it as a guard, in case the account ID does not reach the app intact.

```java
ApproovService.initialize(context, "");
```

A later `initialize` with the account ID turns Approov on at runtime, if the SDK accepts it. Like each `initialize` that succeeds, it resets the configuration to its defaults, so make your configuration calls again after it.

Once protection is on, the package ignores an `initialize` with an empty string, and resets nothing. The SDK rejects a later `initialize` with a different account ID or a different comment. Its exception reaches your code, and the package state does not change. See [initialize in the reference](REFERENCE.md#initialize).

In bypass mode, the `ApproovService` tag logs `initialize: bypass mode, Approov protection not active` at `INFO`.

## Initialize, then configure

You normally initialize the package once. Call `initialize` and handle any exception it throws. Then make every configuration call your app needs, such as:

* the token, trace and binding headers, and `setUseApproovStatusIfNoToken`
* substitution headers
* exclusion regular expressions
* the service mutator, and so message signing
* the logging level

Until your configuration calls run, requests use the defaults.

```java
ApproovService.initialize(getApplicationContext(), "<your-approov-account-id>");
ApproovService.setServiceMutator(ApproovServiceMutator.ALWAYS_PROCEED);
```

Configure immediately after `initialize`, before the app sends protected requests. The [README](README.md#initializing) shows where to call `initialize`.

Each `initialize` that succeeds resets these settings to their defaults:

* the token, trace and binding headers
* `setUseApproovStatusIfNoToken` and the deprecated `setProceedOnNetworkFail`
* the substitution headers and the exclusions
* the service mutator, and so any message signing

It also clears `getLastARC()`. It keeps the logging level. Any other setting made before `initialize` is lost. A repeat call with the same account ID and comment returns at once, but it also resets the configuration.

Two kinds of `initialize` change nothing. The first has an empty account ID after protection is on, and the package ignores it. The second is one that the SDK rejects, for example a repeat call with a different account ID or a different comment. The SDK then throws `IllegalStateException`, which reaches your code.

When the SDK initializes, `initialize` logs `initialize: Approov protection enabled` at `INFO`. When the SDK was already initialized with the same account ID and comment, it logs `initialize: Approov SDK already initialized with the same config and comment` at `DEBUG`.

## Token binding

[Token binding](https://docs.approov.io/backend-integration/token-binding/) ties the Approov token to the value of a header on the request, typically an OAuth `Authorization` header. A token then cannot be replayed with different credentials.

There is no binding header by default. Set one when your requests carry a credential header, such as an OAuth `Authorization` header, whose value changes rarely, such as a long-lived OAuth token. Each new value makes the package fetch a new token from the Approov service. The SDK hashes the value on the device. It never sends the value to the Approov cloud service.

```java
ApproovService.setBindingHeader("Authorization");
```

For each request that carries the binding header, `addApproov` gives the header value to the SDK and then fetches the token. Do not call `setDataHashInToken` while your app also uses a binding header, as that can bind a token to the wrong value.

The call logs `setBindingHeader <name>` at `DEBUG` under the `ApproovService` tag, and the token your backend receives carries the `pay` claim.

## Secure strings

[Secure strings](https://docs.approov.io/backend-integration/secure-strings/) let you remove API keys and other secrets from your app. An app that passes attestation receives them at runtime from the Approov service. You put a placeholder in a request header, and the package replaces it with the secret before it sends the request.

By default there are no substitution headers, so a secure string placeholder goes out unchanged. Register the headers whose values are secure string keys.

```java
ApproovService.addSubstitutionHeader("Api-Key", null);              // whole value is the key
ApproovService.addSubstitutionHeader("Authorization", "Bearer ");   // value after the prefix is the key
```

The package substitutes these headers on requests to your token-protected API domains and to your secrets-only API domains. A secrets-only API has no token header. Call `addSubstitutionHeader` after an `initialize` with your account ID. Before that, and in bypass mode, it does nothing.

If a value's secure string fetch fails, the header keeps the value that your app set, and the request goes ahead. The package logs `Substituting header: <header>, <status>` at `DEBUG` under the `ApproovService` tag, so set the logging level to `DEBUG` to see the reason (see [Diagnostics](#diagnostics)).

The package does not substitute query parameters, because the URL of an `HttpsURLConnection` cannot change after `openConnection`. Fetch the secure string yourself, and build the URL before you open the connection:

```java
String apiKey = ApproovService.fetchSecureString("api_key", null);
URL url = new URL("https://api.example.com/shapes?api_key=" + URLEncoder.encode(apiKey, "UTF-8"));
HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
ApproovService.addApproov(connection);
```

`fetchSecureString` returns `null` if the key is not defined. It throws an `ApproovException` if it cannot fetch the secure string. It can need network access, so do not call it from the UI thread. Do not cache the secure string in your app.

## Excluding URLs

Requests whose URL contains a match for an exclusion regular expression receive no token fetch, no Approov headers and no secure strings. The expression is not anchored, and the package compares it with the full URL, query included. Use `^` and `$` to match the whole URL. The default `handleInterceptorShouldProcessConnection` applies the exclusions, so a mutator that overrides it without calling the default drops them.

There are no exclusions by default. Use them for requests to your API domains that should not fetch a token, such as a health check.

```java
ApproovService.addExclusionURLRegex("^https://api\\.example\\.com/health.*");
```

Pinning still applies to excluded requests on domains added to Approov. An excluded request does not update the pins. Each `initialize` that succeeds resets the exclusions. Call `addExclusionURLRegex` after an `initialize` with your account ID. Before that, and in bypass mode, it does nothing.

`addExclusionURLRegex` logs the expression at `DEBUG`. The package logs an invalid regular expression as an error and adds nothing.

## Connection validation

`addApproov` pins each connection to a domain you added to Approov. It sets a `HostnameVerifier` on the connection, so do not set another one after the call. The verifier first runs the default verifier. It then checks the certificate public keys configured for the domain. For a domain with none defined, it falls back to the Managed Trust Roots.

Pinning is on by default for every domain you added to Approov. A connection that fails the check throws `SSLPeerUnverifiedException`. A certificate that OS trust rejects fails earlier, with `SSLHandshakeException`.

The check uses the certificate chain that your device's trust store accepted. It never uses a certificate the server merely appends. A pin matches the host without regard to case and with one trailing dot ignored.

A domain with no pins of its own and no Managed Trust Roots uses OS trust only, and the package logs a warning. If the SDK cannot supply the pins, the connection continues on OS trust and the package logs one error. Before `initialize` and in bypass mode, the package does not pin.

The verifier checks the pins when a connection opens. So `addApproov` sets `Connection: close` on each pinned request, and each request opens its own connection. If your app sets its own `Connection` header, the package keeps it.

To turn off Approov pinning for some requests, override `handlePinningShouldProcessRequest` in your mutator:

```java
@Override
public boolean handlePinningShouldProcessRequest(HttpURLConnection request) {
    return !request.getURL().getHost().equals("cdn.example.com");
}
```

A failure logs an error under the `ApproovPinVerifier` tag that names the host.

## Redirects

A request that carries a header that the package added, such as the token header or a secure string, does not follow redirects by itself. Otherwise the platform sends those headers to the new location. Your app receives the redirect response. To follow it, read the `Location` header and send a new request to that URL with `addApproov`. The package then adds only what is correct for the new location. A request without such headers follows redirects as before.

## Service mutators

A service mutator, an `ApproovServiceMutator`, is the object that holds the package's decisions, such as whether a failed token fetch fails the request. It has one method for each decision, and the package asks the installed mutator at each decision point. The standard mutators and their decisions are in [What happens by default](#what-happens-by-default).

Write your own mutator when your app needs a decision that the standard ones do not make. Every method has a default, so override only what you need. A mutator of your own that should never abort a request delegates the token decisions to `ApproovServiceMutator.ALWAYS_PROCEED`. A mutator you install, at any time, applies only to requests that you prepare after the call. Install it after `initialize`.

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

The package's signer is also a mutator. To combine it with decisions of your own, see [Message signing](#message-signing).

The hooks:

| Hook | Decides |
| :--- | :--- |
| `handleInterceptorShouldProcessConnection` | whether a request receives Approov processing at all (by default, every request that is not excluded) |
| `handleInterceptorFetchTokenResult` | given the token fetch result, whether to send the request with its Approov headers, send it without them, or abort it |
| `handleInterceptorHeaderSubstitutionResult` | whether to apply a secure string substitution |
| `handleInterceptorProcessedRequest` | final changes to the processed request. The signer signs here, so a mutator that calls it makes its own changes first |
| `handlePinningShouldProcessRequest` | whether Approov pinning (Managed Trust Roots or configured public keys) applies to a request |
| `handlePrecheckResult`, `handleFetchTokenResult`, `handleFetchSecureStringResult`, `handleFetchCustomJWTResult` | how the direct methods turn a result into an exception |

`handleInterceptorProcessedRequest` cannot change or remove the token header or the trace header that the package set. The package puts them back and logs a warning once per process.

## Diagnostics

The package writes a diagnostic line for each token fetch.

The package writes these lines at debug level, which is off by default (see [setLoggingLevel](REFERENCE.md#setlogginglevel)).

To write them, set the level in a debug build:

```java
ApproovService.setLoggingLevel(ApproovLogLevel.DEBUG);
```

Or enable debug logging for the `ApproovService` tag, with no rebuild. This works on any installed build, including a release one. It raises any level except `OFF` to `DEBUG`, for all of the package's tags. It lasts until you set it back or the device reboots:

```sh
adb shell setprop log.tag.ApproovService DEBUG
```

The package never logs a token. For each request it processes, it logs the [loggable form](https://docs.approov.io/core-concepts/approov-tokens/architecture-and-security/#loggable-tokens) of the result in a `Token for <url>` line, under the `ApproovService` tag. Its `arc` claim, the [Attestation Response Code](https://docs.approov.io/app-integration/frontend/attestation/#attestation-response-code), tells why attestation gave that result. The direct methods, such as `fetchToken`, log only the status.

The URL in the line is the request URL without its user info, query or fragment. So the package logs no query value, such as a secure string or personal data.

Before you add your API domains to Approov, the line shows `UNKNOWN_URL`. `addApproov` then adds no Approov headers, but the SDK still contacts the Approov service.

`getLastARC()` returns the Attestation Response Code of the most recent token, secure string or custom JWT fetch. It does not fetch. It returns an empty string if there is no ARC.

To find the reasons behind an `arc`, see [decoding an Attestation Response Code](https://docs.approov.io/app-integration/frontend/attestation/#decoding-an-attestation-response-code). Your account's [metrics](https://docs.approov.io/operations/metrics-graphs/grafana-overview/) show the same results in aggregate. A [development signing certificate](https://docs.approov.io/operations/app-signing-certificates/development-and-testing/#development-app-signing-certificates) lets debug builds and emulators pass attestation.
