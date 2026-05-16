# Usage

This document describes the features and functionality of the Approov Service for HttpsUrlConnection. It provides details on how to interact with the service layer and customize its behavior to suit your application's needs, specifically through the `ApproovServiceMutator`. For a basic integration example, please refer to the [Quickstart guide](https://github.com/approov/quickstart-android-java-httpsurlconn).

## Empty Config Initialization
You can initialize the `ApproovService` with an empty configuration string if you want to use the service layer without active Approov protection. This is useful for apps that remotely activate Approov selectively or when you need the service to function without any Approov processing (e.g., during backend maintenance).

> ```java
> // Initialize with an empty string to bypass Approov processing
> ApproovService.initialize(context, "");
> ```

When initialized this way, calling `connection = ApproovService.addApproov(connection)` performs no operations. It will not perform token injection, message signing, secure string substitution, or dynamic pinning. You can enable full Approov protection later in the application lifecycle by calling `ApproovService.initialize(context, config)` with a valid configuration string.

# Approov Service Mutator

The `ApproovServiceMutator` allows you to customize the behavior of the Approov HttpsUrlConnection layer at key points in the request lifecycle. You can override specific methods to tailor the handling of attestations and requests while retaining the default behavior for other cases.

## Why use a mutator

- Centralize app-specific policy without forking the service layer.
- Add telemetry on rejections or network failures.
- Skip Approov processing for health checks or local endpoints.
- Customize pinning decisions per request.
- Adjust behavior when token or secure string fetches fail.

## Default Behavior

By default, the `ApproovService` processes requests based on the attestation status. It relies on the underlying SDK to provide a proof of attestation, which is a cryptographically signed JWT token. Requesting this attestation typically returns the token immediately; however, a network connection to the Approov cloud is required upon app launch or when the token is nearing expiration. Note that the SDK only knows if an attestation token has been obtained; it cannot determine if the token is valid (validity is checked by your backend). The default behavior is described in more detail in the official documentation section [Approov Token Fetch Results](https://approov.io/docs/latest/approov-usage-documentation/#approov-token-fetch-results) and is summarized in the table below:

| Approov Fetch Status | Action | Result |
| :--- | :--- | :--- |
| **Success** | Proceed | The request acts as expected and is sent with the `Approov-Token`. |
| **No Network / Poor Network / MITM Detected** | Throw Exception | An `ApproovNetworkException` is thrown. The request should be retried. |
| **Rejection** | Throw Exception | An `ApproovRejectionException` is thrown. The request is marked as rejected. |
| **No Approov Service / Unknown URL** | Proceed | The request is sent **without** an `Approov-Token`. |

## Customizing Request Handling with Mutators

You may want to modify this behavior to suit specific app requirements. A common use case is handling `NO_APPROOV_SERVICE` statuses.

### Prevent Access Without a Token (e.g. NO_APPROOV_SERVICE)

The standard behavior for statuses like `NO_APPROOV_SERVICE` is to proceed with the request without adding an Approov token. This might occur, for example, if a device cannot connect to the Approov cloud due to a restricted network environment. You may wish to prevent this behavior to ensure that *only* requests with valid proof of attestation reach your backend API, allowing you to explicitly handle this case within your application.

You can use a mutator to enforce this policy by throwing an error or returning `false` for such statuses.

### Example: Proceed on Selected Failure Statuses

The example below shows a custom mutator that:
- Uses the normal Approov token flow on `SUCCESS`.
- Allows requests to continue on `MITM_DETECTED` and `NO_APPROOV_SERVICE`.
- Signs the final outbound request with `ApproovDefaultMessageSigning`.

To send the failure reason in the token header when the request is allowed to continue without a real token, you must also enable `setUseApproovStatusIfNoToken(true)` as shown in the next section.


> ```java
> import com.criticalblue.approovsdk.Approov;
> import io.approov.service.httpsurlconn.ApproovDefaultMessageSigning;
> import io.approov.service.httpsurlconn.ApproovException;
> import io.approov.service.httpsurlconn.ApproovService;
> import io.approov.service.httpsurlconn.ApproovServiceMutator;
> 
> public class ProceedOnSelectedStatusesMutator extends ApproovDefaultMessageSigning {
> 
>     @Override
>     public boolean handleInterceptorFetchTokenResult(Approov.TokenFetchResult result, String url) throws ApproovException {
>         Approov.TokenFetchStatus status = result.getStatus();
> 
>         // Allow SUCCESS, MITM_DETECTED and NO_APPROOV_SERVICE to proceed
>         if (status == Approov.TokenFetchStatus.SUCCESS ||
>             status == Approov.TokenFetchStatus.MITM_DETECTED ||
>             status == Approov.TokenFetchStatus.NO_APPROOV_SERVICE) {
>             return true;
>         }
> 
>         // For all other statuses, use the default fail-closed behavior.
>         return super.handleInterceptorFetchTokenResult(result, url);
>     }
> }
> ```

### Allow Access Without Token (Optional)

Conversely, if the device could not obtain proof of attestation, for example because of a `POOR_NETWORK` or `NO_NETWORK` response from the SDK, the default behavior is to cancel the request to your API. However, you might prefer to let the request attempt the connection to your backend without the Approov Token to allow for server-side handling (e.g., returning a custom 401/403).

To implement this, check for `POOR_NETWORK` and return `false`, which proceeds without the token validation (skips adding token).

```java
    if (approovResults.getStatus() == Approov.TokenFetchStatus.POOR_NETWORK) {
        return false; // Proceed without token
    }
```


### Add custom headers using a mutator

You can override `handleInterceptorProcessedRequest` to add additional headers or modify the connection after Approov has processed it. This is useful for adding app metadata or other diagnostics.

```java
import javax.net.ssl.HttpsURLConnection;
import io.approov.service.httpsurlconn.ApproovRequestMutations;
import io.approov.service.httpsurlconn.ApproovServiceMutator;

public class MyMutator implements ApproovServiceMutator {
    // If you are composing with another mutator (like a signer), initialize it here.
    // Otherwise, you can use ApproovServiceMutator.DEFAULT.
    private final ApproovServiceMutator signer = ApproovServiceMutator.DEFAULT;

    /// Called after Approov has already mutated the request (token, substitutions, signing).
    ///
    /// Use this to add *additional* headers or rewrite the connection further. This is also
    /// where message signing should remain in place if you use a signer mutator.
    @Override
    public HttpsURLConnection handleInterceptorProcessedRequest(HttpsURLConnection request,
                                           ApproovRequestMutations changes) {
        HttpsURLConnection req = signer.handleInterceptorProcessedRequest(request, changes);
        // Example: attach app metadata for backend diagnostics or routing.
        req.setRequestProperty("Client-Platform", "android");
        return req;
    }
}
```

## How to use a custom mutator in your application

Register your custom mutator and enable status-to-header injection during app startup:

> ```java
> import io.approov.service.httpsurlconn.ApproovService;
> 
> // 1. Standard Initialization
> ApproovService.initialize(context, "<your-config-string>");
> 
> // 2. Enable status-as-token injection (matches React Native behavior)
> ApproovService.setUseApproovStatusIfNoToken(true);
> 
> // 3. Register your custom mutator logic
> ApproovService.setServiceMutator(new ProceedOnSelectedStatusesMutator());
> ```

## Approov Token Fallback Status

If the SDK cannot obtain a valid Approov token (e.g., due to a `NO_NETWORK` or `MITM_DETECTED` state), the request might proceed without the `Approov-Token` header or fail entirely depending on the current policy. To give your backend visibility into *why* there is no token, you can use `ApproovService.setUseApproovStatusIfNoToken(true)`.

When enabled, the service will inject the Approov fetch status directly into the `Approov-Token` header if the actual token fetch fails or is empty. Your backend can then distinguish between a request that was sent without a token due to an attacker stripping it, versus a legitimate request that encountered a specific failure like `POOR_NETWORK`. 

Please note that this behavior is conditional upon the configuration of your `ApproovServiceMutator`. If your mutator explicitly throws an error or aborts the request entirely for a particular status (for example, throwing an exception on `NO_NETWORK`), the request will never proceed to the server, and this status fallback feature will effectively not be used for that specific case.

## Message signing

It is possible to sign HTTP requests using Approov to ensure message integrity and authenticity. There are two types of message signing available:

1.  [Installation Message Signing](https://ext.approov.io/docs/latest/approov-usage-documentation/#installation-message-signing): Uses an installation-specific key (held in the device's Secure Enclave/TEE) to sign requests. This provides strong non-repudiation as the signing key never leaves the device and is unique to that specific installation.
2.  [Account Message Signing](https://ext.approov.io/docs/latest/approov-usage-documentation/#account-message-signing): Uses a shared account-specific secret key (HMAC-SHA256) to sign requests. This key is delivered to the SDK only upon successful attestation.

**Advantages of Message Signing:**
*   **Integrity:** Ensures that the request parameters (headers, body, URL) have not been tampered with during transit.
*   **Authenticity:** Proves that the request originated from a genuine, attested application instance.

Message signing is not enabled unless you opt in. By default, the `ApproovService` uses the interface `ApproovServiceMutator` default, which does no message signing. Even if you install `ApproovDefaultMessageSigning`, a signature is only added when:

- The request already has an `Approov-Token` header (i.e., Approov processing ran).
- A `SignatureParametersFactory` is configured (default or host-specific).

### Enable with default settings

```java
import io.approov.service.httpsurlconn.ApproovDefaultMessageSigning;
import io.approov.service.httpsurlconn.ApproovService;

ApproovDefaultMessageSigning.SignatureParametersFactory factory = ApproovDefaultMessageSigning.generateDefaultSignatureParametersFactory();
ApproovDefaultMessageSigning signer = new ApproovDefaultMessageSigning().setDefaultFactory(factory);
ApproovService.setServiceMutator(signer);
```

If you have already customized the mutator, you can add message signing to it by composing or delegating.

### Customize behavior

```java
import io.approov.service.httpsurlconn.ApproovDefaultMessageSigning.SignatureParametersFactory;

SignatureParametersFactory factory = new SignatureParametersFactory()
    .setUseAccountMessageSigning() // or setUseInstallMessageSigning()
    .setAddCreated(true)
    .setExpiresLifetime(60);

ApproovDefaultMessageSigning signer = new ApproovDefaultMessageSigning()
    .setDefaultFactory(factory)
    .putHostFactory("api.example.com", factory);

ApproovService.setServiceMutator(signer);
```

To disable signing, remove the signer (`setServiceMutator(null)`) or return `null` from your factory for hosts you want to skip.

### Body Digests and Payload Signing

Because `HttpsURLConnection` natively obscures the outgoing body stream until it's written, the standard `addApproov(connection)` method cannot automatically compute a `Signature-Base-Digest` over your request body payload.

If you require body digest signing (for `POST`, `PUT`, or `PATCH` payloads), you must use the overloaded `addApproov` method, passing in the exact byte payload.

**CRITICAL RULES FOR SIGNING**:
When using message signing, the signature is computed *at the moment* you call `addApproov`. Therefore:
1. **Call `addApproov` LAST**: Only call `addApproov(connection, bodyBytes)` after setting your HTTP method and all application headers (e.g., `Authorization`, `Content-Type`).
2. **Do Not Mutate Later**: Modifying any headers or the HTTP method *after* calling `addApproov` will invalidate the signature on the backend.
3. **Exact Body Match**: You must write the exact same `bodyBytes` to the connection's `OutputStream` afterward.
4. **Content-Length**: If your `SignatureParametersFactory` is configured to sign the `Content-Length` header, you *must* explicitly set the length via `connection.setFixedLengthStreamingMode(bodyBytes.length)` *before* calling `addApproov`. Otherwise, the platform's automatic length calculation later will invalidate the signature.

```java
// 1. Set method and all headers first
connection.setRequestMethod("POST");
connection.setRequestProperty("Content-Type", "application/json");
connection.setRequestProperty("Authorization", auth);

// 2. Prepare the repeatable payload
byte[] bodyBytes = json.getBytes(StandardCharsets.UTF_8);

// 3. (Optional) Set fixed length if you sign Content-Length
// connection.setFixedLengthStreamingMode(bodyBytes.length);

// 4. Call addApproov with the payload
connection = ApproovService.addApproov(connection, bodyBytes);

// 5. Write the exact payload to the stream
connection.getOutputStream().write(bodyBytes);
```

> **Note**: This overload is designed for repeatable/in-memory payloads. It cannot support true streaming or one-shot uploads. If you are streaming large files, you must configure your Approov account to make `Content-Digest` optional and use the standard `addApproov(connection)` method.

## Token Binding

[Token Binding](https://ext.approov.io/docs/latest/approov-usage-documentation/#token-binding) allows you to bind the Approov token to a specific piece of data, such as an OAuth token or a user session identifier. This adds an extra layer of security by ensuring that the Approov token can only be used in conjunction with the bound data. The `ApproovService` calculates a hash of the binding data locally and supplies that hash to Approov so the resulting token can carry the corresponding `pay` claim. It is important to note that the actual binding data is never sent to the Approov cloud service; only the hash is transmitted.

To set up token binding, you specify a header name. The value of this header in your requests will be used for the binding.

### Example: Bind to Authorization Header

```java
// Bind the Approov token to the Authorization header (e.g., for OAuth)
ApproovService.setBindingHeader("Authorization");
```

If the value of the binding header changes (e.g., the user logs in and gets a new OAuth token), the SDK automatically invalidates the current Approov token and fetches a new one with the updated binding on the next request.

## Real-world examples

### Policy-driven mutator (host scoping, offline fallback, message signing, pinning)

This example implementation demonstrates how to customize the `ApproovServiceMutator` to apply different options to API requests based on the hostname.

```java
import java.net.HttpURLConnection;
import java.util.Set;
import java.util.HashSet;
import java.util.Arrays;
import javax.net.ssl.HttpsURLConnection;
import io.approov.service.httpsurlconn.*;
import com.criticalblue.approovsdk.Approov;

public class CustomLogic implements ApproovServiceMutator {
    private final ApproovServiceMutator signer = new ApproovDefaultMessageSigning();
    private final Set<String> protectedHosts = new HashSet<>(Arrays.asList("api.example.com"));
    private final Set<String> allowOfflineForHosts = new HashSet<>(Arrays.asList("status.example.com"));
    private final Set<String> skipPinningHosts = new HashSet<>(Arrays.asList("metrics.example.com"));

    @Override
    public boolean handleInterceptorShouldProcessConnection(HttpsURLConnection request) throws ApproovException {
        String host = request.getURL().getHost();
        if (!protectedHosts.contains(host)) return false;
        return ApproovServiceMutator.DEFAULT.handleInterceptorShouldProcessConnection(request);
    }

    @Override
    public boolean handleInterceptorFetchTokenResult(Approov.TokenFetchResult approovResults, String url) throws ApproovException {
        try {
            String host = new java.net.URI(url).getHost();
            if ((approovResults.getStatus() == Approov.TokenFetchStatus.NO_NETWORK || 
                 approovResults.getStatus() == Approov.TokenFetchStatus.POOR_NETWORK) &&
               allowOfflineForHosts.contains(host)) {
                return false;
            }
        } catch (Exception e) {}
        return ApproovServiceMutator.DEFAULT.handleInterceptorFetchTokenResult(approovResults, url);
    }

    @Override
    public HttpsURLConnection handleInterceptorProcessedRequest(HttpsURLConnection request, ApproovRequestMutations changes) throws ApproovException {
        HttpsURLConnection req = signer.handleInterceptorProcessedRequest(request, changes);
        req.setRequestProperty("X-Client-Platform", "android");
        return req;
    }

    @Override
    public boolean handlePinningShouldProcessRequest(HttpURLConnection request) {
        String host = request.getURL().getHost();
        if (skipPinningHosts.contains(host)) return false;
        return true;
    }
}
```

### Log rejections with ARC + device ID to your telemetry

Monitoring and analyzing rejections is a key part of your security strategy. Ideally, your backend should be customized to include the **ARC (Approov Rejection Code)** and **Device ID** in its error responses (e.g., in a JSON body or a custom header) when it rejects a request due to a missing or invalid Approov token.

#### Why Server-Side Logging is Preferred
While you can obtain these values directly from the SDK using `ApproovService.getLastARC()`, it is generally safer and more reliable to log them from the server response for several reasons:

1.  **Avoid Misleading Network Events**: On poor network connections, a call to `getLastARC()` can inadvertently trigger a background network event that successfully completes a delayed attestation. This might provide an ARC associated with a *successful* attestation that occurred *after* your original request failed, creating confusing telemetry.
2.  **Corporate Firewall & MITM Bypass**: If your custom mutator allows a request to proceed on `MITM_DETECTED` (a common result of corporate firewalls), the request is sent without a token. In this state, `getLastARC()` will not yet have a rejection code available for that specific attempt.
3.  **Accuracy and Correlation**: Logging the ARC that the server actually observed and used as the basis for rejection ensures perfect correlation in your monitoring dashboards.

If you must log from the client, ensure you have a fallback strategy for when the server doesn't provide the code.


> ```java
>         int responseCode = connection.getResponseCode();
>         if (responseCode >= 200 && responseCode < 300) {
>             // Process request
>         } else {
>             // Preferred: Extract ARC and Device ID from your own server's response
>             String serverArc = connection.getHeaderField("X-Approov-Error-ARC");
>             
>             // ALTERNATIVE: (DISCOURAGED) Obtain from SDK only if server-side retrieval is impossible.
>             // Note: This may trigger background network events and return misleading results.
>             String sdkArc = (serverArc != null) ? serverArc : ApproovService.getLastARC();
>             String deviceID = ApproovService.getDeviceID();
>             
>             Log.d("Telemetry", "Request rejected. ARC: " + sdkArc + ", DeviceID: " + deviceID);
>         }
> ```

## Tips

- Keep mutator logic fast and side-effect safe. These hooks run on the request path.
- Use `ApproovServiceMutator.DEFAULT` to preserve the existing behavior and layer your changes on top.
- If you override multiple hooks, keep them focused (one concern per hook) for easier testing and maintenance.
