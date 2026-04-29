# Usage

This document describes the features and functionality of the Approov Service for `HttpsURLConnection`. It provides details on how to interact with the service layer and customize its behavior to suit your application's needs, specifically through the `ApproovServiceMutator`. For a basic integration example, please refer to the [Quickstart guide](https://github.com/approov/quickstart-android-java-httpsurlconn/blob/master/README.md).

# Approov Service Mutator

The `ApproovServiceMutator` allows you to customize the behavior of the Approov `HttpsURLConnection` layer at key points in request preparation. You can override specific methods to tailor the handling of attestations and requests while retaining the default behavior for other cases.

## Why use a mutator

- Centralize app-specific policy without forking the service layer.
- Add telemetry on rejections or network failures.
- Skip Approov processing for health checks or local endpoints.
- Customize pinning decisions per request.
- Adjust behavior when token or secure string fetches fail.

## Default behavior

By default, the `ApproovService` prepares requests based on the attestation status. It relies on the underlying SDK to provide a proof of attestation, which is a cryptographically signed JWT token. Requesting this attestation typically returns the token immediately; however, a network connection to the Approov cloud is required upon app launch or when the token is nearing expiration. Note that the SDK only knows if an attestation token has been obtained; it cannot determine if the token is valid, because validity is checked by your backend. The default behavior is described in more detail in the official documentation section [Approov Token Fetch Results](https://approov.io/docs/latest/approov-usage-documentation/#approov-token-fetch-results) and is summarized in the table below:

| Approov Fetch Status | Action | Result |
| :--- | :--- | :--- |
| **Success** | Proceed | The request is sent with the `Approov-Token`. |
| **No Network / Poor Network** | Throw Exception | An `ApproovNetworkException` is thrown. The request should be retried. |
| **Rejection** | Throw Exception | An `ApproovRejectionException` is thrown. The request is marked as rejected. |
| **No Approov Service / Unknown URL / Unprotected URL** | Proceed | The request is sent without an `Approov-Token`. |

## Customizing request handling with mutators

You may want to modify this behavior to suit specific app requirements. A common use case is handling `NO_APPROOV_SERVICE` statuses differently.

### Prevent access without a token

The standard behavior for statuses like `NO_APPROOV_SERVICE` is to proceed with the request without adding an Approov token. This might occur, for example, if a device cannot connect to the Approov cloud due to a restricted network environment. You may wish to prevent this behavior to ensure that only requests with valid proof of attestation reach your backend API, allowing you to explicitly handle this case within your application.

You can use a mutator to enforce this policy by throwing an error for such statuses.

```java
import com.criticalblue.approovsdk.Approov;

import io.approov.service.httpsurlconn.ApproovNetworkException;
import io.approov.service.httpsurlconn.ApproovServiceMutator;

public class EnforceTokenMutator implements ApproovServiceMutator {
    @Override
    public boolean handleInterceptorFetchTokenResult(Approov.TokenFetchResult approovResults, String url)
            throws io.approov.service.httpsurlconn.ApproovException {
        if (approovResults.getStatus() == Approov.TokenFetchStatus.NO_APPROOV_SERVICE) {
            throw new ApproovNetworkException(
                    approovResults.getStatus(),
                    "Network issue. Will attempt connection again."
            );
        }
        return ApproovServiceMutator.DEFAULT.handleInterceptorFetchTokenResult(approovResults, url);
    }
}
```

### Allow access without a token

Conversely, if the device could not obtain proof of attestation, for example because of a `POOR_NETWORK` or `NO_NETWORK` response from the SDK, the default behavior is to cancel the request to your API. However, you might prefer to let the request attempt the connection to your backend without the Approov token to allow for server-side handling.

To implement this, check for `POOR_NETWORK` and return `false`, which proceeds without adding the token.

```java
if (approovResults.getStatus() == Approov.TokenFetchStatus.POOR_NETWORK) {
    return false;
}
```

### Add custom headers using a mutator

You can override `handleInterceptorProcessedRequest` to add additional headers or modify the request after Approov has processed it. This is useful for adding app metadata or other diagnostics.

```java
import javax.net.ssl.HttpsURLConnection;

import io.approov.service.httpsurlconn.ApproovRequestMutations;
import io.approov.service.httpsurlconn.ApproovServiceMutator;

public class MyMutator implements ApproovServiceMutator {
    private final ApproovServiceMutator signer = ApproovServiceMutator.DEFAULT;

    @Override
    public HttpsURLConnection handleInterceptorProcessedRequest(
            HttpsURLConnection request,
            ApproovRequestMutations changes
    ) throws io.approov.service.httpsurlconn.ApproovException {
        HttpsURLConnection processed = signer.handleInterceptorProcessedRequest(request, changes);
        processed.setRequestProperty("Client-Platform", "android");
        return processed;
    }
}
```

## How to use a custom mutator in your application

Create a mutator, then install it once during app startup, for example in your `Application` class or initialization path.

```java
import io.approov.service.httpsurlconn.ApproovService;
import io.approov.service.httpsurlconn.ApproovServiceMutator;

public final class Example {
    public static void install() {
        ApproovService.setServiceMutator(new MyMutator());
    }
}
```

## Preparing `HttpsURLConnection` requests

Requests are prepared by passing a connection through `ApproovService.addApproovToConnection(...)` before the request is sent:

```java
URL url = new URL("https://api.example.com/shapes");
HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
connection.setRequestMethod("GET");
connection = ApproovService.addApproovToConnection(connection);
```

You should always continue using the returned connection reference. In the common case this is the same instance that you passed in. If configured query substitutions change the effective URL then a wrapped connection is returned.

If you need to substitute configured query parameters before opening the connection, you can do so explicitly:

```java
URL url = new URL("https://api.example.com/shapes?api_key=shapes-key");
URL substitutedUrl = ApproovService.substituteQueryParams(url);
HttpsURLConnection connection = (HttpsURLConnection) substitutedUrl.openConnection();
connection = ApproovService.addApproovToConnection(connection);
```

## Message signing

It is possible to sign HTTP requests using Approov to ensure message integrity and authenticity. There are two types of message signing available:

1. [Installation Message Signing](https://ext.approov.io/docs/latest/approov-usage-documentation/#installation-message-signing): Uses an installation-specific key held by the device to sign requests.
2. [Account Message Signing](https://ext.approov.io/docs/latest/approov-usage-documentation/#account-message-signing): Uses a shared account-specific secret key delivered to the SDK only upon successful attestation.

Message signing is not enabled unless you opt in. Even if you install `ApproovDefaultMessageSigning`, a signature is only added when:

- The request already has an `Approov-Token` header, meaning Approov processing ran.
- A `SignatureParametersFactory` is configured for the request host.

### Enable with default settings

```java
import io.approov.service.httpsurlconn.ApproovDefaultMessageSigning;
import io.approov.service.httpsurlconn.ApproovService;

ApproovDefaultMessageSigning.SignatureParametersFactory factory =
        ApproovDefaultMessageSigning.generateDefaultSignatureParametersFactory();
ApproovDefaultMessageSigning signer =
        new ApproovDefaultMessageSigning().setDefaultFactory(factory);
ApproovService.setServiceMutator(signer);
```

### Customize behavior

```java
import io.approov.service.httpsurlconn.ApproovDefaultMessageSigning;

ApproovDefaultMessageSigning.SignatureParametersFactory factory =
        ApproovDefaultMessageSigning.generateDefaultSignatureParametersFactory()
                .setUseAccountMessageSigning()
                .setAddCreated(true)
                .setExpiresLifetime(60);

ApproovDefaultMessageSigning signer = new ApproovDefaultMessageSigning()
        .setDefaultFactory(factory)
        .putHostFactory("api.example.com", factory);

ApproovService.setServiceMutator(signer);
```

Account message signing must also be enabled on the Approov account before the
SDK can generate account signatures. See the Approov CLI documentation for the
`approov secret -messageSigningKey change` command.

To disable signing, remove the signer using `setServiceMutator(null)`, or return `null` from your factory for hosts you want to skip.

## Token binding

[Token Binding](https://ext.approov.io/docs/latest/approov-usage-documentation/#token-binding) allows you to bind the Approov token to a specific piece of data, such as an OAuth token or user session identifier. The `ApproovService` calculates a hash of the binding data locally and includes this hash in the Approov token claims. The actual binding data is never sent to the Approov cloud service; only the hash is transmitted.

To set up token binding, specify a header name. The value of this header in your requests will be used for the binding.

```java
ApproovService.setBindingHeader("Authorization");
```

If the value of the binding header changes, the SDK automatically invalidates the current Approov token and fetches a new one with the updated binding on the next request.

## Real-world example

This example demonstrates how to customize `ApproovServiceMutator` to apply different options to requests based on hostname.

```java
import java.net.URI;
import java.util.Set;

import javax.net.ssl.HttpsURLConnection;

import com.criticalblue.approovsdk.Approov;

import io.approov.service.httpsurlconn.ApproovDefaultMessageSigning;
import io.approov.service.httpsurlconn.ApproovRequestMutations;
import io.approov.service.httpsurlconn.ApproovServiceMutator;

public class CustomLogic implements ApproovServiceMutator {
    private final ApproovServiceMutator signer = new ApproovDefaultMessageSigning();
    private final Set<String> protectedHosts = Set.of("api.example.com");
    private final Set<String> allowOfflineForHosts = Set.of("status.example.com");
    private final Set<String> skipPinningHosts = Set.of("metrics.example.com");

    @Override
    public boolean handleInterceptorShouldProcessConnection(HttpsURLConnection request)
            throws io.approov.service.httpsurlconn.ApproovException {
        String host = request.getURL().getHost();
        if (!protectedHosts.contains(host)) {
            return false;
        }
        return ApproovServiceMutator.DEFAULT.handleInterceptorShouldProcessConnection(request);
    }

    @Override
    public boolean handleInterceptorFetchTokenResult(Approov.TokenFetchResult approovResults, String url)
            throws io.approov.service.httpsurlconn.ApproovException {
        String host = URI.create(url).getHost();
        if ((approovResults.getStatus() == Approov.TokenFetchStatus.NO_NETWORK
                || approovResults.getStatus() == Approov.TokenFetchStatus.POOR_NETWORK)
                && allowOfflineForHosts.contains(host)) {
            return false;
        }
        return ApproovServiceMutator.DEFAULT.handleInterceptorFetchTokenResult(approovResults, url);
    }

    @Override
    public HttpsURLConnection handleInterceptorProcessedRequest(
            HttpsURLConnection request,
            ApproovRequestMutations changes
    ) throws io.approov.service.httpsurlconn.ApproovException {
        HttpsURLConnection processed = signer.handleInterceptorProcessedRequest(request, changes);
        processed.setRequestProperty("X-Client-Platform", "android");
        return processed;
    }

    @Override
    public boolean handlePinningShouldProcessRequest(java.net.HttpURLConnection request) {
        String host = request.getURL().getHost();
        return !skipPinningHosts.contains(host);
    }
}
```

## Tips

- Keep mutator logic fast and side-effect safe. These hooks run on the request path.
- Use `ApproovServiceMutator.DEFAULT` to preserve the existing behavior and layer your changes on top.
- If you override multiple hooks, keep them focused so they remain easy to test and maintain.
