# Approov Package for HttpsURLConnection

![Java](https://img.shields.io/badge/Java-8%2B-007396?logo=openjdk&logoColor=white)
![Android](https://img.shields.io/badge/Android-minSdk%2023-3DDC84?logo=android&logoColor=white)
![Maven Central](https://img.shields.io/maven-central/v/io.approov/service.httpsurlconn?logo=apachemaven&logoColor=white&label=Maven%20Central)
![Message Signing](https://img.shields.io/badge/Message%20Signing-RFC%209421-1f6feb)
![Build](https://github.com/approov/approov-service-httpsurlconn/actions/workflows/build_only.yml/badge.svg)

This package adds [Approov](https://www.approov.io) to an Android app that uses `HttpsURLConnection`. After you initialize it, a call to `addApproov` adds an Approov token to each request that your app sends to your API domains. The token, a signed JWT, provides proof of attestation. Your backend checks it to decide whether to accept or reject the request. A valid token shows that the request came from a genuine, unmodified copy of your app on a device that passed Approov's checks.

The package also checks the TLS connection to each of your API domains. A request goes ahead only if both the operating system and the pins in your Approov account trust the connection. A domain with no pins of its own uses the [Managed Trust Roots](https://docs.approov.io/security-configuration/dynamic-pinning/#managed-trust-roots). [Connection validation](ADVANCED.md#connection-validation) has the details.

## BEFORE YOU START

You need:

* an Approov account, trial or paid, and its [account ID](#your-account-id)
* your API domains [added to Approov](https://docs.approov.io/getting-started/add-api-domains/). The package adds a token only to requests to these domains.

Then follow the steps below. Each step makes the next one possible:

1. [Add the dependency](#adding-the-dependency). This gives your app `ApproovService`.
2. [Initialize](#initializing) `ApproovService` with your account ID. This turns on Approov protection.
3. [Make your requests](#making-requests) with a call to `addApproov` on each connection. Your requests to your API domains then carry a token.
4. [Look in the debug log](ADVANCED.md#diagnostics) to see that each request receives a token.
5. [Register your app and check tokens on your backend](#next-steps). Until your backend checks the token, your API is not protected.

The [Shapes App Example](https://github.com/approov/quickstart-android-java-httpsurlconn/blob/master/SHAPES-EXAMPLE.md) gives a step-by-step tutorial. Optional features are in [ADVANCED.md](ADVANCED.md). Every method is in [REFERENCE.md](REFERENCE.md).

## ADDING THE DEPENDENCY

Make sure `mavenCentral()` is in your repositories. Then add the package to your app's Gradle dependencies:

```groovy
implementation("io.approov:service.httpsurlconn:3.7.0")
```

The package needs core library desugaring. Turn it on in the `build.gradle` file of your app module:

```groovy
android {
    compileOptions {
        coreLibraryDesugaringEnabled true
    }
}

dependencies {
    coreLibraryDesugaring 'com.android.tools:desugar_jdk_libs:2.1.4'
}
```

Without these two lines, the Gradle build of your app fails with an AAR metadata error.

The package supports Android 6.0 (API level 23) and later. It depends on the closed-source [Approov SDK](https://central.sonatype.com/artifact/io.approov/approov-android-sdk) 3.7.0. The Approov SDK needs OkHttp at run time, so the package adds OkHttp to your app. The package does not send your requests with OkHttp.

Add these permissions to your app manifest:

```xml
<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
<uses-permission android:name="android.permission.INTERNET" />
```

If your app targets Android 11 (API level 30) or later, read [this section](https://approov.io/docs/latest/approov-usage-documentation/#targeting-android-11-and-above) of the reference documentation.

Next, [initialize the package](#initializing).

## INITIALIZING

Initialize `ApproovService` once, when your app starts, with your Approov account ID. Do this in the `onCreate` method of your `Application` class. If your app calls `addApproov` before `initialize`, the call throws `ApproovException`.

```java
import android.util.Log;
import io.approov.service.httpsurlconn.ApproovService;

public class YourApp extends Application {
    @Override
    public void onCreate() {
        super.onCreate();
        try {
            // your Approov account ID, from your onboarding email or "approov sdk -getConfigString"
            ApproovService.initialize(getApplicationContext(), "<your-approov-account-id>");
            if (ApproovService.isApproovServiceEnabled() && ApproovService.isApproovProtectionEnabled())
                Log.i("YourApp", "Approov initialized; deviceID=" + ApproovService.getDeviceID());
        } catch (Exception e) {
            // the value passed was not a valid account ID; run without Approov rather than not at all
            Log.e("YourApp", "Approov account ID rejected; starting in bypass mode", e);
            ApproovService.initialize(getApplicationContext(), "");
        }
        // then configure, after initialize (which resets the configuration) and before the
        // app issues protected requests; only the settings your app uses, for example:
        // ApproovService.setTokenHeader("Authorization", "Bearer ");
        // ApproovService.addSubstitutionHeader("Api-Key", null);
    }
}
```

About this example:

* `initialize` throws if the SDK rejects the account ID. The `catch` block then starts the package in **bypass mode**, by initializing with `""`. In bypass mode, `addApproov` sends requests without Approov protection. You can also use bypass mode as a feature flag: initialize with `""` to start your app without Approov.
* Logging the installation device ID is optional. Approov identifies an installation only by its device ID. Log it next to your own user or session ID for correlation.
* Make your configuration calls after `initialize`, before the app sends protected requests. Each `initialize` resets the configuration to its defaults, so the package loses a setting made before it. A setting applies only to requests that you prepare after you make it. See [initialize, then configure](ADVANCED.md#initialize-then-configure).

### Your account ID

Your account ID is in your onboarding email. The Approov CLI also gives it at any time, and calls it the SDK config string:

```sh
approov sdk -getConfigString
```

The account ID is the same for every app in your account, and it is not a secret. You can keep it in your source code or deliver it with your app's configuration. The whole value must reach the app unchanged, including its punctuation.

If the account ID is not available when the app starts, initialize with `""` first. Call `initialize` again when you have the account ID. See [bypass initialization](ADVANCED.md#bypass-initialization).

After you initialize the package, [make your requests](#making-requests) with `addApproov`.

## MAKING REQUESTS

Call `addApproov` on each `HttpsURLConnection` that you want to protect. Make the call after you set the request method and headers, and before you connect:

```java
HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
ApproovService.addApproov(connection);
```

An `HttpsURLConnection` sends one request only. For a retry, open a new connection and call `addApproov` again, so that the request has a current token.

For a request to an API domain that you added to Approov, the call adds the `Approov-Token` header and pins the connection. It also substitutes the header values that you registered as [secure strings](ADVANCED.md#secure-strings). An Approov error throws an `ApproovException`, which is an `IOException`.

Use the method that suits the request:

| Method | Use it for |
| :--- | :--- |
| `addApproov(connection)` | a request with no body to sign, such as a `GET` |
| `addApproov(connection, body)` | a request whose body you have as a `byte[]`, so that a message signature covers the body |
| `addApproovToConnection(connection)` | a `POST`, `PUT` or `PATCH` request, or one with `setDoOutput(true)`, when you write the body to the output stream |

`addApproov(connection)` and `addApproov(connection, body)` change the connection in place. They make the message signature immediately, so set every header that you want signed before the call.

`addApproovToConnection` returns the connection to use for the request. For a request with a body, it returns a new connection. This connection holds the body in memory, and signs the request just before it sends it. Set the request method before the call. Write the body to the returned connection, and read the response from it:

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

For any other request, `addApproovToConnection` returns the connection that you passed in.

## CUSTOMIZING THE BEHAVIOUR

[ADVANCED.md](ADVANCED.md) explains how the package behaves and how to customize it:

* [What each request carries](ADVANCED.md#what-each-request-carries), and [what happens when a token fetch fails](ADVANCED.md#what-happens-by-default). By default, a request fails if the device has a network problem. It goes ahead with an empty token header if the app cannot reach the Approov service.
* [Service mutators](ADVANCED.md#service-mutators), which change those decisions. For example, a mutator can send requests without a valid token. It can also fail a request on chosen errors. Your app then receives an `ApproovException` and decides what to do, for example retry or show a message.
* [Message signing](ADVANCED.md#message-signing), which you install with one call, for example `ApproovDefaultMessageSigning.combined(ApproovServiceMutator.ALWAYS_PROCEED)`
* [Header names](ADVANCED.md#header-names), [secure strings](ADVANCED.md#secure-strings), [token binding](ADVANCED.md#token-binding) and [excluded URLs](ADVANCED.md#excluding-urls)
* [Redirects](ADVANCED.md#redirects), which your app follows itself for a request that carries an Approov header
* [Diagnostics](ADVANCED.md#diagnostics), which show the result of each token fetch in the log

Then continue with the [next steps](#next-steps).

## NEXT STEPS

1. [Register your app's signing certificate](https://docs.approov.io/getting-started/add-app-signing-certificates/), so that your release builds pass attestation.
2. [Check tokens on your backend](https://docs.approov.io/getting-started/integrate-backend/), and signatures if you installed message signing. This is the step that protects your API.
3. [Go live](https://docs.approov.io/getting-started/go-live/). Monitor first, then let your backend reject requests without a valid token.

To remove app secrets, such as API keys for third-party services, from your released app, see [secrets protection](https://github.com/approov/quickstart-android-java-httpsurlconn/blob/master/SECRETS-PROTECTION.md).

## UPGRADING FROM 3.5.x

Read the [changelog](CHANGELOG.md) for the full list of changes. Test your app and backend together.

### Code changes

* `initialize` resets the configuration each time it runs, and no longer compares account IDs itself. Make your configuration calls after `initialize`. A `null` context now throws `IllegalArgumentException`, also in bypass mode.
* The message signing helper classes moved. Change imports of `io.approov.util.sig.*` to `io.approov.util.httpsurlconn.sig.*`, and `io.approov.util.http.sfv.*` to `io.approov.util.httpsurlconn.http.sfv.*`.
* A `SignatureParametersFactory` subclass that sets `useAccountMessageSigning = true` directly now produces both the install and the account signature. To keep the account signature only, call `setUseAccountMessageSigning()` instead. The factory no longer sets the algorithm on the parameters. A subclass that needs one signature only sets the algorithm on the parameters that it returns.
* This release removes `prefetch()`. Remove your calls to it. The SDK does the prefetch itself.
* A request that carries a header that the package added no longer follows redirects by itself. If your app relies on redirects, read the `Location` header of a redirect response and send a new request with `addApproov`. See [redirects](ADVANCED.md#redirects).

If you upgrade from a release before 3.5.7, also remove your calls to the query parameter substitution methods, which 3.5.7 removed. See [secure strings](ADVANCED.md#secure-strings).
