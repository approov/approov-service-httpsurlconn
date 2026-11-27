# Approov Service for HttpsURLConnection

![Java](https://img.shields.io/badge/Java-8%2B-007396?logo=openjdk&logoColor=white)
![Android](https://img.shields.io/badge/Android-minSdk%2023-3DDC84?logo=android&logoColor=white)
![Maven Central](https://img.shields.io/maven-central/v/io.approov/service.httpsurlconn?logo=apachemaven&logoColor=white&label=Maven%20Central)
![Message Signing](https://img.shields.io/badge/Message%20Signing-RFC%209421-1f6feb)
![Build](https://github.com/approov/approov-service-httpsurlconn/actions/workflows/build_only.yml/badge.svg)

This package adds [Approov](https://www.approov.io) to an Android app that uses `HttpsURLConnection`. After you initialize it, a call to `addApproov` adds an Approov token to each request to your API domains, and pins the connection. The token, a signed JWT, provides proof of attestation. Your backend checks it to decide whether to accept or reject the request.

This page gives the steps to add Approov to your app. A step-by-step tutorial with the [Shapes App Example](https://github.com/approov/quickstart-android-java-httpsurlconn/blob/master/SHAPES-EXAMPLE.md) is also available. [USAGE.md](USAGE.md) describes the optional features, and [REFERENCE.md](REFERENCE.md) describes every method.

To follow this guide, you need a trial or paid Approov account and its account ID, which is in your onboarding email.

## ADDING THE DEPENDENCY

Make sure `mavenCentral()` is in your repositories. Then add the package to your app's Gradle dependencies:

```groovy
implementation("io.approov:service.httpsurlconn:3.7.0")
```

The package needs core library desugaring, so turn it on in the `build.gradle` file of your app module:

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

## MANIFEST CHANGES

Add these permissions to your app manifest:

```xml
<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
<uses-permission android:name="android.permission.INTERNET" />
```

If your app targets Android 11 (API level 30) or later, read [this section](https://approov.io/docs/latest/approov-usage-documentation/#targeting-android-11-and-above) of the reference documentation.

## INITIALIZING APPROOV SERVICE

Initialize `ApproovService` once, when your app starts, with your Approov account ID. Do this in the `onCreate` method of your `Application` class:

```Java
import android.util.Log;
import io.approov.service.httpsurlconn.ApproovService;

public class YourApp extends Application {
    @Override
    public void onCreate() {
        super.onCreate();
        try {
            // your Approov account ID, from your onboarding email or "approov sdk -getConfigString"
            ApproovService.initialize(getApplicationContext(), "<your-approov-account-id>");
            if (ApproovService.isApproovProtectionEnabled())
                Log.i("YourApp", "Approov initialized; deviceID=" + ApproovService.getDeviceID());
        } catch (Exception e) {
            // the value passed was not a valid account ID; run without Approov rather than not at all
            Log.e("YourApp", "Approov account ID rejected; starting in bypass mode", e);
            ApproovService.initialize(getApplicationContext(), "");
        }
        // then configure, after initialize (which resets the configuration), for example:
        // ApproovService.setTokenHeader("Authorization", "Bearer ");
        // ApproovService.addSubstitutionHeader("Api-Key", null);
    }
}
```

About this example:

* `initialize` throws if the SDK rejects the account ID. The `catch` block then starts the package in **bypass mode**, with an empty account ID `""`. In bypass mode, `addApproov` sends requests without Approov protection.
* Each `initialize` resets the configuration to its defaults. Make your configuration calls after it. See [initialize, then configure](USAGE.md#initialize-then-configure).
* Logging the device ID is optional. Log it next to your own user or session ID to correlate an installation with your backend logs.

## USING APPROOV SERVICE

Call `addApproov` on each `HttpsURLConnection` just before your app sends the request:

```Java
HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
ApproovService.addApproov(connection);
```

> **NOTE:** Make this call immediately before the request, and inside any retry loop. This makes sure that each request has a current Approov token.

For an API domain that you added to Approov, this adds the `Approov-Token` header and pins the connection. It also substitutes the header values that you registered for [secure strings](USAGE.md#secure-strings). For a request with a body that you want to sign, use `addApproov(connection, body)` or `addApproovToConnection(connection)`. See [adding Approov to a request](USAGE.md#adding-approov-to-a-request).

An Approov error throws an `ApproovException`, which is an `IOException`. A call to `addApproov` before `initialize` also throws `ApproovException`.

## CHECKING IT WORKS

Initially you have not added API domains to Approov, so `addApproov` adds nothing. But it calls Approov, and the SDK contacts the Approov cloud service. To see the result of each token fetch, set the logging level to `DEBUG`:

```Java
ApproovService.setLoggingLevel(ApproovLogLevel.DEBUG);
```

The package then logs a `Token for <url>` line for each request under the `ApproovService` tag. Before you add your API domains, the line shows `UNKNOWN_URL`. See [logging and diagnostics](USAGE.md#logging-and-diagnostics).

Your Approov onboarding email has a link to the [Live Metrics Graphs](https://approov.io/docs/latest/approov-usage-documentation/#metrics-graphs). After you run your app with Approov, the results show in the live metrics within a minute or so.

## NEXT STEPS

To protect your APIs or secrets, do some further steps. Approov gives two options for protection:

* [API PROTECTION](https://github.com/approov/quickstart-android-java-httpsurlconn/blob/master/API-PROTECTION.md): Use this if you control the backend APIs and can change them to check the Approov token that the app sends. An [Approov Token](https://approov.io/docs/latest/approov-usage-documentation/#approov-tokens) is a short-lived, signed JWT that proves the request came from a genuine app.

* [SECRETS PROTECTION](https://github.com/approov/quickstart-android-java-httpsurlconn/blob/master/SECRETS-PROTECTION.md): Use this to remove app secrets, such as API keys for 3rd party services, from the code of your released app. Approov gives these secrets only to valid apps at runtime.

You can use both options together in the same app.

## UPGRADING FROM 3.5.x

Read the [changelog](CHANGELOG.md) for the full list of changes. Test your app and backend together. These changes need a source change:

* `initialize` resets the configuration each time it runs, and no longer compares account IDs itself. Make your configuration calls after `initialize`. A `null` context now throws `IllegalArgumentException`, also in bypass mode.
* The message signing helper classes moved. Change imports of `io.approov.util.sig.*` to `io.approov.util.httpsurlconn.sig.*`, and `io.approov.util.http.sfv.*` to `io.approov.util.httpsurlconn.http.sfv.*`.
* A `SignatureParametersFactory` subclass that sets `useAccountMessageSigning = true` directly now produces both the install and the account signature. To keep the account signature only, call `setUseAccountMessageSigning()`. The factory no longer sets the algorithm on the parameters. A subclass that needs one signature only sets the algorithm on the parameters that it returns.
* This release removes `prefetch()`. Remove your calls to it. The SDK manages prefetching itself.
* A request that carries a header that the package added no longer follows redirects by itself. If your app relies on redirects, read the `Location` header of a redirect response and send a new request with `addApproov`. See [redirects](USAGE.md#redirects).

If you upgrade from a release before 3.5.7, also remove your calls to the query parameter substitution methods, which 3.5.7 removed. See [secure strings in query parameters](USAGE.md#secure-strings-in-query-parameters).

---

## Useful Links

- [Approov SDK](https://github.com/approov/approov-android-sdk)
- [HttpsURLConnection Documentation](https://developer.android.com/reference/javax/net/ssl/HttpsURLConnection)
- [Approov Website](https://www.approov.io)
- [Quickstart Guide](https://github.com/approov/quickstart-android-java-httpsurlconn/blob/master/README.md)
- [Changelog](CHANGELOG.md)
- [Reference Documentation](REFERENCE.md)
- [Usage Guide](USAGE.md)
