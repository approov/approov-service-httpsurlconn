# Approov Service for HttpsUrlConnection

A wrapper for the [Approov SDK](https://github.com/approov/approov-android-sdk) to enable easy integration when using [`HttpsUrlConnection`](https://developer.android.com/reference/javax/net/ssl/HttpsURLConnection) for making the API calls that you wish to protect with Approov. In order to use this you will need a trial or paid [Approov](https://www.approov.io) account.

## ADDING APPROOV SERVICE DEPENDENCY

The Approov integration is available via [`mavenCentral`](https://mvnrepository.com/repos/central). This allows inclusion into the project by simply specifying a dependency in the `gradle` files for the app.

The `mavenCentral()` repository is already present in the gradle.build file so the only import you need to make is the actual service layer itself:

```groovy
implementation("io.approov:service.httpsurlconn:3.5.4")
```

Make sure you do a Gradle sync (by selecting `Sync Now` in the banner at the top of the modified `.gradle` file) after making these changes.

This package is actually an open source wrapper layer that allows you to easily use Approov with `HttpsUrlConnection`. This has a further dependency to the closed source [Approov SDK](https://central.sonatype.com/artifact/io.approov/approov-android-sdk/3.5.0). In some cases you may need to also add this implementation to your dependencies list to avoid build errors:

```groovy
implementation("io.approov:approov-android-sdk:3.5.3")
```

## MANIFEST CHANGES

The following app permissions need to be available in the manifest to use Approov:

```xml
<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
<uses-permission android:name="android.permission.INTERNET" />
```

Note that the minimum SDK version you can use with the Approov package is 23 (Android 6.0). 

Please [read this](https://approov.io/docs/latest/approov-usage-documentation/#targeting-android-11-and-above) section of the reference documentation if targeting Android 11 (API level 30) or above.

## INITIALIZING APPROOV SERVICE

In order to use the `ApproovService` you must initialize it when your app is created, usually in the `onCreate` method:

### Java
```java
import io.approov.service.httpsurlconn.ApproovService;

public class YourApp extends Application {
    @Override
    public void onCreate() {
        super.onCreate();
        ApproovService.initialize(getApplicationContext(), "<enter-your-config-string-here>");
    }
}
```

### Kotlin
```kotlin
import io.approov.service.httpsurlconn.ApproovService

class YourApp: Application() {
    override fun onCreate() {
        super.onCreate()
        ApproovService.initialize(applicationContext, "<enter-your-config-string-here>")
    }
}
```

The `<enter-your-config-string-here>` is a custom string that configures your Approov account access. This will have been provided in your Approov onboarding email.

## USING APPROOV SERVICE

You can make Approov enabled `HttpsUrlConnection` API calls by using `ApproovService.addApproov` on your connection. 

**CRITICAL SEQUENCE:** `ApproovService.addApproov` must be called as the **final step** before you connect to the network or write to the output stream. You must set your HTTP method and all application headers *before* calling `addApproov`.

### Java
```java
// 1. Set method and all your headers FIRST
connection.setRequestMethod("POST");
connection.setRequestProperty("Content-Type", "application/json");
connection.setRequestProperty("Authorization", auth);

// 2. Call addApproov ONLY AFTER the request is fully formed
connection = ApproovService.addApproov(connection);

// 3. Do NOT mutate any headers after this point.
connection.connect();
```

### Kotlin
```kotlin
// 1. Set method and all your headers FIRST
connection.requestMethod = "POST"
connection.setRequestProperty("Content-Type", "application/json")
connection.setRequestProperty("Authorization", auth)

// 2. Call addApproov ONLY AFTER the request is fully formed
connection = ApproovService.addApproov(connection)

// 3. Do NOT mutate any headers after this point.
connection.connect()
```

> **NOTE:** It is important that this call is made just prior to the connection being made and thus within any retry loop, to ensure that an updated Approov token is always made available on the connection request.

**Message Signing Warning:** If you enable Approov Message Signing, modifying any headers, the HTTP method, or writing unexpected body payload bytes *after* calling `addApproov` will silently invalidate the generated signature on the backend. For API domains that are configured to be protected with an Approov token, this adds the `Approov-Token` header and pins the connection. This may also substitute header values when using secrets protection.

Approov errors will generate an `ApproovException`, which is a type of `IOException`. This may be further specialized into an `ApproovNetworkException`, indicating an issue with networking that should provide an option for a user initiated retry.

## CHECKING IT WORKS

Initially you won't have set which API domains to protect, so the any `addApproov` call will not add anything. It will have called Approov though and made contact with the Approov cloud service. You will see logging from Approov saying `UNKNOWN_URL`.

Your Approov onboarding email should contain a link allowing you to access [Live Metrics Graphs](https://approov.io/docs/latest/approov-usage-documentation/#metrics-graphs). After you've run your app with Approov integration you should be able to see the results in the live metrics within a minute or so. At this stage you could even release your app to get details of your app population and the attributes of the devices they are running upon.

## NEXT STEPS

To actually protect your APIs and/or secrets there are some further steps. Approov provides two different options for protection:

* **API PROTECTION**: You should use this if you control the backend API(s) being protected and are able to modify them to ensure that a valid Approov token is being passed by the app. An [Approov Token](https://approov.io/docs/latest/approov-usage-documentation/#approov-tokens) is short lived crytographically signed JWT proving the authenticity of the call.

* **SECRETS PROTECTION**: This allows app secrets, including API keys for 3rd party services, to be protected so that they no longer need to be included in the released app code. These secrets are only made available to valid apps at runtime.

Note that it is possible to use both approaches side-by-side in the same app.

# Interface

Please see the [REFERENCE.md](REFERENCE.md) for more information on the Approov Service for HttpsUrlConnection.

# Usage

Please see the [USAGE.md](USAGE.md) for more information on how to use this wrapper.

# Changelog

Please see the [CHANGELOG.md](CHANGELOG.md) for more information on the changes in each version.
