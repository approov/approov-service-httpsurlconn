package io.approov.service.httpsurlconn;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import android.content.Context;

import com.criticalblue.approovsdk.Approov;

import org.mockito.MockedStatic;

import java.io.IOException;
import java.lang.reflect.Field;
import java.net.URL;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.HttpsURLConnection;

/**
 * Shared fixtures for the unit tests that mock the Approov SDK with Mockito.
 */
final class ApproovTestSupport {
    // a canonical DER encoding of r=1 and s=2, as the SDK returns the install signature
    static final String INSTALL_SIGNATURE = Base64.getEncoder().encodeToString(
            new byte[]{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02});

    // an HMAC-SHA256 sized value, as the SDK returns the account signature
    static final String ACCOUNT_SIGNATURE = Base64.getEncoder().encodeToString(new byte[32]);

    private ApproovTestSupport() {
    }

    static Context mockContext() {
        Context context = mock(Context.class);
        when(context.getApplicationContext()).thenReturn(context);
        return context;
    }

    /**
     * Initializes the service with Approov protection enabled against the mocked SDK, with an empty pin set.
     * The logging level is kept.
     *
     * @param approov is the mocked SDK
     */
    static void initializeApproovService(MockedStatic<Approov> approov) {
        approov.when(() -> Approov.getPins("public-key-sha256")).thenReturn(new HashMap<>());
        ApproovService.initialize(mockContext(), "test-account");
    }

    // the SDK answers both signatures
    static void sdkSignsWithBoth(MockedStatic<Approov> approov) {
        approov.when(() -> Approov.getInstallMessageSignature(anyString())).thenReturn(INSTALL_SIGNATURE);
        approov.when(() -> Approov.getAccountMessageSignature(anyString())).thenReturn(ACCOUNT_SIGNATURE);
    }

    static Approov.TokenFetchResult tokenResult(Approov.TokenFetchStatus status) {
        return tokenResult(status, "", "", null);
    }

    static Approov.TokenFetchResult tokenResult(
            Approov.TokenFetchStatus status,
            String token,
            String secureString,
            String traceID
    ) {
        Approov.TokenFetchResult result = mock(Approov.TokenFetchResult.class);
        when(result.getStatus()).thenReturn(status);
        when(result.getToken()).thenReturn(token);
        when(result.getSecureString()).thenReturn(secureString);
        when(result.getTraceID()).thenReturn(traceID);
        when(result.getLoggableToken()).thenReturn(token);
        when(result.getARC()).thenReturn("ARC123");
        when(result.getRejectionReasons()).thenReturn("hooked,rooted");
        return result;
    }

    static HttpsURLConnection connection(String url) throws IOException {
        return (HttpsURLConnection) new URL(url).openConnection();
    }

    /**
     * Gets a connection that carries the token header and the mutations that record it, as the service layer
     * leaves a request before the processed request hook.
     */
    static HttpsURLConnection tokenConnection(String url) throws IOException {
        HttpsURLConnection connection = connection(url);
        connection.setRequestProperty("Approov-Token", "t");
        return connection;
    }

    static ApproovRequestMutations tokenChanges() {
        ApproovRequestMutations changes = new ApproovRequestMutations();
        changes.setTokenHeaderKey("Approov-Token");
        return changes;
    }

    /**
     * Signs a connection to the URL that carries the token header and returns it.
     */
    static HttpsURLConnection sign(ApproovDefaultMessageSigning signer, String url) throws Exception {
        return signer.handleInterceptorProcessedRequest(tokenConnection(url), tokenChanges());
    }

    // the component identifiers of the first member of a Signature-Input value, in order
    static List<String> components(String signatureInput) {
        List<String> found = new ArrayList<>();
        String inner = signatureInput.substring(signatureInput.indexOf('(') + 1, signatureInput.indexOf(')'));
        Matcher matcher = Pattern.compile("\"([^\"]+)\"").matcher(inner);
        while (matcher.find())
            found.add(matcher.group(1));
        return found;
    }

    // sets whether Approov protection is enabled, without the SDK, for a check that needs it
    static void setProtectionEnabled(boolean enabled) {
        setStaticField("isInitialized", enabled);
        setStaticField("approovProtectionEnabled", enabled);
    }

    private static void setStaticField(String name, Object value) {
        try {
            Field field = ApproovService.class.getDeclaredField(name);
            field.setAccessible(true);
            field.set(null, value);
        } catch (ReflectiveOperationException e) {
            throw new AssertionError("Failed to set field " + name, e);
        }
    }
}
