package io.approov.service.httpsurlconn;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import android.content.Context;

import com.criticalblue.approovsdk.Approov;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import javax.net.ssl.HttpsURLConnection;

import io.approov.util.sig.ComponentProvider;
import io.approov.util.sig.SignatureParameters;

public class ApproovServiceTest {
    private static final String CONFIG = "config";

    private MockedStatic<Approov> mockApproov;
    private MockedStatic<android.util.Base64> mockAndroidBase64;
    private Context context;

    @Before
    public void setUp() {
        context = mock(Context.class);
        when(context.getApplicationContext()).thenReturn(context);
        mockApproov = Mockito.mockStatic(Approov.class);
        mockAndroidBase64 = Mockito.mockStatic(android.util.Base64.class);
        mockApproov.when(() -> Approov.initialize(Mockito.any(), Mockito.anyString(), Mockito.anyString(), Mockito.any())).thenReturn(false);
        mockApproov.when(() -> Approov.setUserProperty(Mockito.anyString())).thenAnswer(invocation -> null);
        mockAndroidBase64.when(() -> android.util.Base64.decode(Mockito.anyString(), Mockito.anyInt()))
                .thenAnswer(invocation ->
                        Base64.getDecoder().decode(invocation.getArgument(0, String.class)));
        mockAndroidBase64.when(() -> android.util.Base64.encodeToString(Mockito.any(byte[].class), Mockito.anyInt()))
                .thenAnswer(invocation -> {
                    byte[] input = invocation.getArgument(0, byte[].class);
                    int flags = invocation.getArgument(1, Integer.class);
                    Base64.Encoder encoder = Base64.getEncoder();
                    if ((flags & android.util.Base64.NO_PADDING) != 0) {
                        encoder = encoder.withoutPadding();
                    }
                    return encoder.encodeToString(input);
                });
        ApproovService.initialize(context, CONFIG);
        ApproovService.setServiceMutator(null);
    }

    @After
    public void tearDown() {
        ApproovService.reset();
        if (mockApproov != null) {
            mockApproov.close();
        }
        if (mockAndroidBase64 != null) {
            mockAndroidBase64.close();
        }
    }

    @Test
    public void addApproovKeepsSameConnectionAndSignsWhenUrlUnchanged() throws Exception {
        String requestUrl = "https://example.com/shapes";
        Approov.TokenFetchResult tokenResult = mockTokenFetchResult(
                Approov.TokenFetchStatus.SUCCESS,
                "approov-token-value",
                null
        );
        mockApproov.when(() -> Approov.fetchApproovTokenAndWait(requestUrl)).thenReturn(tokenResult);

        TestAccountMessageSigning signer = new TestAccountMessageSigning();
        signer.setDefaultFactory(
                new ApproovDefaultMessageSigning.SignatureParametersFactory()
                        .setBaseParameters(
                                new SignatureParameters()
                                        .addComponentIdentifier(ComponentProvider.DC_METHOD)
                                        .addComponentIdentifier(ComponentProvider.DC_TARGET_URI)
                        )
                        .setUseAccountMessageSigning()
                        .setAddCreated(false)
                        .setExpiresLifetime(0)
                        .setAddApproovTokenHeader(true)
                        .setAddApproovTraceIDHeader(false)
                        .addOptionalHeaders()
        );
        ApproovService.setServiceMutator(signer);

        HttpsURLConnection request = newConnection(requestUrl);
        request.setRequestMethod("GET");

        HttpsURLConnection returned = ApproovService.addApproovToConnection(request);

        assertSame(request, returned);
        assertEquals("approov-token-value", request.getRequestProperty("Approov-Token"));
        assertNotNull(request.getRequestProperty("Signature"));
        assertNotNull(request.getRequestProperty("Signature-Input"));
        assertTrue(request.getRequestProperty("Signature-Input").contains("approov-token"));
    }

    @Test
    public void addApproovUsesStatusAsTokenHeaderWhenConfigured() throws Exception {
        String requestUrl = "https://example.com/shapes";
        Approov.TokenFetchResult tokenResult = mockTokenFetchResult(
                Approov.TokenFetchStatus.NO_NETWORK,
                "",
                null
        );
        mockApproov.when(() -> Approov.fetchApproovTokenAndWait(requestUrl)).thenReturn(tokenResult);
        ApproovService.setUseApproovStatusIfNoToken(true);

        HttpsURLConnection request = newConnection(requestUrl);
        request.setRequestMethod("GET");

        HttpsURLConnection returned = ApproovService.addApproovToConnection(request);

        assertSame(request, returned);
        assertEquals("NO_NETWORK", request.getRequestProperty("Approov-Token"));
    }


    private static HttpsURLConnection newConnection(String url) throws Exception {
        return (HttpsURLConnection) new URL(url).openConnection();
    }

    private static Approov.TokenFetchResult mockTokenFetchResult(
            Approov.TokenFetchStatus status,
            String token,
            String secureString
    ) {
        Approov.TokenFetchResult result = mock(Approov.TokenFetchResult.class);
        when(result.getStatus()).thenReturn(status);
        when(result.getToken()).thenReturn(token);
        when(result.getSecureString()).thenReturn(secureString);
        when(result.getLoggableToken()).thenReturn(token == null ? "" : token);
        when(result.getARC()).thenReturn("");
        when(result.getRejectionReasons()).thenReturn("");
        return result;
    }

    private static final class TestAccountMessageSigning extends ApproovDefaultMessageSigning {
        @Override
        protected String getAccountMessageSignature(String message) {
            return Base64.getEncoder()
                    .encodeToString("unit-test-signature".getBytes(StandardCharsets.UTF_8));
        }
    }

    @Test
    public void initializeWithNullConfigThrowsIllegalArgument() {
        ApproovService.reset();
        assertThrows(IllegalArgumentException.class, () -> ApproovService.initialize(context, null));
        // Per TESTING_REQUIREMENTS §17-18: failure preserves the prior (reset/uninitialised) state.
        assertFalse(ApproovService.isInitialized());
    }

    @Test
    public void initializeWithEmptyConfigEntersBypassMode() {
        ApproovService.reset();
        ApproovService.initialize(context, "");
        assertTrue(ApproovService.isInitialized());
        org.junit.Assert.assertFalse(ApproovService.isApproovEnabled());
    }

    @Test(expected = ApproovException.class)
    public void getDeviceIDThrowsWhenBypassed() throws Exception {
        ApproovService.reset();
        ApproovService.initialize(context, "");
        ApproovService.getDeviceID();
    }

    @Test(expected = ApproovException.class)
    public void fetchTokenThrowsWhenBypassed() throws Exception {
        ApproovService.reset();
        ApproovService.initialize(context, "");
        ApproovService.fetchToken("https://example.com");
    }

    @Test(expected = ApproovException.class)
    public void fetchSecureStringThrowsWhenBypassed() throws Exception {
        ApproovService.reset();
        ApproovService.initialize(context, "");
        ApproovService.fetchSecureString("key", null);
    }

    @Test(expected = ApproovException.class)
    public void fetchCustomJWTThrowsWhenBypassed() throws Exception {
        ApproovService.reset();
        ApproovService.initialize(context, "");
        ApproovService.fetchCustomJWT("payload");
    }

    @Test(expected = ApproovException.class)
    public void setDataHashInTokenThrowsWhenBypassed() throws Exception {
        ApproovService.reset();
        ApproovService.initialize(context, "");
        ApproovService.setDataHashInToken("data");
    }

    @Test(expected = ApproovException.class)
    public void setDevKeyThrowsWhenBypassed() throws Exception {
        ApproovService.reset();
        ApproovService.initialize(context, "");
        ApproovService.setDevKey("devkey");
    }

    @Test(expected = ApproovException.class)
    public void setInstallAttrsInTokenThrowsWhenBypassed() throws Exception {
        ApproovService.reset();
        ApproovService.initialize(context, "");
        ApproovService.setInstallAttrsInToken("attrs");
    }

    @Test
    public void doubleInitializationIgnoresSameConfig() {
        ApproovService.reset();
        ApproovService.initialize(context, CONFIG);
        assertTrue(ApproovService.isInitialized());
        assertTrue(ApproovService.isApproovEnabled());
        
        // This should be ignored without throwing an exception
        ApproovService.initialize(context, CONFIG);
    }

    @Test
    public void doubleInitializationThrowsOnDifferentConfigAndPreservesState() {
        ApproovService.reset();
        ApproovService.initialize(context, CONFIG);
        assertTrue(ApproovService.isInitialized());
        assertTrue(ApproovService.isApproovEnabled());

        // SDK throws when initialized with a conflicting config.
        mockApproov.when(() -> Approov.initialize(context, "different-config", "auto", null))
                   .thenThrow(new IllegalStateException("config conflict"));

        assertThrows(IllegalStateException.class,
                () -> ApproovService.initialize(context, "different-config"));
        // Per TESTING_REQUIREMENTS §17-18: failure preserves the prior operating state.
        assertTrue(ApproovService.isInitialized());
        assertTrue(ApproovService.isApproovEnabled());
    }

    @Test
    public void initializeWithCommentCallsNativeInitializeCorrectly() {
        ApproovService.reset();
        ApproovService.initialize(context, CONFIG, "my-custom-comment");
        assertTrue(ApproovService.isInitialized());
        assertTrue(ApproovService.isApproovEnabled());
        mockApproov.verify(() -> Approov.initialize(context, CONFIG, "auto", "my-custom-comment"));
    }

    @Test
    public void doubleInitializationAllowsReinit() {
        ApproovService.reset();
        ApproovService.initialize(context, CONFIG);
        assertTrue(ApproovService.isInitialized());
        
        // A second initialization with a different config is allowed if the comment starts with "reinit"
        ApproovService.initialize(context, "different-config", "reinit:mysecret");
        assertTrue(ApproovService.isInitialized());
        mockApproov.verify(() -> Approov.initialize(context, "different-config", "auto", "reinit:mysecret"));
    }
}
