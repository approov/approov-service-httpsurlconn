package io.approov.service.httpsurlconn;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import android.util.Log;

import com.criticalblue.approovsdk.Approov;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentMatchers;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;
import org.robolectric.shadows.ShadowLog;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;

import javax.net.ssl.HttpsURLConnection;

import io.approov.util.httpsurlconn.sig.ComponentProvider;
import io.approov.util.httpsurlconn.sig.SignatureParameters;

/**
 * Signing edge cases. {@code @query} is the query as sent with its leading {@code ?}, or {@code ?} alone when
 * the URL has none (RFC 9421 section 2.2.7). The fail-closed cases are a body digest configured as required that
 * cannot be generated, reported as an ApproovException whose cause is an IllegalStateException, and an
 * unsupported algorithm, reported as an ApproovException. A signature that cannot be produced, from the SDK or
 * in its encoding, sends the request unsigned and logs an error, as the backend is the enforcement point.
 */
@RunWith(RobolectricTestRunner.class)
@Config(manifest = Config.NONE)
public class SigningEdgeCasesTest {
    private static final String URL = "https://api.example.com/data";

    private MockedStatic<Approov> approov;

    @Before
    public void setUp() {
        approov = Mockito.mockStatic(Approov.class);
        ApproovTestSupport.initializeApproovService(approov);
        ApproovTestSupport.sdkSignsWithBoth(approov);
        ApproovDefaultMessageSigning.resetMissingSignatureLogsForTesting();
        ShadowLog.reset();
    }

    @After
    public void tearDown() {
        approov.close();
        ApproovService.reset();
        ApproovDefaultMessageSigning.resetMissingSignatureLogsForTesting();
        ShadowLog.reset();
    }

    private static ApproovDefaultMessageSigning.HttpsURLConnectionComponentProvider provider(String url)
            throws Exception {
        return new ApproovDefaultMessageSigning.HttpsURLConnectionComponentProvider(ApproovTestSupport.connection(url));
    }

    // the error lines logged by message signing
    private static int signingErrors() {
        int n = 0;
        for (ShadowLog.LogItem item : ShadowLog.getLogs()) {
            if ((item.type == Log.ERROR) && item.msg.startsWith("Message signing"))
                n++;
        }
        return n;
    }

    private static void assertUnsigned(String what, HttpsURLConnection request) {
        assertNull(what, request.getRequestProperty("Signature"));
        assertNull(what, request.getRequestProperty("Signature-Input"));
        assertEquals(what, "t", request.getRequestProperty("Approov-Token"));
    }

    @Test
    public void queryHasItsLeadingQuestionMarkAsSent() throws Exception {
        assertEquals("?path=color:red|weight:5&q=a%20b&pct=100%25",
                provider("https://maps.example.com/p?path=color:red|weight:5&q=a%20b&pct=100%25#frag").getQuery());
        assertEquals("an empty query", "?", provider("https://example.com/p?").getQuery());
        assertEquals("no query", "?", provider("https://example.com/p").getQuery());
        assertEquals("no query and a fragment", "?", provider("https://example.com/p#frag").getQuery());
    }

    @Test
    public void aSignatureCoveringQueryIsMadeWithoutAQuery() throws Exception {
        SignatureParameters base = new SignatureParameters()
                .addComponentIdentifier(ComponentProvider.DC_METHOD)
                .addComponentIdentifier(ComponentProvider.DC_QUERY);
        ApproovDefaultMessageSigning signer = new ApproovDefaultMessageSigning().setDefaultFactory(
                ApproovDefaultMessageSigning.generateDefaultSignatureParametersFactory(base));
        HttpsURLConnection signed = ApproovTestSupport.sign(signer, URL);
        assertNotNull("signed", signed.getRequestProperty("Signature"));
        assertTrue(signed.getRequestProperty("Signature-Input"),
                signed.getRequestProperty("Signature-Input").contains("\"@query\""));
        org.mockito.ArgumentCaptor<String> message = org.mockito.ArgumentCaptor.forClass(String.class);
        approov.verify(() -> Approov.getInstallMessageSignature(message.capture()));
        assertTrue(message.getValue(), message.getValue().contains("\"@query\": ?\n"));
    }

    @Test
    public void queryParamValuesUseTheFormEncodingOfRfc9421() throws Exception {
        ApproovDefaultMessageSigning.HttpsURLConnectionComponentProvider p =
                provider("https://h/p?a=x%20y&b=c+d&e=%2B&n%20m=1&r=1&r=2&f&u=%C3%BC");
        assertEquals("x%20y", p.getQueryParam("a"));
        assertEquals("a plus in the query is a space", "c%20d", p.getQueryParam("b"));
        assertEquals("%2B", p.getQueryParam("e"));
        assertEquals("the name is decoded", "1", p.getQueryParam("n%20m"));
        assertEquals("1", p.getQueryParam("n+m"));
        assertNull("a repeated parameter has no single value", p.getQueryParam("r"));
        assertEquals("a parameter without a value", "", p.getQueryParam("f"));
        assertEquals("%C3%BC", p.getQueryParam("u"));
        try {
            p.getQueryParam("missing");
            fail("a missing parameter cannot be signed");
        } catch (IllegalArgumentException expected) {
            // inside the fail-open of the signer
        }
    }

    @Test
    public void aQueryParamIsSignedInTheSignatureBase() throws Exception {
        SignatureParameters base = new SignatureParameters()
                .addComponentIdentifier(ComponentProvider.DC_METHOD)
                .addComponentIdentifier(io.approov.util.httpsurlconn.http.sfv.StringItem
                        .valueOf(ComponentProvider.DC_QUERY_PARAM)
                        .withParams(io.approov.util.httpsurlconn.http.sfv.Parameters.valueOf(
                                Collections.<String, Object>singletonMap("name", "q"))));
        ApproovDefaultMessageSigning signer = new ApproovDefaultMessageSigning().setDefaultFactory(
                ApproovDefaultMessageSigning.generateDefaultSignatureParametersFactory(base));
        assertNotNull(ApproovTestSupport.sign(signer, URL + "?q=a+b").getRequestProperty("Signature"));
        org.mockito.ArgumentCaptor<String> message = org.mockito.ArgumentCaptor.forClass(String.class);
        approov.verify(() -> Approov.getInstallMessageSignature(message.capture()));
        assertTrue(message.getValue(), message.getValue().contains("\"@query-param\";name=\"q\": a%20b\n"));
    }

    @Test
    public void aRequiredBodyDigestThatCannotBeGeneratedAbortsWithItsOwnCause() throws Exception {
        ApproovDefaultMessageSigning signer = new ApproovDefaultMessageSigning().setDefaultFactory(
                ApproovDefaultMessageSigning.generateDefaultSignatureParametersFactory()
                        .setBodyDigestConfig(ApproovDefaultMessageSigning.DIGEST_SHA256, true));
        try {
            ApproovTestSupport.sign(signer, URL);
            fail("a required body digest that cannot be generated must abort");
        } catch (ApproovException e) {
            assertTrue(String.valueOf(e.getCause()), e.getCause() instanceof IllegalStateException);
        }

        // with a body the digest is generated and the request is signed
        ApproovRequestMutations changes = ApproovTestSupport.tokenChanges();
        changes.setBodyBytes("a=1".getBytes(StandardCharsets.UTF_8));
        HttpsURLConnection request = ApproovTestSupport.tokenConnection(URL);
        request.setRequestMethod("POST");
        HttpsURLConnection signed = signer.handleInterceptorProcessedRequest(request, changes);
        assertNotNull(signed.getRequestProperty("Content-Digest"));
        assertNotNull(signed.getRequestProperty("Signature"));
    }

    @Test
    public void aRequiredBodyDigestFailureReachesTheAppThroughAddApproov() throws Exception {
        Approov.TokenFetchResult success =
                ApproovTestSupport.tokenResult(Approov.TokenFetchStatus.SUCCESS, "jwt", "", "trace");
        approov.when(() -> Approov.fetchApproovTokenAndWait(URL)).thenReturn(success);
        ApproovService.setServiceMutator(new ApproovDefaultMessageSigning().setDefaultFactory(
                ApproovDefaultMessageSigning.generateDefaultSignatureParametersFactory()
                        .setBodyDigestConfig(ApproovDefaultMessageSigning.DIGEST_SHA256, true)));
        try {
            ApproovService.addApproov(ApproovTestSupport.connection(URL));
            fail("must abort");
        } catch (ApproovException e) {
            assertTrue(String.valueOf(e.getCause()), e.getCause() instanceof IllegalStateException);
        }
        // the body given to addApproov is digested
        HttpsURLConnection request = ApproovTestSupport.connection(URL);
        ApproovService.addApproov(request, "a=1".getBytes(StandardCharsets.UTF_8));
        assertNotNull(request.getRequestProperty("Content-Digest"));
        assertNotNull(request.getRequestProperty("Signature"));
    }

    @Test
    public void anUnsupportedAlgorithmFailsTheRequestWithAnApproovException() throws Exception {
        ApproovDefaultMessageSigning.SignatureParametersFactory unsupported =
                new ApproovDefaultMessageSigning.SignatureParametersFactory() {
                    @Override
                    public List<String> getAlgs() {
                        return Collections.singletonList("rsa-v1_5-sha256");
                    }
                }.setBaseParameters(new SignatureParameters().addComponentIdentifier(ComponentProvider.DC_METHOD));
        try {
            ApproovTestSupport.sign(new ApproovDefaultMessageSigning().setDefaultFactory(unsupported), URL);
            fail("an unsupported algorithm must fail the request");
        } catch (ApproovException e) {
            assertTrue(e.getMessage(), e.getMessage().contains("rsa-v1_5-sha256"));
        }

        // an explicit algorithm on the parameters of a factory subclass too
        ApproovDefaultMessageSigning.SignatureParametersFactory explicit =
                new ApproovDefaultMessageSigning.SignatureParametersFactory() {
                    @Override
                    protected SignatureParameters buildSignatureParameters(
                            ApproovDefaultMessageSigning.HttpsURLConnectionComponentProvider provider,
                            ApproovRequestMutations changes) {
                        return super.buildSignatureParameters(provider, changes).setAlg("hmac-sha512");
                    }
                }.setBaseParameters(new SignatureParameters().addComponentIdentifier(ComponentProvider.DC_METHOD));
        try {
            ApproovTestSupport.sign(new ApproovDefaultMessageSigning().setDefaultFactory(explicit), URL);
            fail("an unsupported algorithm must fail the request");
        } catch (ApproovException e) {
            assertTrue(e.getMessage(), e.getMessage().contains("hmac-sha512"));
        }
    }

    @Test
    public void anExplicitSupportedAlgorithmProducesThatSignatureOnly() throws Exception {
        ApproovDefaultMessageSigning.SignatureParametersFactory explicit =
                new ApproovDefaultMessageSigning.SignatureParametersFactory() {
                    @Override
                    protected SignatureParameters buildSignatureParameters(
                            ApproovDefaultMessageSigning.HttpsURLConnectionComponentProvider provider,
                            ApproovRequestMutations changes) {
                        return super.buildSignatureParameters(provider, changes)
                                .setAlg(ApproovDefaultMessageSigning.ALG_HS256);
                    }
                }.setBaseParameters(new SignatureParameters().addComponentIdentifier(ComponentProvider.DC_METHOD))
                        .setUseInstallAndAccountMessageSigning();
        String signature = ApproovTestSupport.sign(new ApproovDefaultMessageSigning().setDefaultFactory(explicit), URL)
                .getRequestProperty("Signature");
        assertTrue(signature, signature.startsWith("account=:"));
        assertTrue(signature, !signature.contains("install="));
    }

    @Test
    public void aSignatureThatCannotBeEncodedIsLeftOut() throws Exception {
        ApproovDefaultMessageSigning signer = ApproovDefaultMessageSigning.combined();
        // not ASN.1 DER
        approov.when(() -> Approov.getInstallMessageSignature(ArgumentMatchers.anyString()))
                .thenReturn(java.util.Base64.getEncoder().encodeToString(new byte[]{1, 2, 3}));
        String signature = ApproovTestSupport.sign(signer, URL).getRequestProperty("Signature");
        assertTrue(signature, signature.startsWith("account=:") && !signature.contains("install="));
        // not base64
        approov.when(() -> Approov.getInstallMessageSignature(ArgumentMatchers.anyString()))
                .thenReturn("this is not base64 !!!");
        approov.when(() -> Approov.getAccountMessageSignature(ArgumentMatchers.anyString()))
                .thenReturn("neither is this !!!");
        ShadowLog.reset();
        assertUnsigned("neither can be decoded", ApproovTestSupport.sign(signer, URL));
        assertEquals(1, signingErrors());
    }

    @Test
    public void aQueryParamTheRequestDoesNotHaveSendsItUnsignedWithAnError() throws Exception {
        SignatureParameters param = new SignatureParameters()
                .addComponentIdentifier(ComponentProvider.DC_METHOD)
                .addComponentIdentifier(io.approov.util.httpsurlconn.http.sfv.StringItem
                        .valueOf(ComponentProvider.DC_QUERY_PARAM)
                        .withParams(io.approov.util.httpsurlconn.http.sfv.Parameters.valueOf(
                                Collections.<String, Object>singletonMap("name", "missing"))));
        ShadowLog.reset();
        assertUnsigned("missing query parameter", ApproovTestSupport.sign(new ApproovDefaultMessageSigning()
                .setDefaultFactory(ApproovDefaultMessageSigning.generateDefaultSignatureParametersFactory(param)),
                URL + "?q=1"));
        assertEquals(1, signingErrors());
    }

    @Test
    public void unconfiguredBaseParametersSendTheRequestUnsigned() throws Exception {
        // only a required body digest fails the request closed, so a factory without base parameters leaves
        // the request unsigned and logs the failure
        ApproovDefaultMessageSigning signer = new ApproovDefaultMessageSigning().setDefaultFactory(
                new ApproovDefaultMessageSigning.SignatureParametersFactory());
        ShadowLog.reset();
        assertUnsigned("unconfigured base parameters", ApproovTestSupport.sign(signer, URL));
        assertEquals(1, signingErrors());
    }

    @Test
    public void anyOtherExceptionFromBuildingTheParametersSendsTheRequestUnsigned() throws Exception {
        RuntimeException[] failures = {
                new IllegalArgumentException("custom factory argument"),
                new NullPointerException("custom factory bug")};
        for (RuntimeException failure : failures) {
            ApproovDefaultMessageSigning.SignatureParametersFactory factory =
                    new ApproovDefaultMessageSigning.SignatureParametersFactory() {
                        @Override
                        protected SignatureParameters buildSignatureParameters(
                                ApproovDefaultMessageSigning.HttpsURLConnectionComponentProvider provider,
                                ApproovRequestMutations changes) {
                            throw failure;
                        }
                    };
            ShadowLog.reset();
            HttpsURLConnection request = ApproovTestSupport.sign(
                    new ApproovDefaultMessageSigning().setDefaultFactory(factory), URL);
            assertUnsigned(failure.toString(), request);
            assertEquals(failure.toString(), 1, signingErrors());
        }
    }

    @Test
    public void aUrlHttpUrlRejectsIsSentAsWrittenUnsignedWithOneErrorLog() throws Exception {
        String url = "https://example.com:99999/p|q";
        assertNull("HttpUrl rejects the port", okhttp3.HttpUrl.parse(url));
        ApproovDefaultMessageSigning signer = ApproovDefaultMessageSigning.combined();
        for (int i = 0; i < 2; i++)
            assertUnsigned("attempt " + i, ApproovTestSupport.sign(signer, url));
        approov.verify(() -> Approov.getInstallMessageSignature(ArgumentMatchers.anyString()), Mockito.never());
        int errors = 0;
        for (ShadowLog.LogItem item : ShadowLog.getLogs()) {
            if ((item.type == Log.ERROR) && item.msg.contains("URL"))
                errors++;
        }
        assertEquals("one error log for the process", 1, errors);
    }

    @Test
    public void signingTwiceReplacesTheSignatureHeaders() throws Exception {
        ApproovDefaultMessageSigning signer = ApproovDefaultMessageSigning.combined();
        HttpsURLConnection request = ApproovTestSupport.tokenConnection(URL);
        request.setRequestProperty("Signature", "stale-signature");
        request.setRequestProperty("Signature-Input", "stale-input");
        signer.handleInterceptorProcessedRequest(request, ApproovTestSupport.tokenChanges());
        signer.handleInterceptorProcessedRequest(request, ApproovTestSupport.tokenChanges());
        assertEquals(1, request.getRequestProperties().get("Signature").size());
        assertEquals(1, request.getRequestProperties().get("Signature-Input").size());
        assertTrue(request.getRequestProperty("Signature").startsWith("install=:"));
        assertNull("no debug digest unless asked", request.getRequestProperty("Signature-Base-Digest"));
    }

    @Test
    public void aRequestWithoutTheTokenHeaderMutationIsNotSigned() throws Exception {
        HttpsURLConnection request = ApproovTestSupport.tokenConnection(URL);
        request.setRequestProperty("Signature", "stale-signature");
        assertSame(request, ApproovDefaultMessageSigning.combined()
                .handleInterceptorProcessedRequest(request, new ApproovRequestMutations()));
        assertEquals("stale-signature", request.getRequestProperty("Signature"));
        assertNull(request.getRequestProperty("Signature-Input"));
    }

    @Test
    public void debugModeAddsTheDigestOfEachSignatureBase() throws Exception {
        ApproovDefaultMessageSigning.SignatureParametersFactory debug =
                new ApproovDefaultMessageSigning.SignatureParametersFactory() {
                    @Override
                    protected SignatureParameters buildSignatureParameters(
                            ApproovDefaultMessageSigning.HttpsURLConnectionComponentProvider provider,
                            ApproovRequestMutations changes) {
                        SignatureParameters params = super.buildSignatureParameters(provider, changes);
                        params.setDebugMode(true);
                        return params;
                    }
                }.setBaseParameters(new SignatureParameters().addComponentIdentifier(ComponentProvider.DC_METHOD))
                        .setUseInstallAndAccountMessageSigning();
        HttpsURLConnection request = ApproovTestSupport.sign(
                ApproovDefaultMessageSigning.combined().setDefaultFactory(debug), URL);
        String digest = request.getRequestProperty("Signature-Base-Digest");
        assertNotNull(digest);
        assertTrue(digest, digest.matches("install=:[^:]+:, account=:[^:]+:"));
    }
}
