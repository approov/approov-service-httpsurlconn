package io.approov.service.httpsurlconn;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;

import javax.net.ssl.HttpsURLConnection;

import io.approov.util.httpsurlconn.sig.ComponentProvider;
import io.approov.util.httpsurlconn.sig.SignatureParameters;

/**
 * The signature configuration and the signing states. The Signature and Content-Digest values are Byte
 * Sequences (base64 between colons, never a quoted string), a covered header with an empty value is a valid
 * component, and the body digest can use SHA-256 or SHA-512, be disabled, or be required of a request that has
 * a body. A signature covers each component once, also when the token header is one of the optional headers of
 * the factory. Out of the box no request is signed; the default factory signs with the install signature only
 * and the opt-in with both. A factory set for one host applies to that host only, and initialize turns signing
 * off again.
 */
@RunWith(RobolectricTestRunner.class)
@Config(manifest = Config.NONE)
public class SigningConfigTest {
    private static final String BASE64 = "[A-Za-z0-9+/]+=*";
    private static final String URL = "https://api.example.com/data";

    private MockedStatic<Approov> approov;

    @Before
    public void setUp() {
        approov = Mockito.mockStatic(Approov.class);
        ApproovTestSupport.initializeApproovService(approov);
        ApproovTestSupport.sdkSignsWithBoth(approov);
        Approov.TokenFetchResult success =
                ApproovTestSupport.tokenResult(Approov.TokenFetchStatus.SUCCESS, "jwt-token", "", "trace-1");
        approov.when(() -> Approov.fetchApproovTokenAndWait(ArgumentMatchers.anyString())).thenReturn(success);
    }

    @After
    public void tearDown() {
        approov.close();
        ApproovService.reset();
    }

    private static ApproovDefaultMessageSigning.SignatureParametersFactory factory() {
        return ApproovDefaultMessageSigning.generateDefaultSignatureParametersFactory();
    }

    // adds Approov to a POST with the body given, as addApproov(connection, body) does, under the factory
    private static HttpsURLConnection post(ApproovDefaultMessageSigning.SignatureParametersFactory factory,
            String body) throws Exception {
        ApproovService.setServiceMutator(new ApproovDefaultMessageSigning().setDefaultFactory(factory));
        HttpsURLConnection request = ApproovTestSupport.connection(URL);
        request.setRequestMethod("POST");
        request.setRequestProperty("Content-Type", "application/json; charset=utf-8");
        ApproovService.addApproov(request, body.getBytes(StandardCharsets.UTF_8));
        return request;
    }

    // adds Approov to a GET of the URL
    private static HttpsURLConnection get(String url) throws Exception {
        HttpsURLConnection request = ApproovTestSupport.connection(url);
        ApproovService.addApproov(request);
        return request;
    }

    private static String digest(String algorithm, String text) throws Exception {
        return Base64.getEncoder().encodeToString(
                MessageDigest.getInstance(algorithm).digest(text.getBytes(StandardCharsets.UTF_8)));
    }

    // ---- configuration

    @Test
    public void theSignatureAndTheDigestAreByteSequences() throws Exception {
        HttpsURLConnection request = post(factory().setUseInstallAndAccountMessageSigning(), "body");
        String signature = request.getRequestProperty("Signature");
        assertTrue(signature, signature.matches("install=:" + BASE64 + ":, account=:" + BASE64 + ":"));
        assertFalse(signature, signature.contains("\""));
        assertEquals("sha-256=:" + digest("SHA-256", "body") + ":", request.getRequestProperty("Content-Digest"));
        String input = request.getRequestProperty("Signature-Input");
        assertTrue(input, input.contains("\"content-digest\"") && input.contains("\"content-type\""));
    }

    @Test
    public void aCoveredHeaderWithAnEmptyValueIsSigned() throws Exception {
        ApproovService.setServiceMutator(new ApproovDefaultMessageSigning().setDefaultFactory(
                factory().addOptionalHeaders("X-Empty")));
        HttpsURLConnection request = ApproovTestSupport.connection(URL);
        request.setRequestProperty("X-Empty", "");
        ApproovService.addApproov(request);
        assertNotNull("the request is signed", request.getRequestProperty("Signature"));
        assertTrue(request.getRequestProperty("Signature-Input"),
                request.getRequestProperty("Signature-Input").contains("\"x-empty\""));
    }

    @Test
    public void anOptionalHeaderThatIsNotSetIsNotCovered() throws Exception {
        ApproovService.setServiceMutator(new ApproovDefaultMessageSigning().setDefaultFactory(
                factory().addOptionalHeaders("X-Absent")));
        HttpsURLConnection request = get(URL);
        assertFalse(request.getRequestProperty("Signature-Input"),
                request.getRequestProperty("Signature-Input").contains("\"x-absent\""));
        assertFalse("a GET has no Content-Type",
                request.getRequestProperty("Signature-Input").contains("\"content-type\""));
    }

    @Test
    public void theDigestCanUseSha512() throws Exception {
        HttpsURLConnection request = post(factory().setBodyDigestConfig(ApproovDefaultMessageSigning.DIGEST_SHA512, false),
                "body");
        assertEquals("sha-512=:" + digest("SHA-512", "body") + ":", request.getRequestProperty("Content-Digest"));
        assertTrue(request.getRequestProperty("Signature-Input").contains("\"content-digest\""));
    }

    @Test
    public void aDisabledDigestSignsWithoutOne() throws Exception {
        HttpsURLConnection request = post(factory().setBodyDigestConfig(null, true), "body");
        assertNull(request.getRequestProperty("Content-Digest"));
        assertNotNull(request.getRequestProperty("Signature"));
        assertFalse(request.getRequestProperty("Signature-Input").contains("content-digest"));
    }

    @Test
    public void anOptionalDigestWithoutABodySignsWithoutOne() throws Exception {
        ApproovService.setServiceMutator(new ApproovDefaultMessageSigning().setDefaultFactory(factory()));
        HttpsURLConnection request = get(URL);
        assertNull(request.getRequestProperty("Content-Digest"));
        assertNotNull(request.getRequestProperty("Signature"));
    }

    @Test
    public void aRequiredDigestOfARequestWithABodyIsMade() throws Exception {
        HttpsURLConnection request = post(factory().setBodyDigestConfig(ApproovDefaultMessageSigning.DIGEST_SHA256, true),
                "body");
        assertEquals("sha-256=:" + digest("SHA-256", "body") + ":", request.getRequestProperty("Content-Digest"));
    }

    @Test
    public void anUnsupportedDigestAlgorithmIsRefusedWhenConfigured() {
        assertThrows(IllegalArgumentException.class, () -> factory().setBodyDigestConfig("md5", false));
    }

    // ---- each component once

    @Test
    public void aTokenHeaderThatIsAlsoAnOptionalHeaderIsCoveredOnce() throws Exception {
        ApproovService.setTokenHeader("X-Token", "Bearer ");
        ApproovService.setServiceMutator(new ApproovDefaultMessageSigning().setDefaultFactory(
                factory().addOptionalHeaders("X-Token", "x-token")));
        HttpsURLConnection request = get(URL);
        assertEquals("Bearer jwt-token", request.getRequestProperty("X-Token"));
        List<String> covered = ApproovTestSupport.components(request.getRequestProperty("Signature-Input"));
        assertEquals(covered.toString(), 1, Collections.frequency(covered, "x-token"));
        assertEquals(covered.toString(), new LinkedHashSet<>(covered).size(), covered.size());
    }

    @Test
    public void aRepeatedOptionalHeaderIsCoveredOnce() throws Exception {
        HttpsURLConnection request = post(factory().addOptionalHeaders("Content-Type", "content-type"), "{}");
        List<String> covered = ApproovTestSupport.components(request.getRequestProperty("Signature-Input"));
        assertEquals(covered.toString(), 1, Collections.frequency(covered, "content-type"));
        assertEquals(covered.toString(), new LinkedHashSet<>(covered).size(), covered.size());
    }

    @Test
    public void aBaseComponentAddedAgainIsCoveredOnce() throws Exception {
        ApproovDefaultMessageSigning.SignatureParametersFactory factory =
                new ApproovDefaultMessageSigning.SignatureParametersFactory()
                        .setBaseParameters(new SignatureParameters()
                                .addComponentIdentifier(ComponentProvider.DC_METHOD)
                                .addComponentIdentifier(ComponentProvider.DC_TARGET_URI)
                                .addComponentIdentifier(ComponentProvider.DC_TARGET_URI)
                                .addComponentIdentifier("Content-Type")
                                .addComponentIdentifier("Approov-Token"))
                        .setUseInstallMessageSigning()
                        .setAddApproovTokenHeader(true)
                        .setAddApproovTraceIDHeader(true)
                        .addOptionalHeaders("content-type", "Approov-TraceID");
        HttpsURLConnection request = post(factory, "{}");
        List<String> covered = ApproovTestSupport.components(request.getRequestProperty("Signature-Input"));
        assertEquals(covered.toString(), java.util.Arrays.asList("@method", "@target-uri", "content-type",
                "approov-token", "approov-traceid"), covered);
    }

    // ---- signing states

    private static void assertUnsigned(String what, HttpsURLConnection request) {
        assertNull(what, request.getRequestProperty("Signature"));
        assertNull(what, request.getRequestProperty("Signature-Input"));
        assertNotNull(what + ": the token is still sent", request.getRequestProperty("Approov-Token"));
    }

    private static void assertInstallOnly(String what, HttpsURLConnection request) {
        assertTrue(what, request.getRequestProperty("Signature").startsWith("install=:"));
        assertFalse(what, request.getRequestProperty("Signature").contains("account="));
        assertFalse(what, request.getRequestProperty("Signature-Input").contains("account="));
        assertTrue(what, request.getRequestProperty("Signature-Input").contains("\"approov-token\""));
    }

    private static void assertBoth(String what, HttpsURLConnection request) {
        assertTrue(what, request.getRequestProperty("Signature").startsWith("install=:"));
        assertTrue(what, request.getRequestProperty("Signature").contains("account=:"));
        assertTrue(what, request.getRequestProperty("Signature-Input").contains("install=("));
        assertTrue(what, request.getRequestProperty("Signature-Input").contains("account=("));
    }

    @Test
    public void signingIsOffInstallOnlyThenBoth() throws Exception {
        assertUnsigned("out of the box", get(URL));

        ApproovService.setServiceMutator(new ApproovDefaultMessageSigning().setDefaultFactory(factory()));
        assertInstallOnly("default factory", get(URL));

        ApproovService.setServiceMutator(new ApproovDefaultMessageSigning().setDefaultFactory(
                factory().setUseInstallAndAccountMessageSigning()));
        assertBoth("opt-in", get(URL));
    }

    @Test
    public void aHostFactoryAppliesToItsHostOnlyWithoutRegardToCaseOrPort() throws Exception {
        ApproovService.setServiceMutator(new ApproovDefaultMessageSigning().putHostFactory("API.Example.com",
                factory()));
        assertInstallOnly("its own host", get(URL));
        assertInstallOnly("its own host with a port", get("https://api.example.com:8443/data"));
        assertInstallOnly("its own host in another case", get("https://Api.EXAMPLE.com/data"));
        assertUnsigned("another host", get("https://other.example.com/data"));
        assertUnsigned("a subdomain", get("https://sub.api.example.com/data"));
    }

    @Test
    public void aHostFactoryTakesPrecedenceAndRemovingItRestoresTheDefault() throws Exception {
        ApproovDefaultMessageSigning signer = new ApproovDefaultMessageSigning()
                .setDefaultFactory(factory())
                .putHostFactory("api.example.com", factory().setUseAccountMessageSigning());
        ApproovService.setServiceMutator(signer);
        assertTrue(get(URL).getRequestProperty("Signature").startsWith("account=:"));
        assertInstallOnly("another host uses the default", get("https://other.example.com/data"));
        signer.putHostFactory("API.EXAMPLE.COM", null);
        assertInstallOnly("the default again", get(URL));
        signer.setDefaultFactory(null);
        assertUnsigned("no factory", get(URL));
        assertThrows(IllegalArgumentException.class, () -> signer.putHostFactory(null, factory()));
    }

    @Test
    public void initializeTurnsSigningOff() throws Exception {
        ApproovService.setServiceMutator(new ApproovDefaultMessageSigning().setDefaultFactory(factory()));
        assertInstallOnly("before", get(URL));
        ApproovService.initialize(ApproovTestSupport.mockContext(), "test-account");
        assertSame(ApproovServiceMutator.DEFAULT, ApproovService.getServiceMutator());
        assertUnsigned("after initialize", get(URL));
    }

    @Test
    public void theCombinedSignerSignsWithBothAndMakesTheDecisionsGiven() throws Exception {
        ApproovService.setServiceMutator(ApproovDefaultMessageSigning.combined());
        assertBoth("combined()", get(URL));
        // the no-argument signer makes the standard decisions, which abort a network failure
        Approov.TokenFetchResult noNetwork =
                ApproovTestSupport.tokenResult(Approov.TokenFetchStatus.NO_NETWORK, "", "", "trace-x");
        approov.when(() -> Approov.fetchApproovTokenAndWait(ArgumentMatchers.anyString())).thenReturn(noNetwork);
        HttpsURLConnection aborted = ApproovTestSupport.connection(URL);
        assertThrows(ApproovNetworkException.class, () -> ApproovService.addApproov(aborted));
        assertNull(aborted.getRequestProperty("Approov-Token"));

        // with the decisions of ALWAYS_PROCEED the failure goes out, signed
        ApproovService.setServiceMutator(ApproovDefaultMessageSigning.combined(ApproovServiceMutator.ALWAYS_PROCEED));
        HttpsURLConnection request = get(URL);
        assertEquals("", request.getRequestProperty("Approov-Token"));
        assertBoth("combined(ALWAYS_PROCEED)", request);
    }
}
