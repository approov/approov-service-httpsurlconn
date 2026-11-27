package io.approov.service.httpsurlconn;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;

import com.criticalblue.approovsdk.Approov;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.io.OutputStream;
import java.net.InetAddress;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import okhttp3.tls.HandshakeCertificates;
import okhttp3.tls.HeldCertificate;

/**
 * Requests sent through HttpsURLConnection to a local HTTPS server. The server receives the token and trace
 * headers the layer set, nothing Approov adds on a request that is not processed, and nothing at all for a
 * request that is aborted. A signed request carries an install signature that verifies over the signature base
 * rebuilt from what the server received, for a GET, a POST whose body is written to the connection that
 * addApproovToConnection returns, and a POST whose body is given to addApproov. The signature covers the token
 * header that the layer set, also when the processed request hook changed it.
 */
@RunWith(RobolectricTestRunner.class)
@Config(manifest = Config.NONE)
public class WireRequestTest {
    private static final HeldCertificate SERVER_CERTIFICATE = new HeldCertificate.Builder()
            .commonName("localhost").addSubjectAlternativeName("localhost").build();

    private static final KeyPair INSTALL_KEY = installKey();

    // the signature bases the install key signed, in order
    private static final List<String> SIGNED = java.util.Collections.synchronizedList(new ArrayList<String>());

    private MockedStatic<Approov> approov;
    private MockWebServer server;
    private SSLSocketFactory clientTrust;
    private String origin;

    private static KeyPair installKey() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"));
            return generator.generateKeyPair();
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }

    // a signer whose install signature is made with a key of the test, as the SDK returns it: ASN.1 DER in base64
    private static final class KeySigner extends ApproovDefaultMessageSigning {
        KeySigner() {
            super();
        }

        KeySigner(ApproovServiceMutator decisions) {
            super(decisions);
        }

        @Override
        protected String getInstallMessageSignature(String message) throws ApproovException {
            SIGNED.add(message);
            try {
                Signature signer = Signature.getInstance("SHA256withECDSA");
                signer.initSign(INSTALL_KEY.getPrivate());
                signer.update(message.getBytes(StandardCharsets.UTF_8));
                return Base64.getEncoder().encodeToString(signer.sign());
            } catch (Exception e) {
                throw new ApproovException(e);
            }
        }
    }

    @Before
    public void setUp() throws Exception {
        SIGNED.clear();
        approov = Mockito.mockStatic(Approov.class);
        ApproovTestSupport.initializeApproovService(approov);
        ApproovTestSupport.sdkSignsWithBoth(approov);
        answer(Approov.TokenFetchStatus.SUCCESS, "jwt-token", "trace-1");
        server = new MockWebServer();
        server.useHttps(new HandshakeCertificates.Builder()
                .heldCertificate(SERVER_CERTIFICATE).build().sslSocketFactory(), false);
        server.start(InetAddress.getByName("localhost"), 0);
        origin = "https://localhost:" + server.getPort();
        clientTrust = new HandshakeCertificates.Builder()
                .addTrustedCertificate(SERVER_CERTIFICATE.certificate()).build().sslSocketFactory();
    }

    @After
    public void tearDown() throws Exception {
        server.shutdown();
        approov.close();
        ApproovService.reset();
    }

    private void answer(Approov.TokenFetchStatus status, String token, String traceID) {
        Approov.TokenFetchResult result = ApproovTestSupport.tokenResult(status, token, "", traceID);
        approov.when(() -> Approov.fetchApproovTokenAndWait(anyString())).thenReturn(result);
    }

    private HttpsURLConnection open(String path) throws Exception {
        HttpsURLConnection connection = (HttpsURLConnection) new URL(origin + path).openConnection();
        connection.setSSLSocketFactory(clientTrust);
        return connection;
    }

    // adds Approov to a GET of the path, sends it, and returns what the server received
    private RecordedRequest get(String path) throws Exception {
        server.enqueue(new MockResponse().setBody("ok"));
        HttpsURLConnection connection = ApproovService.addApproovToConnection(open(path));
        assertEquals(200, connection.getResponseCode());
        return take();
    }

    private RecordedRequest take() throws Exception {
        RecordedRequest recorded = server.takeRequest(5, TimeUnit.SECONDS);
        assertNotNull("not delivered", recorded);
        return recorded;
    }

    private static void assertNoApproovHeaders(String what, RecordedRequest recorded) {
        assertNull(what, recorded.getHeader("Approov-Token"));
        assertNull(what, recorded.getHeader("Approov-TraceID"));
        assertNull(what, recorded.getHeader("Signature"));
        assertNull(what, recorded.getHeader("Signature-Input"));
    }

    // the target of the request line the server received
    private static String requestLineTarget(RecordedRequest recorded) {
        String[] parts = recorded.getRequestLine().split(" ");
        assertEquals(recorded.getRequestLine(), 3, parts.length);
        return parts[1];
    }

    /**
     * Rebuilds the install signature base from the request the server received and checks the install
     * signature over it with the public key of the test.
     *
     * @return the rebuilt signature base
     */
    private String verifyInstallSignature(RecordedRequest recorded) throws Exception {
        String input = recorded.getHeader("Signature-Input");
        String signature = recorded.getHeader("Signature");
        assertNotNull("signed", signature);
        Matcher member = Pattern.compile("install=(\\(([^)]*)\\)[^,]*)").matcher(input);
        assertTrue(input, member.find());
        StringBuilder base = new StringBuilder();
        Matcher component = Pattern.compile("\"([^\"]+)\"").matcher(member.group(2));
        List<String> components = new ArrayList<>();
        while (component.find())
            components.add(component.group(1));
        for (String name : components) {
            String value;
            if (name.equals("@method"))
                value = recorded.getMethod();
            else if (name.equals("@target-uri"))
                value = origin + requestLineTarget(recorded);
            else if (name.startsWith("@"))
                throw new AssertionError("component not rebuilt by the test: " + name);
            else
                value = recorded.getHeader(name).trim();
            base.append('"').append(name).append("\": ").append(value).append('\n');
        }
        base.append("\"@signature-params\": ").append(member.group(1));

        Matcher value = Pattern.compile("install=:([^:]*):").matcher(signature);
        assertTrue(signature, value.find());
        Signature verifier = Signature.getInstance("SHA256withECDSAinP1363Format");
        verifier.initVerify(INSTALL_KEY.getPublic());
        verifier.update(base.toString().getBytes(StandardCharsets.UTF_8));
        assertTrue("the install signature verifies over\n" + base + "\nsigned\n" + SIGNED, verifier.verify(
                Base64.getDecoder().decode(value.group(1))));
        return base.toString();
    }

    private static String sha256(byte[] body) throws Exception {
        return "sha-256=:" + Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(body)) + ":";
    }

    @Test
    public void theServerReceivesTheTokenAndTraceHeaders() throws Exception {
        RecordedRequest recorded = get("/data");
        assertEquals("jwt-token", recorded.getHeader("Approov-Token"));
        assertEquals("trace-1", recorded.getHeader("Approov-TraceID"));
        assertNull(recorded.getHeader("Signature"));
    }

    @Test
    public void aSignedGetVerifiesOverWhatTheServerReceived() throws Exception {
        ApproovService.setServiceMutator(new KeySigner().setDefaultFactory(
                ApproovDefaultMessageSigning.generateDefaultSignatureParametersFactory()));
        RecordedRequest recorded = get("/data?q=a%20b&p=x");
        String base = verifyInstallSignature(recorded);
        assertTrue(base, base.contains("\"@target-uri\": " + origin + "/data?q=a%20b&p=x\n"));
        assertTrue(base, base.contains("\"approov-token\": jwt-token\n"));
        assertTrue(base, base.contains("\"approov-traceid\": trace-1\n"));
    }

    @Test
    public void aPostWrittenToTheReturnedConnectionIsSentWithItsTokenAndDigest() throws Exception {
        ApproovService.setServiceMutator(new KeySigner().setDefaultFactory(
                ApproovDefaultMessageSigning.generateDefaultSignatureParametersFactory()));
        byte[] body = "{\"a\":1}".getBytes(StandardCharsets.UTF_8);
        server.enqueue(new MockResponse().setBody("ok"));
        HttpsURLConnection request = open("/post");
        request.setRequestMethod("POST");
        request.setDoOutput(true);
        request.setRequestProperty("Content-Type", "application/json");
        HttpsURLConnection connection = ApproovService.addApproovToConnection(request);
        assertNotSame("a body is buffered until the request is sent", request, connection);
        try (OutputStream out = connection.getOutputStream()) {
            out.write(body);
        }
        assertEquals(200, connection.getResponseCode());
        RecordedRequest recorded = take();
        assertEquals("POST", recorded.getMethod());
        assertEquals("{\"a\":1}", recorded.getBody().readUtf8());
        assertEquals(sha256(body), recorded.getHeader("Content-Digest"));
        assertEquals("jwt-token", recorded.getHeader("Approov-Token"));
        assertEquals("trace-1", recorded.getHeader("Approov-TraceID"));
        String input = recorded.getHeader("Signature-Input");
        assertTrue(input, input.contains("\"content-digest\"") && input.contains("\"content-type\""));
    }

    @Test
    public void aPostWrittenToTheReturnedConnectionIsDigestedAndSigned() throws Exception {
        ApproovService.setServiceMutator(new KeySigner().setDefaultFactory(
                ApproovDefaultMessageSigning.generateDefaultSignatureParametersFactory()));
        byte[] body = "{\"a\":1}".getBytes(StandardCharsets.UTF_8);
        server.enqueue(new MockResponse().setBody("ok"));
        HttpsURLConnection request = open("/post");
        request.setRequestMethod("POST");
        request.setDoOutput(true);
        request.setRequestProperty("Content-Type", "application/json");
        HttpsURLConnection connection = ApproovService.addApproovToConnection(request);
        assertNotSame("a body is buffered until the request is sent", request, connection);
        try (OutputStream out = connection.getOutputStream()) {
            out.write(body);
        }
        assertEquals(200, connection.getResponseCode());
        RecordedRequest recorded = take();
        assertEquals("POST", recorded.getMethod());
        assertEquals("{\"a\":1}", recorded.getBody().readUtf8());
        assertEquals(sha256(body), recorded.getHeader("Content-Digest"));
        assertEquals("jwt-token", recorded.getHeader("Approov-Token"));
        String base = verifyInstallSignature(recorded);
        assertTrue(base, base.contains("\"content-digest\": " + sha256(body) + "\n"));
        assertTrue(base, base.contains("\"content-type\": application/json\n"));
    }

    @Test
    public void aPostWhoseBodyIsGivenToAddApproovIsDigestedAndSigned() throws Exception {
        ApproovService.setServiceMutator(new KeySigner().setDefaultFactory(
                ApproovDefaultMessageSigning.generateDefaultSignatureParametersFactory()));
        byte[] body = "a=1&b=2".getBytes(StandardCharsets.UTF_8);
        server.enqueue(new MockResponse().setBody("ok"));
        HttpsURLConnection request = open("/form");
        request.setRequestMethod("POST");
        request.setDoOutput(true);
        request.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        ApproovService.addApproov(request, body);
        try (OutputStream out = request.getOutputStream()) {
            out.write(body);
        }
        assertEquals(200, request.getResponseCode());
        RecordedRequest recorded = take();
        assertEquals(sha256(body), recorded.getHeader("Content-Digest"));
        verifyInstallSignature(recorded);
    }

    // a processed request hook that changes the token and adds a header
    private static ApproovServiceMutator forging() {
        return new ApproovServiceMutator() {
            @Override
            public HttpsURLConnection handleInterceptorProcessedRequest(HttpsURLConnection request,
                    ApproovRequestMutations changes) {
                request.setRequestProperty("Approov-Token", "forged");
                request.setRequestProperty("X-App", "added");
                return request;
            }
        };
    }

    @Test
    public void theSignatureCoversTheTokenTheLayerSetWhenTheHookChangesIt() throws Exception {
        ApproovService.setServiceMutator(new KeySigner(forging()).setDefaultFactory(
                ApproovDefaultMessageSigning.generateDefaultSignatureParametersFactory()
                        .setUseInstallAndAccountMessageSigning()
                        .addOptionalHeaders("X-App")));
        RecordedRequest recorded = get("/get");
        assertEquals("jwt-token", recorded.getHeader("Approov-Token"));
        assertEquals("added", recorded.getHeader("X-App"));
        assertTrue(verifyInstallSignature(recorded).contains("\"approov-token\": jwt-token\n"));
        assertTrue(recorded.getHeader("Signature").contains("account=:"));
    }

    @Test
    public void aPostKeepsTheTokenTheLayerSetWhenTheHookChangesIt() throws Exception {
        ApproovService.setServiceMutator(new KeySigner(forging()).setDefaultFactory(
                ApproovDefaultMessageSigning.generateDefaultSignatureParametersFactory()));
        // the hook runs when the body is sent
        server.enqueue(new MockResponse().setBody("ok"));
        HttpsURLConnection request = open("/post");
        request.setRequestMethod("POST");
        request.setDoOutput(true);
        HttpsURLConnection connection = ApproovService.addApproovToConnection(request);
        try (OutputStream out = connection.getOutputStream()) {
            out.write("x".getBytes(StandardCharsets.UTF_8));
        }
        assertEquals(200, connection.getResponseCode());
        RecordedRequest recorded = take();
        assertEquals("jwt-token", recorded.getHeader("Approov-Token"));
        assertEquals("added", recorded.getHeader("X-App"));
        assertNotNull(recorded.getHeader("Signature"));
    }

    @Test
    public void anUnknownUrlIsSentWithNothingApproovAdds() throws Exception {
        ApproovService.setServiceMutator(ApproovDefaultMessageSigning.combined(ApproovServiceMutator.ALWAYS_PROCEED));
        answer(Approov.TokenFetchStatus.UNKNOWN_URL, null, "trace-u");
        assertNoApproovHeaders("UNKNOWN_URL", get("/unknown"));
    }

    @Test
    public void anAbortedRequestSendsNothing() throws Exception {
        answer(Approov.TokenFetchStatus.REJECTED, null, "trace-r");
        HttpsURLConnection request = open("/rejected");
        ApproovFetchStatusException e = assertThrows(ApproovFetchStatusException.class,
                () -> ApproovService.addApproovToConnection(request));
        assertSame(Approov.TokenFetchStatus.REJECTED, e.getTokenFetchStatus());
        assertEquals(0, server.getRequestCount());
    }

    @Test
    public void anAbortedPostSendsNothing() throws Exception {
        answer(Approov.TokenFetchStatus.NO_NETWORK, null, null);
        HttpsURLConnection request = open("/post");
        request.setRequestMethod("POST");
        request.setDoOutput(true);
        assertThrows(ApproovNetworkException.class, () -> ApproovService.addApproovToConnection(request));
        assertEquals(0, server.getRequestCount());
    }

    @Test
    public void aRequiredDigestFailureOfABufferedPostFailsTheResponse() throws Exception {
        ApproovService.setServiceMutator(new KeySigner().setDefaultFactory(
                ApproovDefaultMessageSigning.generateDefaultSignatureParametersFactory()
                        .setBodyDigestConfig(ApproovDefaultMessageSigning.DIGEST_SHA256, true)));
        HttpsURLConnection request = open("/post");
        request.setRequestMethod("POST");
        HttpsURLConnection connection = ApproovService.addApproovToConnection(request);
        // no body is written, so the required digest cannot be made when the request is sent
        java.io.IOException e = assertThrows(java.io.IOException.class, connection::getResponseCode);
        assertTrue(String.valueOf(e.getCause()), e.getCause() instanceof ApproovException);
        assertEquals(0, server.getRequestCount());
    }

    @Test
    public void bypassModeSendsTheRequestUntouched() throws Exception {
        ApproovService.reset();
        ApproovService.initialize(ApproovTestSupport.mockContext(), "");
        RecordedRequest recorded = get("/bypass");
        assertNoApproovHeaders("bypass", recorded);
        approov.verify(() -> Approov.fetchApproovTokenAndWait(anyString()), Mockito.never());
    }
}
