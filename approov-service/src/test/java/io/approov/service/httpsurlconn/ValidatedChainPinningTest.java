package io.approov.service.httpsurlconn;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.criticalblue.approovsdk.Approov;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509ExtendedKeyManager;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.tls.HandshakeCertificates;
import okhttp3.tls.HeldCertificate;

/**
 * The pins are matched against the chain that vouches for the server's leaf certificate, never against any
 * other certificate the server presented. That chain is the one the platform trust manager validated or, where
 * the platform does not validate it or cannot be asked, the chain walked from the leaf by signature through the
 * presented certificates and the platform trust anchors. So a pin on a root the server does not present
 * matches, and a pinned certificate appended to a chain it did not sign does not.
 */
@RunWith(RobolectricTestRunner.class)
@Config(manifest = Config.NONE)
public class ValidatedChainPinningTest {
    private static final String HOST = "localhost";

    private MockedStatic<Approov> approov;
    private HeldCertificate root;
    private HeldCertificate intermediate;
    private HeldCertificate leaf;
    private HeldCertificate otherRoot;
    private HeldCertificate otherIntermediate;
    private HeldCertificate otherLeaf;

    @Before
    public void setUp() {
        approov = Mockito.mockStatic(Approov.class);
        ApproovTestSupport.initializeApproovService(approov);
        root = new HeldCertificate.Builder().commonName("Root").certificateAuthority(1).build();
        intermediate = new HeldCertificate.Builder().commonName("Intermediate").certificateAuthority(0)
                .signedBy(root).build();
        // the leaf names another host, so that the JVM's own host check fails and it asks the verifier
        leaf = new HeldCertificate.Builder().commonName(HOST).addSubjectAlternativeName("approov-pinning.invalid")
                .signedBy(intermediate).build();
        otherRoot = new HeldCertificate.Builder().commonName("Other Root").certificateAuthority(1).build();
        otherIntermediate = new HeldCertificate.Builder().commonName("Other Intermediate").certificateAuthority(0)
                .signedBy(otherRoot).build();
        otherLeaf = new HeldCertificate.Builder().commonName(HOST)
                .addSubjectAlternativeName("approov-pinning.invalid").signedBy(otherIntermediate).build();
    }

    @After
    public void tearDown() {
        approov.close();
        ApproovService.reset();
    }

    private void pins(String... pins) {
        approov.when(() -> Approov.getPins("public-key-sha256"))
                .thenReturn(Collections.singletonMap(HOST, Arrays.asList(pins)));
    }

    private static String pin(HeldCertificate certificate) throws Exception {
        return PinLookupTest.pin(certificate);
    }

    private static SSLSession presenting(HeldCertificate... chain) throws Exception {
        Certificate[] certificates = new Certificate[chain.length];
        for (int i = 0; i < chain.length; i++)
            certificates[i] = chain[i].certificate();
        SSLSession session = mock(SSLSession.class);
        when(session.getPeerCertificates()).thenReturn(certificates);
        return session;
    }

    private static Set<X509Certificate> anchors(HeldCertificate... roots) {
        Set<X509Certificate> anchors = new HashSet<>();
        for (HeldCertificate root : roots)
            anchors.add(root.certificate());
        return anchors;
    }

    // a verifier whose platform cannot validate a chain, with the trust anchors given
    private static PinningHostnameVerifier walking(HeldCertificate... roots) {
        return new PinningHostnameVerifier((hostname, session) -> true,
                new PinningHostnameVerifier.PlatformTrust((presented, host) -> null, anchors(roots)));
    }

    // a verifier whose platform validates the chain as given
    private static PinningHostnameVerifier validating(HeldCertificate... validated) {
        return new PinningHostnameVerifier((hostname, session) -> true,
                new PinningHostnameVerifier.PlatformTrust((presented, host) -> {
                    X509Certificate[] chain = new X509Certificate[validated.length];
                    for (int i = 0; i < validated.length; i++)
                        chain[i] = validated[i].certificate();
                    return Arrays.asList(chain);
                }, Collections.<X509Certificate>emptySet()));
    }

    @Test
    public void theIntermediatePinMatchesThePresentedChain() throws Exception {
        pins(pin(intermediate));
        assertTrue(walking(root).verify(HOST, presenting(leaf, intermediate)));
        pins(pin(leaf));
        assertTrue(walking(root).verify(HOST, presenting(leaf, intermediate)));
    }

    @Test
    public void aRootPinMatchesWhenTheServerDoesNotPresentTheRoot() throws Exception {
        pins(pin(root));
        assertTrue("the root is found among the trust anchors",
                walking(root).verify(HOST, presenting(leaf, intermediate)));
        assertTrue("the root is in the chain the platform validated",
                validating(leaf, intermediate, root).verify(HOST, presenting(leaf, intermediate)));
        assertFalse("the root is not an anchor and not presented",
                walking(otherRoot).verify(HOST, presenting(leaf, intermediate)));
    }

    @Test
    public void aPinnedCertificateAppendedToAnotherChainDoesNotMatch() throws Exception {
        pins(pin(intermediate));
        assertFalse(walking(root, otherRoot).verify(HOST, presenting(otherLeaf, otherIntermediate, intermediate)));
        assertFalse(walking(root, otherRoot).verify(HOST, presenting(otherLeaf, intermediate, otherIntermediate)));

        pins(pin(root));
        assertFalse(walking(otherRoot).verify(HOST, presenting(otherLeaf, otherIntermediate, root)));
        assertFalse("the platform validated the other chain",
                validating(otherLeaf, otherIntermediate, otherRoot)
                        .verify(HOST, presenting(otherLeaf, otherIntermediate, root, intermediate)));
    }

    @Test
    public void aCertificateThatIsNotACaCannotIssueTheLeaf() throws Exception {
        // a certificate for another domain, issued under the pinned intermediate, signs a leaf for the host
        HeldCertificate ownDomain = new HeldCertificate.Builder().commonName("other.example")
                .signedBy(intermediate).build();
        HeldCertificate forged = new HeldCertificate.Builder().commonName(HOST).signedBy(ownDomain).build();
        pins(pin(intermediate));
        assertFalse(walking(root).verify(HOST, presenting(forged, ownDomain, intermediate)));
    }

    @Test
    public void aChainThePlatformDoesNotTrustIsWalkedBySignature() throws Exception {
        PinningHostnameVerifier.PlatformTrust.ChainValidator untrusted = (presented, host) -> {
            throw new CertificateException("not trusted by the platform");
        };
        pins(pin(root));
        assertTrue(new PinningHostnameVerifier((hostname, session) -> true,
                new PinningHostnameVerifier.PlatformTrust(untrusted, anchors(root)))
                .verify(HOST, presenting(leaf, intermediate)));
        pins(pin(intermediate));
        assertFalse(new PinningHostnameVerifier((hostname, session) -> true,
                new PinningHostnameVerifier.PlatformTrust(untrusted, anchors(otherRoot)))
                .verify(HOST, presenting(otherLeaf, otherIntermediate, intermediate)));
    }

    @Test
    public void control_theDefaultPlatformTrustIsUsable() throws Exception {
        // the verifier made by initialize reads the platform trust without failing, whether or not the platform
        // can validate a chain in this environment
        List<X509Certificate> chain = PinningHostnameVerifier.PlatformTrust.platform()
                .vouchingChain(new X509Certificate[] {leaf.certificate(), intermediate.certificate()}, HOST);
        assertEquals(leaf.certificate(), chain.get(0));
        assertTrue(chain.contains(intermediate.certificate()));
    }

    @Test
    public void anAppendedPinnedCertificateIsRefusedOnTheWire() throws Exception {
        // a server whose chain the client trusts, presenting a pinned certificate it was not issued under
        MockWebServer server = new MockWebServer();
        server.useHttps(presentingFactory(otherLeaf, otherIntermediate, intermediate), false);
        server.start(InetAddress.getByName(HOST), 0);
        SSLSocketFactory clientTrust = new HandshakeCertificates.Builder()
                .addTrustedCertificate(root.certificate())
                .addTrustedCertificate(otherRoot.certificate())
                .build().sslSocketFactory();
        PinningHostnameVerifier verifier = walking(root, otherRoot);
        try {
            pins(pin(intermediate));
            HttpsURLConnection refused = (HttpsURLConnection) server.url("/appended").url().openConnection();
            refused.setSSLSocketFactory(clientTrust);
            refused.setHostnameVerifier(verifier);
            try {
                refused.getResponseCode();
                fail("a chain that does not vouch for the leaf through the pin was accepted");
            } catch (IOException expected) {
                // refused by the pin
            }
            assertEquals("nothing reached the server", 0, server.getRequestCount());

            // the pin of the chain that issued the leaf matches
            pins(pin(otherIntermediate));
            server.enqueue(new MockResponse().setBody("ok"));
            HttpsURLConnection accepted = (HttpsURLConnection) server.url("/issuer").url().openConnection();
            accepted.setSSLSocketFactory(clientTrust);
            accepted.setHostnameVerifier(verifier);
            assertEquals(200, accepted.getResponseCode());
            assertEquals(1, server.getRequestCount());
        } finally {
            server.shutdown();
        }
    }

    /**
     * Makes a server socket factory that presents the given certificates as they are, the first being the leaf
     * whose key the server holds, so that a certificate the leaf was not issued under can be appended.
     */
    private static SSLSocketFactory presentingFactory(HeldCertificate leaf, HeldCertificate... more)
            throws Exception {
        X509Certificate[] chain = new X509Certificate[more.length + 1];
        chain[0] = leaf.certificate();
        for (int i = 0; i < more.length; i++)
            chain[i + 1] = more[i].certificate();
        X509ExtendedKeyManager keyManager = new X509ExtendedKeyManager() {
            @Override
            public String[] getClientAliases(String keyType, Principal[] issuers) {
                return null;
            }

            @Override
            public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
                return null;
            }

            @Override
            public String[] getServerAliases(String keyType, Principal[] issuers) {
                return new String[] {"server"};
            }

            @Override
            public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
                return "server";
            }

            @Override
            public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
                return "server";
            }

            @Override
            public X509Certificate[] getCertificateChain(String alias) {
                return chain;
            }

            @Override
            public PrivateKey getPrivateKey(String alias) {
                return leaf.keyPair().getPrivate();
            }
        };
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(new KeyManager[] {keyManager}, null, null);
        return context.getSocketFactory();
    }
}
