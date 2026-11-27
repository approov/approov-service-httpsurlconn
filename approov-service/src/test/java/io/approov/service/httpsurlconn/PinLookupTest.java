package io.approov.service.httpsurlconn;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.when;

import android.util.Log;

import com.criticalblue.approovsdk.Approov;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;
import org.robolectric.shadows.ShadowLog;

import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.net.ssl.SSLSession;

import okhttp3.tls.HeldCertificate;

/**
 * Pin lookup and the pin decisions of PinningHostnameVerifier. The pins of a connection are looked up exactly
 * per host, without regard to case and ignoring one trailing dot, on both the host and the keys of the SDK pin
 * set. The "*" key is the managed trust roots of a listed host with no pins of its own, never a pattern. A
 * listed host with no pins and no managed trust roots connects on OS trust with one warning per host. A pin set
 * that cannot be read (SDK failure or null) continues on OS trust with one error log per process, and a domain
 * with no pin list is a listed host with no pins. A pin mismatch fails the connection, logged at error level
 * without any pin. Before initialization and in bypass mode only the delegate decides.
 */
@RunWith(RobolectricTestRunner.class)
@Config(manifest = Config.NONE)
public class PinLookupTest {
    // a pin no fixture certificate matches
    private static final String WRONG_PIN = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    private static final String OS_TRUST_WARNING =
            "Approov domain localhost: no pins and no managed trust roots, OS trust only";

    private static final HeldCertificate SERVER = new HeldCertificate.Builder().commonName("localhost").build();

    private MockedStatic<Approov> approov;
    private String rightPin;
    private SSLSession session;

    @Before
    public void setUp() throws Exception {
        ShadowLog.reset();
        approov = Mockito.mockStatic(Approov.class);
        ApproovTestSupport.initializeApproovService(approov);
        rightPin = pin(SERVER);
        session = mock(SSLSession.class);
        when(session.getPeerCertificates()).thenReturn(new Certificate[] {SERVER.certificate()});
    }

    @After
    public void tearDown() {
        approov.close();
        ApproovService.reset();
        ShadowLog.reset();
    }

    static String pin(HeldCertificate certificate) throws Exception {
        return Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256")
                .digest(certificate.certificate().getPublicKey().getEncoded()));
    }

    // the pin set the SDK reports, from alternating keys and pin lists
    private void pins(Object... keysAndPins) {
        Map<String, List<String>> map = new HashMap<>();
        for (int i = 0; i < keysAndPins.length; i += 2) {
            @SuppressWarnings("unchecked")
            List<String> list = (List<String>) keysAndPins[i + 1];
            map.put((String) keysAndPins[i], list);
        }
        approov.when(() -> Approov.getPins("public-key-sha256")).thenReturn(map);
    }

    private static List<String> list(String... pins) {
        return new ArrayList<>(Arrays.asList(pins));
    }

    // a verifier whose platform validates the chain as presented
    private static PinningHostnameVerifier verifier() {
        return new PinningHostnameVerifier((hostname, sslSession) -> true,
                new PinningHostnameVerifier.PlatformTrust((presented, host) -> Arrays.asList(presented),
                        Collections.<X509Certificate>emptySet()));
    }

    private boolean verify(String host) {
        return verifier().verify(host, session);
    }

    // the lines the pin verifier logged at the given level
    private static List<String> logged(int type) {
        List<String> lines = new ArrayList<>();
        for (ShadowLog.LogItem item : ShadowLog.getLogs()) {
            if ("ApproovPinVerifier".equals(item.tag) && (item.type == type))
                lines.add(item.msg);
        }
        return lines;
    }

    @Test
    public void aMatchingPinIsAccepted() {
        pins("localhost", list(WRONG_PIN, rightPin));
        assertTrue(verify("localhost"));
        assertEquals(Collections.emptyList(), logged(Log.ERROR));
    }

    @Test
    public void aKeyMatchesWithoutRegardToCase() {
        pins("LocalHost", list(WRONG_PIN));
        assertFalse("a key LocalHost pins localhost", verify("localhost"));
        pins("LOCALHOST", list(rightPin));
        assertTrue(verify("localhost"));
        pins("localhost", list(WRONG_PIN));
        assertFalse("a key localhost pins LocalHost", verify("LocalHost"));
    }

    @Test
    public void oneTrailingDotIsIgnoredOnTheKeyAndTheHost() {
        pins("localhost.", list(WRONG_PIN));
        assertFalse("a key localhost. pins localhost", verify("localhost"));
        pins("localhost", list(WRONG_PIN));
        assertFalse("localhost. is checked against the pins of localhost", verify("localhost."));
        pins("localhost.", list(rightPin));
        assertTrue(verify("LOCALHOST."));
    }

    @Test
    public void theHostIsNormalizedForTheLookup() {
        assertEquals("api.example.com", ApproovService.normalizeHost("API.Example.COM."));
        assertEquals("api.example.com.", ApproovService.normalizeHost("api.example.com.."));
        assertEquals("::1", ApproovService.normalizeHost("[::1]"));
    }

    @Test
    public void theManagedTrustRootsApplyToAListedHostUnderAnySpelling() {
        pins("LocalHost.", list(), "*", list(WRONG_PIN));
        assertFalse(verify("localhost"));
        assertFalse(verify("localhost."));
        pins("LocalHost.", list(), "*", list(rightPin));
        assertTrue(verify("localhost"));
        // a host with pins of its own does not use them
        pins("localhost", list(WRONG_PIN), "*", list(rightPin));
        assertFalse(verify("localhost"));
    }

    @Test
    public void aKeyIsNeverAPattern() {
        // the managed trust roots never apply to a host that is not listed
        pins("*", list(WRONG_PIN));
        assertTrue("* is not a wildcard", verify("localhost"));
        // the pins of a domain never apply to its subdomains or a host that contains it
        pins("host", list(WRONG_PIN), "calhost", list(WRONG_PIN), "*.localhost", list(WRONG_PIN));
        assertTrue(verify("localhost"));
        pins("localhost", list(WRONG_PIN));
        assertTrue("a subdomain is not pinned by its parent", verify("api.localhost"));
        assertEquals("no warning for a host that is not listed", Collections.emptyList(), logged(Log.WARN));
    }

    @Test
    public void anEmptyPinSetListsNoHost() {
        pins();
        assertTrue(verify("localhost"));
        assertEquals(Collections.emptyList(), logged(Log.WARN));
    }

    @Test
    public void aListedHostWithNoPinsAndNoManagedTrustRootsWarnsOncePerHost() {
        // no "*" key
        pins("localhost", list());
        assertTrue(verify("localhost"));
        assertTrue(verify("LocalHost"));
        assertTrue(verify("localhost."));
        assertEquals(Collections.singletonList(OS_TRUST_WARNING), logged(Log.WARN));
        // an empty "*", for another host
        pins("LOCALHOST.", list(), "127.0.0.1", list(), "*", list());
        assertTrue(verify("127.0.0.1"));
        assertTrue(verify("127.0.0.1"));
        assertTrue(verify("localhost"));
        assertEquals(Arrays.asList(OS_TRUST_WARNING,
                "Approov domain 127.0.0.1: no pins and no managed trust roots, OS trust only"), logged(Log.WARN));
    }

    @Test
    public void noWarningForValidManagedTrustRootsOrAHostWithPins() {
        pins("localhost", list(), "*", list(rightPin));
        assertTrue(verify("localhost"));
        pins("localhost", list(rightPin));
        assertTrue(verify("localhost"));
        // a host with pins under another spelling is never OS trust only
        pins("localhost", list(), "LOCALHOST", list(rightPin));
        assertTrue(verify("localhost"));
        assertEquals(Collections.emptyList(), logged(Log.WARN));
    }

    @Test
    public void aMismatchIsLoggedAtErrorWithoutAnyPin() {
        pins("localhost", list(WRONG_PIN, "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="));
        assertFalse(verifier().verify("LocalHost", session));
        assertEquals(Collections.singletonList("Approov pinning: no pin matches for localhost"), logged(Log.ERROR));
        assertEquals(Collections.emptyList(), logged(Log.WARN));
        for (ShadowLog.LogItem item : ShadowLog.getLogs()) {
            assertFalse(item.msg, item.msg.contains(WRONG_PIN));
            assertFalse(item.msg, item.msg.contains(rightPin));
        }
    }

    @Test
    public void aNullPinSetContinuesOnOsTrust() {
        approov.when(() -> Approov.getPins("public-key-sha256")).thenReturn(null);
        assertTrue("a pin set that cannot be read continues on OS trust", verify("localhost"));
        assertTrue(verify("localhost"));
        assertEquals(1, logged(Log.ERROR).size());
        assertTrue(logged(Log.ERROR).get(0), logged(Log.ERROR).get(0)
                .startsWith("Approov pinning: pins unavailable, OS trust only: "));
    }

    @Test
    public void aPinSetTheSdkFailsToGiveContinuesOnOsTrust() {
        IllegalStateException sdkFailure = new IllegalStateException("sdk failure");
        approov.when(() -> Approov.getPins("public-key-sha256")).thenThrow(sdkFailure);
        assertTrue(verify("localhost"));
        // a second connection is also accepted, with no second error
        assertTrue(verify("localhost"));
        assertEquals(Collections.singletonList("Approov pinning: pins unavailable, OS trust only: " + sdkFailure),
                logged(Log.ERROR));
    }

    @Test
    public void aDomainWithNoPinListIsOsTrustWithTheWarningAndOthersStayPinned() {
        pins("localhost", null, "127.0.0.1", list(WRONG_PIN));
        assertTrue(verify("localhost"));
        assertEquals(Collections.singletonList(OS_TRUST_WARNING), logged(Log.WARN));
        assertEquals(Collections.emptyList(), logged(Log.ERROR));
        // another listed host keeps its pins, so a mismatch still fails closed
        assertFalse(verify("127.0.0.1"));
        assertEquals(Collections.singletonList("Approov pinning: no pin matches for 127.0.0.1"), logged(Log.ERROR));
        // and a match still passes
        pins("localhost", null, "127.0.0.1", list(rightPin));
        assertTrue(verify("127.0.0.1"));
    }

    @Test
    public void aPeerWithoutCertificatesMatchesNoPin() throws Exception {
        pins("localhost", list(rightPin));
        SSLSession empty = mock(SSLSession.class);
        when(empty.getPeerCertificates()).thenReturn(new Certificate[0]);
        assertFalse(verifier().verify("localhost", empty));
        SSLSession unverified = mock(SSLSession.class);
        when(unverified.getPeerCertificates()).thenThrow(new javax.net.ssl.SSLPeerUnverifiedException("none"));
        assertFalse(verifier().verify("localhost", unverified));
    }

    @Test
    public void aDelegateRejectionIsFinalAndNoPinIsChecked() throws Exception {
        pins("localhost", list(rightPin));
        PinningHostnameVerifier verifier = new PinningHostnameVerifier((hostname, s) -> false,
                new PinningHostnameVerifier.PlatformTrust((presented, host) -> Arrays.asList(presented),
                        Collections.<X509Certificate>emptySet()));
        approov.clearInvocations();
        assertFalse(verifier.verify("localhost", session));
        Mockito.verify(session, never()).getPeerCertificates();
        approov.verify(() -> Approov.getPins(Mockito.anyString()), never());
    }

    @Test
    public void beforeInitializationAndInBypassModeOnlyTheDelegateDecides() throws Exception {
        pins("localhost", list(WRONG_PIN));
        ApproovService.reset();
        assertTrue("before initialization", verify("localhost"));
        ApproovService.initialize(ApproovTestSupport.mockContext(), "");
        approov.clearInvocations();
        assertTrue("in bypass mode", verify("localhost"));
        approov.verify(() -> Approov.getPins(Mockito.anyString()), never());
    }
}
