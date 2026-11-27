package io.approov.service.httpsurlconn;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;

import com.criticalblue.approovsdk.Approov;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.net.HttpURLConnection;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.net.ssl.HttpsURLConnection;

/**
 * The pinning hook, handlePinningShouldProcessRequest, is asked for every request the layer prepares while
 * Approov protection is enabled, with the connection as it is sent, also for a request that is excluded from
 * token processing. A request it opts out gets no Approov pinning and relies on OS trust only. Message signing
 * forwards the hook to its decisions. Before initialization fails and in bypass mode the hook is not asked
 * and the request is not pinned.
 */
public class PinningHookTest {
    private static final String URL = "https://api.example.com/data";

    private MockedStatic<Approov> approov;

    // the connections the pinning hook was asked about, in order
    private final List<HttpURLConnection> asked = Collections.synchronizedList(new ArrayList<HttpURLConnection>());

    @Before
    public void setUp() {
        approov = Mockito.mockStatic(Approov.class);
        ApproovTestSupport.initializeApproovService(approov);
        Approov.TokenFetchResult success =
                ApproovTestSupport.tokenResult(Approov.TokenFetchStatus.SUCCESS, "jwt-token", "", "trace-1");
        approov.when(() -> Approov.fetchApproovTokenAndWait(anyString())).thenReturn(success);
    }

    @After
    public void tearDown() {
        approov.close();
        ApproovService.reset();
    }

    // a mutator whose pinning hook records the connection it is asked about and answers with the decision given
    private ApproovServiceMutator pinningDecidedBy(boolean pin) {
        return new ApproovServiceMutator() {
            @Override
            public boolean handlePinningShouldProcessRequest(HttpURLConnection request) {
                asked.add(request);
                return pin;
            }
        };
    }

    // true if the connection is checked against the Approov pins
    private static boolean pinned(HttpsURLConnection connection) {
        return connection.getHostnameVerifier() instanceof PinningHostnameVerifier;
    }

    @Test
    public void aRequestIsPinnedByDefault() throws Exception {
        HttpsURLConnection request = ApproovTestSupport.connection(URL);
        ApproovService.addApproov(request);
        assertTrue(pinned(request));
    }

    @Test
    public void theHookIsAskedWithTheConnection() throws Exception {
        ApproovService.setServiceMutator(pinningDecidedBy(true));
        HttpsURLConnection request = ApproovTestSupport.connection(URL);
        ApproovService.addApproov(request);
        assertEquals(1, asked.size());
        assertSame(request, asked.get(0));
        assertTrue(pinned(request));
        assertEquals("jwt-token", request.getRequestProperty("Approov-Token"));
    }

    @Test
    public void anOptedOutRequestGetsNoApproovPinningButKeepsItsToken() throws Exception {
        ApproovService.setServiceMutator(pinningDecidedBy(false));
        HttpsURLConnection request = ApproovTestSupport.connection(URL);
        javax.net.ssl.HostnameVerifier before = request.getHostnameVerifier();
        ApproovService.addApproov(request);
        assertFalse(pinned(request));
        assertSame("the OS verifier is kept", before, request.getHostnameVerifier());
        assertEquals("jwt-token", request.getRequestProperty("Approov-Token"));
    }

    @Test
    public void anExcludedRequestIsStillAskedAndPinned() throws Exception {
        ApproovService.setServiceMutator(pinningDecidedBy(true));
        ApproovService.addExclusionURLRegex(".*/excluded.*");
        HttpsURLConnection request = ApproovTestSupport.connection("https://api.example.com/excluded");
        ApproovService.addApproov(request);
        assertEquals(1, asked.size());
        assertTrue("an excluded request to a protected host is still pinned", pinned(request));
        assertNull(request.getRequestProperty("Approov-Token"));
        approov.verify(() -> Approov.fetchApproovTokenAndWait(anyString()), never());
    }

    @Test
    public void aRequestWhoseTokenFetchFailsIsStillPinned() throws Exception {
        Approov.TokenFetchResult unknown = ApproovTestSupport.tokenResult(Approov.TokenFetchStatus.UNKNOWN_URL);
        approov.when(() -> Approov.fetchApproovTokenAndWait(anyString())).thenReturn(unknown);
        HttpsURLConnection request = ApproovTestSupport.connection(URL);
        ApproovService.addApproov(request);
        assertTrue(pinned(request));
    }

    @Test
    public void messageSigningForwardsTheHookToItsDecisions() throws Exception {
        ApproovService.setServiceMutator(ApproovDefaultMessageSigning.combined(pinningDecidedBy(false)));
        HttpsURLConnection request = ApproovTestSupport.connection(URL);
        ApproovService.addApproov(request);
        assertEquals(1, asked.size());
        assertFalse(pinned(request));
    }

    @Test
    public void inBypassModeTheHookIsNotAskedAndNothingIsPinned() throws Exception {
        ApproovService.reset();
        ApproovService.initialize(ApproovTestSupport.mockContext(), "");
        ApproovService.setServiceMutator(pinningDecidedBy(true));
        HttpsURLConnection request = ApproovTestSupport.connection(URL);
        ApproovService.addApproov(request);
        assertEquals(0, asked.size());
        assertFalse(pinned(request));
        assertNull(request.getRequestProperty("Approov-Token"));
    }

    @Test
    public void eachInitializeMakesOneVerifierThatTheRequestsShare() throws Exception {
        HttpsURLConnection first = ApproovTestSupport.connection(URL);
        HttpsURLConnection second = ApproovTestSupport.connection(URL);
        ApproovService.addApproov(first);
        ApproovService.addApproov(second);
        assertSame(first.getHostnameVerifier(), second.getHostnameVerifier());
        ApproovService.initialize(ApproovTestSupport.mockContext(), "test-account");
        HttpsURLConnection third = ApproovTestSupport.connection(URL);
        ApproovService.addApproov(third);
        assertTrue(pinned(third));
        assertFalse(first.getHostnameVerifier() == third.getHostnameVerifier());
    }
}
