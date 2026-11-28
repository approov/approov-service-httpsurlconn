package io.approov.service.httpsurlconn;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;

import com.criticalblue.approovsdk.Approov;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.HttpsURLConnection;

/**
 * The token fetch status of a request URL decides what the request carries:
 *
 * - SUCCESS (a token-protected API): the token header and the trace header, which replace any value the app
 *   set on the same header names.
 * - UNPROTECTED_URL (a secrets-only API) and UNKNOWN_URL (a host not added to Approov): no Approov header and
 *   no signature, under any decisions.
 * - NO_APPROOV_SERVICE: the token header with the prefix and an empty token, or the status name with
 *   setUseApproovStatusIfNoToken(true), and the trace header when the SDK gave a trace ID.
 * - any other failure status: CLOSE_FAILURE aborts with ApproovNetworkException for a network failure and
 *   ApproovFetchStatusException for the rest, unless the status is sent in the token header for a network
 *   failure; ALWAYS_PROCEED proceeds with an empty token or the status name.
 *
 * Nothing Approov adds is set on a request that is aborted, excluded or sent in bypass mode.
 */
@RunWith(RobolectricTestRunner.class)
@Config(manifest = Config.NONE)
public class RequestClassificationTest {
    private static final String URL = "https://api.example.com/data";

    private MockedStatic<Approov> approov;

    @Before
    public void setUp() {
        approov = Mockito.mockStatic(Approov.class);
        ApproovTestSupport.initializeApproovService(approov);
        ApproovTestSupport.sdkSignsWithBoth(approov);
    }

    @After
    public void tearDown() {
        approov.close();
        ApproovService.reset();
    }

    // every token fetch status that is a failure, that is all but SUCCESS, UNKNOWN_URL and UNPROTECTED_URL
    private static List<Approov.TokenFetchStatus> failureStatuses() {
        List<Approov.TokenFetchStatus> statuses = new ArrayList<>();
        for (Approov.TokenFetchStatus status : Approov.TokenFetchStatus.values()) {
            if ((status != Approov.TokenFetchStatus.SUCCESS) && (status != Approov.TokenFetchStatus.UNKNOWN_URL)
                    && (status != Approov.TokenFetchStatus.UNPROTECTED_URL))
                statuses.add(status);
        }
        return statuses;
    }

    private void answer(Approov.TokenFetchStatus status, String token, String traceID) {
        Approov.TokenFetchResult result = ApproovTestSupport.tokenResult(status, token, "", traceID);
        approov.when(() -> Approov.fetchApproovTokenAndWait(anyString())).thenReturn(result);
    }

    private static HttpsURLConnection send() throws Exception {
        HttpsURLConnection request = ApproovTestSupport.connection(URL);
        ApproovService.addApproov(request);
        return request;
    }

    private static void assertNoApproovHeaders(String what, HttpsURLConnection request) {
        assertNull(what, request.getRequestProperty("Approov-Token"));
        assertNull(what, request.getRequestProperty("Approov-TraceID"));
        assertNull(what, request.getRequestProperty("Signature"));
        assertNull(what, request.getRequestProperty("Signature-Input"));
    }

    @Test
    public void successAddsTheTokenAndTraceHeaders() throws Exception {
        answer(Approov.TokenFetchStatus.SUCCESS, "jwt-token", "trace-1");
        HttpsURLConnection request = send();
        assertEquals("jwt-token", request.getRequestProperty("Approov-Token"));
        assertEquals("trace-1", request.getRequestProperty("Approov-TraceID"));
        assertNull("there is no status header", request.getRequestProperty("Approov-Status"));
        approov.verify(() -> Approov.fetchApproovTokenAndWait(URL));
    }

    @Test
    public void theTokenIsFetchedForTheUrlOfTheRequest() throws Exception {
        answer(Approov.TokenFetchStatus.SUCCESS, "jwt-token", null);
        String url = "https://api.example.com:8443/v1/items?q=1";
        ApproovService.addApproov(ApproovTestSupport.connection(url));
        approov.verify(() -> Approov.fetchApproovTokenAndWait(url));
    }

    @Test
    public void theTokenHeaderReplacesAnAppSetValueWhateverItsCase() throws Exception {
        answer(Approov.TokenFetchStatus.SUCCESS, "jwt-token", "trace-1");
        HttpsURLConnection request = ApproovTestSupport.connection(URL);
        request.setRequestProperty("approov-token", "forged");
        request.setRequestProperty("approov-traceid", "x");
        ApproovService.addApproov(request);
        assertEquals("jwt-token", request.getRequestProperty("Approov-Token"));
        assertEquals("trace-1", request.getRequestProperty("Approov-TraceID"));
        int tokens = 0;
        for (String name : request.getRequestProperties().keySet()) {
            if ("approov-token".equalsIgnoreCase(name))
                tokens += request.getRequestProperties().get(name).size();
        }
        assertEquals("one token header", 1, tokens);
    }

    @Test
    public void theTokenHeaderAndPrefixAreConfigurable() throws Exception {
        answer(Approov.TokenFetchStatus.SUCCESS, "jwt-token", "trace-1");
        ApproovService.setTokenHeader("X-Token", "Bearer ");
        ApproovService.setTraceIDHeader("X-Trace");
        HttpsURLConnection request = send();
        assertEquals("Bearer jwt-token", request.getRequestProperty("X-Token"));
        assertEquals("trace-1", request.getRequestProperty("X-Trace"));
        assertNull(request.getRequestProperty("Approov-Token"));
        assertNull(request.getRequestProperty("Approov-TraceID"));
    }

    @Test
    public void aNullTraceIDHeaderOrTraceIDSendsNoTraceHeader() throws Exception {
        answer(Approov.TokenFetchStatus.SUCCESS, "jwt-token", "trace-1");
        ApproovService.setTraceIDHeader(null);
        assertNull(send().getRequestProperty("Approov-TraceID"));
        ApproovService.setTraceIDHeader("Approov-TraceID");
        answer(Approov.TokenFetchStatus.SUCCESS, "jwt-token", null);
        assertNull(send().getRequestProperty("Approov-TraceID"));
    }

    @Test
    public void anEmptyTraceIDIsSentAsAnEmptyHeader() throws Exception {
        answer(Approov.TokenFetchStatus.SUCCESS, "jwt-token", "");
        HttpsURLConnection request = send();
        assertEquals("jwt-token", request.getRequestProperty("Approov-Token"));
        assertEquals("", request.getRequestProperty("Approov-TraceID"));
    }

    @Test
    public void closeFailureSendsNoApproovServiceWithAnEmptyToken() throws Exception {
        answer(Approov.TokenFetchStatus.NO_APPROOV_SERVICE, null, "trace-nas");
        HttpsURLConnection request = send();
        assertEquals("", request.getRequestProperty("Approov-Token"));
        assertEquals("trace-nas", request.getRequestProperty("Approov-TraceID"));
        ApproovService.setTokenHeader("X-Token", "Bearer ");
        assertEquals("Bearer ", send().getRequestProperty("X-Token"));
        ApproovService.setUseApproovStatusIfNoToken(true);
        assertEquals("Bearer NO_APPROOV_SERVICE", send().getRequestProperty("X-Token"));
    }

    // one row per failure status, under both standard mutators, with the status in the token header off and on
    @Test
    public void perStatusTokenTable() throws Exception {
        ApproovServiceMutator[] mutators = {ApproovServiceMutator.CLOSE_FAILURE, ApproovServiceMutator.ALWAYS_PROCEED};
        for (ApproovServiceMutator mutator : mutators) {
            for (boolean useStatus : new boolean[] {false, true}) {
                for (Approov.TokenFetchStatus status : failureStatuses()) {
                    String what = mutator + (useStatus ? " status on " : " status off ") + status;
                    ApproovService.setServiceMutator(mutator);
                    ApproovService.setUseApproovStatusIfNoToken(useStatus);
                    answer(status, null, "trace-" + status);
                    boolean network = ApproovServiceMutator.isNetworkFailure(status);
                    boolean proceeds = (mutator == ApproovServiceMutator.ALWAYS_PROCEED)
                            || (status == Approov.TokenFetchStatus.NO_APPROOV_SERVICE) || (network && useStatus);
                    HttpsURLConnection request = ApproovTestSupport.connection(URL);
                    if (proceeds) {
                        ApproovService.addApproov(request);
                        assertEquals(what, useStatus ? status.name() : "", request.getRequestProperty("Approov-Token"));
                        assertEquals(what, "trace-" + status, request.getRequestProperty("Approov-TraceID"));
                    } else {
                        try {
                            ApproovService.addApproov(request);
                            fail(what + ": must abort");
                        } catch (ApproovFetchStatusException | ApproovNetworkException e) {
                            assertEquals(what, network ? ApproovNetworkException.class
                                    : ApproovFetchStatusException.class, e.getClass());
                            Approov.TokenFetchStatus thrown = (e instanceof ApproovNetworkException)
                                    ? ((ApproovNetworkException) e).getTokenFetchStatus()
                                    : ((ApproovFetchStatusException) e).getTokenFetchStatus();
                            assertSame(what, status, thrown);
                            assertEquals(what, "Approov token fetch for " + URL + ": " + status, e.getMessage());
                        }
                        assertNoApproovHeaders(what, request);
                    }
                }
            }
        }
    }

    // one row per token fetch status, under both standard decisions with a signer installed and the status in
    // the token header off and on: the token header and the signature headers
    @Test
    public void perStatusTokenTableCoversSignatures() throws Exception {
        ApproovServiceMutator[] decisions = {ApproovServiceMutator.CLOSE_FAILURE, ApproovServiceMutator.ALWAYS_PROCEED};
        for (ApproovServiceMutator decision : decisions) {
            for (boolean useStatus : new boolean[] {false, true}) {
                for (Approov.TokenFetchStatus status : Approov.TokenFetchStatus.values()) {
                    String what = decision + (useStatus ? " status on " : " status off ") + status;
                    ApproovService.setServiceMutator(ApproovDefaultMessageSigning.combined(decision));
                    ApproovService.setUseApproovStatusIfNoToken(useStatus);
                    boolean success = status == Approov.TokenFetchStatus.SUCCESS;
                    answer(status, success ? "jwt-token" : null, "trace-" + status);
                    boolean failure = failureStatuses().contains(status);
                    boolean network = ApproovServiceMutator.isNetworkFailure(status);
                    boolean aborts = failure && (decision == ApproovServiceMutator.CLOSE_FAILURE)
                            && (status != Approov.TokenFetchStatus.NO_APPROOV_SERVICE) && !(network && useStatus);
                    HttpsURLConnection request = ApproovTestSupport.connection(URL);
                    if (aborts) {
                        assertThrows(what, ApproovException.class, () -> ApproovService.addApproov(request));
                        assertNoApproovHeaders(what, request);
                        continue;
                    }
                    ApproovService.addApproov(request);
                    boolean token = success || failure;
                    String expectedToken = success ? "jwt-token" : (failure ? (useStatus ? status.name() : "") : null);
                    assertEquals(what + ": token header", expectedToken, request.getRequestProperty("Approov-Token"));
                    assertEquals(what + ": trace header", token ? "trace-" + status : null,
                            request.getRequestProperty("Approov-TraceID"));
                    if (token) {
                        String input = request.getRequestProperty("Signature-Input");
                        assertNotNull(what + ": Signature-Input", input);
                        assertNotNull(what + ": Signature", request.getRequestProperty("Signature"));
                        assertTrue(what + ": " + input, input.contains("\"approov-token\""));
                    } else {
                        assertNoApproovHeaders(what, request);
                    }
                }
            }
        }
    }

    @Test
    public void outOfTheBoxAndWithNullTheDecisionsAreCloseFailure() throws Exception {
        for (boolean installNull : new boolean[] {false, true}) {
            if (installNull)
                ApproovService.setServiceMutator(null);
            assertSame(ApproovServiceMutator.CLOSE_FAILURE, ApproovService.getServiceMutator());
            answer(Approov.TokenFetchStatus.REJECTED, null, "trace-r");
            ApproovFetchStatusException rejected = assertThrows(ApproovFetchStatusException.class,
                    RequestClassificationTest::send);
            assertSame(Approov.TokenFetchStatus.REJECTED, rejected.getTokenFetchStatus());
            answer(Approov.TokenFetchStatus.NO_NETWORK, null, "trace-n");
            ApproovNetworkException network = assertThrows(ApproovNetworkException.class,
                    RequestClassificationTest::send);
            assertSame(Approov.TokenFetchStatus.NO_NETWORK, network.getTokenFetchStatus());
            answer(Approov.TokenFetchStatus.NO_APPROOV_SERVICE, null, "trace-s");
            HttpsURLConnection request = send();
            assertEquals("", request.getRequestProperty("Approov-Token"));
            assertEquals("trace-s", request.getRequestProperty("Approov-TraceID"));
        }
    }

    @Test
    @SuppressWarnings("deprecation")
    public void proceedOnNetworkFailSendsANetworkFailureWithoutApproovHeaders() throws Exception {
        ApproovService.setProceedOnNetworkFail(true);
        answer(Approov.TokenFetchStatus.POOR_NETWORK, null, "trace-p");
        assertNoApproovHeaders("proceed on network fail", send());
        // the status in the token header takes precedence
        ApproovService.setUseApproovStatusIfNoToken(true);
        assertEquals("POOR_NETWORK", send().getRequestProperty("Approov-Token"));
    }

    @Test
    public void aProceedingFailureIsSignedOverTheTokenHeaderAsSent() throws Exception {
        ApproovService.setServiceMutator(ApproovDefaultMessageSigning.combined(ApproovServiceMutator.ALWAYS_PROCEED));
        answer(Approov.TokenFetchStatus.NO_NETWORK, null, "trace-nn");
        HttpsURLConnection request = send();
        assertEquals("", request.getRequestProperty("Approov-Token"));
        String input = request.getRequestProperty("Signature-Input");
        assertNotNull("Signature-Input", input);
        assertNotNull("Signature", request.getRequestProperty("Signature"));
        assertTrue(input, input.contains("\"approov-token\""));
    }

    @Test
    public void unknownAndUnprotectedURLsCarryNoApproovHeader() throws Exception {
        ApproovService.setServiceMutator(ApproovDefaultMessageSigning.combined(ApproovServiceMutator.ALWAYS_PROCEED));
        ApproovService.setUseApproovStatusIfNoToken(true);
        for (Approov.TokenFetchStatus status : new Approov.TokenFetchStatus[] {
                Approov.TokenFetchStatus.UNKNOWN_URL, Approov.TokenFetchStatus.UNPROTECTED_URL}) {
            answer(status, null, "trace-" + status);
            assertNoApproovHeaders(status.name(), send());
        }
    }

    @Test
    public void anExcludedURLIsNotProcessed() throws Exception {
        answer(Approov.TokenFetchStatus.SUCCESS, "jwt-token", "trace-1");
        ApproovService.addExclusionURLRegex("/excluded");
        HttpsURLConnection request = ApproovTestSupport.connection("https://api.example.com/excluded");
        ApproovService.addApproov(request);
        assertNoApproovHeaders("excluded", request);
        approov.verify(() -> Approov.fetchApproovTokenAndWait(anyString()), never());
    }

    @Test
    public void aCustomShouldProcessDecisionSkipsTheRequest() throws Exception {
        answer(Approov.TokenFetchStatus.SUCCESS, "jwt-token", "trace-1");
        ApproovService.setServiceMutator(new ApproovServiceMutator() {
            @Override
            public boolean handleInterceptorShouldProcessConnection(HttpsURLConnection request) {
                return false;
            }
        });
        assertNoApproovHeaders("skipped", send());
        approov.verify(() -> Approov.fetchApproovTokenAndWait(anyString()), never());
    }

    @Test
    public void anExceptionFromTheAppsMutatorReachesTheAppAndNothingIsAdded() throws Exception {
        answer(Approov.TokenFetchStatus.SUCCESS, "jwt-token", "trace-1");
        ApproovException own = new ApproovException("only my own hosts");
        ApproovService.setServiceMutator(new ApproovServiceMutator() {
            @Override
            public boolean handleInterceptorFetchTokenResult(Approov.TokenFetchResult results, String url)
                    throws ApproovException {
                throw own;
            }
        });
        HttpsURLConnection request = ApproovTestSupport.connection(URL);
        assertSame(own, assertThrows(ApproovException.class, () -> ApproovService.addApproov(request)));
        assertNoApproovHeaders("aborted by the app", request);
    }

    @Test
    public void bypassModeAddsNothingAndFetchesNothing() throws Exception {
        ApproovService.reset();
        ApproovService.initialize(ApproovTestSupport.mockContext(), "");
        approov.clearInvocations();
        HttpsURLConnection request = ApproovTestSupport.connection(URL);
        assertSame(request, ApproovService.addApproovToConnection(request));
        assertNoApproovHeaders("bypass", request);
        approov.verifyNoInteractions();
    }

    @Test
    public void theBindingHeaderValueIsSetInTheTokenBeforeTheFetch() throws Exception {
        answer(Approov.TokenFetchStatus.SUCCESS, "jwt-token", null);
        ApproovService.setBindingHeader("X-Binding");
        HttpsURLConnection request = ApproovTestSupport.connection(URL);
        request.setRequestProperty("X-Binding", "user-session");
        approov.clearInvocations();
        ApproovService.addApproov(request);
        org.mockito.InOrder order = Mockito.inOrder(Approov.class);
        order.verify(approov, () -> Approov.setDataHashInToken("user-session"));
        order.verify(approov, () -> Approov.fetchApproovTokenAndWait(URL));
        // a request without the binding header sets nothing
        approov.clearInvocations();
        send();
        approov.verify(() -> Approov.setDataHashInToken(anyString()), never());
    }
}
