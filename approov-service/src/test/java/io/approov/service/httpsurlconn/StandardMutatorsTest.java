package io.approov.service.httpsurlconn;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.criticalblue.approovsdk.Approov;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.util.Arrays;
import java.util.List;

/**
 * The decisions of the standard mutators on every token fetch status. CLOSE_FAILURE, whose decisions are
 * also the interface defaults, aborts on a failure other than NO_APPROOV_SERVICE and ALWAYS_PROCEED never
 * aborts. Under both, a secure string that cannot be obtained never aborts a request.
 */
public class StandardMutatorsTest {
    private static final String URL = "https://api.example.com/v1/items";

    private static final List<Approov.TokenFetchStatus> NETWORK_FAILURES = Arrays.asList(
            Approov.TokenFetchStatus.NO_NETWORK,
            Approov.TokenFetchStatus.POOR_NETWORK,
            Approov.TokenFetchStatus.MITM_DETECTED);

    @Before
    public void setUp() {
        ApproovService.reset();
    }

    @After
    public void tearDown() {
        ApproovService.reset();
    }

    private static Approov.TokenFetchResult result(Approov.TokenFetchStatus status) {
        return ApproovTestSupport.tokenResult(status);
    }

    // an anonymous mutator that inherits every default
    private static final ApproovServiceMutator INHERITING = new ApproovServiceMutator() {
    };

    @Test
    public void defaultIsCloseFailure() {
        assertSame(ApproovServiceMutator.CLOSE_FAILURE, ApproovServiceMutator.DEFAULT);
        assertEquals("ApproovServiceMutator.CLOSE_FAILURE", ApproovServiceMutator.CLOSE_FAILURE.toString());
        assertEquals("ApproovServiceMutator.ALWAYS_PROCEED", ApproovServiceMutator.ALWAYS_PROCEED.toString());
        ApproovService.setServiceMutator(ApproovServiceMutator.ALWAYS_PROCEED);
        ApproovService.setServiceMutator(null);
        assertSame(ApproovServiceMutator.CLOSE_FAILURE, ApproovService.getServiceMutator());
    }

    @Test
    public void closeFailureProceedsOnSuccessAndNoApproovService() throws Exception {
        for (ApproovServiceMutator mutator : Arrays.asList(ApproovServiceMutator.CLOSE_FAILURE, INHERITING)) {
            assertTrue(mutator.handleInterceptorFetchTokenResult(result(Approov.TokenFetchStatus.SUCCESS), URL));
            assertTrue(mutator.handleInterceptorFetchTokenResult(
                    result(Approov.TokenFetchStatus.NO_APPROOV_SERVICE), URL));
        }
    }

    @Test
    public void closeFailureSendsNoHeadersForUnknownAndUnprotectedUrls() throws Exception {
        for (ApproovServiceMutator mutator : Arrays.asList(ApproovServiceMutator.CLOSE_FAILURE, INHERITING)) {
            assertFalse(mutator.handleInterceptorFetchTokenResult(result(Approov.TokenFetchStatus.UNKNOWN_URL), URL));
            assertFalse(mutator.handleInterceptorFetchTokenResult(
                    result(Approov.TokenFetchStatus.UNPROTECTED_URL), URL));
        }
    }

    @Test
    public void closeFailureThrowsTheNetworkExceptionForNetworkFailures() {
        for (Approov.TokenFetchStatus status : NETWORK_FAILURES) {
            assertTrue(status.name(), ApproovServiceMutator.isNetworkFailure(status));
            ApproovNetworkException e = assertThrows(ApproovNetworkException.class, () ->
                    ApproovServiceMutator.CLOSE_FAILURE.handleInterceptorFetchTokenResult(result(status), URL));
            assertEquals(status, e.getTokenFetchStatus());
            assertEquals("Approov token fetch for " + URL + ": " + status, e.getMessage());
        }
    }

    @Test
    public void closeFailureProceedsOnANetworkFailureWhenTheStatusIsSent() throws Exception {
        ApproovService.setUseApproovStatusIfNoToken(true);
        for (Approov.TokenFetchStatus status : NETWORK_FAILURES)
            assertTrue(ApproovServiceMutator.CLOSE_FAILURE.handleInterceptorFetchTokenResult(result(status), URL));
    }

    @Test
    @SuppressWarnings("deprecation")
    public void closeFailureProceedsWithoutHeadersOnANetworkFailureWhenProceedOnNetworkFailIsSet() throws Exception {
        ApproovService.setProceedOnNetworkFail(true);
        for (Approov.TokenFetchStatus status : NETWORK_FAILURES)
            assertFalse(ApproovServiceMutator.CLOSE_FAILURE.handleInterceptorFetchTokenResult(result(status), URL));
        // only the network failures
        assertThrows(ApproovFetchStatusException.class, () -> ApproovServiceMutator.CLOSE_FAILURE
                .handleInterceptorFetchTokenResult(result(Approov.TokenFetchStatus.REJECTED), URL));
    }

    @Test
    public void closeFailureThrowsTheFetchStatusExceptionForEveryOtherStatus() {
        for (Approov.TokenFetchStatus status : Approov.TokenFetchStatus.values()) {
            switch (status) {
                case SUCCESS:
                case NO_APPROOV_SERVICE:
                case UNKNOWN_URL:
                case UNPROTECTED_URL:
                case NO_NETWORK:
                case POOR_NETWORK:
                case MITM_DETECTED:
                    continue;
                default:
                    break;
            }
            assertFalse(status.name(), ApproovServiceMutator.isNetworkFailure(status));
            ApproovFetchStatusException e = assertThrows("status " + status, ApproovFetchStatusException.class, () ->
                    ApproovServiceMutator.CLOSE_FAILURE.handleInterceptorFetchTokenResult(result(status), URL));
            assertEquals(status, e.getTokenFetchStatus());
            // REJECTED is reported as a fetch status failure like the rest, not a rejection
            assertEquals(status.name(), ApproovFetchStatusException.class, e.getClass());
        }
    }

    @Test
    public void alwaysProceedNeverThrowsAndProceedsOnEveryStatusButUnknownAndUnprotected() throws Exception {
        ApproovServiceMutator mutator = ApproovServiceMutator.ALWAYS_PROCEED;
        for (Approov.TokenFetchStatus status : Approov.TokenFetchStatus.values()) {
            boolean expected = status != Approov.TokenFetchStatus.UNKNOWN_URL
                    && status != Approov.TokenFetchStatus.UNPROTECTED_URL;
            assertEquals("status " + status, expected, mutator.handleInterceptorFetchTokenResult(result(status), URL));
        }
    }

    @Test
    public void substitutionDecisionsAreIdenticalAndNeverThrowInBothStandardMutators() throws Exception {
        for (ApproovServiceMutator mutator : Arrays.asList(
                ApproovServiceMutator.CLOSE_FAILURE, ApproovServiceMutator.ALWAYS_PROCEED, INHERITING)) {
            for (Approov.TokenFetchStatus status : Approov.TokenFetchStatus.values()) {
                boolean expected = status == Approov.TokenFetchStatus.SUCCESS;
                assertEquals(mutator + " header " + status, expected,
                        mutator.handleInterceptorHeaderSubstitutionResult(result(status), "X-Api-Key"));
            }
        }
    }

    @Test
    public void shouldProcessIsTrueForARequestAndAbortsForNone() throws Exception {
        ApproovService.initialize(ApproovTestSupport.mockContext(), "");
        for (ApproovServiceMutator mutator : Arrays.asList(
                ApproovServiceMutator.CLOSE_FAILURE, ApproovServiceMutator.ALWAYS_PROCEED)) {
            assertTrue(mutator.handleInterceptorShouldProcessConnection(ApproovTestSupport.connection(URL)));
            assertThrows(ApproovException.class, () -> mutator.handleInterceptorShouldProcessConnection(null));
        }
    }

    @Test
    public void theStandardMutatorsPinEveryRequest() throws Exception {
        for (ApproovServiceMutator mutator : Arrays.asList(ApproovServiceMutator.CLOSE_FAILURE,
                ApproovServiceMutator.ALWAYS_PROCEED, INHERITING, new ApproovDefaultMessageSigning(),
                ApproovDefaultMessageSigning.combined(),
                ApproovDefaultMessageSigning.combined(ApproovServiceMutator.ALWAYS_PROCEED)))
            assertTrue(mutator.toString(), mutator.handlePinningShouldProcessRequest(ApproovTestSupport.connection(URL)));
    }

    @Test
    public void theProcessedRequestHookOfTheStandardMutatorsReturnsTheRequestUnchanged() throws Exception {
        for (ApproovServiceMutator mutator : Arrays.asList(
                ApproovServiceMutator.CLOSE_FAILURE, ApproovServiceMutator.ALWAYS_PROCEED)) {
            javax.net.ssl.HttpsURLConnection request = ApproovTestSupport.tokenConnection(URL);
            assertSame(request, mutator.handleInterceptorProcessedRequest(request, ApproovTestSupport.tokenChanges()));
            assertEquals("t", request.getRequestProperty("Approov-Token"));
        }
    }

    @Test
    public void thePrecheckAndDirectMethodDecisionsAreUnchanged() throws Exception {
        ApproovServiceMutator mutator = ApproovServiceMutator.CLOSE_FAILURE;
        assertThrows(ApproovRejectionException.class, () ->
                mutator.handlePrecheckResult(result(Approov.TokenFetchStatus.REJECTED)));
        mutator.handlePrecheckResult(result(Approov.TokenFetchStatus.UNKNOWN_KEY));
        assertThrows(ApproovNetworkException.class, () ->
                mutator.handleFetchTokenResult(result(Approov.TokenFetchStatus.NO_NETWORK)));
        assertThrows(ApproovFetchStatusException.class, () ->
                mutator.handleFetchTokenResult(result(Approov.TokenFetchStatus.REJECTED)));
        mutator.handleFetchSecureStringResult(result(Approov.TokenFetchStatus.UNKNOWN_KEY), "lookup", "k");
        assertThrows(ApproovRejectionException.class, () ->
                mutator.handleFetchSecureStringResult(result(Approov.TokenFetchStatus.REJECTED), "lookup", "k"));
        assertThrows(ApproovRejectionException.class, () ->
                mutator.handleFetchCustomJWTResult(result(Approov.TokenFetchStatus.REJECTED)));
        // ALWAYS_PROCEED changes only the request decisions, never those of the direct methods
        assertThrows(ApproovNetworkException.class, () -> ApproovServiceMutator.ALWAYS_PROCEED
                .handleFetchTokenResult(result(Approov.TokenFetchStatus.NO_NETWORK)));
    }
}
