package io.approov.service.httpsurlconn;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;

import com.criticalblue.approovsdk.Approov;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.util.Arrays;
import java.util.Collections;

import javax.net.ssl.HttpsURLConnection;

/**
 * Header substitution with secure strings. On SUCCESS the placeholder after any required prefix is replaced by
 * the secure string. Under both standard mutators a secure string that cannot be obtained, for any other
 * status, skips the substitution and the request proceeds with the value as the app wrote it. A custom mutator
 * can still abort. No secure string is fetched for a request whose token decision sends no Approov header or
 * aborts.
 */
public class SecureStringSubstitutionTest {
    private static final String URL = "https://api.example.com/data";
    private static final String PLACEHOLDER = "api-key-placeholder";
    private static final String SECRET = "real-api-key-value";

    private MockedStatic<Approov> approov;

    @Before
    public void setUp() {
        approov = Mockito.mockStatic(Approov.class);
        ApproovTestSupport.initializeApproovService(approov);
        answerToken(Approov.TokenFetchStatus.SUCCESS);
        answerSecureString(Approov.TokenFetchStatus.SUCCESS);
        ApproovService.addSubstitutionHeader("Api-Key", "Bearer ");
    }

    @After
    public void tearDown() {
        approov.close();
        ApproovService.reset();
    }

    private void answerToken(Approov.TokenFetchStatus status) {
        Approov.TokenFetchResult result = ApproovTestSupport.tokenResult(status,
                (status == Approov.TokenFetchStatus.SUCCESS) ? "jwt-token" : null, "", null);
        approov.when(() -> Approov.fetchApproovTokenAndWait(anyString())).thenReturn(result);
    }

    private void answerSecureString(Approov.TokenFetchStatus status) {
        Approov.TokenFetchResult result = ApproovTestSupport.tokenResult(status, "",
                (status == Approov.TokenFetchStatus.SUCCESS) ? SECRET : null, null);
        approov.when(() -> Approov.fetchSecureStringAndWait(PLACEHOLDER, null)).thenReturn(result);
    }

    private static HttpsURLConnection send(String value) throws Exception {
        HttpsURLConnection request = ApproovTestSupport.connection(URL);
        if (value != null)
            request.setRequestProperty("Api-Key", value);
        ApproovService.addApproov(request);
        return request;
    }

    @Test
    public void successReplacesThePlaceholderAfterThePrefix() throws Exception {
        HttpsURLConnection request = send("Bearer " + PLACEHOLDER);
        assertEquals("Bearer " + SECRET, request.getRequestProperty("Api-Key"));
        assertEquals("jwt-token", request.getRequestProperty("Approov-Token"));
        approov.verify(() -> Approov.fetchSecureStringAndWait(PLACEHOLDER, null));
    }

    @Test
    public void theSubstitutedHeaderIsReportedToTheProcessedRequestHook() throws Exception {
        ApproovRequestMutations[] seen = new ApproovRequestMutations[1];
        ApproovService.setServiceMutator(new ApproovServiceMutator() {
            @Override
            public HttpsURLConnection handleInterceptorProcessedRequest(HttpsURLConnection request,
                    ApproovRequestMutations changes) {
                seen[0] = changes;
                return request;
            }
        });
        send("Bearer " + PLACEHOLDER);
        assertEquals(Collections.singletonList("Api-Key"), seen[0].getSubstitutionHeaderKeys());
        assertEquals("Approov-Token", seen[0].getTokenHeaderKey());
    }

    @Test
    public void aSecureStringThatCannotBeObtainedNeverAbortsUnderTheStandardMutators() throws Exception {
        for (ApproovServiceMutator mutator : Arrays.asList(
                ApproovServiceMutator.CLOSE_FAILURE, ApproovServiceMutator.ALWAYS_PROCEED)) {
            for (Approov.TokenFetchStatus status : Approov.TokenFetchStatus.values()) {
                if (status == Approov.TokenFetchStatus.SUCCESS)
                    continue;
                ApproovService.setServiceMutator(mutator);
                answerSecureString(status);
                HttpsURLConnection request = send("Bearer " + PLACEHOLDER);
                String what = mutator + " " + status;
                assertEquals(what, "Bearer " + PLACEHOLDER, request.getRequestProperty("Api-Key"));
                assertEquals(what, "jwt-token", request.getRequestProperty("Approov-Token"));
            }
        }
    }

    @Test
    public void aCustomMutatorCanAbortOnASecureString() throws Exception {
        answerSecureString(Approov.TokenFetchStatus.REJECTED);
        ApproovService.setServiceMutator(new ApproovServiceMutator() {
            @Override
            public boolean handleInterceptorHeaderSubstitutionResult(Approov.TokenFetchResult results, String header)
                    throws ApproovException {
                throw new ApproovRejectionException("my policy for " + header, results.getARC(),
                        results.getRejectionReasons());
            }
        });
        ApproovRejectionException e = assertThrows(ApproovRejectionException.class,
                () -> send("Bearer " + PLACEHOLDER));
        assertEquals("my policy for Api-Key", e.getMessage());
        assertEquals("ARC123", ApproovService.getLastARC());
    }

    @Test
    public void aValueWithoutThePrefixOrWithoutAKeyIsNotLookedUp() throws Exception {
        assertEquals(PLACEHOLDER, send(PLACEHOLDER).getRequestProperty("Api-Key"));
        assertEquals("Bearer ", send("Bearer ").getRequestProperty("Api-Key"));
        assertNull(send(null).getRequestProperty("Api-Key"));
        approov.verify(() -> Approov.fetchSecureStringAndWait(anyString(), any()), never());
    }

    @Test
    public void aHeaderWithoutAPrefixIsSubstitutedWhole() throws Exception {
        ApproovService.addSubstitutionHeader("X-Secret", null);
        assertEquals("", ApproovService.getSubstitutionHeaders().get("X-Secret"));
        HttpsURLConnection request = ApproovTestSupport.connection(URL);
        request.setRequestProperty("X-Secret", PLACEHOLDER);
        ApproovService.addApproov(request);
        assertEquals(SECRET, request.getRequestProperty("X-Secret"));
    }

    @Test
    public void noSecureStringIsFetchedWhenTheTokenDecisionSendsNoHeaderOrAborts() throws Exception {
        for (Approov.TokenFetchStatus status : new Approov.TokenFetchStatus[] {
                Approov.TokenFetchStatus.UNKNOWN_URL, Approov.TokenFetchStatus.UNPROTECTED_URL}) {
            answerToken(status);
            assertEquals(status.name(), "Bearer " + PLACEHOLDER, send("Bearer " + PLACEHOLDER).getRequestProperty("Api-Key"));
        }
        answerToken(Approov.TokenFetchStatus.REJECTED);
        HttpsURLConnection request = ApproovTestSupport.connection(URL);
        request.setRequestProperty("Api-Key", "Bearer " + PLACEHOLDER);
        assertThrows(ApproovFetchStatusException.class, () -> ApproovService.addApproov(request));
        assertEquals("Bearer " + PLACEHOLDER, request.getRequestProperty("Api-Key"));
        approov.verify(() -> Approov.fetchSecureStringAndWait(anyString(), any()), never());
    }

    @Test
    public void substitutionHeadersCanBeRemoved() throws Exception {
        ApproovService.removeSubstitutionHeader("Api-Key");
        assertTrue(ApproovService.getSubstitutionHeaders().isEmpty());
        assertEquals("Bearer " + PLACEHOLDER, send("Bearer " + PLACEHOLDER).getRequestProperty("Api-Key"));
        approov.verify(() -> Approov.fetchSecureStringAndWait(anyString(), any()), never());
    }

    @Test
    public void theDirectSecureStringFetchReturnsTheValueOrNullForAnUnknownKey() throws Exception {
        assertEquals(SECRET, ApproovService.fetchSecureString(PLACEHOLDER, null));
        Approov.TokenFetchResult unknown = ApproovTestSupport.tokenResult(Approov.TokenFetchStatus.UNKNOWN_KEY, "", null, null);
        approov.when(() -> Approov.fetchSecureStringAndWait("missing-key", null)).thenReturn(unknown);
        assertNull(ApproovService.fetchSecureString("missing-key", null));
        Approov.TokenFetchResult noNetwork = ApproovTestSupport.tokenResult(Approov.TokenFetchStatus.NO_NETWORK);
        approov.when(() -> Approov.fetchSecureStringAndWait("slow-key", null)).thenReturn(noNetwork);
        assertSame(Approov.TokenFetchStatus.NO_NETWORK, assertThrows(ApproovNetworkException.class,
                () -> ApproovService.fetchSecureString("slow-key", null)).getTokenFetchStatus());
    }
}
