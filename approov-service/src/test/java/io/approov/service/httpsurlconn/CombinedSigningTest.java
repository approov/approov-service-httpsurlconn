package io.approov.service.httpsurlconn;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.criticalblue.approovsdk.Approov;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.HttpURLConnection;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import javax.net.ssl.HttpsURLConnection;

/**
 * The signer makes the decisions of another mutator: every decision hook calls the hook of that mutator, and
 * its processed request hook calls the one of that mutator first and then signs the result. combined() signs
 * with both the install and the account signature.
 */
@RunWith(RobolectricTestRunner.class)
@Config(manifest = Config.NONE)
public class CombinedSigningTest {
    private static final String URL = "https://api.example.com/data";

    private MockedStatic<Approov> approov;

    @Before
    public void setUp() {
        approov = Mockito.mockStatic(Approov.class);
        ApproovTestSupport.initializeApproovService(approov);
        ApproovTestSupport.sdkSignsWithBoth(approov);
        ApproovDefaultMessageSigning.resetMissingSignatureLogsForTesting();
    }

    @After
    public void tearDown() {
        approov.close();
        ApproovService.reset();
        ApproovDefaultMessageSigning.resetMissingSignatureLogsForTesting();
    }

    private static Approov.TokenFetchResult result(Approov.TokenFetchStatus status) {
        return ApproovTestSupport.tokenResult(status, "jwt", "", "trace");
    }

    // an app mutator that records every hook call with its arguments and decides the opposite of the interface
    // default for a SUCCESS result, so that a decision the signer made itself is told apart from its own
    static final class RecordingDecisions implements ApproovServiceMutator {
        final List<String> hooks = Collections.synchronizedList(new ArrayList<>());
        final List<Object[]> arguments = Collections.synchronizedList(new ArrayList<>());
        HttpsURLConnection processedResult;

        private void record(String hook, Object... args) {
            hooks.add(hook);
            arguments.add(args);
        }

        @Override
        public void handlePrecheckResult(Approov.TokenFetchResult approovResults) throws ApproovException {
            record("handlePrecheckResult", approovResults);
            throw new ApproovException("decided by handlePrecheckResult");
        }

        @Override
        public void handleFetchTokenResult(Approov.TokenFetchResult approovResults) throws ApproovException {
            record("handleFetchTokenResult", approovResults);
            throw new ApproovException("decided by handleFetchTokenResult");
        }

        @Override
        public void handleFetchSecureStringResult(Approov.TokenFetchResult approovResults, String operation,
                String key) throws ApproovException {
            record("handleFetchSecureStringResult", approovResults, operation, key);
            throw new ApproovException("decided by handleFetchSecureStringResult");
        }

        @Override
        public void handleFetchCustomJWTResult(Approov.TokenFetchResult approovResults) throws ApproovException {
            record("handleFetchCustomJWTResult", approovResults);
            throw new ApproovException("decided by handleFetchCustomJWTResult");
        }

        @Override
        public boolean handleInterceptorShouldProcessConnection(HttpsURLConnection request) {
            record("handleInterceptorShouldProcessConnection", request);
            return false;
        }

        @Override
        public boolean handleInterceptorFetchTokenResult(Approov.TokenFetchResult approovResults, String url) {
            record("handleInterceptorFetchTokenResult", approovResults, url);
            return false;
        }

        @Override
        public boolean handleInterceptorHeaderSubstitutionResult(Approov.TokenFetchResult approovResults,
                String header) {
            record("handleInterceptorHeaderSubstitutionResult", approovResults, header);
            return false;
        }

        @Override
        public HttpsURLConnection handleInterceptorProcessedRequest(HttpsURLConnection request,
                ApproovRequestMutations changes) {
            record("handleInterceptorProcessedRequest", request, changes);
            return (processedResult != null) ? processedResult : request;
        }

        @Override
        public boolean handlePinningShouldProcessRequest(HttpURLConnection request) {
            record("handlePinningShouldProcessRequest", request);
            return false;
        }
    }

    interface ThrowingCall {
        void run() throws ApproovException;
    }

    private static void assertDecidedBy(String hook, ThrowingCall call) {
        try {
            call.run();
            fail(hook + ": the signer decided itself");
        } catch (ApproovException e) {
            assertEquals(hook, "decided by " + hook, e.getMessage());
        }
    }

    @Test
    public void everyHookOfTheMutatorInterfaceIsForwarded() throws Exception {
        Approov.TokenFetchResult success = result(Approov.TokenFetchStatus.SUCCESS);
        HttpsURLConnection request = ApproovTestSupport.connection(URL);
        RecordingDecisions decisions = new RecordingDecisions();
        ApproovDefaultMessageSigning signer = new ApproovDefaultMessageSigning(decisions);
        Set<String> hooks = new TreeSet<>();
        for (Method hook : ApproovServiceMutator.class.getDeclaredMethods()) {
            if (!hook.isDefault())
                continue;
            hooks.add(hook.getName());
            Class<?>[] types = hook.getParameterTypes();
            Object[] args = new Object[types.length];
            for (int i = 0; i < types.length; i++) {
                if ((types[i] == HttpsURLConnection.class) || (types[i] == HttpURLConnection.class))
                    args[i] = request;
                else if (types[i] == Approov.TokenFetchResult.class)
                    args[i] = success;
                else if (types[i] == String.class)
                    args[i] = "argument-" + i;
                else if (types[i] == ApproovRequestMutations.class)
                    args[i] = new ApproovRequestMutations();
                else
                    fail(hook.getName() + ": a parameter type the test does not know: " + types[i]);
            }
            decisions.hooks.clear();
            decisions.arguments.clear();
            try {
                signer.getClass().getMethod(hook.getName(), types).invoke(signer, args);
            } catch (InvocationTargetException e) {
                assertTrue(hook.getName() + ": " + e.getCause(), e.getCause() instanceof ApproovException);
            }
            assertEquals(hook.getName() + " is forwarded", Collections.singletonList(hook.getName()),
                    decisions.hooks);
            assertTrue(hook.getName() + " passes its arguments", Arrays.equals(args, decisions.arguments.get(0)));
        }
        assertEquals("the hooks found: " + hooks, 9, hooks.size());
    }

    @Test
    public void eachDecisionHookIsTheDecisionsOwn() throws Exception {
        Approov.TokenFetchResult success = result(Approov.TokenFetchStatus.SUCCESS);
        HttpsURLConnection request = ApproovTestSupport.connection(URL);
        ApproovDefaultMessageSigning signer = new ApproovDefaultMessageSigning(new RecordingDecisions());

        // the interface default on SUCCESS is true for each of these, or no exception
        assertFalse(signer.handleInterceptorShouldProcessConnection(request));
        assertFalse(signer.handleInterceptorFetchTokenResult(success, URL));
        assertFalse(signer.handleInterceptorHeaderSubstitutionResult(success, "X-Api-Key"));
        assertFalse(signer.handlePinningShouldProcessRequest(request));
        assertDecidedBy("handlePrecheckResult", () -> signer.handlePrecheckResult(success));
        assertDecidedBy("handleFetchTokenResult", () -> signer.handleFetchTokenResult(success));
        assertDecidedBy("handleFetchSecureStringResult",
                () -> signer.handleFetchSecureStringResult(success, "lookup", "the-key"));
        assertDecidedBy("handleFetchCustomJWTResult", () -> signer.handleFetchCustomJWTResult(success));
    }

    @Test
    public void theProcessedRequestHookOfTheDecisionsRunsFirstAndTheSignerSignsItsResult() throws Exception {
        HttpsURLConnection request = ApproovTestSupport.tokenConnection(URL);
        RecordingDecisions decisions = new RecordingDecisions();
        ApproovDefaultMessageSigning signer = new ApproovDefaultMessageSigning(decisions);

        // a request without a token header mutation is not signed, so the result is the decisions' own
        ApproovRequestMutations none = new ApproovRequestMutations();
        assertSame(request, signer.handleInterceptorProcessedRequest(request, none));
        assertSame(request, decisions.arguments.get(0)[0]);
        assertSame(none, decisions.arguments.get(0)[1]);
        assertNull(request.getRequestProperty("Signature"));

        // with a token header mutation and a factory the result of the decisions is what is signed
        signer.setDefaultFactory(ApproovDefaultMessageSigning.generateDefaultSignatureParametersFactory());
        HttpsURLConnection other = ApproovTestSupport.connection(URL);
        other.setRequestProperty("X-Decisions", "ran");
        decisions.processedResult = other;
        HttpsURLConnection signed = signer.handleInterceptorProcessedRequest(request,
                ApproovTestSupport.tokenChanges());
        assertSame(other, signed);
        assertEquals("ran", signed.getRequestProperty("X-Decisions"));
        assertNotNull(signed.getRequestProperty("Signature"));
        assertEquals(Arrays.asList("handleInterceptorProcessedRequest", "handleInterceptorProcessedRequest"),
                decisions.hooks);
    }

    @Test
    public void aNullResultOfTheDecisionsPropagates() throws Exception {
        ApproovServiceMutator returnsNull = new ApproovServiceMutator() {
            @Override
            public HttpsURLConnection handleInterceptorProcessedRequest(HttpsURLConnection request,
                    ApproovRequestMutations changes) {
                return null;
            }
        };
        ApproovDefaultMessageSigning signer = ApproovDefaultMessageSigning.combined(returnsNull);
        assertNull(signer.handleInterceptorProcessedRequest(ApproovTestSupport.tokenConnection(URL),
                ApproovTestSupport.tokenChanges()));
    }

    @Test
    public void theNoArgumentSignerStillMakesCloseFailureDecisions() throws Exception {
        ApproovDefaultMessageSigning plain = new ApproovDefaultMessageSigning();
        HttpsURLConnection request = ApproovTestSupport.connection(URL);
        Approov.TokenFetchResult success = result(Approov.TokenFetchStatus.SUCCESS);
        assertTrue(plain.handleInterceptorShouldProcessConnection(request));
        assertTrue(plain.handleInterceptorFetchTokenResult(success, URL));
        assertTrue(plain.handleInterceptorFetchTokenResult(result(Approov.TokenFetchStatus.NO_APPROOV_SERVICE), URL));
        assertFalse(plain.handleInterceptorHeaderSubstitutionResult(result(Approov.TokenFetchStatus.REJECTED), "h"));
        plain.handlePrecheckResult(success);
        assertEquals("ApproovDefaultMessageSigning", plain.toString());
        // and signs nothing until a factory is set
        assertNull(ApproovTestSupport.sign(plain, URL).getRequestProperty("Signature"));
    }

    // the result of the token decision of the signer for a failed fetch, true if the request proceeds
    private static boolean proceedsOnNoNetwork(ApproovDefaultMessageSigning signer) {
        try {
            return signer.handleInterceptorFetchTokenResult(result(Approov.TokenFetchStatus.NO_NETWORK), URL);
        } catch (ApproovException e) {
            return false;
        }
    }

    @Test
    public void combinedMakesTheDecisionsGiven() {
        assertTrue(proceedsOnNoNetwork(ApproovDefaultMessageSigning.combined(ApproovServiceMutator.ALWAYS_PROCEED)));
        assertFalse(proceedsOnNoNetwork(ApproovDefaultMessageSigning.combined(ApproovServiceMutator.CLOSE_FAILURE)));
        assertFalse("the DEFAULT decisions", proceedsOnNoNetwork(ApproovDefaultMessageSigning.combined()));
    }

    @Test
    public void combinedDescribesItsDecisions() {
        assertEquals("ApproovDefaultMessageSigning(ApproovServiceMutator.ALWAYS_PROCEED)",
                ApproovDefaultMessageSigning.combined(ApproovServiceMutator.ALWAYS_PROCEED).toString());
    }

    @Test
    public void combinedRejectsNullDecisions() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> ApproovDefaultMessageSigning.combined(null));
        assertTrue(e.getMessage(), e.getMessage().contains("decisions"));
    }

    @Test
    public void combinedReturnsANewSignerEachTime() {
        assertNotSame(ApproovDefaultMessageSigning.combined(), ApproovDefaultMessageSigning.combined());
    }

    @Test
    public void theConstructorThatTakesAMutatorIsNotPublic() {
        for (java.lang.reflect.Constructor<?> constructor : ApproovDefaultMessageSigning.class.getConstructors())
            assertEquals("only the no-argument constructor is public", 0, constructor.getParameterCount());
    }

    @Test
    public void combinedSignsWithBothTheInstallAndTheAccountSignature() throws Exception {
        HttpsURLConnection signed = ApproovTestSupport.sign(ApproovDefaultMessageSigning.combined(), URL);

        String input = signed.getRequestProperty("Signature-Input");
        String signature = signed.getRequestProperty("Signature");
        assertNotNull(input);
        assertNotNull(signature);
        assertTrue(input, input.contains("install=(") && input.contains("account=("));
        assertTrue(signature, signature.contains("install=:") && signature.contains("account=:"));
        assertTrue(input, input.indexOf("install=(") < input.indexOf("account=("));
        assertTrue(input, input.contains("alg=\"ecdsa-p256-sha256\"") && input.contains("alg=\"hmac-sha256\""));
    }

    @Test
    public void combinedSignsARequestThroughTheServiceAndKeepsItsDecisions() throws Exception {
        Approov.TokenFetchResult success = result(Approov.TokenFetchStatus.SUCCESS);
        approov.when(() -> Approov.fetchApproovTokenAndWait(URL)).thenReturn(success);
        ApproovService.setServiceMutator(ApproovDefaultMessageSigning.combined());
        HttpsURLConnection request = ApproovTestSupport.connection(URL);
        assertSame(request, ApproovService.addApproovToConnection(request));
        assertEquals("jwt", request.getRequestProperty("Approov-Token"));
        assertEquals("trace", request.getRequestProperty("Approov-TraceID"));
        String input = request.getRequestProperty("Signature-Input");
        assertNotNull(input);
        assertTrue(input, input.contains("\"approov-token\"") && input.contains("\"approov-traceid\""));
        assertTrue(request.getRequestProperty("Signature"),
                request.getRequestProperty("Signature").matches("install=:[^:]+:, account=:[^:]+:"));
    }
}
