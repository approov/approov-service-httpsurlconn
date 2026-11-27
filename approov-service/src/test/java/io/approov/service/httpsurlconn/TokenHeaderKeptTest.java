package io.approov.service.httpsurlconn;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;

import com.criticalblue.approovsdk.Approov;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;
import org.robolectric.shadows.ShadowLog;

import java.io.IOException;

import javax.net.ssl.HttpsURLConnection;

/**
 * The token and trace headers are set by the layer, so a processed request hook that changes them, or returns
 * a connection without them, does not change what is sent: the layer puts its headers back, signs with them,
 * and logs a warning once per process for each header. A header the hook adds is kept.
 */
@RunWith(RobolectricTestRunner.class)
@Config(manifest = Config.NONE)
public class TokenHeaderKeptTest {
    private static final String URL = "https://api.example.com/h";
    private static final String WARNING =
            "handleInterceptorProcessedRequest: removed or changed the Approov token header, restored";
    private static final String TRACE_WARNING =
            "handleInterceptorProcessedRequest: removed or changed the Approov trace header, restored";

    private MockedStatic<Approov> approov;

    // what a hook does to the request it is given
    private interface Hook {
        HttpsURLConnection apply(HttpsURLConnection request) throws IOException;
    }

    private static ApproovServiceMutator mutator(Hook hook) {
        return new ApproovServiceMutator() {
            @Override
            public HttpsURLConnection handleInterceptorProcessedRequest(HttpsURLConnection request,
                    ApproovRequestMutations changes) throws ApproovException {
                try {
                    return hook.apply(request);
                } catch (ApproovException e) {
                    throw e;
                } catch (IOException e) {
                    throw new ApproovException(e);
                }
            }
        };
    }

    // a hook that returns a new connection with only the header it adds
    private static HttpsURLConnection onlyApp(HttpsURLConnection request) throws IOException {
        HttpsURLConnection other = ApproovTestSupport.connection(request.getURL().toString());
        other.setRequestProperty("X-App", "added");
        return other;
    }

    // a hook that changes the token and the trace header
    private static HttpsURLConnection forged(HttpsURLConnection request) {
        request.setRequestProperty("Approov-Token", "forged");
        request.setRequestProperty("Approov-TraceID", "forged-trace");
        return request;
    }

    @Before
    public void setUp() {
        approov = Mockito.mockStatic(Approov.class);
        ApproovTestSupport.initializeApproovService(approov);
        ApproovTestSupport.sdkSignsWithBoth(approov);
        Approov.TokenFetchResult success =
                ApproovTestSupport.tokenResult(Approov.TokenFetchStatus.SUCCESS, "jwt-token", "", "trace-1");
        approov.when(() -> Approov.fetchApproovTokenAndWait(anyString())).thenReturn(success);
        ShadowLog.reset();
    }

    @After
    public void tearDown() {
        approov.close();
        ApproovService.reset();
        ShadowLog.reset();
    }

    private static HttpsURLConnection deliver() throws Exception {
        return ApproovService.addApproovToConnection(ApproovTestSupport.connection(URL));
    }

    private static int warnings(String text) {
        int n = 0;
        for (ShadowLog.LogItem item : ShadowLog.getLogs()) {
            if (item.msg.contains(text))
                n++;
        }
        return n;
    }

    @Test
    public void droppedTokenIsRestoredAndWarnedOnce() throws Exception {
        ApproovService.setServiceMutator(mutator(TokenHeaderKeptTest::onlyApp));
        for (int i = 0; i < 2; i++) {
            HttpsURLConnection sent = deliver();
            assertEquals("jwt-token", sent.getRequestProperty("Approov-Token"));
            assertEquals("trace-1", sent.getRequestProperty("Approov-TraceID"));
            assertEquals("added", sent.getRequestProperty("X-App"));
        }
        assertEquals(1, warnings(WARNING));
        assertEquals(1, warnings(TRACE_WARNING));
    }

    @Test
    public void changedTokenIsRestoredAndWarnedOnce() throws Exception {
        ApproovService.setServiceMutator(mutator(TokenHeaderKeptTest::forged));
        for (int i = 0; i < 2; i++) {
            HttpsURLConnection sent = deliver();
            assertEquals("jwt-token", sent.getRequestProperty("Approov-Token"));
            assertEquals("trace-1", sent.getRequestProperty("Approov-TraceID"));
        }
        assertEquals(1, warnings(WARNING));
        assertEquals(1, warnings(TRACE_WARNING));
    }

    @Test
    public void theLegacyInPlaceApiKeepsTheTokenToo() throws Exception {
        ApproovService.setServiceMutator(mutator(TokenHeaderKeptTest::forged));
        HttpsURLConnection request = ApproovTestSupport.connection(URL);
        ApproovService.addApproov(request);
        assertEquals("jwt-token", request.getRequestProperty("Approov-Token"));
        assertEquals(1, warnings(WARNING));
    }

    @Test
    public void aHookThatOnlyAddsAHeaderCausesNoWarning() throws Exception {
        ApproovService.setServiceMutator(mutator(request -> {
            request.setRequestProperty("X-App", "added");
            return request;
        }));
        HttpsURLConnection sent = deliver();
        assertEquals("jwt-token", sent.getRequestProperty("Approov-Token"));
        assertEquals("added", sent.getRequestProperty("X-App"));
        assertEquals(0, warnings("restored"));
    }

    @Test
    public void aCustomTokenHeaderIsKeptToo() throws Exception {
        ApproovService.setTokenHeader("X-Token", "Bearer ");
        ApproovService.setServiceMutator(mutator(request -> {
            request.setRequestProperty("X-Token", "Bearer forged");
            return request;
        }));
        assertEquals("Bearer jwt-token", deliver().getRequestProperty("X-Token"));
        assertEquals(1, warnings(WARNING));
    }

    private String signedTokenLine() {
        ArgumentCaptor<String> base = ArgumentCaptor.forClass(String.class);
        approov.verify(() -> Approov.getInstallMessageSignature(base.capture()), Mockito.atLeastOnce());
        String last = base.getAllValues().get(base.getAllValues().size() - 1);
        assertTrue(last, last.contains("\"approov-token\": jwt-token\n"));
        return last;
    }

    @Test
    public void signatureCoversTheRestoredTokenWhenTheHookDropsIt() throws Exception {
        ApproovService.setServiceMutator(ApproovDefaultMessageSigning.combined(mutator(TokenHeaderKeptTest::onlyApp)));
        HttpsURLConnection sent = deliver();
        assertEquals("jwt-token", sent.getRequestProperty("Approov-Token"));
        String input = sent.getRequestProperty("Signature-Input");
        assertNotNull(input);
        assertTrue(input, input.contains("\"approov-token\""));
        signedTokenLine();
        assertEquals(1, warnings(WARNING));
    }

    @Test
    public void signatureCoversTheRestoredTokenWhenTheHookChangesIt() throws Exception {
        ApproovService.setServiceMutator(ApproovDefaultMessageSigning.combined(mutator(TokenHeaderKeptTest::forged)));
        for (int i = 0; i < 2; i++) {
            HttpsURLConnection sent = deliver();
            assertEquals("jwt-token", sent.getRequestProperty("Approov-Token"));
            assertTrue(sent.getRequestProperty("Signature-Input").contains("\"approov-token\""));
            assertTrue(signedTokenLine().contains("\"approov-traceid\": trace-1\n"));
        }
        assertEquals(1, warnings(WARNING));
    }

    @Test
    public void theRestoreIsSkippedForARequestWithoutApproovHeaders() throws Exception {
        HttpsURLConnection request = ApproovTestSupport.connection(URL);
        ApproovService.restoreApproovHeaders(request, new ApproovRequestMutations());
        ApproovService.restoreApproovHeaders(null, ApproovTestSupport.tokenChanges());
        assertEquals(0, warnings("restored"));
        assertSame(null, request.getRequestProperty("Approov-Token"));
    }
}
