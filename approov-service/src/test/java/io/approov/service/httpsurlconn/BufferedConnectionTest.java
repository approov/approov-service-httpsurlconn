package io.approov.service.httpsurlconn;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertSame;
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
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.HttpsURLConnection;

/**
 * addApproovToConnection returns the connection it is given for a request without a body, and a buffered
 * connection for a POST, PUT or PATCH or a request with output enabled, so that the processed request hook and
 * message signing run when the request is sent, over the body written to it. The legacy addApproov always
 * prepares the connection in place.
 */
@RunWith(RobolectricTestRunner.class)
@Config(manifest = Config.NONE)
public class BufferedConnectionTest {
    private static final String URL = "https://api.example.com/data";

    private MockedStatic<Approov> approov;
    private final List<HttpsURLConnection> processed = new ArrayList<>();

    @Before
    public void setUp() {
        approov = Mockito.mockStatic(Approov.class);
        ApproovTestSupport.initializeApproovService(approov);
        Approov.TokenFetchResult success =
                ApproovTestSupport.tokenResult(Approov.TokenFetchStatus.SUCCESS, "jwt-token", "", "trace-1");
        approov.when(() -> Approov.fetchApproovTokenAndWait(anyString())).thenReturn(success);
        ApproovService.setServiceMutator(new ApproovServiceMutator() {
            @Override
            public HttpsURLConnection handleInterceptorProcessedRequest(HttpsURLConnection request,
                    ApproovRequestMutations changes) {
                processed.add(request);
                return request;
            }
        });
    }

    @After
    public void tearDown() {
        approov.close();
        ApproovService.reset();
    }

    private static HttpsURLConnection request(String method, boolean output) throws Exception {
        HttpsURLConnection request = ApproovTestSupport.connection(URL);
        request.setRequestMethod(method);
        request.setDoOutput(output);
        return request;
    }

    @Test
    public void aRequestWithoutABodyIsPreparedInPlace() throws Exception {
        for (String method : new String[] {"GET", "DELETE", "HEAD", "OPTIONS"}) {
            HttpsURLConnection request = request(method, false);
            assertSame(method, request, ApproovService.addApproovToConnection(request));
            assertSame(method, request, processed.get(processed.size() - 1));
        }
    }

    @Test
    public void aRequestWithABodyIsBufferedAndProcessedWhenSent() throws Exception {
        // the JVM's HttpURLConnection does not accept PATCH, which Android's does
        for (String method : new String[] {"POST", "PUT"}) {
            HttpsURLConnection request = request(method, false);
            HttpsURLConnection buffered = ApproovService.addApproovToConnection(request);
            assertNotSame(method, request, buffered);
            assertTrue(method, buffered instanceof ApproovBufferedHttpsURLConnection);
            assertEquals(method, buffered.getRequestMethod());
            assertEquals(URL, buffered.getURL().toString());
            assertEquals("jwt-token", buffered.getRequestProperty("Approov-Token"));
            assertEquals("trace-1", buffered.getRequestProperty("Approov-TraceID"));
        }
        HttpsURLConnection output = ApproovService.addApproovToConnection(request("GET", true));
        assertTrue(output instanceof ApproovBufferedHttpsURLConnection);
        assertEquals("the hook runs when the request is sent", 0, processed.size());
    }

    @Test
    public void theBodyWrittenToTheBufferedConnectionIsKept() throws Exception {
        HttpsURLConnection buffered = ApproovService.addApproovToConnection(request("POST", true));
        try (OutputStream out = buffered.getOutputStream()) {
            out.write("{\"a\":1}".getBytes(StandardCharsets.UTF_8));
        }
        assertArrayEquals("{\"a\":1}".getBytes(StandardCharsets.UTF_8),
                ((ApproovBufferedHttpsURLConnection) buffered).getBufferedRequestBody());
    }

    @Test
    public void theLegacyApiPreparesABodyRequestInPlace() throws Exception {
        HttpsURLConnection request = request("POST", true);
        ApproovService.addApproov(request);
        assertEquals("jwt-token", request.getRequestProperty("Approov-Token"));
        assertEquals(1, processed.size());
        assertSame(request, processed.get(0));
    }

    @Test
    public void theBufferedConnectionFindsAHeaderWithoutRegardToCase() throws Exception {
        HttpsURLConnection buffered = ApproovService.addApproovToConnection(request("POST", true));
        assertEquals("jwt-token", buffered.getRequestProperty("approov-token"));
        buffered.setRequestProperty("content-type", "application/json");
        buffered.setRequestProperty("Content-Type", "text/plain");
        assertEquals("one Content-Type", 1, buffered.getRequestProperties().keySet().stream()
                .filter(name -> "content-type".equalsIgnoreCase(name)).count());
    }
}
