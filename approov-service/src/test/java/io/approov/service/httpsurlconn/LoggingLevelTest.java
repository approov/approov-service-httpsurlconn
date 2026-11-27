package io.approov.service.httpsurlconn;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

import android.util.Log;

import com.criticalblue.approovsdk.Approov;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.MockedStatic;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;
import org.robolectric.shadows.ShadowLog;

import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.net.ssl.SSLSession;

/**
 * ApproovService.setLoggingLevel: ERROR writes errors, WARNING adds warnings, INFO (the default) adds
 * information and DEBUG adds debug lines, the loggable token of each request among them. OFF writes
 * nothing from the layer, errors included. The level is configuration, so initialize never resets it.
 * Debug logging enabled for the ApproovService tag (adb shell setprop log.tag.ApproovService DEBUG,
 * which ShadowLog.setLoggable stands in for) raises any level but OFF to DEBUG. No line carries the query,
 * user info or fragment of a request URL.
 */
@RunWith(RobolectricTestRunner.class)
@Config(manifest = Config.NONE)
public class LoggingLevelTest {
    private static final Set<String> LAYER_TAGS = new HashSet<>(Arrays.asList(
            "ApproovService", "ApproovPinVerifier", "ApproovMsgSign"));

    // a distinctive line logged at each level
    private static final String ERROR_LINE = "getDeviceID: SDK not initialized";
    private static final String WARNING_LINE = "no pins and no managed trust roots, OS trust only";
    private static final String INFO_LINE = "initialize: bypass mode";
    private static final String DEBUG_LINE = "setBindingHeader Probe-Binding";

    private static final String QUERY_VALUE = "query-value-never-logged";
    private static final String USER = "user-never-logged";

    @Before
    public void setUp() {
        ApproovService.reset();
        ShadowLog.reset();
    }

    @After
    public void tearDown() {
        ApproovService.reset();
        ShadowLog.reset();
    }

    private static List<ShadowLog.LogItem> layerLogs() {
        List<ShadowLog.LogItem> items = new ArrayList<>();
        for (ShadowLog.LogItem item : ShadowLog.getLogs()) {
            if (LAYER_TAGS.contains(item.tag))
                items.add(item);
        }
        return items;
    }

    private static boolean logged(int type, String text) {
        for (ShadowLog.LogItem item : layerLogs()) {
            if ((item.type == type) && (item.msg != null) && item.msg.contains(text))
                return true;
        }
        return false;
    }

    // the number of hosts warned of, so that each warning names a new host
    private static int warnedHosts = 0;

    // causes the warning for an Approov domain with no pins and no managed trust roots, once for a new host,
    // with Approov protection enabled only while the pins are checked
    private static void osTrustOnlyWarning() throws Exception {
        String host = "api-" + (++warnedHosts) + ".example.com";
        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            approov.when(() -> Approov.getPins("public-key-sha256")).thenReturn(Collections.singletonMap(
                    host, Collections.<String>emptyList()));
            SSLSession session = mock(SSLSession.class);
            when(session.getPeerCertificates()).thenReturn(new Certificate[0]);
            ApproovTestSupport.setProtectionEnabled(true);
            try {
                assertTrue(new PinningHostnameVerifier((hostname, s) -> true).verify(host, session));
            } finally {
                ApproovTestSupport.setProtectionEnabled(false);
            }
        }
    }

    // logs one line at each level: an error (a direct method before initialization), a warning (an Approov
    // domain with no pins), a debug line, then an information line (bypass mode initialization)
    private void logOneLineAtEachLevel() throws Exception {
        assertThrows(ApproovException.class, ApproovService::getDeviceID);
        osTrustOnlyWarning();
        ApproovService.setBindingHeader("Probe-Binding");
        ApproovService.initialize(ApproovTestSupport.mockContext(), "");
    }

    private void assertLevelsLogged(String what, boolean error, boolean warning, boolean info, boolean debug) {
        assertEquals(what + ": error", error, logged(Log.ERROR, ERROR_LINE));
        assertEquals(what + ": warning", warning, logged(Log.WARN, WARNING_LINE));
        assertEquals(what + ": info", info, logged(Log.INFO, INFO_LINE));
        assertEquals(what + ": debug", debug, logged(Log.DEBUG, DEBUG_LINE));
    }

    // adds Approov to a request whose URL carries a query, a fragment and user info, with debug logging
    // enabled for the ApproovService tag if asked, and returns the token lines logged for it
    private List<String> tokenLinesForAProtectedRequest(boolean debugTag, Approov.TokenFetchStatus status)
            throws Exception {
        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            ApproovTestSupport.initializeApproovService(approov);
            String url = "https://" + USER + ":pw@api.example.com:8443/v1/items?q=" + QUERY_VALUE + "#frag";
            Approov.TokenFetchResult result = ApproovTestSupport.tokenResult(status, "jwt-token", "", null);
            approov.when(() -> Approov.fetchApproovTokenAndWait(anyString())).thenReturn(result);
            ShadowLog.reset();
            if (debugTag)
                ShadowLog.setLoggable("ApproovService", Log.DEBUG);
            try {
                ApproovService.addApproov(ApproovTestSupport.connection(url));
            } catch (ApproovException e) {
                assertFalse("the query is in the exception: " + e.getMessage(), e.getMessage().contains(QUERY_VALUE));
                assertFalse("the user info is in the exception: " + e.getMessage(), e.getMessage().contains(USER));
                assertFalse("the fragment is in the exception: " + e.getMessage(), e.getMessage().contains("frag"));
            }
            List<String> lines = new ArrayList<>();
            for (ShadowLog.LogItem item : layerLogs()) {
                assertFalse("the query is logged: " + item.msg, item.msg.contains(QUERY_VALUE));
                assertFalse("the user info is logged: " + item.msg, item.msg.contains(USER));
                assertFalse("the fragment is logged: " + item.msg, item.msg.contains("frag"));
                if (item.msg.startsWith("Token for "))
                    lines.add(item.msg);
            }
            return lines;
        }
    }

    @Test
    public void eachLevelLogsItsOwnLinesAndThoseOfTheLevelsBefore() throws Exception {
        for (ApproovLogLevel level : ApproovLogLevel.values()) {
            ApproovService.reset();
            ShadowLog.reset();
            ApproovService.setLoggingLevel(level);
            logOneLineAtEachLevel();
            int n = level.ordinal();
            assertLevelsLogged(level.name(), n >= 1, n >= 2, n >= 3, n >= 4);
        }
    }

    @Test
    public void theLevelsAreInOrder() {
        assertEquals(Arrays.asList(ApproovLogLevel.OFF, ApproovLogLevel.ERROR, ApproovLogLevel.WARNING,
                ApproovLogLevel.INFO, ApproovLogLevel.DEBUG), Arrays.asList(ApproovLogLevel.values()));
    }

    @Test
    public void theDefaultIsInfo() throws Exception {
        logOneLineAtEachLevel();
        assertLevelsLogged("default", true, true, true, false);
    }

    @Test
    public void offLogsNothingFromTheLayer() throws Exception {
        ApproovService.setLoggingLevel(ApproovLogLevel.OFF);
        logOneLineAtEachLevel();
        assertEquals("layer lines at OFF: " + layerLogs().size(), 0, layerLogs().size());
    }

    @Test
    public void theDefaultDoesNotLogTheLoggableToken() throws Exception {
        assertEquals(new ArrayList<String>(), tokenLinesForAProtectedRequest(false, Approov.TokenFetchStatus.SUCCESS));
    }

    @Test
    public void debugLogsTheLoggableTokenWithTheUrlWithoutItsQuery() throws Exception {
        ApproovService.setLoggingLevel(ApproovLogLevel.DEBUG);
        List<String> lines = tokenLinesForAProtectedRequest(false, Approov.TokenFetchStatus.SUCCESS);
        assertEquals("one token line: " + lines, 1, lines.size());
        assertEquals("Token for https://api.example.com:8443/v1/items: jwt-token", lines.get(0));
    }

    @Test
    public void aRejectedRequestIsLoggedAndReportedWithoutTheQuery() throws Exception {
        ApproovService.setLoggingLevel(ApproovLogLevel.DEBUG);
        assertEquals(1, tokenLinesForAProtectedRequest(false, Approov.TokenFetchStatus.REJECTED).size());
    }

    @Test
    public void debugLoggingForTheTagEnablesDebugLinesAtAnyLevelButOff() throws Exception {
        for (ApproovLogLevel level : ApproovLogLevel.values()) {
            ApproovService.reset();
            ShadowLog.reset();
            ShadowLog.setLoggable("ApproovService", Log.DEBUG);
            ApproovService.setLoggingLevel(level);
            logOneLineAtEachLevel();
            boolean on = level != ApproovLogLevel.OFF;
            assertLevelsLogged(level.name() + " with the tag at debug", on, on, on, on);
        }
        // and the loggable token, at the default level
        ApproovService.reset();
        assertEquals(1, tokenLinesForAProtectedRequest(true, Approov.TokenFetchStatus.SUCCESS).size());
    }

    @Test
    public void debugLoggingForTheTagDoesNotOverrideOff() throws Exception {
        ApproovService.setLoggingLevel(ApproovLogLevel.OFF);
        assertEquals(new ArrayList<String>(), tokenLinesForAProtectedRequest(true, Approov.TokenFetchStatus.SUCCESS));
        assertEquals("layer lines at OFF", 0, layerLogs().size());
    }

    @Test
    public void aLevelSetBeforeInitializeSurvivesIt() throws Exception {
        // OFF before initialize: initialize logs nothing, and the lines after it neither
        ApproovService.setLoggingLevel(ApproovLogLevel.OFF);
        ApproovService.initialize(ApproovTestSupport.mockContext(), "");
        ApproovService.setBindingHeader("Probe-Binding");
        assertEquals("layer lines at OFF across initialize", 0, layerLogs().size());

        // DEBUG before initialize: debug lines still logged after it, also after a protected initialize
        ApproovService.reset();
        ShadowLog.reset();
        ApproovService.setLoggingLevel(ApproovLogLevel.DEBUG);
        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            ApproovService.initialize(ApproovTestSupport.mockContext(), "account-a");
        }
        ApproovService.setBindingHeader("Probe-Binding");
        assertTrue("debug after initialize", logged(Log.DEBUG, DEBUG_LINE));
    }

    @Test
    public void aNullLevelIsRejectedAndLeavesTheLevelUnchanged() throws Exception {
        ApproovService.setLoggingLevel(ApproovLogLevel.ERROR);
        assertThrows(IllegalArgumentException.class, () -> ApproovService.setLoggingLevel(null));
        logOneLineAtEachLevel();
        assertLevelsLogged("ERROR kept", true, false, false, false);
    }

    @Test
    public void theLoggableUrlHasNoQueryUserInfoOrFragment() {
        assertEquals("https://api.example.com:8443/v1/items",
                ApproovLog.loggableURL("https://u:p@api.example.com:8443/v1/items?q=secret#frag"));
        assertEquals("https://api.example.com/", ApproovLog.loggableURL("https://api.example.com?q=secret"));
        assertEquals("(URL not shown)", ApproovLog.loggableURL("not a url secret"));
        assertEquals("(URL not shown)", ApproovLog.loggableURL("ftp://api.example.com/secret"));
        assertEquals("(URL not shown)", ApproovLog.loggableURL((String) null));
    }
}
