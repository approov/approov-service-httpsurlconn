package io.approov.service.httpsurlconn;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import android.util.Log;

import com.criticalblue.approovsdk.Approov;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentMatchers;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;
import org.robolectric.shadows.ShadowLog;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.net.ssl.HttpsURLConnection;

/**
 * A signature that cannot be produced is logged once per process at a visible level, and at debug level after
 * that, for each kind. The request is signed with the other signature, or goes unsigned, as before.
 */
@RunWith(RobolectricTestRunner.class)
@Config(manifest = Config.NONE)
public class MissingSignatureLoggingTest {
    private MockedStatic<Approov> approov;

    @Before
    public void setUp() {
        approov = Mockito.mockStatic(Approov.class);
        ApproovTestSupport.initializeApproovService(approov);
        ApproovTestSupport.sdkSignsWithBoth(approov);
        ApproovService.setLoggingLevel(ApproovLogLevel.DEBUG);
        ApproovDefaultMessageSigning.resetMissingSignatureLogsForTesting();
        ShadowLog.reset();
    }

    @After
    public void tearDown() {
        approov.close();
        ApproovService.reset();
        ApproovDefaultMessageSigning.resetMissingSignatureLogsForTesting();
        ShadowLog.reset();
    }

    private void installMissing() {
        approov.when(() -> Approov.getInstallMessageSignature(ArgumentMatchers.anyString())).thenReturn("");
    }

    private void accountMissing() {
        approov.when(() -> Approov.getAccountMessageSignature(ArgumentMatchers.anyString())).thenReturn("");
    }

    // signs a request carrying the token header with both signatures
    private static HttpsURLConnection sign() throws Exception {
        return ApproovTestSupport.sign(ApproovDefaultMessageSigning.combined(), "https://api.example.com/data");
    }

    // the levels of the lines logged since the last call about the signature of the kind, then clears the log
    private static List<Integer> levels(String kind) {
        List<Integer> levels = new ArrayList<>();
        for (ShadowLog.LogItem item : ShadowLog.getLogs()) {
            if (item.msg.startsWith("Message signing:") && item.msg.contains(kind))
                levels.add(item.type);
        }
        ShadowLog.reset();
        return levels;
    }

    private static List<Integer> levels(Integer... expected) {
        return new ArrayList<>(Arrays.asList(expected));
    }

    @Test
    public void aMissingInstallSignatureIsWarnedOnceThenDebug() throws Exception {
        installMissing();
        HttpsURLConnection signed = sign();
        assertTrue(signed.getRequestProperty("Signature"), signed.getRequestProperty("Signature").startsWith("account=:"));
        assertEquals(levels(Log.WARN), levels("install signature"));
        sign();
        assertEquals(levels(Log.DEBUG), levels("install signature"));
    }

    @Test
    public void aMissingAccountSignatureIsWarnedOnceThenDebug() throws Exception {
        accountMissing();
        HttpsURLConnection signed = sign();
        assertTrue(signed.getRequestProperty("Signature"), signed.getRequestProperty("Signature").startsWith("install=:"));
        assertEquals(levels(Log.WARN), levels("account signature"));
        sign();
        assertEquals(levels(Log.DEBUG), levels("account signature"));
    }

    @Test
    public void anUnavailableSignatureIsLoggedLikeAnEmptyOne() throws Exception {
        approov.when(() -> Approov.getAccountMessageSignature(ArgumentMatchers.anyString()))
                .thenThrow(new IllegalStateException("no key"));
        HttpsURLConnection signed = sign();
        assertTrue(signed.getRequestProperty("Signature"), signed.getRequestProperty("Signature").startsWith("install=:"));
        assertEquals(levels(Log.WARN), levels("account signature"));
    }

    @Test
    public void whenBothAreMissingTheRequestIsUnsignedAndLoggedAsAnErrorOnceThenDebug() throws Exception {
        installMissing();
        accountMissing();
        HttpsURLConnection unsigned = sign();
        assertNull(unsigned.getRequestProperty("Signature"));
        assertNull(unsigned.getRequestProperty("Signature-Input"));
        assertNotNull(unsigned.getRequestProperty("Approov-Token"));
        assertEquals(levels(Log.ERROR), levels("no signature produced"));
        sign();
        assertEquals(levels(Log.DEBUG), levels("no signature produced"));
    }

    @Test
    public void theResetRestoresTheFirstTimeLogs() throws Exception {
        installMissing();
        sign();
        sign();
        ShadowLog.reset();
        ApproovDefaultMessageSigning.resetMissingSignatureLogsForTesting();
        sign();
        assertEquals(levels(Log.WARN), levels("install signature"));
    }
}
