package io.approov.service.httpsurlconn;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mockStatic;

import android.content.Context;
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

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Collections;

import javax.net.ssl.HttpsURLConnection;

/**
 * Contract checks of the public surface that need no request: the exceptions the mutator hooks declare, an
 * exclusion pattern that cannot be compiled, the exact exception messages of the direct methods, and the
 * exception hierarchy.
 */
@RunWith(RobolectricTestRunner.class)
@Config(manifest = Config.NONE)
public class ContractTest {
    private Context context;

    @Before
    public void setUp() {
        ApproovService.reset();
        context = ApproovTestSupport.mockContext();
        ShadowLog.reset();
    }

    @After
    public void tearDown() {
        ApproovService.reset();
        ShadowLog.reset();
    }

    // every hook of the mutator that is asked about a request or a result declares ApproovException, and the
    // pinning hook declares none
    @Test
    public void everyHookDeclaresApproovExceptionAndThePinningHookNone() {
        int hooks = 0;
        for (Method method : ApproovServiceMutator.class.getDeclaredMethods()) {
            if (!method.getName().startsWith("handle") || method.isSynthetic())
                continue;
            hooks++;
            boolean declares = false;
            for (Class<?> type : method.getExceptionTypes())
                declares |= (type == ApproovException.class);
            if (method.getName().equals("handlePinningShouldProcessRequest"))
                assertEquals("the pinning hook declares an exception", 0, method.getExceptionTypes().length);
            else
                assertTrue(method.getName() + " does not declare ApproovException", declares);
        }
        assertEquals("hooks found", 9, hooks);
    }

    @Test
    public void theMessageSigningHookDeclaresApproovExceptionAndADelegatingOverrideCan() throws Exception {
        Method hook = ApproovDefaultMessageSigning.class.getMethod("handleInterceptorProcessedRequest",
                HttpsURLConnection.class, ApproovRequestMutations.class);
        assertEquals(ApproovException.class, hook.getExceptionTypes()[0]);
        // an override that delegates to the standard decisions and declares it compiles and runs
        ApproovServiceMutator delegating = new ApproovServiceMutator() {
            @Override
            public HttpsURLConnection handleInterceptorProcessedRequest(HttpsURLConnection request,
                    ApproovRequestMutations changes) throws ApproovException {
                return ApproovServiceMutator.ALWAYS_PROCEED.handleInterceptorProcessedRequest(request, changes);
            }
        };
        HttpsURLConnection request = ApproovTestSupport.connection("https://a.example/");
        assertSame(request, delegating.handleInterceptorProcessedRequest(request, new ApproovRequestMutations()));
    }

    @Test
    public void anExclusionPatternThatCannotBeCompiledIsLoggedAndAddsNothing() throws Exception {
        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            ApproovService.initialize(context, "account-a");
            ApproovService.addExclusionURLRegex("/earlier");
            ApproovService.addExclusionURLRegex("([unclosed");
            assertEquals(Collections.singleton("/earlier"), ApproovService.getExclusionURLRegexs().keySet());
            boolean logged = false;
            for (ShadowLog.LogItem item : ShadowLog.getLogs())
                logged |= (item.type == Log.ERROR) && item.msg.startsWith("addExclusionURLRegex ([unclosed error");
            assertTrue("no error line", logged);
            // the earlier exclusion still matches
            assertFalse(ApproovServiceMutator.DEFAULT.handleInterceptorShouldProcessConnection(
                    ApproovTestSupport.connection("https://a.example/earlier/x")));
            assertTrue(ApproovServiceMutator.DEFAULT.handleInterceptorShouldProcessConnection(
                    ApproovTestSupport.connection("https://a.example/other")));
            ApproovService.removeExclusionURLRegex("/earlier");
            assertTrue(ApproovService.getExclusionURLRegexs().isEmpty());
        }
    }

    @Test
    public void theDirectMethodsFailBeforeInitializeAndInBypassModeWithTheirOwnName() throws Exception {
        String[] methods = {"precheck", "getDeviceID", "fetchToken", "getAccountMessageSignature",
                "getInstallMessageSignature", "fetchSecureString", "fetchCustomJWT", "setDataHashInToken",
                "setDevKey", "setInstallAttrsInToken", "getServerAdjustedCurrentTimeMS"};
        Class<?>[][] parameters = {{}, {}, {String.class}, {String.class}, {String.class},
                {String.class, String.class}, {String.class}, {String.class}, {String.class}, {String.class}, {}};
        for (int round = 0; round < 2; round++) {
            if (round == 1)
                ApproovService.initialize(context, "");
            for (int i = 0; i < methods.length; i++) {
                Object[] args = new Object[parameters[i].length];
                for (int a = 0; a < args.length; a++)
                    args[a] = "x";
                try {
                    ApproovService.class.getMethod(methods[i], parameters[i]).invoke(null, args);
                    fail(methods[i] + " did not throw");
                } catch (InvocationTargetException e) {
                    assertEquals(methods[i], ApproovException.class, e.getCause().getClass());
                    assertEquals(methods[i] + ": SDK not initialized", e.getCause().getMessage());
                }
            }
        }
    }

    @Test
    public void aRequestBeforeInitializeFails() throws Exception {
        ApproovException e = assertThrows(ApproovException.class,
                () -> ApproovService.addApproov(ApproovTestSupport.connection("https://a.example/")));
        assertEquals("Approov not initialized", e.getMessage());
        assertThrows(ApproovException.class,
                () -> ApproovService.addApproovToConnection(ApproovTestSupport.connection("https://a.example/")));
    }

    @Test
    public void anSdkExceptionOfADirectMethodIsAnApproovException() {
        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            ApproovTestSupport.initializeApproovService(approov);
            approov.when(() -> Approov.fetchApproovTokenAndWait("https://example.com/a"))
                    .thenThrow(new IllegalStateException("sdk broke"));
            ApproovException error = assertThrows(ApproovException.class,
                    () -> ApproovService.fetchToken("https://example.com/a"));
            assertTrue(error.getMessage(), error.getMessage().contains("sdk broke"));
        }
    }

    @Test
    public void aMissingSignatureHasItsOwnMessage() {
        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            ApproovTestSupport.initializeApproovService(approov);
            approov.when(() -> Approov.getAccountMessageSignature("m")).thenReturn(null);
            approov.when(() -> Approov.getInstallMessageSignature("m")).thenReturn(null);
            assertEquals("no account signature available", assertThrows(ApproovException.class,
                    () -> ApproovService.getAccountMessageSignature("m")).getMessage());
            assertEquals("no device signature available", assertThrows(ApproovException.class,
                    () -> ApproovService.getInstallMessageSignature("m")).getMessage());
        }
    }

    @Test
    public void aSigningFailureOfTheSdkIsWrapped() {
        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            ApproovTestSupport.initializeApproovService(approov);
            approov.when(() -> Approov.getInstallMessageSignature("message"))
                    .thenThrow(new IllegalStateException("private key unavailable"));
            ApproovException error = assertThrows(ApproovException.class,
                    () -> ApproovService.getInstallMessageSignature("message"));
            assertTrue(error.getMessage(), error.getMessage().contains("private key unavailable"));
        }
    }

    @Test
    public void aRejectionNamesTheOperationTheStatusTheArcAndTheReasons() {
        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            ApproovTestSupport.initializeApproovService(approov);
            Approov.TokenFetchResult rejected = ApproovTestSupport.tokenResult(Approov.TokenFetchStatus.REJECTED);
            approov.when(() -> Approov.fetchSecureStringAndWait("precheck-dummy-key", null)).thenReturn(rejected);
            approov.when(() -> Approov.fetchSecureStringAndWait("the-key", null)).thenReturn(rejected);
            approov.when(() -> Approov.fetchCustomJWTAndWait("{}")).thenReturn(rejected);
            assertEquals("precheck: REJECTED: ARC123 hooked,rooted",
                    assertThrows(ApproovRejectionException.class, ApproovService::precheck).getMessage());
            assertEquals("fetchCustomJWT: REJECTED: ARC123 hooked,rooted", assertThrows(
                    ApproovRejectionException.class, () -> ApproovService.fetchCustomJWT("{}")).getMessage());
            assertEquals("fetchSecureString lookup for the-key: REJECTED: ARC123 hooked,rooted", assertThrows(
                    ApproovRejectionException.class, () -> ApproovService.fetchSecureString("the-key", null))
                    .getMessage());
        }
    }

    @Test
    public void aRejectionIsAFetchStatusExceptionWithItsGettersUnchanged() {
        ApproovRejectionException built = new ApproovRejectionException("m", "ARC9", "rooted");
        assertTrue(built instanceof ApproovFetchStatusException);
        assertTrue(built instanceof ApproovException);
        assertEquals(Approov.TokenFetchStatus.REJECTED, built.getTokenFetchStatus());
        assertEquals("m", built.getMessage());
        assertEquals("ARC9", built.getARC());
        assertEquals("rooted", built.getRejectionReasons());
        assertNull(new ApproovRejectionException("m", null, null).getRejectionReasons());

        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            ApproovTestSupport.initializeApproovService(approov);
            Approov.TokenFetchResult rejected = ApproovTestSupport.tokenResult(Approov.TokenFetchStatus.REJECTED);
            approov.when(() -> Approov.fetchCustomJWTAndWait("{}")).thenReturn(rejected);
            try {
                ApproovService.fetchCustomJWT("{}");
                fail("a rejection must be thrown");
            } catch (ApproovFetchStatusException e) {
                assertTrue(e instanceof ApproovRejectionException);
                assertEquals("ARC123", ((ApproovRejectionException) e).getARC());
                assertEquals("hooked,rooted", ((ApproovRejectionException) e).getRejectionReasons());
                assertEquals(Approov.TokenFetchStatus.REJECTED, e.getTokenFetchStatus());
            } catch (ApproovException e) {
                fail("a rejection must be caught as an ApproovFetchStatusException");
            }
        }
    }

    @Test
    public void aNetworkExceptionIsAnApproovExceptionWithItsStatus() {
        ApproovNetworkException e = new ApproovNetworkException(Approov.TokenFetchStatus.POOR_NETWORK, "m");
        assertTrue(e instanceof ApproovException);
        assertEquals(Approov.TokenFetchStatus.POOR_NETWORK, e.getTokenFetchStatus());
        assertNull(new ApproovNetworkException("m").getTokenFetchStatus());
    }

    @Test
    public void theApproovExceptionKeepsTheOriginalCause() {
        IllegalStateException cause = new IllegalStateException("original");
        ApproovException withMessage = new ApproovException("context", cause);
        assertEquals("context", withMessage.getMessage());
        assertSame(cause, withMessage.getCause());
        ApproovException wrapped = new ApproovException(cause);
        assertSame(cause, wrapped.getCause());
        assertTrue(wrapped.getMessage(), wrapped.getMessage().contains("original"));
        assertTrue(wrapped instanceof java.io.IOException);
    }

    @Test
    public void aNullLevelIsRejected() {
        assertThrows(IllegalArgumentException.class, () -> ApproovService.setLoggingLevel(null));
    }
}
