package io.approov.service.httpsurlconn;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

import android.content.Context;

import com.criticalblue.approovsdk.Approov;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.MockedStatic;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.Collections;

/**
 * The method names shared by all Approov packages, the removed methods, the enabled flags, getLastARC
 * and the initialize contract.
 */
public class CommonInterfaceTest {
    private Context context;

    @Before
    public void setUp() {
        ApproovService.reset();
        context = ApproovTestSupport.mockContext();
    }

    @After
    public void tearDown() {
        ApproovService.reset();
    }

    private static Method method(String name, Class<?>... parameters) throws NoSuchMethodException {
        return ApproovService.class.getMethod(name, parameters);
    }

    private static boolean hasMethod(String name) {
        for (Method method : ApproovService.class.getDeclaredMethods()) {
            if (method.getName().equals(name))
                return true;
        }
        return false;
    }

    // ---- names

    @Test
    public void theSharedNamesArePublicAndNotDeprecated() throws Exception {
        for (Method method : Arrays.asList(
                method("setTokenHeader", String.class, String.class),
                method("getTokenHeader"),
                method("getTokenPrefix"),
                method("setTraceIDHeader", String.class),
                method("getTraceIDHeader"),
                method("isApproovServiceEnabled"),
                method("isApproovProtectionEnabled"),
                method("setInstallAttributes", String.class),
                method("getLastARC"),
                method("getServerAdjustedCurrentTimeMS"),
                method("setLoggingLevel", ApproovLogLevel.class),
                method("getAccountMessageSignature", String.class))) {
            assertTrue(method.getName(), Modifier.isPublic(method.getModifiers()));
            assertTrue(method.getName(), Modifier.isStatic(method.getModifiers()));
            assertFalse(method.getName(), method.isAnnotationPresent(Deprecated.class));
        }
    }

    @Test
    public void theOldNamesAreDeprecatedAliases() throws Exception {
        for (Method method : Arrays.asList(
                method("setApproovHeader", String.class, String.class),
                method("setApproovTraceIDHeader", String.class),
                method("getApproovTokenHeader"),
                method("getApproovTokenPrefix"),
                method("getApproovTraceIDHeader"),
                method("getMessageSignature", String.class)))
            assertTrue(method.getName(), method.isAnnotationPresent(Deprecated.class));
    }

    @Test
    @SuppressWarnings("deprecation")
    public void theDeprecatedAliasesSetTheSameConfiguration() {
        ApproovService.setApproovHeader("X-Token", "Bearer ");
        assertEquals("X-Token", ApproovService.getTokenHeader());
        assertEquals("Bearer ", ApproovService.getTokenPrefix());
        assertEquals("X-Token", ApproovService.getApproovTokenHeader());
        assertEquals("Bearer ", ApproovService.getApproovTokenPrefix());
        ApproovService.setApproovHeader("X-Token", null);
        assertEquals("a null prefix is no prefix", "", ApproovService.getTokenPrefix());
        ApproovService.setApproovTraceIDHeader("X-Trace");
        assertEquals("X-Trace", ApproovService.getTraceIDHeader());
        assertEquals("X-Trace", ApproovService.getApproovTraceIDHeader());
        ApproovService.setTraceIDHeader(null);
        assertNull(ApproovService.getTraceIDHeader());
    }

    @Test
    public void prefetchIsRemoved() {
        assertFalse(hasMethod("prefetch"));
    }

    @Test
    @SuppressWarnings("deprecation")
    public void getMessageSignatureReturnsTheAccountSignature() throws Exception {
        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            ApproovTestSupport.initializeApproovService(approov);
            approov.when(() -> Approov.getAccountMessageSignature("message")).thenReturn("account-sig");
            assertEquals("account-sig", ApproovService.getMessageSignature("message"));
            assertEquals("account-sig", ApproovService.getAccountMessageSignature("message"));
        }
    }

    @Test
    public void setInstallAttributesBehavesAsSetInstallAttrsInToken() throws Exception {
        // before protection is enabled both throw the same way
        ApproovException shared = assertThrows(ApproovException.class,
                () -> ApproovService.setInstallAttributes("a.b.c"));
        assertTrue(shared.getMessage(), shared.getMessage().contains("not initialized"));
        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            ApproovTestSupport.initializeApproovService(approov);
            ApproovService.setInstallAttributes("a.b.c");
            approov.verify(() -> Approov.setInstallAttrsInToken("a.b.c"));
        }
    }

    // ---- enabled flags

    @Test
    public void theEnabledFlagsFollowInitialization() {
        assertFalse(ApproovService.isApproovServiceEnabled());
        assertFalse(ApproovService.isApproovProtectionEnabled());

        ApproovService.initialize(context, "");
        assertTrue(ApproovService.isApproovServiceEnabled());
        assertFalse(ApproovService.isApproovProtectionEnabled());
        assertTrue(ApproovService.isInitialized());
        assertFalse(ApproovService.isApproovEnabled());

        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            ApproovService.initialize(context, "account-a");
            assertTrue(ApproovService.isApproovServiceEnabled());
            assertTrue(ApproovService.isApproovProtectionEnabled());
            assertTrue(ApproovService.isApproovEnabled());
        }
    }

    // ---- getLastARC

    private static Approov.TokenFetchResult withARC(String arc) {
        Approov.TokenFetchResult result = ApproovTestSupport.tokenResult(
                Approov.TokenFetchStatus.SUCCESS, "jwt", "", "");
        when(result.getARC()).thenReturn(arc);
        return result;
    }

    @Test
    public void getLastARCMakesNoFetchAndIsEmptyBeforeAnyFetch() {
        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            ApproovTestSupport.initializeApproovService(approov);
            approov.when(() -> Approov.getPins("public-key-sha256"))
                    .thenReturn(Collections.singletonMap("api.example.com", Collections.singletonList("pin")));

            assertEquals("", ApproovService.getLastARC());

            approov.verify(() -> Approov.fetchApproovTokenAndWait(anyString()), never());
        }
    }

    @Test
    public void getLastARCReturnsTheARCOfTheLastFetchAndOnlyThat() throws Exception {
        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            ApproovTestSupport.initializeApproovService(approov);
            Approov.TokenFetchResult first = withARC("ARC-ONE");
            Approov.TokenFetchResult second = withARC("ARC-TWO");
            Approov.TokenFetchResult none = withARC(null);
            approov.when(() -> Approov.fetchApproovTokenAndWait("https://one.example.com/")).thenReturn(first);
            approov.when(() -> Approov.fetchApproovTokenAndWait("https://two.example.com/")).thenReturn(second);
            approov.when(() -> Approov.fetchApproovTokenAndWait("https://none.example.com/")).thenReturn(none);

            ApproovService.fetchToken("https://one.example.com/");
            assertEquals("ARC-ONE", ApproovService.getLastARC());
            ApproovService.fetchToken("https://two.example.com/");
            assertEquals("ARC-TWO", ApproovService.getLastARC());
            // a fetch without an ARC clears the previous one
            ApproovService.fetchToken("https://none.example.com/");
            assertEquals("", ApproovService.getLastARC());

            approov.verify(() -> Approov.fetchApproovTokenAndWait(anyString()), times(3));
        }
    }

    @Test
    public void theSecureStringAndCustomJWTFetchesRecordTheirARC() throws Exception {
        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            ApproovTestSupport.initializeApproovService(approov);
            Approov.TokenFetchResult secure = withARC("ARC-SECURE");
            Approov.TokenFetchResult jwt = withARC("ARC-JWT");
            approov.when(() -> Approov.fetchSecureStringAndWait("key", null)).thenReturn(secure);
            approov.when(() -> Approov.fetchCustomJWTAndWait("{}")).thenReturn(jwt);
            ApproovService.fetchSecureString("key", null);
            assertEquals("ARC-SECURE", ApproovService.getLastARC());
            ApproovService.fetchCustomJWT("{}");
            assertEquals("ARC-JWT", ApproovService.getLastARC());
        }
    }

    @Test
    public void aFetchThatThrowsLeavesNoARC() throws Exception {
        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            ApproovTestSupport.initializeApproovService(approov);
            Approov.TokenFetchResult first = withARC("ARC-ONE");
            approov.when(() -> Approov.fetchApproovTokenAndWait("https://one.example.com/")).thenReturn(first);
            approov.when(() -> Approov.fetchApproovTokenAndWait("https://bad.example.com/"))
                    .thenThrow(new IllegalStateException("not initialized"));
            ApproovService.fetchToken("https://one.example.com/");
            assertEquals("ARC-ONE", ApproovService.getLastARC());

            assertThrows(ApproovException.class, () -> ApproovService.fetchToken("https://bad.example.com/"));
            assertEquals("", ApproovService.getLastARC());
        }
    }

    @Test
    public void theARCOfARequestFetchIsRecordedAndInitializeClearsIt() throws Exception {
        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            ApproovTestSupport.initializeApproovService(approov);
            Approov.TokenFetchResult result = withARC("ARC-REQ");
            approov.when(() -> Approov.fetchApproovTokenAndWait("https://api.example.com/reply")).thenReturn(result);
            ApproovService.addApproov(ApproovTestSupport.connection("https://api.example.com/reply"));
            assertEquals("ARC-REQ", ApproovService.getLastARC());

            ApproovService.initialize(context, "account-a");
            assertEquals("", ApproovService.getLastARC());
        }
    }

    @Test
    public void theARCOfARejectedRequestCanBeRead() throws Exception {
        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            ApproovTestSupport.initializeApproovService(approov);
            Approov.TokenFetchResult rejected = ApproovTestSupport.tokenResult(Approov.TokenFetchStatus.REJECTED);
            approov.when(() -> Approov.fetchApproovTokenAndWait(anyString())).thenReturn(rejected);
            assertThrows(ApproovFetchStatusException.class,
                    () -> ApproovService.addApproov(ApproovTestSupport.connection("https://api.example.com/x")));
            assertEquals("ARC123", ApproovService.getLastARC());
        }
    }

    // ---- initialize

    @Test
    public void aNullContextIsRejectedInEveryMode() {
        assertThrows(IllegalArgumentException.class, () -> ApproovService.initialize(null, ""));
        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            assertThrows(IllegalArgumentException.class, () -> ApproovService.initialize(null, "account-a"));
            approov.verifyNoInteractions();
        }
        assertFalse(ApproovService.isApproovServiceEnabled());
    }

    @Test
    public void aNullAccountIdIsRejected() {
        assertThrows(IllegalArgumentException.class, () -> ApproovService.initialize(context, null));
        assertFalse(ApproovService.isApproovServiceEnabled());
    }

    @Test
    public void everyNonEmptyAccountIdAndCommentReachesTheSdkUnchanged() {
        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            approov.when(() -> Approov.initialize(any(), anyString(), anyString(), any())).thenReturn(true);

            ApproovService.initialize(context, "account-a", "first comment");
            ApproovService.initialize(context, "account-b", null);
            ApproovService.initialize(context, "account-a", "other comment");
            ApproovService.initialize(context, "account-a");

            approov.verify(() -> Approov.initialize(context, "account-a", "auto", "first comment"));
            approov.verify(() -> Approov.initialize(context, "account-b", "auto", null));
            approov.verify(() -> Approov.initialize(context, "account-a", "auto", "other comment"));
            approov.verify(() -> Approov.initialize(context, "account-a", "auto", null));
            assertTrue(ApproovService.isApproovProtectionEnabled());
        }
    }

    @Test
    public void aRepeatWithTheSameAccountIdReachesTheSdkEachTime() {
        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            ApproovService.initialize(context, "account-a");
            ApproovService.initialize(context, "account-a");
            approov.verify(() -> Approov.initialize(context, "account-a", "auto", null), times(2));
            assertTrue(ApproovService.isApproovProtectionEnabled());
        }
    }

    @Test
    public void theServiceLayerNeverComparesAccountIds() {
        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            // the SDK accepts a different account ID, so the layer must too
            approov.when(() -> Approov.initialize(any(), anyString(), anyString(), any())).thenReturn(false);
            ApproovService.initialize(context, "account-a");
            ApproovService.initialize(context, "account-b");
            assertTrue(ApproovService.isApproovProtectionEnabled());
            approov.verify(() -> Approov.initialize(context, "account-b", "auto", null));
        }
    }

    @Test
    public void anSdkExceptionIsThrownUnchangedAndLeavesTheStateUntouched() {
        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            ApproovService.initialize(context, "account-a");
            ApproovService.setTokenHeader("X-Token", "Bearer ");
            ApproovService.setServiceMutator(ApproovServiceMutator.ALWAYS_PROCEED);
            IllegalStateException conflict = new IllegalStateException("config conflict");
            approov.when(() -> Approov.initialize(any(), anyString(), anyString(), any())).thenThrow(conflict);

            IllegalStateException thrown = assertThrows(IllegalStateException.class,
                    () -> ApproovService.initialize(context, "account-b"));

            assertSame(conflict, thrown);
            assertTrue(ApproovService.isApproovProtectionEnabled());
            assertEquals("X-Token", ApproovService.getTokenHeader());
            assertEquals("Bearer ", ApproovService.getTokenPrefix());
            assertSame(ApproovServiceMutator.ALWAYS_PROCEED, ApproovService.getServiceMutator());

            // an IllegalArgumentException from the SDK too
            IllegalArgumentException bad = new IllegalArgumentException("bad config");
            approov.when(() -> Approov.initialize(any(), anyString(), anyString(), any())).thenThrow(bad);
            assertSame(bad, assertThrows(IllegalArgumentException.class,
                    () -> ApproovService.initialize(context, "account-a", "other comment")));
            assertEquals("X-Token", ApproovService.getTokenHeader());
        }
    }

    @Test
    public void aFailedFirstInitializationLeavesTheServiceDisabled() {
        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            approov.when(() -> Approov.initialize(any(), anyString(), anyString(), any()))
                    .thenThrow(new IllegalArgumentException("bad config"));
            assertThrows(IllegalArgumentException.class, () -> ApproovService.initialize(context, "bad"));
            assertFalse(ApproovService.isApproovServiceEnabled());
            assertFalse(ApproovService.isApproovProtectionEnabled());
        }
    }

    @Test
    public void anEmptyAccountIdNeverDowngradesActiveProtectionAndIsNotPassedToTheSdk() {
        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            ApproovService.initialize(context, "account-a");
            ApproovService.setTokenHeader("X-Token", "Bearer ");
            approov.clearInvocations();

            ApproovService.initialize(context, "");

            assertTrue(ApproovService.isApproovProtectionEnabled());
            // ignored, so the configuration is not reset either
            assertEquals("X-Token", ApproovService.getTokenHeader());
            approov.verifyNoInteractions();
        }
    }

    @Test
    public void bypassModeIsNeverPassedToTheSdk() {
        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            ApproovService.initialize(context, "");
            approov.verifyNoInteractions();
        }
    }

    @Test
    @SuppressWarnings("deprecation")
    public void eachInitializationThatIsNotIgnoredResetsTheConfiguration() {
        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            ApproovService.initialize(context, "account-a");
            ApproovService.setTokenHeader("X-Token", "Bearer ");
            ApproovService.setTraceIDHeader("X-Trace");
            ApproovService.setBindingHeader("Authorization");
            ApproovService.setUseApproovStatusIfNoToken(true);
            ApproovService.setProceedOnNetworkFail(true);
            ApproovService.addSubstitutionHeader("Api-Key", "Bearer ");
            ApproovService.addExclusionURLRegex("/excluded");
            ApproovService.setServiceMutator(ApproovDefaultMessageSigning.combined());
            assertFalse(ApproovService.getSubstitutionHeaders().isEmpty());
            assertFalse(ApproovService.getExclusionURLRegexs().isEmpty());

            ApproovService.initialize(context, "account-a");

            assertEquals("Approov-Token", ApproovService.getTokenHeader());
            assertEquals("", ApproovService.getTokenPrefix());
            assertEquals("Approov-TraceID", ApproovService.getTraceIDHeader());
            assertNull(ApproovService.getBindingHeader());
            assertFalse(ApproovService.getUseApproovStatusIfNoToken());
            assertFalse(ApproovService.getProceedOnNetworkFail());
            assertTrue(ApproovService.getSubstitutionHeaders().isEmpty());
            assertTrue(ApproovService.getExclusionURLRegexs().isEmpty());
            assertSame("signing is off", ApproovServiceMutator.DEFAULT, ApproovService.getServiceMutator());
        }
        // and the same for bypass mode
        ApproovService.reset();
        ApproovService.initialize(context, "");
        ApproovService.setTokenHeader("X-Token", null);
        ApproovService.initialize(context, "");
        assertEquals("Approov-Token", ApproovService.getTokenHeader());
    }

    @Test
    public void theUserPropertyIsSetWhenProtectionIsFirstEnabled() {
        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            ApproovService.initialize(context, "account-a");
            ApproovService.initialize(context, "account-a");
            approov.verify(() -> Approov.setUserProperty(
                    "approov-service-httpsurlconn/" + BuildConfig.APPROOV_SERVICE_VERSION), times(1));
        }
    }

    @Test
    public void aUserPropertyFailureDoesNotFailInitialization() {
        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            approov.when(() -> Approov.setUserProperty(anyString())).thenThrow(new IllegalStateException("no"));
            ApproovService.initialize(context, "account-a");
            assertTrue(ApproovService.isApproovProtectionEnabled());
        }
    }

    @Test
    public void theSubstitutionAndExclusionGettersAreEmptyBeforeInitialize() {
        ApproovService.reset();
        assertTrue(ApproovService.getSubstitutionHeaders().isEmpty());
        assertTrue(ApproovService.getExclusionURLRegexs().isEmpty());
    }
}
