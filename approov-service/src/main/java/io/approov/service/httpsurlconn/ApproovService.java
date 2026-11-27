//
// MIT License
// 
// Copyright (c) 2016-present, Critical Blue Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files
// (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge,
// publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR
// ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH
// THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package io.approov.service.httpsurlconn;

import android.content.Context;

import com.criticalblue.approovsdk.Approov;

import java.net.MalformedURLException;
import java.net.URL;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import javax.net.ssl.HttpsURLConnection;

// ApproovService provides a mediation layer to the Approov SDK itself
public class ApproovService {
    // logging tag
    private static final String TAG = "ApproovService";

    // default header that will carry any optional Approov TraceID debug value from
    // the SDK
    private static final String APPROOV_TRACE_ID_HEADER = "Approov-TraceID";

    // header that will be added to Approov enabled requests
    private static final String APPROOV_TOKEN_HEADER = "Approov-Token";

    // any prefix to be added before the Approov token, such as "Bearer "
    private static final String APPROOV_TOKEN_PREFIX = "";

    // hostname verifier that checks against the current Approov pins or null if SDK not initialized
    private static PinningHostnameVerifier pinningHostnameVerifier = null;

    // true if the ApproovService has been initialized
    private static boolean isInitialized = false;

    // true once the Approov SDK has been initialized by a successful initialize with a non-empty account ID
    private static boolean approovProtectionEnabled = false;

    // the ARC of the most recent token, secure string or custom JWT fetch, or empty if none
    private static String lastARC = "";

    // true if request preparation should proceed on network failures and not add
    // an Approov token
    private static boolean proceedOnNetworkFail = false;

    // true if the Approov fetch status should be used as the token header value if the
    // actual token fetch fails or returns an empty token
    private static boolean useApproovStatusIfNoToken = false;

    // header to be used to send Approov tokens
    private static String approovTokenHeader = null;

    // header used to send any optional Approov TraceID debug value provided by the
    // SDK
    private static String approovTraceIDHeader = null;


    // any prefix String to be added before the transmitted Approov token
    private static String approovTokenPrefix = null;

    // any header to be used for binding in Approov tokens or null if not set
    private static String bindingHeader = null;

    // The mutator instance used to control ApproovService behaviour at key points in the flow.
    // Unless set using the ApproovService.setServiceMutator() method, the default behaviour
    // defined in the default implementation of ApproovServiceMutator will be used.
    private static ApproovServiceMutator serviceMutator = ApproovServiceMutator.DEFAULT;

    // map of headers that should have their values substituted for secure strings, mapped to their
    // required prefixes
    private static Map<String, String> substitutionHeaders = null;

    // set of URL regexs that should be excluded from any Approov protection, mapped to the compiled Pattern
    private static Map<String, Pattern> exclusionURLRegexs = null;

    /**
     * Construction is disallowed as this is a static only class.
     */
    private ApproovService() {
    }

    /**
     * Initializes the ApproovService with an Approov account ID and comment. A non-empty account ID is always
     * passed to the Approov SDK with the comment unchanged and the SDK decides: a repeat with the same account
     * ID and comment returns at once, while anything else the SDK rejects is thrown unchanged with the service
     * state untouched. An empty account ID enables the service in bypass mode, without Approov protection,
     * and is ignored once protection is enabled. Each initialization that is not ignored resets the
     * configuration to its defaults (headers, substitutions, exclusions, the service mutator, and so any
     * message signing), so make any configuration calls after initialize.
     *
     * @param context is the Application context
     * @param config is your Approov account ID, or an empty string for bypass mode with no SDK initialization
     * @param comment is the comment passed to the SDK unchanged, or null for no comment
     * @throws IllegalArgumentException if the context or account ID is null, or the SDK rejects the account ID
     * @throws IllegalStateException if the SDK is already initialized with a different account ID or comment
     */
    public static synchronized void initialize(Context context, String config, String comment) {
        if (context == null)
            throw new IllegalArgumentException("initialize: null context");
        if (config == null)
            throw new IllegalArgumentException("config must not be null; pass \"\" for bypass mode");

        if (config.isEmpty()) {
            if (approovProtectionEnabled) {
                // an empty account ID never downgrades active Approov protection and is not passed to the SDK
                ApproovLog.i(TAG, "initialize: empty config ignored, Approov protection already enabled");
            } else {
                ApproovLog.i(TAG, "initialize: bypass mode, Approov protection not active");
                resetConfiguration();
                isInitialized = true;
            }
            return;
        }

        // pass every non-empty account ID to the SDK with the comment exactly as given, as the SDK is the
        // only judge of a repeat call and any exception it throws reaches the caller with the state untouched
        boolean newlyInitialized;
        try {
            newlyInitialized = Approov.initialize(context.getApplicationContext(), config, "auto", comment);
        } catch (RuntimeException e) {
            ApproovLog.e(TAG, "initialize: Approov SDK failed: " + e);
            throw e;
        }
        boolean protectionWasEnabled = approovProtectionEnabled;
        resetConfiguration();
        isInitialized = true;
        approovProtectionEnabled = true;
        pinningHostnameVerifier = new PinningHostnameVerifier(HttpsURLConnection.getDefaultHostnameVerifier());
        if (newlyInitialized)
            ApproovLog.i(TAG, "initialize: Approov protection enabled");
        else
            ApproovLog.d(TAG, "initialize: Approov SDK already initialized with the same config and comment");
        if (!protectionWasEnabled) {
            try {
                Approov.setUserProperty("approov-service-httpsurlconn/" + BuildConfig.APPROOV_SERVICE_VERSION);
            } catch (RuntimeException e) {
                // the property is diagnostic only and must not fail a successful initialization
                ApproovLog.e(TAG, "initialize: Approov user property not set: " + e);
            }
        }
    }

    /**
     * Resets the configuration to its defaults, as each initialization does. The logging level is kept.
     */
    private static synchronized void resetConfiguration() {
        lastARC = "";
        pinningHostnameVerifier = null;
        proceedOnNetworkFail = false;
        useApproovStatusIfNoToken = false;
        approovTokenHeader = APPROOV_TOKEN_HEADER;
        approovTraceIDHeader = APPROOV_TRACE_ID_HEADER;
        approovTokenPrefix = APPROOV_TOKEN_PREFIX;
        bindingHeader = null;
        substitutionHeaders = new HashMap<>();
        exclusionURLRegexs = new HashMap<>();
        serviceMutator = ApproovServiceMutator.DEFAULT;
    }
    /**
     * Initializes the ApproovService with an account configuration.
     *
     * @param context the Application context
     * @param config the configuration string, or empty for no SDK initialization
     */
    public static void initialize(Context context, String config) {
        initialize(context, config, null);
    }

    /**
     * Determines if the ApproovService is enabled, which is true once any initialize has succeeded,
     * including bypass mode with an empty account ID.
     *
     * @return true if the service has been enabled by a successful initialize, false otherwise
     */
    public static synchronized boolean isApproovServiceEnabled() {
        return isInitialized;
    }

    /**
     * Determines if Approov protection is enabled, which is true once the Approov SDK has been initialized
     * by a successful initialize with a non-empty account ID. It is false before initialization and in
     * bypass mode, where requests are sent without Approov processing.
     *
     * @return true if the Approov SDK is initialized and requests are protected, false otherwise
     */
    public static synchronized boolean isApproovProtectionEnabled() {
        return isInitialized && approovProtectionEnabled;
    }

    /**
     * Indicates whether the service layer has been initialized, bypass mode included. This is the same as
     * isApproovServiceEnabled().
     *
     * @return true if the service layer has been initialized, false otherwise
     */
    public static synchronized boolean isInitialized() {
        return isApproovServiceEnabled();
    }

    /**
     * Indicates whether Approov protection is enabled for this service layer instance. If initialization
     * used an empty account ID then the layer is initialized but Approov protection is bypassed. This is
     * the same as isApproovProtectionEnabled().
     *
     * @return true if Approov protection is enabled, false otherwise
     */
    public static synchronized boolean isApproovEnabled() {
        return isApproovProtectionEnabled();
    }
    /**
     * Resets the ApproovService state. This should only be used for testing purposes.
     */
    static synchronized void reset() {
        isInitialized = false;
        approovProtectionEnabled = false;
        lastARC = "";
        messageSignatureDeprecationLogged.set(false);
        resetRestoreWarnings();
        PinningHostnameVerifier.resetWarnings();
        pinningHostnameVerifier = null;
        proceedOnNetworkFail = false;
        useApproovStatusIfNoToken = false;
        approovTokenHeader = null;
        approovTraceIDHeader = null;
        approovTokenPrefix = null;
        bindingHeader = null;
        serviceMutator = ApproovServiceMutator.DEFAULT;
        substitutionHeaders = null;
        exclusionURLRegexs = null;
        ApproovLog.setLevel(ApproovLogLevel.INFO);
    }

    /**
     * Normalizes a host for comparison with the keys of the SDK pin set: lowercase, without one trailing
     * dot and without the brackets of an IPv6 address.
     *
     * @param host is the host
     * @return the normalized host
     */
    static String normalizeHost(String host) {
        String normalized = host.toLowerCase(Locale.ROOT);
        if (normalized.endsWith("."))
            normalized = normalized.substring(0, normalized.length() - 1);
        if (normalized.startsWith("[") && normalized.endsWith("]"))
            normalized = normalized.substring(1, normalized.length() - 1);
        return normalized;
    }

    /**
     * Sets the logging level of the service layer. ERROR writes errors only, WARNING adds warnings, INFO
     * (the default) adds information and DEBUG adds the debug lines, including the loggable token of each
     * request whose claims include the device ID. OFF writes nothing. The level may be set at any time and
     * is not reset by initialize. Debug logging enabled for the ApproovService tag, with
     * "adb shell setprop log.tag.ApproovService DEBUG", raises any level but OFF to DEBUG without a rebuild.
     * Note that the logging of the Approov SDK itself is not affected.
     *
     * @param level is the logging level to be used
     * @throws IllegalArgumentException if the level is null
     */
    public static void setLoggingLevel(ApproovLogLevel level) {
        if (level == null)
            throw new IllegalArgumentException("setLoggingLevel: null level");
        ApproovLog.setLevel(level);
        ApproovLog.d(TAG, "setLoggingLevel " + level);
    }

    /**
     * Sets a flag indicating if request preparation should proceed anyway if it is
     * not possible to obtain an Approov token due to a networking failure. If this is set
     * then your backend API can receive calls without the expected Approov token header
     * being added, or without header/query parameter substitutions being made. Note that
     * this should be used with caution because it may allow a request to be established
     * before any dynamic pins have been received via Approov, thus potentially opening
     * the channel to a MitM.
     *
     * @param proceed is true if Approov networking fails should allow continuation
     */
    public static synchronized void setProceedOnNetworkFail(boolean proceed) {
        ApproovLog.d(TAG, "setProceedOnNetworkFail " + proceed);
        proceedOnNetworkFail = proceed;
    }

    /**
     * Sets a development key indicating that the app is a development version and it should
     * pass attestation even if the app is not registered or it is running on an emulator. The
     * development key value can be rotated at any point in the account if a version of the app
     * containing the development key is accidentally released. This is primarily
     * used for situations where the app package must be modified or resigned in
     * some way as part of the testing process.
     *
     * @param devKey is the development key to be used
     * @throws ApproovException if there was a problem
     */
    public static synchronized void setDevKey(String devKey) throws ApproovException {
        if (!isApproovEnabled()) {
            ApproovLog.e(TAG, "setDevKey: SDK not initialized");
            throw new ApproovException("setDevKey: SDK not initialized");
        }
        try {
            Approov.setDevKey(devKey);
            ApproovLog.d(TAG, "setDevKey");
        }
        catch (IllegalStateException e) {
            throw new ApproovException("IllegalState: " + e.getMessage());
        }
        catch (IllegalArgumentException e) {
            throw new ApproovException("IllegalArgument: " + e.getMessage());
        }
    }

    /**
     * Sets the header that the Approov token is added on, as well as an optional prefix String (such as
     * "Bearer "). By default the token is provided on "Approov-Token" with no prefix.
     *
     * @param header is the header to place the Approov token on
     * @param prefix is any prefix String for the Approov token header, or null for none
     */
    public static synchronized void setTokenHeader(String header, String prefix) {
        ApproovLog.d(TAG, "setTokenHeader " + header + ", " + prefix);
        approovTokenHeader = header;
        // a null prefix means no prefix, so it is never concatenated as the literal string "null"
        approovTokenPrefix = (prefix == null) ? "" : prefix;
    }

    /**
     * Gets the header that is used to add the Approov token.
     *
     * @return String of the header used for the Approov token
     */
    public static synchronized String getTokenHeader() {
        return approovTokenHeader;
    }

    /**
     * Gets the prefix that is added before the Approov token in the header.
     *
     * @return String of the prefix added before the Approov token
     */
    public static synchronized String getTokenPrefix() {
        return approovTokenPrefix;
    }

    /**
     * Sets the header name that is used to pass any optional Approov TraceID debug value. By default the
     * TraceID is provided on "Approov-TraceID" if one is available. Passing null disables the header.
     *
     * @param header is the name of the header on which to place the Approov TraceID, or null to disable it
     */
    public static synchronized void setTraceIDHeader(String header) {
        ApproovLog.d(TAG, "setTraceIDHeader " + header);
        approovTraceIDHeader = header;
    }

    /**
     * Gets the header used to hold the optional Approov TraceID.
     *
     * @return the header name used for the Approov TraceID, or null if disabled
     */
    public static synchronized String getTraceIDHeader() {
        return approovTraceIDHeader;
    }

    /**
     * Sets the header that the Approov token is added on, as well as an optional prefix String.
     *
     * @param header is the header to place the Approov token on
     * @param prefix is any prefix String for the Approov token header, or null for none
     * @deprecated Use setTokenHeader.
     */
    @Deprecated
    public static void setApproovHeader(String header, String prefix) {
        setTokenHeader(header, prefix);
    }

    /**
     * Sets the header that any optional Approov TraceID debug value is added on.
     *
     * @param header is the header to place the Approov TraceID on, or null to disable the header
     * @deprecated Use setTraceIDHeader.
     */
    @Deprecated
    public static void setApproovTraceIDHeader(String header) {
        setTraceIDHeader(header);
    }

    /**
     * Gets the header that is used to add the Approov token.
     *
     * @return String of the header used for the Approov token
     * @deprecated Use getTokenHeader.
     */
    @Deprecated
    public static String getApproovTokenHeader() {
        return getTokenHeader();
    }

    /**
     * Gets the name of the header that is used to hold the optional Approov TraceID.
     *
     * @return the header name used for the Approov TraceID, or null if disabled
     * @deprecated Use getTraceIDHeader.
     */
    @Deprecated
    public static String getApproovTraceIDHeader() {
        return getTraceIDHeader();
    }

    /**
     * Gets the prefix that is added before the Approov token in the header.
     *
     * @return String of the prefix added before the Approov token
     * @deprecated Use getTokenPrefix.
     */
    @Deprecated
    public static String getApproovTokenPrefix() {
        return getTokenPrefix();
    }
    /**
     * Sets a binding header that must be present on all requests using the Approov service. A
     * header should be chosen whose value is unchanging for most requests (such as an
     * Authorization header). A hash of the header value is included in the issued Approov tokens
     * to bind them to the value. This may then be verified by the backend API integration. This
     * method should typically only be called once.
     *
     * @param header is the header to use for Approov token binding
     */
    public static synchronized void setBindingHeader(String header) {
        ApproovLog.d(TAG, "setBindingHeader " + header);
        bindingHeader = header;
    }

    /**
     * Gets any current binding header.
     *
     * @return binding header or null if not set
     */
    static synchronized String getBindingHeader() {
        return bindingHeader;
    }

    /**
     * Adds the name of a header which should be subject to secure strings substitution. This
     * means that if the header is present then the value will be used as a key to look up a
     * secure string value which will be substituted into the header value instead. This allows
     * easy migration to the use of secure strings. Note that this should be done on initialization
     * rather than for every request so the same configuration is applied consistently to each
     * HttpsURLConnection. A required
     * prefix may be specified to deal with cases such as the use of "Bearer " prefixed before values
     * in an authorization header.
     *
     * @param header is the header to be marked for substitution
     * @param requiredPrefix is any required prefix to the value being substituted or null if not required
     */
    public static synchronized void addSubstitutionHeader(String header, String requiredPrefix) {
        if (pinningHostnameVerifier != null) {
            ApproovLog.d(TAG, "addSubstitutionHeader " + header + ", " + requiredPrefix);
            if (requiredPrefix == null)
                substitutionHeaders.put(header, "");
            else
                substitutionHeaders.put(header, requiredPrefix);
        }
    }

    /**
     * Removes a header previously added using addSubstitutionHeader.
     *
     * @param header is the header to be removed for substitution
     */
    public static synchronized void removeSubstitutionHeader(String header) {
        if (pinningHostnameVerifier != null) {
            ApproovLog.d(TAG, "removeSubstitutionHeader " + header);
            substitutionHeaders.remove(header);
        }
    }

    /**
     * Gets the map of headers that are subject to substitution.
     *
     * @return a map of headers that are subject to substitution, mapped to the
     *         required prefix
     */
    public static synchronized Map<String, String> getSubstitutionHeaders() {
        return new HashMap<>(substitutionHeaders);
    }

    // Automated query-parameter substitution was removed (Issue #14): java.net.URL is
    // immutable once the connection is opened, and the automated path broke request-mutation
    // tracking that message signing relies on. Secure-string query values must now be fetched
    // manually via fetchSecureString() and built into the URL before openConnection().
    // See USAGE.md ("Substituting Query Parameters").

    /**
     * Adds an exclusion URL regular expression. If a URL for a request matches this regular expression
     * then it will not be subject to any Approov protection. Note that this facility must be used with
     * EXTREME CAUTION due to the impact of dynamic pinning. Pinning may be applied to all domains added
     * using Approov, and updates to the pins are received when an Approov fetch is performed. If you
     * exclude some URLs on domains that are protected with Approov, then these will be protected with
     * Approov pins but without a path to update the pins until a URL is used that is not excluded. Thus
     * you are responsible for ensuring that there is always a possibility of calling a non-excluded
     * URL, or you should make an explicit call to fetchToken if there are persistent pinning failures.
     * Conversely, use of those option may allow a request to be established before any dynamic pins
     * have been received via Approov, thus potentially opening the channel to a MitM.
     *
     * @param urlRegex is the regular expression that will be compared against URLs to exclude them
     */
    public static synchronized void addExclusionURLRegex(String urlRegex) {
        if (pinningHostnameVerifier != null) {
            try {
                Pattern pattern = Pattern.compile(urlRegex);
                exclusionURLRegexs.put(urlRegex, pattern);
                ApproovLog.d(TAG, "addExclusionURLRegex " + urlRegex);
            } catch (PatternSyntaxException e) {
                ApproovLog.e(TAG, "addExclusionURLRegex " + urlRegex + " error: " + e.getMessage());
            }
        }
    }

    /**
     * Removes an exclusion URL regular expression previously added using addExclusionURLRegex.
     *
     * @param urlRegex is the regular expression that will be compared against URLs to exclude them
     */
    public static synchronized void removeExclusionURLRegex(String urlRegex) {
        if (pinningHostnameVerifier != null) {
            ApproovLog.d(TAG, "removeExclusionURLRegex " + urlRegex);
            exclusionURLRegexs.remove(urlRegex);
        }
    }

    /**
     * Sets the ApproovServiceMutator instance to handle callbacks from the
     * ApproovService implementation. This facility enables customization of
     * ApproovService operations at key points in the configuration and
     * attestation flows. It should reduce the number of times this service
     * layer implementation needs to be forked in order to introduce custom
     * behavior.
     *
     * @param mutator is the ApproovServiceMutator with callback handlers that may
     *                override the default behavior of the ApproovService singleton.
     *                Passing null to this method will reinstate the default
     *                behavior.
     */
    public static synchronized void setServiceMutator(ApproovServiceMutator mutator) {
        if (mutator == null) {
            mutator = ApproovServiceMutator.DEFAULT;
        }
        ApproovLog.d(TAG, "Applied ApproovServiceMutator:" + mutator.toString());
        serviceMutator = mutator;
    }


    /**
     * Gets the active service mutator instance that is handling callbacks from
     * ApproovService.
     *
     * @return the service mutator instance (never null)
     */
    public static synchronized ApproovServiceMutator getServiceMutator() {
        return serviceMutator;
    }

    /**
     * @deprecated Use setServiceMutator instead
     */
    @Deprecated
    public static void setApproovInterceptorExtensions(ApproovServiceMutator mutator) {
        setServiceMutator(mutator);
    }

    /**
     * Gets the legacy interceptor extensions callback handlers.
     *
     * @return the callback handlers currently used by the service mutator API
     * @deprecated Use getServiceMutator instead
     */
    @Deprecated
    public static ApproovServiceMutator getApproovInterceptorExtensions() {
        return getServiceMutator();
    }


    // Performs a precheck to determine if the app will pass attestation. This requires secure
    // strings to be enabled for the account, although no strings need to be set up. This will
    // likely require network access so may take some time to complete. It may throw ApproovException
    // if the precheck fails or if there is some other problem. ApproovRejectionException is thrown
    // if the app has failed Approov checks or ApproovNetworkException for networking issues where a
    // user initiated retry of the operation should be allowed. An ApproovRejectionException may provide
    // additional information about the cause of the rejection.
    //
    // @throws ApproovException if there was a problem
    public static void precheck() throws ApproovException {
        if (!isApproovEnabled()) {
            ApproovLog.e(TAG, "precheck: SDK not initialized");
            throw new ApproovException("precheck: SDK not initialized");
        }
        // try and fetch a non-existent secure string in order to check for a rejection
        Approov.TokenFetchResult approovResults;
        try {
            approovResults = fetchRecording(() -> Approov.fetchSecureStringAndWait("precheck-dummy-key", null));
            ApproovLog.d(TAG, "precheck: " + approovResults.getStatus().toString());
        }
        catch (IllegalStateException e) {
            throw new ApproovException("IllegalState: " + e.getMessage());
        }
        catch (IllegalArgumentException e) {
            throw new ApproovException("IllegalArgument: " + e.getMessage());
        }

        // process the returned Approov status using decision maker
        getServiceMutator().handlePrecheckResult(approovResults);
    }

    /**
     * Gets the device ID used by Approov to identify the particular device that the SDK is running on. Note
     * that different Approov apps on the same device will return a different ID. Moreover, the ID may be
     * changed by an uninstall and reinstall of the app.
     *
     * @return String of the device ID
     * @throws ApproovException if there was a problem
     */
    public static String getDeviceID() throws ApproovException {
        if (!isApproovEnabled()) {
            ApproovLog.e(TAG, "getDeviceID: SDK not initialized");
            throw new ApproovException("getDeviceID: SDK not initialized");
        }
        try {
            String deviceID = Approov.getDeviceID();
            ApproovLog.d(TAG, "getDeviceID: " + deviceID);
            return deviceID;
        }
        catch (IllegalStateException e) {
            throw new ApproovException("IllegalState: " + e.getMessage());
        }
    }

    /**
     * Checks that Approov protection is enabled before a public method uses the Approov SDK, so that the
     * SDK is not called before initialization or in bypass mode.
     *
     * @param method is the name of the public method, for the exception message
     * @throws ApproovException if Approov protection is not enabled
     */
    private static void requireProtection(String method) throws ApproovException {
        if (!isApproovProtectionEnabled()) {
            ApproovLog.e(TAG, method + ": SDK not initialized");
            throw new ApproovException(method + ": SDK not initialized");
        }
    }

    /**
     * Gets the current time in milliseconds since the epoch, adjusted to the Approov servers' clock. This
     * is the device clock corrected by the offset the Approov SDK learns at each attestation, and before the
     * first attestation it is the device clock. Message signatures take their created and expires times from
     * it, so that a device whose clock is wrong still signs within the window your backend accepts. Use it for
     * timestamps of your own that your backend compares with its clock. If the server time is not available,
     * it is the device clock.
     *
     * @return the current time in milliseconds since the epoch, adjusted to the Approov servers' clock
     * @throws ApproovException if Approov protection is not enabled or the SDK call fails
     */
    public static long getServerAdjustedCurrentTimeMS() throws ApproovException {
        requireProtection("getServerAdjustedCurrentTimeMS");
        try {
            return sdkServerAdjustedTimeMS();
        } catch (RuntimeException e) {
            ApproovException wrapped = new ApproovException(e);
            ApproovLog.e(TAG, "getServerAdjustedCurrentTimeMS: " + wrapped.getMessage());
            throw wrapped;
        }
    }

    /**
     * Gets the time message signatures are stamped with, in milliseconds since the epoch: the server adjusted
     * time while protection is enabled, so that a wrong device clock does not put created and expires outside
     * the backend's window, and the device clock otherwise. A signature is never left out for want of it, so
     * an SDK failure falls back to the device clock and is logged.
     *
     * @return the time for the created and expires signature parameters, in milliseconds since the epoch
     */
    static long signatureTimeMillis() {
        if (isApproovProtectionEnabled()) {
            try {
                return sdkServerAdjustedTimeMS();
            } catch (RuntimeException e) {
                ApproovLog.w(TAG, "Message signing: server adjusted time unavailable, using the device clock: " + e);
            }
        }
        return System.currentTimeMillis();
    }

    /**
     * Gets the server adjusted time from the Approov SDK.
     *
     * @return the current time in milliseconds since the epoch, adjusted to the Approov servers' clock
     * @throws RuntimeException as the SDK call throws it, such as an IllegalStateException before
     *         initialization, or an IllegalStateException if the Approov SDK the app runs with is older than
     *         the one the package is built against and does not have the method
     */
    private static long sdkServerAdjustedTimeMS() {
        try {
            return Approov.getServerAdjustedCurrentTimeMS();
        } catch (LinkageError e) {
            throw new IllegalStateException("Approov SDK has no getServerAdjustedCurrentTimeMS", e);
        }
    }

    /**
     * Directly sets the data hash to be included in subsequently fetched Approov tokens. If the hash is
     * different from any previously set value then this will cause the next token fetch operation to
     * fetch a new token with the correct payload data hash. The hash appears in the
     * 'pay' claim of the Approov token as a base64 encoded string of the SHA256 hash of the
     * data. Note that the data is hashed locally and never sent to the Approov cloud service.
     *
     * @param data is the data to be hashed and set in the token
     * @throws ApproovException if there was a problem
     */
    public static void setDataHashInToken(String data) throws ApproovException {
        if (!isApproovEnabled()) {
            ApproovLog.e(TAG, "setDataHashInToken: SDK not initialized");
            throw new ApproovException("setDataHashInToken: SDK not initialized");
        }
        try {
            Approov.setDataHashInToken(data);
            ApproovLog.d(TAG, "setDataHashInToken");
        }
        catch (IllegalStateException e) {
            throw new ApproovException("IllegalState: " + e.getMessage());
        }
        catch (IllegalArgumentException e) {
            throw new ApproovException("IllegalArgument: " + e.getMessage());
        }
    }

    /**
     * Performs an Approov token fetch for the given URL. This should be used in situations where it
     * is not possible to use the networking interception to add the token. This will
     * likely require network access so may take some time to complete. If the attestation fails
     * for any reason then an ApproovException is thrown. This will be ApproovNetworkException for
     * networking issues wher a user initiated retry of the operation should be allowed. Note that
     * the returned token should NEVER be cached by your app, you should call this function when
     * it is needed.
     *
     * @param url is the URL giving the domain for the token fetch
     * @return String of the fetched token
     * @throws ApproovException if there was a problem
     */
    public static String fetchToken(String url) throws ApproovException {
        if (!isApproovEnabled()) {
            ApproovLog.e(TAG, "fetchToken: SDK not initialized");
            throw new ApproovException("fetchToken: SDK not initialized");
        }
        // fetch the Approov token
        Approov.TokenFetchResult approovResults;
        try {
            approovResults = fetchRecording(() -> Approov.fetchApproovTokenAndWait(url));
            ApproovLog.d(TAG, "fetchToken: " + approovResults.getStatus().toString());
        }
        catch (IllegalStateException e) {
            throw new ApproovException("IllegalState: " + e.getMessage());
        }
        catch (IllegalArgumentException e) {
            throw new ApproovException("IllegalArgument: " + e.getMessage());
        }

        // process the status using decision maker
        getServiceMutator().handleFetchTokenResult(approovResults);
        return approovResults.getToken();
    }

    /**
     * Gets the signature for the given message. This uses an account specific message signing key that is
     * transmitted to the SDK after a successful fetch if the facility is enabled for the account. Note
     * that if the attestation failed then the signing key provided is actually random so that the
     * signature will be incorrect. An Approov token should always be included in the message
     * being signed and sent alongside this signature to prevent replay attacks. If no signature is
     * available, because there has been no prior fetch or the feature is not enabled, then an
     * ApproovException is thrown.
     *
     * @param message is the message whose content is to be signed
     * @return String of the base64 encoded message signature
     * @throws ApproovException if there was a problem
     * @deprecated Use getAccountMessageSignature. The first call logs a deprecation warning.
     */
    @Deprecated
    public static String getMessageSignature(String message) throws ApproovException {
        if (messageSignatureDeprecationLogged.compareAndSet(false, true))
            ApproovLog.w(TAG, "getMessageSignature is deprecated: use getAccountMessageSignature");
        return getAccountMessageSignature(message);
    }

    // true once the deprecation warning of getMessageSignature has been logged
    private static final AtomicBoolean messageSignatureDeprecationLogged = new AtomicBoolean();

    /**
     * Fetches a secure string with the given key. If newDef is not null then a
     * secure string for the particular app instance may be defined. In this case the
     * new value is returned as the secure string. Use of an empty string for newDef removes
     * the string entry. Note that this call may require network transaction and thus may block
     * for some time, so should not be called from the UI thread. If the attestation fails
     * for any reason then an ApproovException is thrown. This will be ApproovRejectionException
     * if the app has failed Approov checks or ApproovNetworkException for networking issues where
     * a user initiated retry of the operation should be allowed. Note that the returned string
     * should NEVER be cached by your app, you should call this function when it is needed.
     *
     * @param key is the secure string key to be looked up
     * @param newDef is any new definition for the secure string, or null for lookup only
     * @return secure string (should not be cached by your app) or null if it was not defined
     * @throws ApproovException if there was a problem
     */
    public static String fetchSecureString(String key, String newDef) throws ApproovException {
        if (!isApproovEnabled()) {
            ApproovLog.e(TAG, "fetchSecureString: SDK not initialized");
            throw new ApproovException("fetchSecureString: SDK not initialized");
        }
        // determine the type of operation as the values themselves cannot be logged
        String type = "lookup";
        if (newDef != null)
            type = "definition";

        // fetch any secure string keyed by the value, catching any exceptions the SDK might throw
        Approov.TokenFetchResult approovResults;
        try {
            approovResults = fetchRecording(() -> Approov.fetchSecureStringAndWait(key, newDef));
            ApproovLog.d(TAG, "fetchSecureString " + type + ": " + key + ", " + approovResults.getStatus().toString());
        }
        catch (IllegalStateException e) {
            throw new ApproovException("IllegalState: " + e.getMessage());
        }
        catch (IllegalArgumentException e) {
            throw new ApproovException("IllegalArgument: " + e.getMessage());
        }

        // process the returned Approov status using decision maker
        getServiceMutator().handleFetchSecureStringResult(approovResults, type, key);
        return approovResults.getSecureString();
    }

    /**
     * Fetches a custom JWT with the given payload. Note that this call will require network
     * transaction and thus will block for some time, so should not be called from the UI thread.
     * If the attestation fails for any reason then an IOException is thrown. This will be
     * ApproovRejectionException if the app has failed Approov checks or ApproovNetworkException
     * for networking issues where a user initiated retry of the operation should be allowed.
     *
     * @param payload is the marshaled JSON object for the claims to be included
     * @return custom JWT string
     * @throws ApproovException if there was a problem
     */
    public static String fetchCustomJWT(String payload) throws ApproovException {
        if (!isApproovEnabled()) {
            ApproovLog.e(TAG, "fetchCustomJWT: SDK not initialized");
            throw new ApproovException("fetchCustomJWT: SDK not initialized");
        }
        // fetch the custom JWT catching any exceptions the SDK might throw
        Approov.TokenFetchResult approovResults;
        try {
            approovResults = fetchRecording(() -> Approov.fetchCustomJWTAndWait(payload));
            ApproovLog.d(TAG, "fetchCustomJWT: " + approovResults.getStatus().toString());
        }
        catch (IllegalStateException e) {
            throw new ApproovException("IllegalState: " + e.getMessage());
        }
        catch (IllegalArgumentException e) {
            throw new ApproovException("IllegalArgument: " + e.getMessage());
        }

        // process the returned Approov status using decision maker
        getServiceMutator().handleFetchCustomJWTResult(approovResults);
        return approovResults.getToken();
    }

    /**
     * Gets the Attestation Response Code (ARC) from the most recent token, secure string or custom JWT
     * fetch made by this layer, either for a request or by a direct method. It performs no fetch of its
     * own, so it can be read after a rejected request to correlate with your backend API. An empty string
     * is returned if no fetch has been made, if the last fetch carried no ARC or failed without a result,
     * or if ARC is not enabled for the account. Note that it is preferable to obtain the ARC on the server
     * side where possible.
     *
     * @return the ARC of the most recent fetch, or an empty string
     */
    public static synchronized String getLastARC() {
        return lastARC;
    }

    /**
     * Records the ARC of a fetch result as the most recent one. An empty or null ARC clears the previous
     * value, as the ARC belongs to the last fetch.
     *
     * @param approovResults is the fetch result, or null if the fetch failed without a result
     * @return the fetch result passed in
     */
    static synchronized Approov.TokenFetchResult recordLastARC(Approov.TokenFetchResult approovResults) {
        String arc = (approovResults != null) ? approovResults.getARC() : null;
        lastARC = (arc != null) ? arc : "";
        return approovResults;
    }

    // a fetch made by the SDK
    interface SdkFetch {
        Approov.TokenFetchResult fetch();
    }

    /**
     * Performs a fetch with the SDK and records its ARC. A fetch that throws or returns no result leaves no
     * ARC.
     *
     * @param fetch is the SDK call
     * @return the fetch result
     */
    static Approov.TokenFetchResult fetchRecording(SdkFetch fetch) {
        recordLastARC(null);
        return recordLastARC(fetch.fetch());
    }

    /**
     * Sets an install attributes token to be sent to the server and associated with this particular
     * app installation for future Approov token fetches, as setInstallAttrsInToken does. This is the name
     * shared by all Approov packages.
     *
     * @param attrs is the signed JWT holding the new install attributes
     * @throws ApproovException if the attrs parameter is invalid or the SDK is not initialized
     */
    public static void setInstallAttributes(String attrs) throws ApproovException {
        setInstallAttrsInToken(attrs);
    }

    /**
     * Sets an install attributes token to be sent to the server and associated with this particular
     * app installation for future Approov token fetches. The token must be signed, within its
     * expiry time and bound to the correct device ID for it to be accepted by the server.
     * Calling this method ensures that the next call to fetch an Approov
     * token will not use a cached version, so that this information can be transmitted to the server.
     *
     * @param attrs is the signed JWT holding the new install attributes
     * @return void
     * @throws ApproovException if the attrs parameter is invalid or the SDK is not initialized
     */
    public static void setInstallAttrsInToken(String attrs) throws ApproovException {
        if (!isApproovEnabled()) {
            ApproovLog.e(TAG, "setInstallAttrsInToken: SDK not initialized");
            throw new ApproovException("setInstallAttrsInToken: SDK not initialized");
        }
        try {
            Approov.setInstallAttrsInToken(attrs);
            ApproovLog.d(TAG, "setInstallAttrsInToken");
        } catch (IllegalArgumentException e) {
            ApproovLog.e(TAG, "setInstallAttrsInToken failed with IllegalArgument: " + e.getMessage());
            throw new ApproovException("setInstallAttrsInToken: " + e.getMessage());
        } catch (IllegalStateException e) {
            ApproovLog.e(TAG, "setInstallAttrsInToken failed with IllegalState: " + e.getMessage());
            throw new ApproovException("setInstallAttrsInToken: " + e.getMessage());
        }
    }

    /**
     * Gets a copy of the current exclusion URL regexs.
     *
     * @return Map<String, Pattern> of the exclusion regexs to their respective Patterns
     */
    static synchronized Map<String, Pattern> getExclusionURLRegexs() {
        return new HashMap<>(exclusionURLRegexs);
    }

    /**
     * Sets a flag indicating if the Approov fetch status (e.g. "NO_NETWORK",
     * "MITM_DETECTED")
     * should be used as the token header value if the actual token fetch fails or
     * returns an empty token.
     * This allows passing error condition information to the backend via the
     * Approov-Token header,
     * which might otherwise be empty or missing.
     *
     * @param shouldUse is true if the status should be used as the token value
     */
    public static synchronized void setUseApproovStatusIfNoToken(boolean shouldUse) {
        ApproovLog.d(TAG, "setUseApproovStatusIfNoToken " + shouldUse);
        useApproovStatusIfNoToken = shouldUse;
    }
    /**
     * Gets a flag indicating if the Approov fetch status should be used as the token header value
     * if the actual token fetch fails or returns an empty token.
     *
     * @return true if the status should be used as the token value, false otherwise
     */
    public static synchronized boolean getUseApproovStatusIfNoToken() {
        return useApproovStatusIfNoToken;
    }

    /**
     * Gets a flag indicating if request preparation should proceed anyway if it is
     * not possible to obtain an Approov token due to a networking failure.
     *
     * @return true if Approov networking fails should allow continuation, false otherwise
     * @deprecated Use setServiceMutator to control this behavior
     */
    @Deprecated
    public static synchronized boolean getProceedOnNetworkFail() {
        return proceedOnNetworkFail;
    }

    /**
     * Gets the signature for the given message. This uses an account specific message signing key that is
     * transmitted to the SDK after a successful fetch if the facility is enabled for the account. Note
     * that if the attestation failed then the signing key provided is actually random so that the
     * signature will be incorrect. An Approov token should always be included in the message
     * being signed and sent alongside this signature to prevent replay attacks. If no signature is
     * available, because there has been no prior fetch or the feature is not enabled, then an
     * ApproovException is thrown.
     *
     * @param message is the message whose content is to be signed
     * @return String of the base64 encoded message signature
     * @throws ApproovException if there was a problem
     */
    public static String getAccountMessageSignature(String message) throws ApproovException {
        if (!isApproovEnabled()) {
            ApproovLog.e(TAG, "getAccountMessageSignature: SDK not initialized");
            throw new ApproovException("getAccountMessageSignature: SDK not initialized");
        }
        try {
            String signature = Approov.getAccountMessageSignature(message);
            ApproovLog.d(TAG, "getAccountMessageSignature");
            if (signature == null)
                throw new ApproovException("no account signature available");
            return signature;
        }
        catch (IllegalStateException e) {
            throw new ApproovException("IllegalState: " + e.getMessage());
        }
        catch (IllegalArgumentException e) {
            throw new ApproovException("IllegalArgument: " + e.getMessage());
        }
    }

    /**
     * Gets the install signature for the given message. This uses an app install specific message
     * signing key that is generated the first time an app launches. This signing mechanism uses an
     * ECC key pair where the private key is managed by the secure element or trusted execution
     * environment of the device. Where it can, Approov uses attested key pairs to perform the
     * message signing.
     * <p>
     * An Approov token should always be included in the message being signed and sent alongside
     * this signature to prevent replay attacks.
     * <p>
     * If no signature is available, because there has been no prior fetch or the feature is not
     * enabled, then an ApproovException is thrown.
     *
     * @param message is the message whose content is to be signed
     * @return String of the base64 encoded message signature in ASN.1 DER format
     * @throws ApproovException if there was a problem
     */
    public static String getInstallMessageSignature(String message) throws ApproovException {
        if (!isApproovEnabled()) {
            ApproovLog.e(TAG, "getInstallMessageSignature: SDK not initialized");
            throw new ApproovException("getInstallMessageSignature: SDK not initialized");
        }
        try {
            String signature = Approov.getInstallMessageSignature(message);
            ApproovLog.d(TAG, "getInstallMessageSignature");
            if (signature == null)
                throw new ApproovException("no device signature available");
            return signature;
        }
        catch (IllegalStateException e) {
            throw new ApproovException("IllegalState: " + e.getMessage());
        }
        catch (IllegalArgumentException e) {
            throw new ApproovException("IllegalArgument: " + e.getMessage());
        }
    }

    /**
     * Gets any optional TraceID debug value carried on a token fetch result. Older
     * SDK versions do not expose this method, so we resolve it reflectively and
     * silently treat it as unavailable when the runtime does not support it.
     *
     * @param approovResults the token fetch result returned by the SDK
     * @return the TraceID value, or null if unavailable
     */
    private static String getTokenFetchTraceID(Approov.TokenFetchResult approovResults) {
        try {
            Method method = approovResults.getClass().getMethod("getTraceID");
            Object value = method.invoke(approovResults);
            return (value instanceof String) ? (String) value : null;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Holds the outcome of the non-signing part of request processing. In the
     * httpsurlconn service layer, token fetch, header substitution, and query
     * substitution are resolved before the final processed-request callback is
     * invoked.
     */
    static final class PreparedRequestData {
        final ApproovServiceMutator mutator;
        final ApproovRequestMutations changes;
        final boolean invokeProcessedCallback;

        PreparedRequestData(
                ApproovServiceMutator mutator,
                ApproovRequestMutations changes,
                boolean invokeProcessedCallback
        ) {
            this.mutator = mutator;
            this.changes = changes;
            this.invokeProcessedCallback = invokeProcessedCallback;
        }
    }

    /**
     * Holds the effective URL for a prepared request. Automated query-parameter substitution
     * was removed (Issue #14), so the URL is never changed here; this wrapper is retained only
     * to carry the URL into the buffered-connection body-digest flow.
     */
    static final class QuerySubstitutionResult {
        final URL url;

        QuerySubstitutionResult(URL url) {
            this.url = url;
        }
    }

    /**
     * Determines if request processing should be deferred through a buffered
     * connection so the final processed-request callback can see any body bytes
     * written after addApproov returns.
     *
     * @param request is the request being prepared
     * @return true if the caller must continue using a buffered connection wrapper
     */
    private static boolean shouldUseBufferedConnection(HttpsURLConnection request) {
        if (request.getDoOutput()) {
            return true;
        }

        String method = request.getRequestMethod();
        return "POST".equalsIgnoreCase(method)
                || "PUT".equalsIgnoreCase(method)
                || "PATCH".equalsIgnoreCase(method);
    }

    /**
     * Performs the token fetch, optional TraceID propagation, and secure string
     * header substitutions for a request. This method intentionally stops short of
     * invoking the processed request callback so wrappers can finish any remaining
     * transport-specific work, such as URL substitution or body buffering, before
     * message signing occurs.
     *
     * @param request is the request being prepared
     * @return the request preparation result
     * @throws ApproovException if a token or secure string could not be obtained
     */
    static synchronized PreparedRequestData prepareApproovRequest(HttpsURLConnection request) throws ApproovException {
        // throw if we couldn't initialize the SDK
        if (!isInitialized)
            throw new ApproovException("Approov not initialized");

        if (!isApproovEnabled()) {
            // In bypass mode, return empty/noop modifications immediately without invoking processed request callback
            return new PreparedRequestData(getServiceMutator(), new ApproovRequestMutations(), false);
        }

        // cache the mutator for the duration of the request processing to make
        // sure it is not changed mid-flight
        ApproovServiceMutator mutator = getServiceMutator();
        ApproovRequestMutations changes = new ApproovRequestMutations();

        // first check if we are to proceed with pinning processing
        if (mutator.handlePinningShouldProcessRequest(request)) {
            // ensure the request is pinned even if the request later turns out to be
            // excluded from Approov token processing
            request.setHostnameVerifier(pinningHostnameVerifier);
        }

        // first check if we are to proceed with any Approov processing
        if (!mutator.handleInterceptorShouldProcessConnection(request)) {
            // we are not to proceed with any Approov processing so just continue
            return new PreparedRequestData(mutator, changes, false);
        }

        // update the data hash based on any token binding header (presence is optional)
        String currentBindingHeader = getBindingHeader();
        if (currentBindingHeader != null) {
            String bindingValue = request.getRequestProperty(currentBindingHeader);
            if (bindingValue != null)
                Approov.setDataHashInToken(bindingValue);
        }

        String urlString = request.getURL().toString();

        // request an Approov token for the request URL
        Approov.TokenFetchResult approovResults = fetchRecording(() -> Approov.fetchApproovTokenAndWait(urlString));

        // provide information about the obtained token or error (note "approov token
        // -check" can be used to check the validity of the token and if you use
        // token annotations they will appear here to determine why a request is
        // being rejected)
        ApproovLog.d(TAG, "Token for " + ApproovLog.loggableURL(urlString) + ": " + approovResults.getLoggableToken());

        // check the status of Approov token fetch using decision maker
        String setTokenHeaderKey = null;
        String setTokenHeaderValue = null;
        String setTraceIDHeaderKey = null;
        String setTraceIDHeaderValue = null;
        if (mutator.handleInterceptorFetchTokenResult(approovResults, urlString)) {
            // we successfully obtained a token so add it to the header for the request
            setTokenHeaderKey = getTokenHeader();

            String fetchedToken = approovResults.getToken();
            if (((fetchedToken == null) || fetchedToken.isEmpty()) && getUseApproovStatusIfNoToken())
                setTokenHeaderValue = getTokenPrefix() + approovResults.getStatus().toString();
            else
                setTokenHeaderValue = getTokenPrefix() + (fetchedToken == null ? "" : fetchedToken);

            String traceIDHeader = getTraceIDHeader();
            String traceID = getTokenFetchTraceID(approovResults);
            // Emit the trace header whenever the SDK provides a value, even an empty one, as
            // evidence that Approov processing occurred. Only a null trace ID (none available)
            // leaves the header off.
            if ((traceIDHeader != null) && (traceID != null)) {
                setTraceIDHeaderKey = traceIDHeader;
                setTraceIDHeaderValue = traceID;
            }
        } else {
            // we only continue additional processing if we had a valid status from
            // Approov, to prevent additional delays by trying to fetch from Approov
            // again and this also protects against header substitutions in domains not
            // protected by Approov and therefore potentially subject to a MitM
            return new PreparedRequestData(mutator, changes, false);
        }

        if (setTokenHeaderKey != null) {
            request.setRequestProperty(setTokenHeaderKey, setTokenHeaderValue);
            changes.setTokenHeaderKey(setTokenHeaderKey);
            changes.setTokenHeaderValue(setTokenHeaderValue);
        }
        if (setTraceIDHeaderKey != null) {
            request.setRequestProperty(setTraceIDHeaderKey, setTraceIDHeaderValue);
            changes.setTraceIDHeaderKey(setTraceIDHeaderKey);
            changes.setTraceIDHeaderValue(setTraceIDHeaderValue);
        }

        // we now deal with any header substitutions, which may require further fetches
        // but these should be using cached results
        Map<String, String> substitutionHeaders = getSubstitutionHeaders();
        Map<String, String> setSubstitutionHeaders = new LinkedHashMap<>(substitutionHeaders.size());
        for (Map.Entry<String, String> entry : substitutionHeaders.entrySet()) {
            String header = entry.getKey();
            String prefix = entry.getValue();
            String value = request.getRequestProperty(header);
            if ((value != null) && value.startsWith(prefix) && (value.length() > prefix.length())) {
                approovResults = fetchRecording(() -> Approov.fetchSecureStringAndWait(value.substring(prefix.length()), null));
                ApproovLog.d(TAG, "Substituting header: " + header + ", " + approovResults.getStatus().toString());
                if (mutator.handleInterceptorHeaderSubstitutionResult(approovResults, header)) {
                    setSubstitutionHeaders.put(header, prefix + approovResults.getSecureString());
                }
            }
        }

        if (!setSubstitutionHeaders.isEmpty()) {
            for (Map.Entry<String, String> entry : setSubstitutionHeaders.entrySet()) {
                // substitute the header
                request.setRequestProperty(entry.getKey(), entry.getValue());
            }
            changes.setSubstitutionHeaderKeys(new ArrayList<>(setSubstitutionHeaders.keySet()));
        }

        return new PreparedRequestData(mutator, changes, true);
    }

    /**
     * Adds Approov to the given request using the legacy in-place API. The
     * Approov token is added in a header, any optional TraceID debug value is
     * added in a separate header, the HostnameVerifier may be overridden to pin
     * the request, and configured secure string header substitutions are applied.
     *
     * This method preserves the binary-compatible API from earlier releases. Use
     * addApproovToConnection(HttpsURLConnection) when the caller needs deferred
     * body-aware processing such as message-signing body digests.
     *
     * @param request is the HttpsUrlConnection to which Approov is being added
     * @throws ApproovException if it is not possible to obtain an Approov token or
     *                          secure strings
     */
    public static synchronized void addApproov(HttpsURLConnection request) throws ApproovException {
        addApproovInternal(request, false, null);
    }

    /**
     * Adds Approov to the given request, supplying the request body bytes so that a
     * message-signing {@code Content-Digest} can be computed over them. Use this overload
     * when message signing is configured with a body digest and the body is available as a
     * repeatable byte array. The SHA-256 (or SHA-512) digest of {@code body} is set in the
     * {@code Content-Digest} header and covered by the signature.
     *
     * @param request is the HttpsUrlConnection to which Approov is being added
     * @param body    is the exact request body that will be written, used for the digest
     * @throws ApproovException if it is not possible to obtain an Approov token or secure strings
     */
    public static synchronized void addApproov(HttpsURLConnection request, byte[] body) throws ApproovException {
        addApproovInternal(request, false, body);
    }

    /**
     * Adds Approov to the given request. The Approov token is added in a header,
     * any optional TraceID debug value is added in a separate header, the
     * HostnameVerifier may be overridden to pin the request, and configured secure
     * string substitutions are applied. The mutator acts as the single place
     * where token fetch, substitution, pinning, and final processed-request
     * behavior can be customized for HttpsURLConnection requests.
     *
     * @param request is the HttpsUrlConnection to which Approov is being added
     * @return the processed request, ready to be used by the caller. In the
     *         common case this is the same connection instance that was passed in.
     *         If deferred body-aware processing is required, a buffered wrapper
     *         connection is returned and the caller must continue to use that
     *         returned instance.
     * @throws ApproovException if it is not possible to obtain an Approov token or
     *                          secure strings
     */
    public static synchronized HttpsURLConnection addApproovToConnection(HttpsURLConnection request) throws ApproovException {
        return addApproovInternal(request, true, null);
    }

    private static HttpsURLConnection addApproovInternal(
            HttpsURLConnection request,
            boolean allowBufferedConnection,
            byte[] body
    ) throws ApproovException {
        // throw if we couldn't initialize the SDK
        if (!isInitialized)
            throw new ApproovException("Approov not initialized");

        // Apply the non-signing parts of the HttpsURLConnection preparation flow immediately so
        // callers continue to see any ApproovException at addApproov() time.
        PreparedRequestData preparedRequestData = prepareApproovRequest(request);

        // Thread explicit body bytes (from addApproov(connection, byte[])) into the mutations
        // so message signing can compute the Content-Digest over them.
        if (body != null) {
            preparedRequestData.changes.setBodyBytes(body);
        }

        if (!preparedRequestData.invokeProcessedCallback) {
            return request;
        }

        // Query parameters are never auto-substituted (Issue #14), so the effective URL never
        // changes here. A buffered connection is still used for body-bearing methods so message
        // signing can compute the Content-Digest over the body written after addApproov returns.
        QuerySubstitutionResult querySubstitutionResult = new QuerySubstitutionResult(request.getURL());
        if (shouldUseBufferedConnection(request) && allowBufferedConnection) {
            return new ApproovBufferedHttpsURLConnection(request, preparedRequestData, querySubstitutionResult);
        }

        HttpsURLConnection processed = preparedRequestData.mutator.handleInterceptorProcessedRequest(
                request,
                preparedRequestData.changes
        );
        // the token and trace headers are set by the layer, so a callback cannot drop or change them
        restoreApproovHeaders(processed, preparedRequestData.changes);
        return processed;
    }

    // true once the warning for a token or trace header that a callback changed is logged
    private static final AtomicBoolean tokenRestoreLogged = new AtomicBoolean();
    private static final AtomicBoolean traceRestoreLogged = new AtomicBoolean();

    /**
     * Puts back the token and trace headers the layer set on a request, if the processed request callback
     * removed them or changed their values. The layer sets these headers independently of the mutator, so a
     * mutator cannot drop them. The first time for each header in a process a warning is logged.
     *
     * @param request is the request the callback returned, or null
     * @param changes are the mutations of the request, which hold the header names and values the layer set
     */
    static void restoreApproovHeaders(HttpsURLConnection request, ApproovRequestMutations changes) {
        if ((request == null) || (changes == null))
            return;
        String[] names = {changes.getTokenHeaderKey(), changes.getTraceIDHeaderKey()};
        String[] values = {changes.getTokenHeaderValue(), changes.getTraceIDHeaderValue()};
        AtomicBoolean[] logged = {tokenRestoreLogged, traceRestoreLogged};
        String[] kinds = {"token", "trace"};
        for (int i = 0; i < names.length; i++) {
            if ((names[i] == null) || (values[i] == null))
                continue;
            try {
                if (values[i].equals(request.getRequestProperty(names[i])))
                    continue;
                request.setRequestProperty(names[i], values[i]);
            } catch (IllegalStateException e) {
                // the callback connected the request, so its headers can no longer be changed
                ApproovLog.e(TAG, "handleInterceptorProcessedRequest: Approov " + kinds[i]
                        + " header not restored, request already connected");
                continue;
            }
            String message = "handleInterceptorProcessedRequest: removed or changed the Approov " + kinds[i]
                    + " header, restored";
            if (logged[i].compareAndSet(false, true))
                ApproovLog.w(TAG, message);
            else
                ApproovLog.d(TAG, message);
        }
    }

    /**
     * Clears the once per process flags of the header restore warnings. This is for tests only.
     */
    static void resetRestoreWarnings() {
        tokenRestoreLogged.set(false);
        traceRestoreLogged.set(false);
    }

    // substituteQueryParams(URL) and substituteQueryParam(URL, String) were removed (Issue #14).
    // Fetch secure-string query values manually with fetchSecureString() and build the URL before
    // openConnection(); see USAGE.md ("Substituting Query Parameters").
}

