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

import android.util.Log;
import android.content.Context;

import com.criticalblue.approovsdk.Approov;

import java.net.MalformedURLException;
import java.net.URL;
import java.lang.reflect.Method;
import java.security.PublicKey;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import okio.ByteString;

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

    // set of query parameters that may be substituted, specified by the key name
    // and mapped to the compiled Pattern
    private static Map<String, Pattern> substitutionQueryParams = null;

    // set of URL regexs that should be excluded from any Approov protection, mapped to the compiled Pattern
    private static Map<String, Pattern> exclusionURLRegexs = null;

    /**
     * Construction is disallowed as this is a static only class.
     */
    private ApproovService() {
    }

    /**
     * Initializes the ApproovService with an account configuration.
     *
     * @param context the Application context
     * @param config the configuration string, or empty for no SDK initialization
     */
    public static void initialize(Context context, String config) {
        // setup for using Appproov
        pinningHostnameVerifier = null;
        proceedOnNetworkFail = false;
        useApproovStatusIfNoToken = false;
        approovTokenHeader = APPROOV_TOKEN_HEADER;
        approovTraceIDHeader = APPROOV_TRACE_ID_HEADER;
        approovTokenPrefix = APPROOV_TOKEN_PREFIX;
        bindingHeader = null;
        substitutionHeaders = new HashMap<>();
        substitutionQueryParams = new HashMap<>();
        exclusionURLRegexs = new HashMap<>();
        serviceMutator = ApproovServiceMutator.DEFAULT;
        // initialize the Approov SDK
        try {
            if (config.length() != 0)
                Approov.initialize(context, config, "auto", null);
            Approov.setUserProperty("approov-service-httpsurlconn");
        } catch (IllegalArgumentException e) {
            Log.e(TAG, "Approov initialization failed: " + e.getMessage());
            return;
        }

        // build the custom hostname verifier
        pinningHostnameVerifier = new PinningHostnameVerifier(HttpsURLConnection.getDefaultHostnameVerifier());
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
        Log.d(TAG, "setProceedOnNetworkFail " + proceed);
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
        try {
            Approov.setDevKey(devKey);
            Log.d(TAG, "setDevKey");
        }
        catch (IllegalStateException e) {
            throw new ApproovException("IllegalState: " + e.getMessage());
        }
        catch (IllegalArgumentException e) {
            throw new ApproovException("IllegalArgument: " + e.getMessage());
        }
    }

    /**
     * Sets the header that the Approov token is added on, as well as an optional
     * prefix String (such as "Bearer "). By default the token is provided on
     * "Approov-Token" with no prefix.
     *
     * @param header is the header to place the Approov token on
     * @param prefix is any prefix String for the Approov token header
     */
    public static synchronized void setApproovHeader(String header, String prefix) {
        Log.d(TAG, "setApproovHeader " + header + ", " + prefix);
        approovTokenHeader = header;
        approovTokenPrefix = prefix;
    }

    /**
     * Sets the header name that is used to pass any optional Approov TraceID debug
     * value. By default the TraceID is provided on "Approov-TraceID" if one is
     * available. Passing null disables adding the TraceID header.
     *
     * @param header is the name of the header on which to place the Approov
     *               TraceID, or null to disable the header
     */
    public static synchronized void setApproovTraceIDHeader(String header) {
        Log.d(TAG, "setApproovTraceIDHeader " + header);
        approovTraceIDHeader = header;
    }

    /**
     * Gets the header that is used to add the Approov token.
     *
     * @return String of the header used for the Approov token
     */
    public static synchronized String getApproovTokenHeader() {
        return approovTokenHeader;
    }

    /**
     * Gets the name of the header that is used to hold the optional Approov
     * TraceID.
     *
     * @return String the name of the header used for the Approov TraceID, or
     *         null if disabled
     */
    public static synchronized String getApproovTraceIDHeader() {
        return approovTraceIDHeader;
    }

    /**
     * Gets the prefix that is added before the Approov token in the header.
     *
     * @return String of the prefix added before the Approov token
     */
    public static synchronized String getApproovTokenPrefix() {
        return approovTokenPrefix;
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
        Log.d(TAG, "setBindingHeader " + header);
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
            Log.d(TAG, "addSubstitutionHeader " + header + ", " + requiredPrefix);
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
            Log.d(TAG, "removeSubstitutionHeader " + header);
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

    /**
     * Adds a key name for a query parameter that should be subject to secure
     * strings substitution. This means that if the query parameter is present in a
     * URL then the value will be used as a key to look up a secure string value
     * which will be substituted as the query parameter value instead. This allows
     * easy migration to the use of secure strings.
     *
     * @param key is the query parameter key name to be added for substitution
     */
    public static synchronized void addSubstitutionQueryParam(String key) {
        if (pinningHostnameVerifier != null) {
            Log.d(TAG, "addSubstitutionQueryParam " + key);
            try {
                Pattern pattern = Pattern.compile("[\\?&]" + Pattern.quote(key) + "=([^&;]+)");
                substitutionQueryParams.put(key, pattern);
            } catch (PatternSyntaxException e) {
                Log.e(TAG, "addSubstitutionQueryParam " + key + " error: " + e.getMessage());
            }
        }
    }

    /**
     * Removes a query parameter key name previously added using
     * addSubstitutionQueryParam.
     *
     * @param key is the query parameter key name to be removed for substitution
     */
    public static synchronized void removeSubstitutionQueryParam(String key) {
        if (pinningHostnameVerifier != null) {
            Log.d(TAG, "removeSubstitutionQueryParam " + key);
            substitutionQueryParams.remove(key);
        }
    }

    /**
     * Gets the map of substitution query parameters.
     *
     * @return a map of query parameters to be substituted, mapped to the compiled
     *         Pattern
     */
    public static synchronized Map<String, Pattern> getSubstitutionQueryParams() {
        return new HashMap<>(substitutionQueryParams);
    }

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
                Log.d(TAG, "addExclusionURLRegex " + urlRegex);
            } catch (PatternSyntaxException e) {
                Log.e(TAG, "addExclusionURLRegex " + urlRegex + " error: " + e.getMessage());
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
            Log.d(TAG, "removeExclusionURLRegex " + urlRegex);
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
        Log.d(TAG, "Applied ApproovServiceMutator:" + mutator.toString());
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


    /**
     * Prefetches in the background to lower the effective latency of a subsequent token fetch or
     * secure string fetch by starting the operation earlier so the subsequent fetch may be able to
     * use cached data.
     */
    public static synchronized void prefetch() {
        if (pinningHostnameVerifier != null)
            // fetch an Approov token using a placeholder domain
            Approov.fetchApproovToken(new PrefetchCallbackHandler(), "approov.io");
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
        // try and fetch a non-existent secure string in order to check for a rejection
        Approov.TokenFetchResult approovResults;
        try {
            approovResults = Approov.fetchSecureStringAndWait("precheck-dummy-key", null);
            Log.d(TAG, "precheck: " + approovResults.getStatus().toString());
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
        try {
            String deviceID = Approov.getDeviceID();
            Log.d(TAG, "getDeviceID: " + deviceID);
            return deviceID;
        }
        catch (IllegalStateException e) {
            throw new ApproovException("IllegalState: " + e.getMessage());
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
        try {
            Approov.setDataHashInToken(data);
            Log.d(TAG, "setDataHashInToken");
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
        // fetch the Approov token
        Approov.TokenFetchResult approovResults;
        try {
            approovResults = Approov.fetchApproovTokenAndWait(url);
            Log.d(TAG, "fetchToken: " + approovResults.getStatus().toString());
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
     */
    @Deprecated
    public static String getMessageSignature(String message) throws ApproovException {
        return getAccountMessageSignature(message);
    }

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
        // determine the type of operation as the values themselves cannot be logged
        String type = "lookup";
        if (newDef != null)
            type = "definition";

        // fetch any secure string keyed by the value, catching any exceptions the SDK might throw
        Approov.TokenFetchResult approovResults;
        try {
            approovResults = Approov.fetchSecureStringAndWait(key, newDef);
            Log.d(TAG, "fetchSecureString " + type + ": " + key + ", " + approovResults.getStatus().toString());
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
        // fetch the custom JWT catching any exceptions the SDK might throw
        Approov.TokenFetchResult approovResults;
        try {
            approovResults = Approov.fetchCustomJWTAndWait(payload);
            Log.d(TAG, "fetchCustomJWT: " + approovResults.getStatus().toString());
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
     * Gets the last ARC (Attestation Response Code) code.
     *
     * Always resolves with a string (ARC or empty string).
     * NOTE: You MUST only call this method upon succesfull attestation completion. Any networking
     * errors returned from the service layer will not return a meaningful ARC code if the method is called!!!
     * @return String ARC from last attestation request or empty string if network unavailable
     */
    public static String getLastARC() {
        // Get the dynamic pins from Approov
        Map<String, List<String>> approovPins = Approov.getPins("public-key-sha256");
        if (approovPins == null || approovPins.isEmpty()) {
            Log.e(TAG, "ApproovService: no host pinning information available");
            return "";
        }
        // The approovPins contains a map of hostnames to pin strings. Skip '*' and use another hostname if available.
        String hostname = null;
        for (String key : approovPins.keySet()) {
            if (!"*".equals(key)) {
                hostname = key;
                break;
            }
        }
        if (hostname != null) {
            try {
                Approov.TokenFetchResult result = Approov.fetchApproovTokenAndWait(hostname);
                if (result.getToken() != null && !result.getToken().isEmpty()) {
                    String arc = result.getARC();
                    if (arc != null) {
                        return arc;
                    }
                }
                Log.i(TAG, "ApproovService: ARC code unavailable");
                return "";
            } catch (Exception e) {
                Log.e(TAG, "ApproovService: error fetching ARC", e);
                return "";
            }
        } else {
            Log.i(TAG, "ApproovService: ARC code unavailable");
            return "";
        }
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
        try {
            Approov.setInstallAttrsInToken(attrs);
            Log.d(TAG, "setInstallAttrsInToken");
        } catch (IllegalArgumentException e) {
            Log.e(TAG, "setInstallAttrsInToken failed with IllegalArgument: " + e.getMessage());
            throw new ApproovException("setInstallAttrsInToken: " + e.getMessage());
        } catch (IllegalStateException e) {
            Log.e(TAG, "setInstallAttrsInToken failed with IllegalState: " + e.getMessage());
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
        Log.d(TAG, "setUseApproovStatusIfNoToken " + shouldUse);
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
        try {
            String signature = Approov.getAccountMessageSignature(message);
            Log.d(TAG, "getAccountMessageSignature");
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
        try {
            String signature = Approov.getInstallMessageSignature(message);
            Log.d(TAG, "getInstallMessageSignature");
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
     * Holds the outcome of configured query parameter substitutions so callers can
     * update both the effective URL and the mutation metadata in a single step.
     */
    static final class QuerySubstitutionResult {
        final URL url;
        final String originalURL;
        final List<String> substitutedQueryKeys;

        QuerySubstitutionResult(URL url, String originalURL, List<String> substitutedQueryKeys) {
            this.url = url;
            this.originalURL = originalURL;
            this.substitutedQueryKeys = substitutedQueryKeys;
        }

        boolean hasEffectiveUrlChange() {
            return !originalURL.equals(url.toString());
        }
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
        if (pinningHostnameVerifier == null)
            throw new ApproovException("Approov not initialized");

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
        Approov.TokenFetchResult approovResults = Approov.fetchApproovTokenAndWait(urlString);

        // provide information about the obtained token or error (note "approov token
        // -check" can be used to check the validity of the token and if you use
        // token annotations they will appear here to determine why a request is
        // being rejected)
        Log.d(TAG, "Token for " + urlString + ": " + approovResults.getLoggableToken());

        // check the status of Approov token fetch using decision maker
        String setTokenHeaderKey = null;
        String setTokenHeaderValue = null;
        String setTraceIDHeaderKey = null;
        String setTraceIDHeaderValue = null;
        if (mutator.handleInterceptorFetchTokenResult(approovResults, urlString)) {
            // we successfully obtained a token so add it to the header for the request
            setTokenHeaderKey = getApproovTokenHeader();

            String fetchedToken = approovResults.getToken();
            if (((fetchedToken == null) || fetchedToken.isEmpty()) && getUseApproovStatusIfNoToken())
                setTokenHeaderValue = getApproovTokenPrefix() + approovResults.getStatus().toString();
            else
                setTokenHeaderValue = getApproovTokenPrefix() + (fetchedToken == null ? "" : fetchedToken);

            String traceIDHeader = getApproovTraceIDHeader();
            String traceID = getTokenFetchTraceID(approovResults);
            if ((traceIDHeader != null) && (traceID != null) && !traceID.isEmpty()) {
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
        }
        if (setTraceIDHeaderKey != null) {
            request.setRequestProperty(setTraceIDHeaderKey, setTraceIDHeaderValue);
            changes.setTraceIDHeaderKey(setTraceIDHeaderKey);
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
                approovResults = Approov.fetchSecureStringAndWait(value.substring(prefix.length()), null);
                Log.d(TAG, "Substituting header: " + header + ", " + approovResults.getStatus().toString());
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
     * Performs the configured query parameter substitutions for a URL and captures
     * the mutation metadata needed by the httpsurlconn service layer to keep
     * request-header and URL substitutions in sync.
     *
     * @param url     is the URL being analyzed for substitution
     * @param mutator is the mutator that decides how substitution results are handled
     * @return the query substitution result
     * @throws ApproovException if it is not possible to obtain secure strings for
     *                          substitution
     */
    static synchronized QuerySubstitutionResult substituteQueryParamsDetailed(URL url, ApproovServiceMutator mutator)
            throws ApproovException {
        // throw if we couldn't initialize the SDK
        if (pinningHostnameVerifier == null)
            throw new ApproovException("Approov not initialized");

        // check if the URL matches one of the exclusion regexs and just return if so
        String originalURL = url.toString();
        for (Pattern pattern : exclusionURLRegexs.values()) {
            Matcher matcher = pattern.matcher(originalURL);
            if (matcher.find())
                return new QuerySubstitutionResult(url, originalURL, Collections.emptyList());
        }

        String replacementURL = originalURL;
        Map<String, Pattern> queryParams = getSubstitutionQueryParams();
        List<String> queryKeys = new ArrayList<>(queryParams.size());
        for (Map.Entry<String, Pattern> entry : queryParams.entrySet()) {
            String queryKey = entry.getKey();
            Matcher matcher = entry.getValue().matcher(replacementURL);
            if (matcher.find()) {
                // we have found an occurrence of the query parameter to be replaced so
                // we look up the existing value as a key for a secure string
                String queryValue = matcher.group(1);
                Approov.TokenFetchResult approovResults = Approov.fetchSecureStringAndWait(queryValue, null);
                Log.d(TAG, "Substituting query parameter: " + queryKey + ", " + approovResults.getStatus().toString());
                if (mutator.handleInterceptorQueryParamSubstitutionResult(approovResults, queryKey)) {
                    queryKeys.add(queryKey);
                    replacementURL = new StringBuilder(replacementURL)
                            .replace(matcher.start(1), matcher.end(1), approovResults.getSecureString())
                            .toString();
                }
            }
        }

        if (originalURL.equals(replacementURL))
            return new QuerySubstitutionResult(url, originalURL, Collections.emptyList());

        try {
            return new QuerySubstitutionResult(new URL(replacementURL), originalURL, queryKeys);
        } catch (MalformedURLException e) {
            throw new ApproovException("Malformed substituted URL: " + e.getMessage());
        }
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
     *         If configured query substitutions change the target URL then a
     *         wrapped connection is returned and the caller must continue to use
     *         that returned instance.
     * @throws ApproovException if it is not possible to obtain an Approov token or
     *                          secure strings
     */
    public static synchronized HttpsURLConnection addApproov(HttpsURLConnection request) throws ApproovException {
        // throw if we couldn't initialize the SDK
        if (pinningHostnameVerifier == null)
            throw new ApproovException("Approov not initialized");

        // Apply the non-signing parts of the HttpsURLConnection preparation flow immediately so
        // callers continue to see any ApproovException at addApproov() time.
        PreparedRequestData preparedRequestData = prepareApproovRequest(request);

        // Apply any configured query parameter substitutions before deciding if we
        // can finish processing on the original connection or if we need a wrapper
        // because the effective URL changed.
        QuerySubstitutionResult querySubstitutionResult;
        if (preparedRequestData.invokeProcessedCallback) {
            querySubstitutionResult = substituteQueryParamsDetailed(request.getURL(), preparedRequestData.mutator);
        } else {
            querySubstitutionResult = new QuerySubstitutionResult(
                    request.getURL(),
                    request.getURL().toString(),
                    Collections.emptyList()
            );
        }

        if (!preparedRequestData.invokeProcessedCallback) {
            return request;
        }

        if (!querySubstitutionResult.hasEffectiveUrlChange()) {
            return preparedRequestData.mutator.handleInterceptorProcessedRequest(
                    request,
                    preparedRequestData.changes
            );
        }

        return new ApproovBufferedHttpsURLConnection(request, preparedRequestData, querySubstitutionResult);
    }

    /**
     * Applies all configured query parameter substitutions to the supplied URL.
     * Since this modifies the URL itself it must be done before opening the
     * HttpsURLConnection. The mutator is consulted for each substitution result so
     * callers can customize how secure string fetch outcomes are handled.
     *
     * @param url is the URL being analyzed for substitution
     * @return URL passed in, or modified with a new URL if substitutions were made
     * @throws ApproovException if it is not possible to obtain secure strings for
     *                          substitution
     */
    public static synchronized URL substituteQueryParams(URL url) throws ApproovException {
        return substituteQueryParamsDetailed(url, getServiceMutator()).url;
    }

    /**
     * Substitutes the given query parameter in the URL. If no substitution is made then the
     * original URL is returned, otherwise a new one is constructed with the revised query
     * parameter value. Since this modifies the URL itself this must be done before opening the
     * HttpsURLConnection. If it is not currently possible to fetch secure strings token due to
     * networking issues then ApproovNetworkException is thrown and a user initiated retry of the
     * operation should be allowed. ApproovRejectionException may be thrown if the attestation
     * fails and secure strings cannot be obtained. Other ApproovExecptions represent a more
     * permanent error condition.
     *
     * @param url is the URL being analyzed for substitution
     * @param queryParameter is the parameter to be potentially substituted
     * @return URL passed in, or modified with a new URL if required
     * @throws ApproovException if it is not possible to obtain secure strings for substitution
     */
    public static synchronized URL substituteQueryParam(URL url, String queryParameter) throws ApproovException {
        // throw if we couldn't initialize the SDK
        if (pinningHostnameVerifier == null)
            throw new ApproovException("Approov not initialized");

        // check if the URL matches one of the exclusion regexs and just return if so
        String urlString = url.toString();
        for (Pattern pattern: exclusionURLRegexs.values()) {
            Matcher matcher = pattern.matcher(urlString);
            if (matcher.find())
                return url;
        }

        ApproovServiceMutator mutator = getServiceMutator();

        // perform the query substitution if it is present
        Pattern pattern = Pattern.compile("[\\?&]" + Pattern.quote(queryParameter) + "=([^&;]+)");
        Matcher matcher = pattern.matcher(urlString);
        if (matcher.find()) {
            // we have found an occurrence of the query parameter to be replaced so we look up the existing
            // value as a key for a secure string
            String queryValue = matcher.group(1);
            Approov.TokenFetchResult approovResults = Approov.fetchSecureStringAndWait(queryValue, null);
            Log.d(TAG, "Substituting query parameter: " + queryParameter + ", " + approovResults.getStatus().toString());
            if (mutator.handleInterceptorQueryParamSubstitutionResult(approovResults, queryParameter)) {
                // perform a query substitution
                try {
                    return new URL(new StringBuilder(urlString).replace(matcher.start(1),
                            matcher.end(1), approovResults.getSecureString()).toString());
                }
                catch(MalformedURLException e) {
                    Log.d(TAG, "Substituting query parameter exception: " + e.toString());
                    return url;
                }
            }
        }
        return url;
    }
}

/**
 * Callback handler for prefetching. We simply log as we don't need the result
 * itself, as it will be returned as a cached value on a subsequent fetch.
 */
final class PrefetchCallbackHandler implements Approov.TokenFetchCallback {
    // logging tag
    private static final String TAG = "ApproovPrefetch";

    @Override
    public void approovCallback(Approov.TokenFetchResult result) {
        if ((result.getStatus() == Approov.TokenFetchStatus.SUCCESS) ||
                (result.getStatus() == Approov.TokenFetchStatus.UNKNOWN_URL))
            Log.d(TAG, "Prefetch success");
        else
            Log.e(TAG, "Prefetch failure: " + result.getStatus().toString());
    }
}

/**
 * Performs pinning for use with HttpsUrlConnection. This implementation of HostnameVerifier is
 * intended to enhance the HostnameVerifier your TLS implementation normally uses. The
 * HostnameVerifier passed into the constructor continues to be executed when verify is called. The
 * is only applied if the usual HostnameVerifier first passes (so this implementation can only be
 * more secure). This pins to the SHA256 of the public key hash of any certificate in the trust
 * chain for the host (so technically this is public key rather than certificate pinning). Note that
 * this uses the current live Approov pins so is immediately updated if there is a configuration
 * update to the app.
 */
final class PinningHostnameVerifier implements HostnameVerifier {

    // HostnameVerifier you would normally be using
    private final HostnameVerifier delegate;

    // trust anchors used to resolve the validated root certificate when it is not
    // present in the peer chain
    private final Set<TrustAnchor> trustAnchors;

    // Tag for log messages
    private static final String TAG = "ApproovPinVerifier";

    /**
     * Construct a PinningHostnameVerifier which delegates
     * the initial verify to a user defined HostnameVerifier before
     * applying pinning on top.
     *
     * @param delegate is the HostnameVerifier to apply before the custom pinning
     */
    public PinningHostnameVerifier(HostnameVerifier delegate) {
        this.delegate = delegate;
        this.trustAnchors = getDefaultTrustAnchors();
    }

    /**
     * Gets the platform default trust anchors so we can validate the peer chain and
     * identify the resolved trust root when it is not included in the TLS peer
     * certificates.
     */
    private Set<TrustAnchor> getDefaultTrustAnchors() {
        try {
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init((KeyStore) null);
            Set<TrustAnchor> anchors = new HashSet<>();
            for (TrustManager trustManager : trustManagerFactory.getTrustManagers()) {
                if (trustManager instanceof X509TrustManager) {
                    for (X509Certificate cert : ((X509TrustManager) trustManager).getAcceptedIssuers())
                        anchors.add(new TrustAnchor(cert, null));
                }
            }
            return anchors;
        } catch (Exception e) {
            Log.e(TAG, "Unable to initialize default trust anchors", e);
            return Collections.emptySet();
        }
    }

    /**
     * Hashes a public key using the Approov pinning format.
     */
    private String hashPublicKey(PublicKey publicKey) {
        ByteString digest = ByteString.of(publicKey.getEncoded()).sha256();
        return digest.base64();
    }

    /**
     * Validates the peer chain with PKIX and returns the resolved trust anchor
     * certificate if one is available as a certificate object.
     */
    private X509Certificate getTrustAnchorCertificate(SSLSession session) {
        if (trustAnchors.isEmpty())
            return null;

        try {
            List<X509Certificate> peerCertificates = new ArrayList<>();
            for (Certificate cert : session.getPeerCertificates()) {
                if (cert instanceof X509Certificate)
                    peerCertificates.add((X509Certificate) cert);
            }
            if (peerCertificates.isEmpty())
                return null;

            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            CertPath certPath = certificateFactory.generateCertPath(peerCertificates);
            CertPathValidator validator = CertPathValidator.getInstance("PKIX");
            PKIXParameters pkixParameters = new PKIXParameters(trustAnchors);
            pkixParameters.setRevocationEnabled(false);
            PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult) validator.validate(certPath, pkixParameters);
            return result.getTrustAnchor().getTrustedCert();
        } catch (CertificateException e) {
            Log.e(TAG, "Unable to validate certificate chain", e);
        } catch (SSLException e) {
            Log.e(TAG, "Unable to read peer certificate chain", e);
        } catch (Exception e) {
            Log.e(TAG, "Unable to resolve trust anchor", e);
        }
        return null;
    }

    @Override
    public boolean verify(String hostname, SSLSession session) {
        // check the delegate function first and only proceed if it passes
        if (delegate.verify(hostname, session)) try {
            // extract the set of valid pins for the hostname
            Set<String> hostPins = new HashSet<>();
            Map<String, List<String>> allPins = Approov.getPins("public-key-sha256");
            List<String> pins = allPins.get(hostname);
            if ((pins != null) && pins.isEmpty())
                // if there are no pins associated with the hostname domain then we use any pins
                // associated with the "*" domain for managed trust roots (note we do not
                // apply this to domains that are not added at all)
                pins = allPins.get("*");
            if (pins != null) {
                // convert the list of pins into a set
                for (String pin: pins)
                    hostPins.add(pin);
            }

            // if there are no pins then we accept any certificate
            if (hostPins.isEmpty())
                return true;

            // check to see if any of the pins are in the certificate chain
            for (Certificate cert: session.getPeerCertificates()) {
                if (cert instanceof X509Certificate) {
                    X509Certificate x509Cert = (X509Certificate) cert;
                    String hash = hashPublicKey(x509Cert.getPublicKey());
                    if (hostPins.contains(hash))
                        return true;
                }
                else
                    Log.e(TAG, "Certificate not X.509");
            }

            // If the validated trust anchor/root was not presented by the peer, resolve it
            // from the platform trust store and check its public key hash too.
            X509Certificate trustAnchorCert = getTrustAnchorCertificate(session);
            if ((trustAnchorCert != null) && hostPins.contains(hashPublicKey(trustAnchorCert.getPublicKey())))
                return true;

            // the connection is rejected
            Log.w(TAG, "Pinning rejection for " + hostname);
            return false;
        } catch (SSLException e) {
            Log.e(TAG, "Delegate Exception");
            throw new RuntimeException(e);
        }
        return false;
    }
}
