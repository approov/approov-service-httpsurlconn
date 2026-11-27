//
// MIT License
// 
// Copyright (c) 2016-present, Approov Ltd.
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

import android.util.Base64;

import com.criticalblue.approovsdk.Approov;

import io.approov.util.httpsurlconn.tink.subtle.EllipticCurves;

import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.net.ssl.HttpsURLConnection;

import io.approov.util.httpsurlconn.http.sfv.ByteSequenceItem;
import io.approov.util.httpsurlconn.http.sfv.Dictionary;
import io.approov.util.httpsurlconn.http.sfv.ListElement;
import io.approov.util.httpsurlconn.sig.ComponentProvider;
import io.approov.util.httpsurlconn.sig.SignatureBaseBuilder;
import io.approov.util.httpsurlconn.sig.SignatureParameters;
import okio.ByteString;


/**
 * Provides a base implementation of message signing for Approov when using
 * httpsurlconn requests. This class provides mechanisms to configure and apply
 * message signatures to HTTP requests based on specified parameters and
 * algorithms.
 */
public class ApproovDefaultMessageSigning implements ApproovServiceMutator {
    // logging tag
    private static final String TAG = "ApproovMsgSign";

    /**
     * Constant for the SHA-256 digest algorithm (used for body digests).
     */
    public static final String DIGEST_SHA256 = "sha-256";

    /**
     * Constant for the SHA-512 digest algorithm (used for body digests).
     */
    public static final String DIGEST_SHA512 = "sha-512";

    /**
     * Constant for the ECDSA P-256 with SHA-256 algorithm (used when signing with install private key).
     */
    public final static String ALG_ES256 = "ecdsa-p256-sha256";

    /**
     * Constant for the HMAC with SHA-256 algorithm (used when signing with the account signing key).
     */
    public final static String ALG_HS256 = "hmac-sha256";

    /**
     * The Signature dictionary member name for the install message signature.
     */
    public static final String SIG_ID_INSTALL = "install";

    /**
     * The Signature dictionary member name for the account message signature.
     */
    public static final String SIG_ID_ACCOUNT = "account";

    // the factory used for every host without a factory of its own, or null to sign nothing, which is
    // volatile as it is read on the request threads; protected so that subclasses can read and set it
    protected volatile SignatureParametersFactory defaultFactory;

    // factories for individual hosts, keyed by the lowercase host name without any port; protected so that
    // subclasses can read and change them
    protected final Map<String, SignatureParametersFactory> hostFactories = new ConcurrentHashMap<>();

    // true once a missing install signature, a missing account signature, and a request left unsigned for
    // want of any signature have been logged at a visible level, after which they are logged at debug level
    private static final AtomicBoolean installMissingLogged = new AtomicBoolean();
    private static final AtomicBoolean accountMissingLogged = new AtomicBoolean();
    private static final AtomicBoolean unsignedLogged = new AtomicBoolean();

    // clears the once per process flags of the missing signature logs
    static void resetMissingSignatureLogsForTesting() {
        installMissingLogged.set(false);
        accountMissingLogged.set(false);
        unsignedLogged.set(false);
    }

    // the mutator whose decisions the signer makes, or null for the interface default decisions
    private final ApproovServiceMutator decisions;

    /**
     * Constructs a new message signing mutator with no factory, so that nothing is signed until a default
     * factory or a host factory is set. Install it with ApproovService.setServiceMutator.
     */
    public ApproovDefaultMessageSigning() {
        decisions = null;
    }

    /**
     * Constructs a message signing service mutator with no factory that makes the decisions of another
     * mutator, such as ApproovServiceMutator.ALWAYS_PROCEED or your own. Every decision hook calls the hook of
     * that mutator. The processed request hook calls the processed request hook of that mutator first and
     * then signs the result, so that the signature covers any change that mutator makes. Nothing is signed
     * until a default factory or a host factory is set. Apps use combined(ApproovServiceMutator) to get a
     * signer.
     *
     * @param decisions is the mutator whose decisions are to be made
     * @throws IllegalArgumentException if decisions is null
     */
    ApproovDefaultMessageSigning(ApproovServiceMutator decisions) {
        if (decisions == null)
            throw new IllegalArgumentException("decisions must not be null");
        this.decisions = decisions;
    }

    /**
     * Gets a new message signing service mutator that adds both the install and the account signature to
     * every request carrying the Approov token header, and makes the decisions of the given mutator, such as
     * ApproovServiceMutator.CLOSE_FAILURE, ApproovServiceMutator.ALWAYS_PROCEED or your own. A signature that
     * cannot be produced is left out and the request goes ahead with the other one, or unsigned. Install it
     * with ApproovService.setServiceMutator.
     *
     * @param decisions is the mutator whose decisions are to be made
     * @return a new signer with the default factory set to sign with both signatures
     * @throws IllegalArgumentException if decisions is null
     */
    public static ApproovDefaultMessageSigning combined(ApproovServiceMutator decisions) {
        return new ApproovDefaultMessageSigning(decisions).setDefaultFactory(
                generateDefaultSignatureParametersFactory().setUseInstallAndAccountMessageSigning());
    }

    /**
     * Gets a new message signing service mutator that adds both the install and the account signature and
     * makes the ApproovServiceMutator.DEFAULT decisions. See combined(ApproovServiceMutator).
     *
     * @return a new signer with the default factory set to sign with both signatures
     */
    public static ApproovDefaultMessageSigning combined() {
        return combined(ApproovServiceMutator.DEFAULT);
    }

    @Override
    public String toString() {
        if (decisions == null)
            return "ApproovDefaultMessageSigning";
        return "ApproovDefaultMessageSigning(" + decisions + ")";
    }

    /**
     * Gets the mutator whose decisions the signer makes.
     *
     * @return the mutator given to the constructor, or CLOSE_FAILURE, whose decisions are the interface
     * defaults, for the signer constructed with no argument
     */
    private ApproovServiceMutator decisions() {
        return (decisions != null) ? decisions : ApproovServiceMutator.CLOSE_FAILURE;
    }

    @Override
    public void handlePrecheckResult(Approov.TokenFetchResult approovResults) throws ApproovException {
        decisions().handlePrecheckResult(approovResults);
    }

    @Override
    public void handleFetchTokenResult(Approov.TokenFetchResult approovResults) throws ApproovException {
        decisions().handleFetchTokenResult(approovResults);
    }

    @Override
    public void handleFetchSecureStringResult(Approov.TokenFetchResult approovResults, String operation, String key)
            throws ApproovException {
        decisions().handleFetchSecureStringResult(approovResults, operation, key);
    }

    @Override
    public void handleFetchCustomJWTResult(Approov.TokenFetchResult approovResults) throws ApproovException {
        decisions().handleFetchCustomJWTResult(approovResults);
    }

    @Override
    public boolean handleInterceptorShouldProcessConnection(HttpsURLConnection request) throws ApproovException {
        return decisions().handleInterceptorShouldProcessConnection(request);
    }

    @Override
    public boolean handleInterceptorFetchTokenResult(Approov.TokenFetchResult approovResults, String url)
            throws ApproovException {
        return decisions().handleInterceptorFetchTokenResult(approovResults, url);
    }

    @Override
    public boolean handleInterceptorHeaderSubstitutionResult(Approov.TokenFetchResult approovResults, String header)
            throws ApproovException {
        return decisions().handleInterceptorHeaderSubstitutionResult(approovResults, header);
    }

    @Override
    public boolean handlePinningShouldProcessRequest(HttpURLConnection request) {
        return decisions().handlePinningShouldProcessRequest(request);
    }

    /**
     * Sets the factory used for every host without a factory of its own.
     *
     * @param factory The factory to set as the default, or null to sign nothing for such hosts.
     * @return The current instance for method chaining.
     */
    public ApproovDefaultMessageSigning setDefaultFactory(SignatureParametersFactory factory) {
        this.defaultFactory = factory;
        return this;
    }

    /**
     * Associates a specific host with a factory for generating signature parameters.
     *
     * @param hostName The host name, matched without regard to case and without any port.
     * @param factory The factory to associate with the host, or null to use the default factory again.
     * @return The current instance for method chaining.
     */
    public ApproovDefaultMessageSigning putHostFactory(String hostName, SignatureParametersFactory factory) {
        if (hostName == null)
            throw new IllegalArgumentException("hostName must not be null");
        String key = hostName.toLowerCase(Locale.ROOT);
        if (factory == null)
            hostFactories.remove(key);
        else
            hostFactories.put(key, factory);
        return this;
    }

    /**
     * Selects the factory for a request, which is the factory of its host if there is one or otherwise
     * the default factory.
     *
     * @param provider the component provider for the request
     * @return the factory, or null if none applies
     */
    private SignatureParametersFactory factoryFor(HttpsURLConnectionComponentProvider provider) {
        SignatureParametersFactory factory = hostFactories.get(provider.getHost());
        return (factory != null) ? factory : defaultFactory;
    }

    /**
     * Builds the signature parameters for a request from the factory for its host, or the default factory.
     * A subclass may override this to choose or adjust the parameters per request.
     *
     * @param provider The component provider for the request.
     * @param changes The request mutations to apply.
     * @return The generated {@link SignatureParameters}, or {@code null} if the request is not to be signed.
     */
    protected SignatureParameters buildSignatureParameters(
            HttpsURLConnectionComponentProvider provider,
            ApproovRequestMutations changes
    ) {
        SignatureParametersFactory factory = factoryFor(provider);
        if (factory == null)
            return null;
        return factory.buildSignatureParameters(provider, changes);
    }

    /**
     * Retrieves an install message signature for the supplied message.
     *
     * @param message The message to be signed.
     * @return The base64-encoded ASN.1 DER signature.
     * @throws ApproovException If signing is unavailable.
     */
    protected String getInstallMessageSignature(String message) throws ApproovException {
        return ApproovService.getInstallMessageSignature(message);
    }

    /**
     * Retrieves an account message signature for the supplied message.
     *
     * @param message The message to be signed.
     * @return The base64-encoded signature.
     * @throws ApproovException If signing is unavailable.
     */
    protected String getAccountMessageSignature(String message) throws ApproovException {
        return ApproovService.getAccountMessageSignature(message);
    }

    /**
     * Decodes a base64-encoded signature value.
     *
     * @param base64 The signature bytes encoded as base64.
     * @return The decoded bytes.
     */
    protected byte[] decodeBase64(String base64) {
        return Base64.decode(base64, Base64.NO_WRAP);
    }

    /**
     * Converts an ASN.1 DER encoded ECDSA P-256 signature, as the SDK returns the install message signature,
     * to the raw 64 byte r||s form that ecdsa-p256-sha256 requires. Only the canonical DER encoding of the
     * result is accepted, since the Tink conversion does not check that r and s fit in 32 bytes.
     *
     * @param der is the DER encoded signature
     * @return the raw r||s signature
     * @throws IllegalArgumentException if der is not a canonical DER ES256 signature
     */
    static byte[] es256DerToRaw(byte[] der) {
        byte[] raw;
        byte[] canonical;
        try {
            raw = EllipticCurves.ecdsaDer2Ieee(der, 64);
            canonical = EllipticCurves.ecdsaIeee2Der(raw);
        } catch (GeneralSecurityException | RuntimeException e) {
            throw new IllegalArgumentException("Not an ASN.1 DER ES256 signature: " + e, e);
        }
        if (!Arrays.equals(canonical, der))
            throw new IllegalArgumentException("Not an ASN.1 DER ES256 signature: integer exceeds 32 bytes");
        return raw;
    }

    /**
     * Adds message signature headers to a request after the httpsurlconn
     * service layer has applied its token and substitution changes. The request
     * is only modified if an Approov token header was added and if there is a
     * defined SignatureParametersFactory for the request host. The processed
     * request hook of the mutator whose decisions the signer makes is called
     * first, so that the signature covers any change it makes.
     * <p>
     * Message signing is fail-open. If a signature cannot be produced, for either install (ES256) or account
     * (HS256) signing, because it is unavailable or empty or an ASN.1/base64 decode fails, it is left out
     * and the request is signed with the other one, or sent unsigned if neither can be produced. The only
     * fail-closed cases are an unsupported signing algorithm and a body digest configured as required that
     * cannot be generated; both raise an {@code ApproovException}. The backend remains the enforcement point
     * for message signatures.
     *
     * @param request The prepared HTTP request.
     * @param changes The request mutations that were applied during Approov
     *                processing.
     * @return The processed HTTP request with the signature headers added.
     * @throws ApproovException If a body digest configured as required cannot be generated, a signature
     *                          algorithm is unsupported, or the mutator whose decisions the signer makes
     *                          throws it.
     */
    @Override
    public HttpsURLConnection handleInterceptorProcessedRequest(HttpsURLConnection request, ApproovRequestMutations changes) throws ApproovException {
        // the decisions make their changes before signing, and an exception they throw is theirs rather than a
        // signing decision
        HttpsURLConnection processed = decisions().handleInterceptorProcessedRequest(request, changes);
        if (processed == null)
            return null;
        return sign(processed, changes);
    }

    /**
     * Signs a request as handleInterceptorProcessedRequest describes.
     *
     * @param request the request as the service layer and the decisions left it
     * @param changes the mutations applied to the request by Approov
     * @return the request, with the signature headers set if it is signed
     * @throws ApproovException if a body digest configured as required cannot be generated or a signature
     *                          algorithm is unsupported
     */
    private HttpsURLConnection sign(HttpsURLConnection request, ApproovRequestMutations changes) throws ApproovException {
        if (changes == null || changes.getTokenHeaderKey() == null) {
            // the request doesn't have an Approov token, so we don't need to sign it
            return request;
        }
        // generate and add a message signature
        HttpsURLConnectionComponentProvider provider = new HttpsURLConnectionComponentProvider(request);
        SignatureParameters params;
        try {
            params = buildSignatureParameters(provider, changes);
        } catch (IllegalStateException e) {
            // Deliberate fail-closed conditions (a required body digest that cannot be generated,
            // or unconfigured base parameters) must surface via the documented ApproovException
            // contract of addApproov(...), not as a raw unchecked exception.
            throw new ApproovException(e.getMessage(), e);
        }
        if (params == null) {
            // No sig to be added to the request; return the original request.
            return request;
        }

        // Everything below is fail-open: any failure to obtain, decode, or serialize a signature leaves that
        // signature out, or the request unsigned. The single exception is an unsupported algorithm, which is
        // thrown as ApproovException (checked, so it is NOT caught by the fail-open RuntimeException handler
        // and propagates to abort the request).
        try {
            // determine the algorithms to sign with, which is a single algorithm if the factory sets one
            // explicitly on the parameters, or otherwise the algorithms configured on the factory (by default
            // the install signature only)
            List<String> algs;
            if (params.getAlg() != null) {
                algs = Collections.singletonList(params.getAlg());
            } else {
                SignatureParametersFactory factory = factoryFor(provider);
                try {
                    // a factory with no algorithm enabled throws IllegalStateException here
                    algs = (factory != null) ? factory.getAlgs() : Collections.singletonList(ALG_ES256);
                } catch (RuntimeException e) {
                    ApproovLog.e(TAG, "Message signing: no usable algorithm, proceeding unsigned: " + e);
                    return request;
                }
                if (algs == null || algs.isEmpty()) {
                    ApproovLog.e(TAG, "Message signing: no usable algorithm, proceeding unsigned: empty algorithm list");
                    return request;
                }
            }
            for (String alg : algs) {
                // an unsupported algorithm is a configuration error and fails closed
                if (!ALG_ES256.equals(alg) && !ALG_HS256.equals(alg))
                    throw new ApproovException("Message signing: unsupported algorithm identifier: " + alg);
            }

            // generate a signature per algorithm over the same covered components, each with its own signature
            // base since the base includes the algorithm
            Map<String, ListElement<?>> signatures = new LinkedHashMap<>();
            Map<String, ListElement<?>> signatureInputs = new LinkedHashMap<>();
            Map<String, String> messages = new LinkedHashMap<>();
            // the reason each signature that could not be produced is missing, by signature identifier
            Map<String, String> missing = new LinkedHashMap<>();
            for (String alg : algs) {
                SignatureParameters algParams = new SignatureParameters(params).setAlg(alg);
                // WARNING never log the message as it contains an Approov token which provides access to
                // your API
                String message = new SignatureBaseBuilder(algParams, provider).createSignatureBase();
                String sigId = ALG_ES256.equals(alg) ? SIG_ID_INSTALL : SIG_ID_ACCOUNT;
                byte[] signature = ALG_ES256.equals(alg) ? installSignature(message, missing)
                        : accountSignature(message, missing);
                if (signature == null) {
                    // this signature could not be produced so we proceed with any other
                    continue;
                }
                signatures.put(sigId, ByteSequenceItem.valueOf(signature));
                signatureInputs.put(sigId, algParams.toComponentValue());
                messages.put(sigId, message);
            }
            if (signatures.isEmpty()) {
                StringBuilder line = new StringBuilder("Message signing: no signature produced, proceeding unsigned");
                for (Map.Entry<String, String> entry : missing.entrySet())
                    line.append(": ").append(entry.getKey()).append(" signature ").append(entry.getValue());
                if (unsignedLogged.compareAndSet(false, true))
                    ApproovLog.e(TAG, line.toString());
                else
                    ApproovLog.d(TAG, line.toString());
                return request;
            }
            for (Map.Entry<String, String> entry : missing.entrySet()) {
                String line = "Message signing: " + entry.getKey() + " signature " + entry.getValue()
                        + ", signed without it";
                AtomicBoolean logged = SIG_ID_INSTALL.equals(entry.getKey()) ? installMissingLogged : accountMissingLogged;
                if (logged.compareAndSet(false, true))
                    ApproovLog.w(TAG, line);
                else
                    ApproovLog.d(TAG, line);
            }

            // each signature is a Byte Sequence member of the same Signature and Signature-Input dictionaries,
            // serialized as colon delimited base64 (for example install=:<base64>:)
            String sigHeader = Dictionary.valueOf(signatures).serialize();
            String sigInputHeader = Dictionary.valueOf(signatureInputs).serialize();

            // HttpURLConnection doesn't have a removeHeader function, so we use
            // setRequestProperty to replace any previous values and avoid accumulating
            // duplicate signature headers across retries or repeated processing.
            request.setRequestProperty("Signature", sigHeader);
            request.setRequestProperty("Signature-Input", sigInputHeader);

            ApproovLog.d(TAG, "Constructed Signature header: " + sigHeader);
            ApproovLog.d(TAG, "Constructed Signature-Input header: " + sigInputHeader);

            if (params.isDebugMode()) {
                try {
                    MessageDigest digestBuilder = MessageDigest.getInstance("SHA-256");
                    Map<String, ListElement<?>> digests = new LinkedHashMap<>();
                    for (Map.Entry<String, String> entry : messages.entrySet()) {
                        digestBuilder.reset();
                        byte[] digest = digestBuilder.digest(entry.getValue().getBytes(StandardCharsets.UTF_8));
                        digests.put(entry.getKey(), ByteSequenceItem.valueOf(digest));
                    }
                    request.setRequestProperty("Signature-Base-Digest", Dictionary.valueOf(digests).serialize());
                } catch (NoSuchAlgorithmException e) {
                    ApproovLog.d(TAG, "Message signing: digest algorithm unavailable, no debug entry: " + e);
                }
            }
            return request;
        } catch (RuntimeException e) {
            // Fail-open: any other signing failure (signature-base component missing, serialization, etc.)
            // is logged and the request proceeds unsigned. ApproovException is checked and is NOT caught
            // here, so the unsupported-algorithm fail-closed path propagates.
            ApproovLog.e(TAG, "Message signing failed - proceeding unsigned: " + e, e);
            return request;
        }
    }

    /**
     * Produces the install message signature over the given message as the raw 64 byte r||s value that
     * ecdsa-p256-sha256 requires.
     *
     * @param message the signature base
     * @param missing receives the reason if the signature is not available
     * @return the signature bytes, or null if not available
     */
    private byte[] installSignature(String message, Map<String, String> missing) {
        String base64;
        try {
            base64 = getInstallMessageSignature(message);
        } catch (ApproovException e) {
            missing.put(SIG_ID_INSTALL, "unavailable: " + e);
            return null;
        }
        if (base64 == null || base64.isEmpty()) {
            missing.put(SIG_ID_INSTALL, "unavailable");
            return null;
        }
        byte[] signature;
        try {
            signature = decodeBase64(base64);
        } catch (RuntimeException e) {
            missing.put(SIG_ID_INSTALL, "not base64: " + e);
            return null;
        }
        // decode the signature from ASN.1 DER format
        try {
            return es256DerToRaw(signature);
        } catch (RuntimeException e) {
            missing.put(SIG_ID_INSTALL, "not ASN.1 DER ES256: " + e);
            return null;
        }
    }

    /**
     * Produces the account message signature over the given message, which may not be available as the
     * account key is only delivered on a successful attestation.
     *
     * @param message the signature base
     * @param missing receives the reason if the signature is not available
     * @return the signature bytes, or null if not available
     */
    private byte[] accountSignature(String message, Map<String, String> missing) {
        String base64;
        try {
            base64 = getAccountMessageSignature(message);
        } catch (ApproovException e) {
            missing.put(SIG_ID_ACCOUNT, "unavailable: " + e);
            return null;
        }
        if (base64 == null || base64.isEmpty()) {
            missing.put(SIG_ID_ACCOUNT, "unavailable");
            return null;
        }
        try {
            return decodeBase64(base64);
        } catch (RuntimeException e) {
            missing.put(SIG_ID_ACCOUNT, "not base64: " + e);
            return null;
        }
    }

    /**
     * Generates a default {@link SignatureParametersFactory} with predefined settings.
     *
     * @return A new instance of {@link SignatureParametersFactory}.
     */
    public static SignatureParametersFactory generateDefaultSignatureParametersFactory() {
        return generateDefaultSignatureParametersFactory(null);
    }

    /**
     * Generates a default {@link SignatureParametersFactory} with optional base parameters.
     *
     * @param baseParametersOverride The base parameters to override, or {@code null} to use defaults.
     * @return A new instance of {@link SignatureParametersFactory}.
     */
    public static SignatureParametersFactory generateDefaultSignatureParametersFactory(
            SignatureParameters baseParametersOverride
    ) {
        // default expiry seconds - must encompass worst case request retry
        // time and clock skew
        long defaultExpiresLifetime = 15;
        SignatureParameters baseParameters;
        if (baseParametersOverride != null) {
            baseParameters = baseParametersOverride;
        } else {
            baseParameters = new SignatureParameters()
                    .addComponentIdentifier(ComponentProvider.DC_METHOD)
                    .addComponentIdentifier(ComponentProvider.DC_TARGET_URI)
                    ;
        }
        return new SignatureParametersFactory()
                .setBaseParameters(baseParameters)
                .setUseInstallMessageSigning()
                .setAddCreated(true)
                .setExpiresLifetime(defaultExpiresLifetime)
                .setAddApproovTokenHeader(true)
                .setAddApproovTraceIDHeader(true)
                .addOptionalHeaders("Authorization", "Content-Length", "Content-Type")
                .setBodyDigestConfig(DIGEST_SHA256, false)
                ;
    }

    /**
     * Factory class for creating pre-request {@link SignatureParameters} with
     * configurable settings. Each request passed to the factory builds a new
     * SignatureParameters instance based on the configured settings and
     * specific for the request.
     */
    public static class SignatureParametersFactory {
        protected SignatureParameters baseParameters;
        protected String bodyDigestAlgorithm;
        protected boolean bodyDigestRequired;
        // true to produce the install message signature (ECDSA P-256 with the per installation key)
        protected boolean useInstallMessageSigning = true;
        // true to produce the account message signature (HMAC-SHA256 with the account key), so that by
        // default a bare factory produces the install signature only
        protected boolean useAccountMessageSigning;
        protected boolean addCreated;
        protected long expiresLifetime;
        protected boolean addApproovTokenHeader;
        protected boolean addApproovTraceIDHeader;
        protected List<String> optionalHeaders;

        /**
         * Sets the base parameters for the factory.
         *
         * @param baseParameters The base parameters to set.
         * @return The current instance for method chaining.
         */
        public SignatureParametersFactory setBaseParameters(SignatureParameters baseParameters) {
            this.baseParameters = baseParameters;
            return this;
        }

        /**
         * Configures the body digest settings for the factory.
         *
         * @param bodyDigestAlgorithm The digest algorithm to use, or {@code null} to disable.
         * @param required Whether the body digest is required.
         * @return The current instance for method chaining.
         * @throws IllegalArgumentException If an unsupported algorithm is specified.
         */
        public SignatureParametersFactory setBodyDigestConfig(String bodyDigestAlgorithm, boolean required) {
            if (bodyDigestAlgorithm == null) {
                required = false;
            } else if (!bodyDigestAlgorithm.equals(DIGEST_SHA256)
                    && !bodyDigestAlgorithm.equals(DIGEST_SHA512)) {
                throw new IllegalArgumentException("Unsupported body digest algorithm: " + bodyDigestAlgorithm);
            }
            this.bodyDigestAlgorithm = bodyDigestAlgorithm;
            this.bodyDigestRequired = required;
            return this;
        }

        /**
         * Sets the factory to produce only the install message signature. This is the default of a newly
         * constructed factory and of generateDefaultSignatureParametersFactory().
         *
         * @return The current instance for method chaining.
         */
        public SignatureParametersFactory setUseInstallMessageSigning() {
            this.useInstallMessageSigning = true;
            this.useAccountMessageSigning = false;
            return this;
        }

        /**
         * Sets the factory to produce only the account message signature.
         *
         * @return The current instance for method chaining.
         */
        public SignatureParametersFactory setUseAccountMessageSigning() {
            this.useInstallMessageSigning = false;
            this.useAccountMessageSigning = true;
            return this;
        }

        /**
         * Sets the factory to produce both the install and the account message signatures, as the members
         * "install" and "account" of the same Signature and Signature-Input headers over the same covered
         * components.
         *
         * @return The current instance for method chaining.
         */
        public SignatureParametersFactory setUseInstallAndAccountMessageSigning() {
            this.useInstallMessageSigning = true;
            this.useAccountMessageSigning = true;
            return this;
        }

        /**
         * Gets the signature algorithms configured on this factory, in the order the signatures are emitted.
         *
         * @return the algorithm identifiers
         * @throws IllegalStateException if neither signature is enabled
         */
        public List<String> getAlgs() {
            List<String> algs = new ArrayList<>(2);
            if (useInstallMessageSigning)
                algs.add(ALG_ES256);
            if (useAccountMessageSigning)
                algs.add(ALG_HS256);
            if (algs.isEmpty())
                throw new IllegalStateException("No message signing algorithm is enabled");
            return algs;
        }

        /**
         * Sets whether the "created" field should be added to the signature parameters.
         *
         * @param addCreated Whether to add the "created" field.
         * @return The current instance for method chaining.
         */
        public SignatureParametersFactory setAddCreated(boolean addCreated) {
            this.addCreated = addCreated;
            return this;
        }

        /**
         * Sets the expiration lifetime for the signature parameters. Only a
         * value >0 will cause the expires attribute to be added to the
         * SignatureParameters for a request.
         *
         * @param expiresLifetime The expiration lifetime in seconds, if <=0
         * no expiration is added.
         * @return The current instance for method chaining.
         */
        public SignatureParametersFactory setExpiresLifetime(long expiresLifetime) {
            this.expiresLifetime = expiresLifetime;
            return this;
        }

        /**
         * Sets whether the Approov token header should be added to the signature parameters.
         *
         * @param addApproovTokenHeader Whether to add the Approov token header.
         * @return The current instance for method chaining.
         */
        public SignatureParametersFactory setAddApproovTokenHeader(boolean addApproovTokenHeader) {
            this.addApproovTokenHeader = addApproovTokenHeader;
            return this;
        }

        /**
         * Sets whether the optional Approov traceID header should be added to the signature
         * parameters.
         *
         * @param addApproovTraceIDHeader Whether to add the Approov traceID header.
         * @return The current instance for method chaining.
         */
        public SignatureParametersFactory setAddApproovTraceIDHeader(boolean addApproovTraceIDHeader) {
            this.addApproovTraceIDHeader = addApproovTraceIDHeader;
            return this;
        }

        /**
         * Adds optional headers to the signature parameters. Headers
         * configured as optional are added to the generated
         * SignatureParameters if the target request includes the header
         * otherwise they are ignored.
         *
         * @param headers The headers to add.
         * @return The current instance for method chaining.
         */
        public SignatureParametersFactory addOptionalHeaders(String ... headers) {
            if (this.optionalHeaders == null) {
                this.optionalHeaders = new ArrayList<>(Arrays.asList(headers));
            } else {
                this.optionalHeaders.addAll(Arrays.asList(headers));
            }
            return this;
        }

        /**
         * Generates a body digest for the request if possible.
         *
         * @param provider The component provider for the request.
         * @param requestParameters The signature parameters to update.
         * @return {@code true} if the body digest was successfully generated, {@code false} otherwise.
         */
        protected boolean generateBodyDigest(
                HttpsURLConnectionComponentProvider provider,
                SignatureParameters requestParameters,
                byte[] explicitBody
        ) {
            // Prefer body bytes supplied explicitly via addApproov(connection, byte[]);
            // otherwise fall back to a buffered connection body if one is available.
            byte[] body = explicitBody;
            if (body == null) {
                HttpsURLConnection request = provider.request;
                if (request instanceof ApproovBufferedHttpsURLConnection) {
                    body = ((ApproovBufferedHttpsURLConnection) request).getBufferedRequestBody();
                }
            }
            if (body == null || body.length == 0) {
                return false;
            }

            ByteString digest;
            switch (bodyDigestAlgorithm) {
                case DIGEST_SHA256:
                    digest = ByteString.of(body).sha256();
                    break;
                case DIGEST_SHA512:
                    digest = ByteString.of(body).sha512();
                    break;
                default:
                    return false;
            }

            Map<String, ListElement<?>> digestMap = new LinkedHashMap<>();
            digestMap.put(bodyDigestAlgorithm, ByteSequenceItem.valueOf(digest.toByteArray()));
            Dictionary digestHeader = Dictionary.valueOf(digestMap);

            provider.request.setRequestProperty("Content-Digest", digestHeader.serialize());
            requestParameters.addComponentIdentifier("Content-Digest");
            return true;
        }


        /**
         * Builds the signature parameters for a given request.
         *
         * @param provider The component provider for the request.
         * @param changes The request mutations to apply.
         * @return The generated {@link SignatureParameters}.
         * @throws IllegalStateException If required parameters cannot be generated.
         */
        protected SignatureParameters buildSignatureParameters(HttpsURLConnectionComponentProvider provider, ApproovRequestMutations changes) {
            if (baseParameters == null) {
                throw new IllegalStateException("Message signing base parameters have not been configured");
            }
            // the algorithm is left unset so that one signature per configured algorithm is produced over
            // these same parameters, while a subclass may set an explicit algorithm for a single signature
            SignatureParameters requestParameters = new SignatureParameters(baseParameters);
            if (addCreated || expiresLifetime > 0) {
                long currentTime = ApproovService.signatureTimeMillis() / 1000;
                if (addCreated) {
                    requestParameters.setCreated(currentTime);
                }
                if (expiresLifetime > 0) {
                    requestParameters.setExpires(currentTime + expiresLifetime);
                }
            }
            if (addApproovTokenHeader) {
                requestParameters.addComponentIdentifier(changes.getTokenHeaderKey());
            }
            if (addApproovTraceIDHeader && changes.getTraceIDHeaderKey() != null) {
                requestParameters.addComponentIdentifier(changes.getTraceIDHeaderKey());
            }
            if (optionalHeaders != null && !optionalHeaders.isEmpty()) {
                for (String headerName: optionalHeaders) {
                    if (provider.hasField(headerName)) {
                        requestParameters.addComponentIdentifier(headerName);
                    }
                }
            }
            if (bodyDigestAlgorithm != null) {
                if (!generateBodyDigest(provider, requestParameters, changes.getBodyBytes()) && bodyDigestRequired) {
                    throw new IllegalStateException("Failed to create required body digest");
                }
            }
            return requestParameters;
        }
    }

    /**
     * HttpsURLConnectionComponentProvider adapts a {@link HttpsURLConnection}
     * request to the generic signature ComponentProvider interface. Every
     * component is derived from the connection's java.net.URL as the stack sends
     * it, which is never parsed again with java.net.URI, as that encodes some
     * characters differently and rejects some URLs the stack sends.
     * <p>
     * Some derived components deliberately deviate from a strict reading of RFC 9421 so that all Approov
     * service layers produce identical signature bases for the Approov verifier:
     * <ul>
     * <li>{@code @authority} is the lowercase host and a non-default port; a default port is left out
     * (RFC 9421 section 2.2.3);</li>
     * <li>{@code @target-uri} is the request URL without any fragment, which is never sent, and without an
     * explicit default port (RFC 9421 section 2.2.2);</li>
     * <li>{@code @query} has no leading {@code ?} and is unavailable when the URL has
     * no query (RFC 9421 section 2.2.7 includes the {@code ?} and uses {@code ?} alone
     * for an absent query).</li>
     * </ul>
     */
    protected static final class HttpsURLConnectionComponentProvider implements ComponentProvider {
        private HttpsURLConnection request;

        // the URL of the connection, and its text exactly as the URL holds it
        private final URL url;
        private final String urlString;

        /**
         * Constructs an instance of {@code HttpsURLConnectionComponentProvider}.
         *
         * @param request The HttpsURLConnection request to wrap.
         */
        HttpsURLConnectionComponentProvider(HttpsURLConnection request) {
            this.request = request;
            this.url = request.getURL();
            this.urlString = url.toString();
        }

        /**
         * Gets the host of the request without any port, in lowercase, which is used to select a host
         * factory. An IPv6 address keeps its brackets.
         *
         * @return the host of the request
         */
        String getHost() {
            return url.getHost().toLowerCase(Locale.ROOT);
        }

        @Override
        public String getMethod() {
            return request.getRequestMethod();
        }

        /**
         * Gets the @authority derived component, which is the lowercase host, in brackets for an IPv6
         * address, followed by the port only if it is not the default port of the scheme.
         *
         * @return the authority of the request
         */
        @Override
        public String getAuthority() {
            String authority = getHost();
            if (url.getPort() != -1 && url.getPort() != url.getDefaultPort())
                authority += ":" + url.getPort();
            return authority;
        }

        @Override
        public String getScheme() { return url.getProtocol(); }

        /**
         * Gets the @target-uri derived component, which is the request URL as the stack sends it, leaving
         * out any fragment as that is never sent, and any explicit default port (":443" for https and ":80"
         * for http). Nothing else changes, so the path, the query and their percent-encoding are as the app
         * wrote them. An absent path is the root path, as the stack sends it.
         *
         * @return the target URI of the request
         */
        @Override
        public String getTargetUri() {
            String text = urlString;
            int fragment = text.indexOf('#');
            if (fragment >= 0)
                text = text.substring(0, fragment);

            // the authority runs from after "://" to the first of "/", "?" or the end of the text
            int authorityStart = text.indexOf("://") + 3;
            int authorityEnd = text.length();
            for (int i = authorityStart; i < text.length(); i++) {
                char c = text.charAt(i);
                if (c == '/' || c == '?') {
                    authorityEnd = i;
                    break;
                }
            }
            String authority = text.substring(authorityStart, authorityEnd);
            // an explicit port follows the last colon after any user info and any IPv6 address in brackets
            int portColon = authority.lastIndexOf(':');
            if (portColon > authority.lastIndexOf(']') && portColon > authority.lastIndexOf('@')
                    && url.getPort() == url.getDefaultPort() && url.getPort() != -1)
                authority = authority.substring(0, portColon);
            String rest = text.substring(authorityEnd);
            if (rest.isEmpty() || rest.charAt(0) == '?')
                rest = "/" + rest;
            return text.substring(0, authorityStart) + authority + rest;
        }

        @Override
        public String getRequestTarget() {
            String requestTarget = getPath();
            String query = url.getQuery();
            if (query != null) {
                requestTarget += "?" + query;
            }
            return requestTarget;
        }

        @Override
        public String getPath() {
            String path = url.getPath();
            return (path == null || path.isEmpty()) ? "/" : path;
        }

        @Override
        public String getQuery() {
            return url.getQuery();
        }

        @Override
        public String getQueryParam(String name) {
            // Parse from the query as written to preserve encoded bytes exactly as used by signature construction.
            String query = url.getQuery();
            if (query == null || query.isEmpty()) throw new IllegalArgumentException("Could not find query parameter named " + name);
            String[] parts = query.split("&");
            String found = null;
            for (String part : parts) {
                int idx = part.indexOf('=');
                String k = idx >= 0 ? part.substring(0, idx) : part;
                String v = idx >= 0 ? part.substring(idx + 1) : "";
                if (k.equals(name)) {
                    if (found != null) return null;
                    found = v;
                }
            }
            if (found == null) throw new IllegalArgumentException("Could not find query parameter named " + name);
            return found;
        }
        @Override
        public String getStatus() { throw new IllegalStateException("Only requests are supported"); }

        @Override
        public boolean hasField(String name) { return request.getRequestProperty(name) != null; }

        @Override
        public String getField(String name) {
            String value = request.getRequestProperty(name);
            return value == null ? "" : value;
        }

        @Override
        public boolean hasBody() {
            String method = request.getRequestMethod();
            return "POST".equalsIgnoreCase(method) || "PUT".equalsIgnoreCase(method) || "PATCH".equalsIgnoreCase(method);
        }
    }
}
