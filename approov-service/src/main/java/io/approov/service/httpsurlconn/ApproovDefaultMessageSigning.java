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

import android.util.Log;
import android.util.Base64;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.net.ssl.HttpsURLConnection;

import io.approov.util.http.sfv.ByteSequenceItem;
import io.approov.util.http.sfv.Dictionary;
import io.approov.util.sig.ComponentProvider;
import io.approov.util.sig.SignatureBaseBuilder;
import io.approov.util.sig.SignatureParameters;
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
     * The default factory for generating signature parameters.
     */
    protected SignatureParametersFactory defaultFactory;

    /**
     * A map of host-specific factories for generating signature parameters.
     */
    protected final Map<String, SignatureParametersFactory> hostFactories;

    /**
     * Constructs an instance of {@code ApproovDefaultMessageSigning}.
     */
    public ApproovDefaultMessageSigning() {
        hostFactories = new HashMap<>();
    }

    @Override
    public String toString() {
        return "ApproovDefaultMessageSigning";
    }

    /**
     * Sets the default factory for generating signature parameters.
     *
     * @param factory The factory to set as the default.
     * @return The current instance for method chaining.
     */
    public ApproovDefaultMessageSigning setDefaultFactory(SignatureParametersFactory factory) {
        this.defaultFactory = factory;
        return this;
    }

    /**
     * Associates a specific host with a factory for generating signature parameters.
     *
     * @param hostName The host name.
     * @param factory The factory to associate with the host.
     * @return The current instance for method chaining.
     */
    public ApproovDefaultMessageSigning putHostFactory(String hostName, SignatureParametersFactory factory) {
        this.hostFactories.put(hostName, factory);
        return this;
    }

    /**
     * Builds the signature parameters for a given request.
     *
     * @param provider The component provider for the request.
     * @param changes The request mutations to apply.
     * @return The generated {@link SignatureParameters}, or {@code null} if no factory is available.
     */
    protected SignatureParameters buildSignatureParameters(
            HttpsURLConnectionComponentProvider provider,
            ApproovRequestMutations changes
    ) {
        SignatureParametersFactory factory = hostFactories.get(provider.getAuthority());
        if (factory == null) {
            factory = defaultFactory;
            if (factory == null) {
                return null;
            }
        }
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
     * Converts one part, encoded as an ASN1Integer, of an ASN.1 DER encoded ES256 signature to a byte array of
     * exactly 32 bytes. Throws IllegalArgumentException if this is not possible.
     *
     * @param bytesAsASN1Integer The ASN1Integer to convert.
     * @return A byte array of length 32, containing the raw bytes of the signature part.
     * @throws IllegalArgumentException if the ASN1Integer is not representing a 32 byte array.
     */
    private static byte[] to32ByteArray(ASN1Integer bytesAsASN1Integer) {
        BigInteger bytesAsBigInteger = bytesAsASN1Integer.getValue();
        byte[] bytes = bytesAsBigInteger.toByteArray();
        byte[] bytes32;
        if (bytes.length < 32) {
            bytes32 = new byte[32];
            System.arraycopy(bytes, 0, bytes32, 32 - bytes.length, bytes.length);
        } else if (bytes.length == 32) {
            bytes32 = bytes;
        } else if (bytes.length == 33 && bytes[0] == 0) {
            bytes32 = new byte[32];
            System.arraycopy(bytes, 1, bytes32, 0, 32);
        } else {
            throw new IllegalArgumentException("Not an ASN.1 DER ES256 signature part");
        }
        return bytes32;
    }

    /**
     * Adds message signature headers to a request after the httpsurlconn
     * service layer has applied its token and substitution changes. The request
     * is only modified if an Approov token header was added and if there is a
     * defined SignatureParametersFactory for the request host.
     *
     * @param request The prepared HTTP request.
     * @param changes The request mutations that were applied during Approov
     *                processing.
     * @return The processed HTTP request with the signature headers added.
     * @throws ApproovException If an error occurs during processing.
     */
    @Override
    public HttpsURLConnection handleInterceptorProcessedRequest(HttpsURLConnection request, ApproovRequestMutations changes) throws ApproovException {
        if (changes == null || changes.getTokenHeaderKey() == null) {
            // the request doesn't have an Approov token, so we don't need to sign it
            return request;
        }
        // generate and add a message signature
        HttpsURLConnectionComponentProvider provider = new HttpsURLConnectionComponentProvider(request);
        SignatureParameters params = buildSignatureParameters(provider, changes);
        if (params == null) {
            // No sig to be added to the request; return the original request.
            return request;
        }

        // Apply the params to get the message
        SignatureBaseBuilder baseBuilder = new SignatureBaseBuilder(params, provider);
        String message = baseBuilder.createSignatureBase();
        // WARNING never log the message as it contains an Approov token which provides access to your API.

        // Generate the signature
        String sigId;
        byte[] signature;
        switch (params.getAlg()) {
            case ALG_ES256: {
                sigId = "install";
                String base64;
                try {
                    base64 = getInstallMessageSignature(message);
                } catch (ApproovException e) {
                    Log.d(TAG, "Failed to get InstallMessageSignature - skipping message signing " + e);
                    return request;
                }
                if (base64.isEmpty()) {
                    Log.d(TAG, "InstallMessageSignature is empty - skipping message signing");
                    return request;
                }
                signature = decodeBase64(base64);
                // decode the signature from ASN.1 DER format
                try (ASN1InputStream asn1InputStream = new ASN1InputStream(signature)) {
                    ASN1Sequence sequence = (ASN1Sequence) asn1InputStream.readObject();
                    if (sequence instanceof ASN1Sequence) {
                        // Combine r and s into a single byte array
                        byte[] rBytes = to32ByteArray((ASN1Integer) sequence.getObjectAt(0));
                        byte[] sBytes = to32ByteArray((ASN1Integer) sequence.getObjectAt(1));
                        signature = new byte[rBytes.length + sBytes.length];
                        System.arraycopy(rBytes, 0, signature, 0, rBytes.length);
                        System.arraycopy(sBytes, 0, signature, rBytes.length, sBytes.length);
                    } else {
                        throw new IllegalStateException("Not an ASN1Sequence");
                    }
                } catch (Exception e) {
                    throw new IllegalStateException("Failed to decode ASN.1 DER ES256 signature", e);
                }
                break;
            }
            case ALG_HS256: {
                sigId = "account";
                String base64 = getAccountMessageSignature(message);
                signature = decodeBase64(base64);
                break;
            }
            default:
                throw new IllegalStateException("Unsupported algorithm identifier: " + params.getAlg());
        }

        // Calculate the signature and message descriptor headers.
        String sigHeader = Dictionary.valueOf(Map.of(
                sigId, ByteSequenceItem.valueOf(signature))).serialize();
        String sigInputHeader = Dictionary.valueOf(Map.of(
                sigId, params.toComponentValue())).serialize();

        // HttpURLConnection doesn't have a removeHeader function, so we use
        // setRequestProperty to replace any previous values and avoid accumulating
        // duplicate signature headers across retries or repeated processing.
        request.setRequestProperty("Signature", sigHeader);
        request.setRequestProperty("Signature-Input", sigInputHeader);

        Log.d(TAG, "Constructed Signature header: " + sigHeader);
        Log.d(TAG, "Request Signature header after set: " + request.getRequestProperty("Signature"));
        Log.d(TAG, "Constructed Signature-Input header: " + sigInputHeader);

        // Debugging - log the message and signature-related headers
        // WARNING never log the message in production code as it contains the Approov token which allows API access
        // Log.d(TAG, "Message Value - Signature Message: " + message);
        // Log.d(TAG, "Message Header - Signature: " + sigHeader);
        // Log.d(TAG, "Message Header Signature-Input: " + sigInputHeader);

        if (params.isDebugMode()) {
            try {
                MessageDigest digestBuilder = MessageDigest.getInstance("SHA-256");
                byte[] digest = digestBuilder.digest(message.getBytes(StandardCharsets.UTF_8));
                String digestHeader = Dictionary.valueOf(Map.of(
                        DIGEST_SHA256, ByteSequenceItem.valueOf(digest))).serialize();
                request.setRequestProperty("Signature-Base-Digest", digestHeader);
            } catch (NoSuchAlgorithmException e) {
                Log.d(TAG, "Failed to get digest algorithm - no debug entry " + e);
            }
        }
        return request;
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
         * Configures the factory to use device message signing.
         *
         * @return The current instance for method chaining.
         */
        public SignatureParametersFactory setUseInstallMessageSigning() {
            this.useAccountMessageSigning = false;
            return this;
        }

        /**
         * Configures the factory to use account message signing.
         *
         * @return The current instance for method chaining.
         */
        public SignatureParametersFactory setUseAccountMessageSigning() {
            this.useAccountMessageSigning = true;
            return this;
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
                SignatureParameters requestParameters
        ) {
            HttpsURLConnection request = provider.request;
            if (!(request instanceof ApproovBufferedHttpsURLConnection)) {
                return false;
            }

            byte[] body = ((ApproovBufferedHttpsURLConnection) request).getBufferedRequestBody();
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

            Dictionary digestHeader = Dictionary.valueOf(Map.of(
                    bodyDigestAlgorithm, ByteSequenceItem.valueOf(digest.toByteArray())));

            request.setRequestProperty("Content-Digest", digestHeader.serialize());
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
            SignatureParameters requestParameters = new SignatureParameters(baseParameters);
            if (useAccountMessageSigning) {
                requestParameters.setAlg(ALG_HS256);
            } else {
                requestParameters.setAlg(ALG_ES256);
            }
            if (addCreated || expiresLifetime > 0) {
                long currentTime = System.currentTimeMillis() / 1000;
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
            for (String headerName: optionalHeaders) {
                if (provider.hasField(headerName)) {
                    requestParameters.addComponentIdentifier(headerName);
                }
            }
            if (bodyDigestAlgorithm != null) {
                if (!generateBodyDigest(provider, requestParameters) && bodyDigestRequired) {
                    throw new IllegalStateException("Failed to create required body digest");
                }
            }
            return requestParameters;
        }
    }

    /**
     * HttpsURLConnectionComponentProvider adapts a {@link HttpsURLConnection}
     * request to the generic signature ComponentProvider interface.
     */
    protected static final class HttpsURLConnectionComponentProvider implements ComponentProvider {
        private HttpsURLConnection request;
        
        private java.net.URL url;

        /**
         * Constructs an instance of {@code HttpsURLConnectionComponentProvider}.
         *
         * @param request The HttpsURLConnection request to wrap.
         */
        HttpsURLConnectionComponentProvider(HttpsURLConnection request) {
            this.request = request;
            this.url = request.getURL();
        }

        @Override
        public String getMethod() {
            return request.getRequestMethod();
        }

        @Override
        public String getAuthority() {
            return url.getHost();
        }

        @Override
        public String getScheme() { return url.getProtocol(); }

        @Override
        public String getTargetUri() {
            // Use URI canonical form to avoid subtle encoding differences in signed target-uri.
            try {
                return url.toURI().toString();
            } catch (Exception e) {
                return url.toString();
            }
        }

        @Override
        public String getRequestTarget() {
            try {
                URI uri = url.toURI();
                String path = uri.getRawPath() == null ? "" : uri.getRawPath();
                String query = uri.getRawQuery();
                return (query == null || query.isEmpty()) ? path : path + "?" + query;
            } catch (Exception e){
                String path = (url.getPath() == null) ? "" : url.getPath();
                String query = url.getQuery();
                return (query == null || query.isEmpty()) ? path : path + "?" + query;
            }
        }

        @Override
        public String getPath() {
            try {
                URI uri = url.toURI();
                return uri.getRawPath();
            } catch (Exception e) {
                return url.getPath();
            }
        }

        @Override
        public String getQuery() {
            try {
                URI uri = url.toURI();
                return uri.getRawQuery();
            } catch (Exception e) {
                return url.getQuery();
            }
        }

        @Override
        public String getQueryParam(String name) {
            // Parse from raw query to preserve encoded bytes exactly as used by signature construction.
            String query;
            try {
                query = url.toURI().getRawQuery();
            } catch (Exception e) {
                query = url.getQuery();
            }
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
