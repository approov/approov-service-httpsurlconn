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

import android.net.http.X509TrustManagerExtensions;
import android.util.Base64;

import com.criticalblue.approovsdk.Approov;

import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * Performs pinning for use with HttpsUrlConnection. This implementation of HostnameVerifier is
 * intended to enhance the HostnameVerifier your TLS implementation normally uses. The
 * HostnameVerifier passed into the constructor continues to be executed when verify is called, and
 * the pinning is only applied if it first passes (so this implementation can only be more secure).
 * This pins to the SHA256 of the public key hash of any certificate in the chain that vouches for
 * the server's leaf certificate, never of another certificate the server presented (so technically
 * this is public key rather than certificate pinning). The pins of the host are
 * looked up without regard to case and ignoring one trailing dot, on both the host and the keys of
 * the pin set. Note that this uses the current live Approov pins so is immediately updated if there
 * is a configuration update to the app.
 * <p>
 * Each initialize makes one verifier that the pinned connections share, so it keeps no state for a
 * connection. A HostnameVerifier can only reject a host, and HttpsURLConnection reports a rejection
 * as an SSLPeerUnverifiedException.
 */
final class PinningHostnameVerifier implements HostnameVerifier {
    // logging tag
    private static final String TAG = "ApproovPinVerifier";

    // the hosts already warned of as listed with no pins while the managed trust roots are empty or absent,
    // which is per process as each initialize makes a new verifier
    private static final Set<String> warnedOsTrustOnlyHosts = new HashSet<>();

    // true once the pins being unavailable has been logged, which is per process as each initialize makes a new
    // verifier
    private static boolean loggedPinsUnavailable;

    // HostnameVerifier you would normally be using
    private final HostnameVerifier delegate;

    // the platform trust that gives the chain the pins are matched against
    private final PlatformTrust platformTrust;

    /**
     * Construct a PinningHostnameVerifier which delegates
     * the initial verify to a user defined HostnameVerifier before
     * applying pinning on top.
     *
     * @param delegate is the HostnameVerifier to apply before the custom pinning
     */
    public PinningHostnameVerifier(HostnameVerifier delegate) {
        this(delegate, PlatformTrust.platform());
    }

    // for tests only
    PinningHostnameVerifier(HostnameVerifier delegate, PlatformTrust platformTrust) {
        this.delegate = delegate;
        this.platformTrust = platformTrust;
    }

    /**
     * Forgets the hosts already warned of. This should only be used for testing.
     */
    static void resetWarnings() {
        synchronized (warnedOsTrustOnlyHosts) {
            warnedOsTrustOnlyHosts.clear();
            loggedPinsUnavailable = false;
        }
    }

    @Override
    public boolean verify(String hostname, SSLSession session) {
        // check the delegate function first and only proceed if it passes
        if (!delegate.verify(hostname, session))
            return false;

        // before initialization and in bypass mode no Approov pinning is applied, only OS trust
        if (!ApproovService.isApproovProtectionEnabled())
            return true;

        // the pins are looked up for the normalized host, so that neither a pin key nor a host spelled with a
        // different case or a trailing dot escapes the pins
        String host = ApproovService.normalizeHost(hostname);

        // a pin set that cannot be read leaves the host on OS trust only, which the delegate has checked
        Map<String, List<String>> allPins;
        Set<String> hostPins;
        try {
            allPins = Approov.getPins("public-key-sha256");
            if (allPins == null)
                throw new IllegalStateException("getPins returned no pins");
            hostPins = pinsFor(host, allPins);
        } catch (RuntimeException e) {
            logPinsUnavailable(e);
            return true;
        }

        // with no pins the host is validated by OS trust only, which the delegate has checked
        if (hostPins.isEmpty()) {
            if (isListed(host, allPins))
                warnOsTrustOnly(host);
            return true;
        }

        // check to see if any of the pins are in the chain that vouches for the leaf
        try {
            for (X509Certificate cert : platformTrust.vouchingChain(presented(session), hostname)) {
                if (hostPins.contains(sha256Base64(cert.getPublicKey().getEncoded())))
                    return true;
            }
        } catch (SSLPeerUnverifiedException | RuntimeException e) {
            // a peer whose certificates cannot be read matches no pin
            ApproovLog.d(TAG, "Peer certificates of " + host + " not read: " + e);
        }

        // the connection is rejected, naming the host and never a pin
        ApproovLog.e(TAG, "Approov pinning: no pin matches for " + host);
        return false;
    }

    /**
     * Logs once per process that the Approov pins could not be read, so connections continue on OS trust only.
     * The exception is named, never a pin.
     *
     * @param e is the failure to read the pins
     */
    private static void logPinsUnavailable(RuntimeException e) {
        synchronized (warnedOsTrustOnlyHosts) {
            if (loggedPinsUnavailable)
                return;
            loggedPinsUnavailable = true;
        }
        ApproovLog.e(TAG, "Approov pinning: pins unavailable, OS trust only: " + e);
    }

    /**
     * Gets the certificates the peer presented, leaf first.
     *
     * @param session is the SSL session of the connection
     * @return the presented certificates
     * @throws SSLPeerUnverifiedException if there are none or one is not X.509
     */
    private static X509Certificate[] presented(SSLSession session) throws SSLPeerUnverifiedException {
        Certificate[] peer = session.getPeerCertificates();
        if ((peer == null) || (peer.length == 0))
            throw new SSLPeerUnverifiedException("no peer certificates");
        X509Certificate[] presented = new X509Certificate[peer.length];
        for (int i = 0; i < peer.length; i++) {
            if (!(peer[i] instanceof X509Certificate))
                throw new SSLPeerUnverifiedException("peer certificate is not X.509");
            presented[i] = (X509Certificate) peer[i];
        }
        return presented;
    }

    /**
     * Gets the pins for a host from the SDK pin set. Each domain that normalizes to the host gives its pins or,
     * if it has none, the managed trust roots (the "*" pin set) if present. The "*" key is never a pattern and
     * never applies to a host that is not listed, and no domain applies to another host, such as a subdomain.
     *
     * @param host is the normalized host
     * @param allPins is the SDK pin set
     * @return the pins for the host, which are empty if the host is not listed or has no pins and no managed
     * trust roots
     */
    static Set<String> pinsFor(String host, Map<String, List<String>> allPins) {
        List<String> managedTrustRoots = allPins.get("*");
        Set<String> hostPins = new HashSet<>();
        for (Map.Entry<String, List<String>> entry : allPins.entrySet()) {
            String domain = entry.getKey();
            if ("*".equals(domain))
                continue;
            // a domain without a pin list is listed with no pins, so it adds none
            if ((domain == null) || (entry.getValue() == null))
                continue;
            if (!ApproovService.normalizeHost(domain).equals(host))
                continue;

            // if there are no pins then we try and use any managed trust roots
            List<String> pins = entry.getValue();
            if (pins.isEmpty() && (managedTrustRoots != null))
                pins = managedTrustRoots;
            for (String pin : pins) {
                if (pin != null)
                    hostPins.add(pin);
            }
        }
        return hostPins;
    }

    /**
     * Determines if a host is listed in the SDK pin set, as a key other than "*" that normalizes to it.
     *
     * @param host is the normalized host
     * @param allPins is the SDK pin set
     * @return true if the host is listed
     */
    private static boolean isListed(String host, Map<String, List<String>> allPins) {
        for (String domain : allPins.keySet()) {
            if ((domain != null) && !domain.equals("*") && ApproovService.normalizeHost(domain).equals(host))
                return true;
        }
        return false;
    }

    /**
     * Warns once per host that an Approov domain with no pins of its own is validated by OS trust only,
     * because the managed trust roots are empty or absent. This is a valid development setup, but should
     * not be silent. The host is named, never a pin.
     *
     * @param host is the normalized host
     */
    private static void warnOsTrustOnly(String host) {
        synchronized (warnedOsTrustOnlyHosts) {
            if (!warnedOsTrustOnlyHosts.add(host))
                return;
        }
        ApproovLog.w(TAG, "Approov domain " + host + ": no pins and no managed trust roots, OS trust only");
    }

    /**
     * Computes the base64-encoded SHA-256 of the given bytes, matching the Approov
     * "public-key-sha256" pin form. Uses the platform MessageDigest/Base64 so the service layer
     * carries no third-party dependency purely for pin hashing.
     *
     * @param data the bytes to hash (a certificate's encoded public key)
     * @return the base64 (no-wrap) SHA-256 digest
     */
    private static String sha256Base64(byte[] data) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(data);
            return Base64.encodeToString(digest, Base64.NO_WRAP);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is guaranteed available on every Android platform; a failure here is fatal.
            throw new IllegalStateException("SHA-256 algorithm not available", e);
        }
    }

    /**
     * The platform trust that gives the chain the pins are matched against: the chain that vouches for the
     * server's leaf certificate, never any other certificate the server presented. This is the chain the
     * platform trust manager validated or, if the platform does not trust the chain (such as one an app's own
     * trust manager accepts) or cannot be asked, the chain walked from the leaf by signature through the
     * presented certificates and the platform trust anchors.
     */
    static final class PlatformTrust {
        // the longest chain walked from the leaf, as the OkHttp chain cleaner allows
        private static final int MAX_CHAIN_LENGTH = 10;

        // the platform trust, read once per process
        private static PlatformTrust platform;

        /**
         * Validates a chain as the platform trust manager does.
         */
        interface ChainValidator {
            /**
             * Validates the presented certificates for a host.
             *
             * @param presented are the certificates the peer presented, leaf first
             * @param host is the host
             * @return the validated chain, leaf first, or null if the platform cannot be asked
             * @throws CertificateException if the platform does not trust the chain
             */
            List<X509Certificate> validatedChain(X509Certificate[] presented, String host)
                    throws CertificateException;
        }

        // the platform chain validator
        private final ChainValidator validator;

        // the trust anchors used to find the root of a walked chain when the peer does not present it
        private final Set<X509Certificate> anchors;

        PlatformTrust(ChainValidator validator, Set<X509Certificate> anchors) {
            this.validator = validator;
            this.anchors = anchors;
        }

        /**
         * Gets the platform default trust, read once per process. Its first X509TrustManager validates a chain,
         * through X509TrustManagerExtensions, and the issuers every X509TrustManager accepts are the trust
         * anchors.
         *
         * @return the platform trust
         */
        static synchronized PlatformTrust platform() {
            if (platform != null)
                return platform;
            X509TrustManager trustManager = null;
            Set<X509Certificate> anchors = new HashSet<>();
            try {
                TrustManagerFactory factory = TrustManagerFactory.getInstance(
                        TrustManagerFactory.getDefaultAlgorithm());
                factory.init((KeyStore) null);
                for (TrustManager manager : factory.getTrustManagers()) {
                    if (manager instanceof X509TrustManager) {
                        if (trustManager == null)
                            trustManager = (X509TrustManager) manager;
                        Collections.addAll(anchors, ((X509TrustManager) manager).getAcceptedIssuers());
                    }
                }
            } catch (Exception e) {
                ApproovLog.e(TAG, "Platform trust store not read: " + e);
            }
            X509TrustManagerExtensions extensions = null;
            if (trustManager != null) {
                try {
                    extensions = new X509TrustManagerExtensions(trustManager);
                } catch (RuntimeException e) {
                    // the platform trust manager cannot validate a chain for a host, so chains are walked
                    ApproovLog.d(TAG, "Platform chain validation unavailable: " + e);
                }
            }
            X509TrustManagerExtensions platformExtensions = extensions;
            platform = new PlatformTrust((presented, host) -> (platformExtensions == null) ? null
                    : platformExtensions.checkServerTrusted(presented, "RSA", host),
                    Collections.unmodifiableSet(anchors));
            return platform;
        }

        /**
         * Gets the chain that vouches for the leaf of the presented certificates.
         *
         * @param presented are the certificates the peer presented, leaf first
         * @param host is the host
         * @return the chain, leaf first
         */
        List<X509Certificate> vouchingChain(X509Certificate[] presented, String host) {
            try {
                List<X509Certificate> validated = validator.validatedChain(presented, host);
                if ((validated != null) && !validated.isEmpty())
                    return validated;
            } catch (CertificateException | RuntimeException e) {
                // a chain the platform does not trust, accepted by the app's own trust, is walked instead
                ApproovLog.d(TAG, "Platform trust does not validate the chain of " + host
                        + ": pins matched on the chain that signed the leaf: " + e);
            }
            return signingChain(presented);
        }

        /**
         * Walks the chain of issuers from the leaf. Each next certificate is a presented certificate that is a
         * CA, or a trust anchor, whose subject is the issuer of the current certificate and whose key verifies
         * its signature. A presented certificate that signed nothing on the path is never in it.
         *
         * @param presented are the certificates the peer presented, leaf first
         * @return the chain, leaf first
         */
        private List<X509Certificate> signingChain(X509Certificate[] presented) {
            List<X509Certificate> chain = new ArrayList<>();
            X509Certificate current = presented[0];
            chain.add(current);
            while (chain.size() < MAX_CHAIN_LENGTH) {
                // a self-signed certificate ends the chain
                if (signedBy(current, current))
                    break;
                X509Certificate issuer = null;
                for (int i = 1; (i < presented.length) && (issuer == null); i++) {
                    if (!chain.contains(presented[i]) && isCa(presented[i]) && signedBy(current, presented[i]))
                        issuer = presented[i];
                }
                if (issuer == null) {
                    // a trust anchor is a CA by being trusted
                    for (X509Certificate anchor : anchors) {
                        if (!chain.contains(anchor) && signedBy(current, anchor)) {
                            issuer = anchor;
                            break;
                        }
                    }
                }
                if (issuer == null)
                    break;
                chain.add(issuer);
                current = issuer;
            }
            return chain;
        }

        // true if the certificate may issue certificates, by its basic constraints and any key usage
        private static boolean isCa(X509Certificate cert) {
            if (cert.getBasicConstraints() < 0)
                return false;
            // keyCertSign is bit 5 of the key usage, when it is present
            boolean[] keyUsage = cert.getKeyUsage();
            return (keyUsage == null) || ((keyUsage.length > 5) && keyUsage[5]);
        }

        // true if the certificate names the issuer as its issuer and carries its signature
        private static boolean signedBy(X509Certificate cert, X509Certificate issuer) {
            try {
                if (!cert.getIssuerX500Principal().equals(issuer.getSubjectX500Principal()))
                    return false;
                cert.verify(issuer.getPublicKey());
                return true;
            } catch (Exception e) {
                return false;
            }
        }
    }
}
