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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ProtocolException;
import java.net.URL;
import java.security.Permission;
import java.security.Principal;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSocketFactory;

/**
 * A delegating {@link HttpsURLConnection} that buffers request body bytes so the
 * final processed-request callback can run immediately before the real network
 * request is sent. This allows the httpsurlconn service layer to finish any
 * URL substitutions on the effective connection and include the actual request
 * body bytes in message signing.
 */
final class ApproovBufferedHttpsURLConnection extends HttpsURLConnection {
    private final HttpsURLConnection originalRequest;
    private final ApproovService.PreparedRequestData preparedRequestData;

    private URL configuredUrl;
    private String requestMethod;
    private int connectTimeout;
    private int readTimeout;
    private boolean doInput;
    private boolean doOutput;
    private boolean allowUserInteraction;
    private boolean useCaches;
    private boolean defaultUseCaches;
    private long ifModifiedSince;
    private boolean instanceFollowRedirects;
    private int fixedLengthStreamingMode = -1;
    private long fixedLengthStreamingModeLong = -1L;
    private int chunkLength = -1;
    private SSLSocketFactory sslSocketFactory;
    private HostnameVerifier hostnameVerifier;
    private Map<String, List<String>> requestProperties;

    private ByteArrayOutputStream requestBodyBuffer;
    private OutputStream bufferedOutputStream;

    private HttpsURLConnection networkRequest;
    private boolean processedRequestApplied;
    private boolean requestBodyTransmitted;

    /**
     * Constructs a new buffered connection wrapper from a request that has
     * already had all non-signing Approov processing applied.
     *
     * @param request             the request to wrap
     * @param preparedRequestData the precomputed token/header substitution result
     * @param queryResult         the precomputed query substitution result
     */
    ApproovBufferedHttpsURLConnection(
            HttpsURLConnection request,
            ApproovService.PreparedRequestData preparedRequestData,
            ApproovService.QuerySubstitutionResult queryResult
    ) {
        super(queryResult.url);
        this.originalRequest = request;
        this.preparedRequestData = preparedRequestData;
        this.configuredUrl = queryResult.url;
        this.requestMethod = request.getRequestMethod();
        this.connectTimeout = request.getConnectTimeout();
        this.readTimeout = request.getReadTimeout();
        this.doInput = request.getDoInput();
        this.doOutput = request.getDoOutput();
        this.allowUserInteraction = request.getAllowUserInteraction();
        this.useCaches = request.getUseCaches();
        this.defaultUseCaches = request.getDefaultUseCaches();
        this.ifModifiedSince = request.getIfModifiedSince();
        this.instanceFollowRedirects = request.getInstanceFollowRedirects();
        this.sslSocketFactory = request.getSSLSocketFactory();
        this.hostnameVerifier = request.getHostnameVerifier();
        this.requestProperties = copyRequestProperties(request.getRequestProperties());

        if (!queryResult.substitutedQueryKeys.isEmpty()) {
            preparedRequestData.changes.setSubstitutionQueryParamResults(
                    queryResult.originalURL,
                    queryResult.substitutedQueryKeys
            );
        }
    }

    /**
     * Gets the buffered request body bytes, or null if no body has been written.
     *
     * @return a copy of the buffered request body
     */
    byte[] getBufferedRequestBody() {
        if (requestBodyBuffer == null) {
            return null;
        }
        return requestBodyBuffer.toByteArray();
    }

    private static Map<String, List<String>> copyRequestProperties(Map<String, List<String>> headers) {
        Map<String, List<String>> copy = new LinkedHashMap<>();
        if (headers == null) {
            return copy;
        }
        for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
            if (entry.getKey() == null) {
                continue;
            }
            List<String> values = entry.getValue();
            if (values == null) {
                copy.put(entry.getKey(), new ArrayList<>());
            } else {
                copy.put(entry.getKey(), new ArrayList<>(values));
            }
        }
        return copy;
    }

    private void ensureMutable() {
        if (processedRequestApplied || networkRequest != null) {
            throw new IllegalStateException("Cannot modify request after network processing has started");
        }
    }

    private void setHeaderValue(String key, String value) {
        List<String> values = new ArrayList<>(1);
        values.add(value);
        requestProperties.put(key, values);
    }

    private void addHeaderValue(String key, String value) {
        List<String> values = requestProperties.get(key);
        if (values == null) {
            values = new ArrayList<>();
            requestProperties.put(key, values);
        }
        values.add(value);
    }

    private void applyProcessedRequestIfNeeded() throws IOException {
        if (processedRequestApplied) {
            return;
        }

        if (!preparedRequestData.invokeProcessedCallback) {
            processedRequestApplied = true;
            return;
        }

        try {
            HttpsURLConnection processedRequest = preparedRequestData.mutator.handleInterceptorProcessedRequest(
                    this,
                    preparedRequestData.changes
            );
            if ((processedRequest != null) && (processedRequest != this)) {
                synchronizeFromReturnedRequest(processedRequest);
            }
            processedRequestApplied = true;
        } catch (ApproovException e) {
            throw new IOException("Approov processed request callback failed", e);
        }
    }

    private void synchronizeFromReturnedRequest(HttpsURLConnection processedRequest) {
        this.configuredUrl = processedRequest.getURL();
        this.requestMethod = processedRequest.getRequestMethod();
        this.connectTimeout = processedRequest.getConnectTimeout();
        this.readTimeout = processedRequest.getReadTimeout();
        this.doInput = processedRequest.getDoInput();
        this.doOutput = processedRequest.getDoOutput();
        this.allowUserInteraction = processedRequest.getAllowUserInteraction();
        this.useCaches = processedRequest.getUseCaches();
        this.defaultUseCaches = processedRequest.getDefaultUseCaches();
        this.ifModifiedSince = processedRequest.getIfModifiedSince();
        this.instanceFollowRedirects = processedRequest.getInstanceFollowRedirects();
        this.sslSocketFactory = processedRequest.getSSLSocketFactory();
        this.hostnameVerifier = processedRequest.getHostnameVerifier();
        this.requestProperties = copyRequestProperties(processedRequest.getRequestProperties());
    }

    private HttpsURLConnection createNetworkRequestIfNeeded() throws IOException {
        if (networkRequest != null) {
            return networkRequest;
        }

        HttpsURLConnection targetRequest;
        if (configuredUrl.toString().equals(originalRequest.getURL().toString())) {
            targetRequest = originalRequest;
        } else {
            targetRequest = (HttpsURLConnection) configuredUrl.openConnection();
        }

        targetRequest.setConnectTimeout(connectTimeout);
        targetRequest.setReadTimeout(readTimeout);
        targetRequest.setDoInput(doInput);
        targetRequest.setDoOutput(doOutput);
        targetRequest.setAllowUserInteraction(allowUserInteraction);
        targetRequest.setUseCaches(useCaches);
        targetRequest.setDefaultUseCaches(defaultUseCaches);
        targetRequest.setIfModifiedSince(ifModifiedSince);
        targetRequest.setInstanceFollowRedirects(instanceFollowRedirects);
        if (sslSocketFactory != null) {
            targetRequest.setSSLSocketFactory(sslSocketFactory);
        }
        if (hostnameVerifier != null) {
            targetRequest.setHostnameVerifier(hostnameVerifier);
        }
        try {
            targetRequest.setRequestMethod(requestMethod);
        } catch (ProtocolException e) {
            throw new IOException("Failed to set request method", e);
        }
        if (fixedLengthStreamingModeLong >= 0) {
            targetRequest.setFixedLengthStreamingMode(fixedLengthStreamingModeLong);
        } else if (fixedLengthStreamingMode >= 0) {
            targetRequest.setFixedLengthStreamingMode(fixedLengthStreamingMode);
        } else if (chunkLength >= 0) {
            targetRequest.setChunkedStreamingMode(chunkLength);
        }
        for (Map.Entry<String, List<String>> entry : requestProperties.entrySet()) {
            List<String> values = entry.getValue();
            if (values == null || values.isEmpty()) {
                continue;
            }
            targetRequest.setRequestProperty(entry.getKey(), values.get(0));
            for (int i = 1; i < values.size(); i++) {
                targetRequest.addRequestProperty(entry.getKey(), values.get(i));
            }
        }

        networkRequest = targetRequest;
        return networkRequest;
    }

    private void ensureRequestReadyForNetwork() throws IOException {
        applyProcessedRequestIfNeeded();
        createNetworkRequestIfNeeded();
    }

    private void ensureRequestBodyTransmitted() throws IOException {
        ensureRequestReadyForNetwork();
        if (requestBodyTransmitted) {
            return;
        }

        if (doOutput || requestBodyBuffer != null) {
            OutputStream outputStream = networkRequest.getOutputStream();
            if (requestBodyBuffer != null) {
                requestBodyBuffer.writeTo(outputStream);
            }
            outputStream.close();
        }

        requestBodyTransmitted = true;
        connected = true;
    }

    private void ensureResponseReady() throws IOException {
        ensureRequestBodyTransmitted();
    }

    @Override
    public String getCipherSuite() {
        try {
            ensureResponseReady();
        } catch (IOException e) {
            throw new IllegalStateException("Failed to prepare network request", e);
        }
        return networkRequest.getCipherSuite();
    }

    @Override
    public Certificate[] getLocalCertificates() {
        try {
            ensureResponseReady();
        } catch (IOException e) {
            throw new IllegalStateException("Failed to prepare network request", e);
        }
        return networkRequest.getLocalCertificates();
    }

    @Override
    public Certificate[] getServerCertificates() throws SSLPeerUnverifiedException {
        try {
            ensureResponseReady();
        } catch (IOException e) {
            SSLPeerUnverifiedException exception =
                    new SSLPeerUnverifiedException("Failed to prepare network request");
            exception.initCause(e);
            throw exception;
        }
        return networkRequest.getServerCertificates();
    }

    @Override
    public Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
        try {
            ensureResponseReady();
        } catch (IOException e) {
            SSLPeerUnverifiedException exception =
                    new SSLPeerUnverifiedException("Failed to prepare network request");
            exception.initCause(e);
            throw exception;
        }
        return networkRequest.getPeerPrincipal();
    }

    @Override
    public Principal getLocalPrincipal() {
        try {
            ensureResponseReady();
        } catch (IOException e) {
            throw new IllegalStateException("Failed to prepare network request", e);
        }
        return networkRequest.getLocalPrincipal();
    }

    @Override
    public void disconnect() {
        if (networkRequest != null) {
            networkRequest.disconnect();
        } else {
            originalRequest.disconnect();
        }
    }

    @Override
    public boolean usingProxy() {
        if (networkRequest != null) {
            return networkRequest.usingProxy();
        }
        return originalRequest.usingProxy();
    }

    @Override
    public void connect() throws IOException {
        ensureResponseReady();
        networkRequest.connect();
        connected = true;
    }

    @Override
    public URL getURL() {
        return configuredUrl;
    }

    @Override
    public void setConnectTimeout(int timeout) {
        ensureMutable();
        this.connectTimeout = timeout;
    }

    @Override
    public int getConnectTimeout() {
        return connectTimeout;
    }

    @Override
    public void setReadTimeout(int timeout) {
        ensureMutable();
        this.readTimeout = timeout;
    }

    @Override
    public int getReadTimeout() {
        return readTimeout;
    }

    @Override
    public void setDoInput(boolean doinput) {
        ensureMutable();
        this.doInput = doinput;
    }

    @Override
    public boolean getDoInput() {
        return doInput;
    }

    @Override
    public void setDoOutput(boolean dooutput) {
        ensureMutable();
        this.doOutput = dooutput;
    }

    @Override
    public boolean getDoOutput() {
        return doOutput;
    }

    @Override
    public void setAllowUserInteraction(boolean allowuserinteraction) {
        ensureMutable();
        this.allowUserInteraction = allowuserinteraction;
    }

    @Override
    public boolean getAllowUserInteraction() {
        return allowUserInteraction;
    }

    @Override
    public void setUseCaches(boolean usecaches) {
        ensureMutable();
        this.useCaches = usecaches;
    }

    @Override
    public boolean getUseCaches() {
        return useCaches;
    }

    @Override
    public void setDefaultUseCaches(boolean defaultusecaches) {
        ensureMutable();
        this.defaultUseCaches = defaultusecaches;
    }

    @Override
    public boolean getDefaultUseCaches() {
        return defaultUseCaches;
    }

    @Override
    public void setIfModifiedSince(long ifmodifiedsince) {
        ensureMutable();
        this.ifModifiedSince = ifmodifiedsince;
    }

    @Override
    public long getIfModifiedSince() {
        return ifModifiedSince;
    }

    @Override
    public void setInstanceFollowRedirects(boolean followRedirects) {
        ensureMutable();
        this.instanceFollowRedirects = followRedirects;
    }

    @Override
    public boolean getInstanceFollowRedirects() {
        return instanceFollowRedirects;
    }

    @Override
    public void setRequestMethod(String method) throws ProtocolException {
        ensureMutable();
        this.requestMethod = method;
    }

    @Override
    public String getRequestMethod() {
        return requestMethod;
    }

    @Override
    public void setFixedLengthStreamingMode(int contentLength) {
        ensureMutable();
        this.fixedLengthStreamingMode = contentLength;
        this.fixedLengthStreamingModeLong = -1L;
        this.chunkLength = -1;
    }

    @Override
    public void setFixedLengthStreamingMode(long contentLength) {
        ensureMutable();
        this.fixedLengthStreamingModeLong = contentLength;
        this.fixedLengthStreamingMode = -1;
        this.chunkLength = -1;
    }

    @Override
    public void setChunkedStreamingMode(int chunklen) {
        ensureMutable();
        this.chunkLength = chunklen;
        this.fixedLengthStreamingMode = -1;
        this.fixedLengthStreamingModeLong = -1L;
    }

    @Override
    public void setRequestProperty(String key, String value) {
        ensureMutable();
        setHeaderValue(key, value);
    }

    @Override
    public void addRequestProperty(String key, String value) {
        ensureMutable();
        addHeaderValue(key, value);
    }

    @Override
    public String getRequestProperty(String key) {
        List<String> values = requestProperties.get(key);
        if (values == null || values.isEmpty()) {
            return null;
        }
        return values.get(values.size() - 1);
    }

    @Override
    public Map<String, List<String>> getRequestProperties() {
        Map<String, List<String>> copy = new LinkedHashMap<>();
        for (Map.Entry<String, List<String>> entry : requestProperties.entrySet()) {
            copy.put(entry.getKey(), new ArrayList<>(entry.getValue()));
        }
        return Collections.unmodifiableMap(copy);
    }

    @Override
    public void setSSLSocketFactory(SSLSocketFactory sf) {
        ensureMutable();
        this.sslSocketFactory = sf;
    }

    @Override
    public SSLSocketFactory getSSLSocketFactory() {
        return sslSocketFactory;
    }

    @Override
    public void setHostnameVerifier(HostnameVerifier v) {
        ensureMutable();
        this.hostnameVerifier = v;
    }

    @Override
    public HostnameVerifier getHostnameVerifier() {
        return hostnameVerifier;
    }

    @Override
    public OutputStream getOutputStream() throws IOException {
        if (processedRequestApplied) {
            throw new IllegalStateException("Cannot obtain the request body stream after signing has been applied");
        }
        doOutput = true;
        if (requestBodyBuffer == null) {
            requestBodyBuffer = new ByteArrayOutputStream();
            bufferedOutputStream = new OutputStream() {
                @Override
                public void write(int b) {
                    requestBodyBuffer.write(b);
                }

                @Override
                public void write(byte[] b, int off, int len) {
                    requestBodyBuffer.write(b, off, len);
                }

                @Override
                public void flush() {
                    // nothing to flush until the real request is sent
                }

                @Override
                public void close() {
                    // keep the buffer available until the wrapped request is finalized
                }
            };
        }
        return bufferedOutputStream;
    }

    @Override
    public InputStream getInputStream() throws IOException {
        ensureResponseReady();
        return networkRequest.getInputStream();
    }

    @Override
    public InputStream getErrorStream() {
        try {
            ensureResponseReady();
            return networkRequest.getErrorStream();
        } catch (IOException e) {
            return null;
        }
    }

    @Override
    public int getResponseCode() throws IOException {
        ensureResponseReady();
        return networkRequest.getResponseCode();
    }

    @Override
    public String getResponseMessage() throws IOException {
        ensureResponseReady();
        return networkRequest.getResponseMessage();
    }

    @Override
    public Permission getPermission() throws IOException {
        ensureRequestReadyForNetwork();
        return networkRequest.getPermission();
    }

    @Override
    public Map<String, List<String>> getHeaderFields() {
        try {
            ensureResponseReady();
        } catch (IOException e) {
            throw new IllegalStateException("Failed to prepare network request", e);
        }
        return networkRequest.getHeaderFields();
    }

    @Override
    public String getHeaderField(String name) {
        try {
            ensureResponseReady();
        } catch (IOException e) {
            throw new IllegalStateException("Failed to prepare network request", e);
        }
        return networkRequest.getHeaderField(name);
    }

    @Override
    public String getHeaderField(int n) {
        try {
            ensureResponseReady();
        } catch (IOException e) {
            throw new IllegalStateException("Failed to prepare network request", e);
        }
        return networkRequest.getHeaderField(n);
    }

    @Override
    public String getHeaderFieldKey(int n) {
        try {
            ensureResponseReady();
        } catch (IOException e) {
            throw new IllegalStateException("Failed to prepare network request", e);
        }
        return networkRequest.getHeaderFieldKey(n);
    }

    @Override
    public Object getContent() throws IOException {
        ensureResponseReady();
        return networkRequest.getContent();
    }

    @Override
    public Object getContent(Class[] classes) throws IOException {
        ensureResponseReady();
        return networkRequest.getContent(classes);
    }
}
