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

import java.util.List;

/**
 * ApproovRequestMutations stores information about changes made to a network request
 * during Approov processing, such as token headers, substituted headers, and query parameters.
 */
public class ApproovRequestMutations {
    private String tokenHeaderKey;
    private List<String> substitutionHeaderKeys;
    private String traceIDHeaderKey;
    private byte[] bodyBytes;


    /**
     * Gets the header key used for the Approov token.
     *
     * @return the Approov token header key
     */
    public String getTokenHeaderKey() {
        return tokenHeaderKey;
    }

    /**
     * Sets the header key used for the Approov token.
     *
     * @param tokenHeaderKey the Approov token header key
     */
    public void setTokenHeaderKey(String tokenHeaderKey) {
        this.tokenHeaderKey = tokenHeaderKey;
    }

    /**
     * Gets the list of headers that were substituted with secure strings.
     *
     * @return the list of substituted header keys
     */
    public List<String> getSubstitutionHeaderKeys() {
        return substitutionHeaderKeys;
    }

    /**
     * Sets the list of headers that were substituted with secure strings.
     *
     * @param substitutionHeaderKeys the list of substituted header keys
     */
    public void setSubstitutionHeaderKeys(List<String> substitutionHeaderKeys) {
        this.substitutionHeaderKeys = substitutionHeaderKeys;
    }


    /**
     * Gets the header key used for the optional Approov TraceID debug header.
     *
     * @return the Approov TraceID header key. Null if the TraceID header was not used.
     */
    public String getTraceIDHeaderKey() {
        return traceIDHeaderKey;
    }

    /**
     * Sets the header key used for the optional Approov TraceID debug header.
     *
     * @param traceIDHeaderKey the Approov TraceID header key
     */
    public void setTraceIDHeaderKey(String traceIDHeaderKey) {
        this.traceIDHeaderKey = traceIDHeaderKey;
    }

    /**
     * Gets the request body bytes supplied via the {@code addApproov(connection, byte[])}
     * overload, used to compute the message-signing {@code Content-Digest}.
     *
     * @return the request body bytes, or null if none were supplied
     */
    public byte[] getBodyBytes() {
        return bodyBytes;
    }

    /**
     * Sets the request body bytes used to compute the message-signing {@code Content-Digest}.
     *
     * @param bodyBytes the request body bytes
     */
    public void setBodyBytes(byte[] bodyBytes) {
        this.bodyBytes = bodyBytes;
    }
}
