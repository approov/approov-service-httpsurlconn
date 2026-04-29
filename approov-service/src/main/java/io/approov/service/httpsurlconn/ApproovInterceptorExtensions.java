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

import java.net.URL;
import java.net.HttpURLConnection;

import javax.net.ssl.HttpsURLConnection;

/**
 * Legacy callback interface for customizing the httpsurlconn service layer after
 * Approov has applied its request changes.
 *
 * @deprecated Replace implementations of this interface with ApproovServiceMutator
 * while changing the name of the ApproovInterceptorExtensions.processedRequest
 * method to ApproovServiceMutator.handleInterceptorProcessedRequest.
 */
@Deprecated
public interface ApproovInterceptorExtensions extends ApproovServiceMutator{

    /**
     * Replaces the default implementation of
     * ApproovServiceMutator.handleInterceptorProcessedRequest so existing
     * ApproovInterceptorExtensions implementations continue to receive the final
     * prepared HttpsURLConnection request.
     *
     * @param request the processed request
     * @param changes the mutations applied to the request by Approov
     * @return the final request to use to complete Approov request preparation
     * @throws ApproovException if there is an error during processing
     */
    default HttpsURLConnection handleInterceptorProcessedRequest(HttpsURLConnection request, ApproovRequestMutations changes) throws ApproovException {
        // call the deprecated method to maintain backwards compatibility
        return processedRequest(request, changes);
    }

    /**
     * @deprecated Use ApproovServiceMutator.handleInterceptorProcessedRequest instead.
     */
    @Deprecated
    default HttpsURLConnection processedRequest(HttpsURLConnection request, ApproovRequestMutations changes) throws ApproovException {
        // No further changes to the request are required
        return request;
    }
}
