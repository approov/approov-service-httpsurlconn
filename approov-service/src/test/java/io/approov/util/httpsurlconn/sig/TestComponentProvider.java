package io.approov.util.httpsurlconn.sig;

import java.util.List;

import okhttp3.Request;

public class TestComponentProvider implements ComponentProvider {
    private final Request request;

    TestComponentProvider(Request request) {
        this.request = request;
    }

    @Override
    public String getMethod() {
        return request.method();
    }

    @Override
    public String getAuthority() {
        return request.url().host();
    }

    @Override
    public String getScheme() {
        return request.url().scheme();
    }

    @Override
    public String getTargetUri() {
        return request.url().uri().toString();
    }

    @Override
    public String getRequestTarget() {
        String requestTarget = "";
        if (request.url().uri().getRawPath() != null) {
            requestTarget += request.url().uri().getRawPath();
        }
        if (request.url().uri().getRawQuery() != null) {
            requestTarget += "?" + request.url().uri().getRawQuery();
        }
        return requestTarget;
    }

    @Override
    public String getPath() {
        return request.url().uri().getRawPath();
    }

    @Override
    public String getQuery() {
        return request.url().uri().getRawQuery();
    }

    @Override
    public String getQueryParam(String name) {
        List<String> values = request.url().queryParameterValues(name);
        if (values.isEmpty()) {
            throw new IllegalArgumentException("Could not find query parameter named " + name);
        } else if (values.size() > 1) {
            return null;
        }
        return values.get(0);
    }

    @Override
    public String getStatus() {
        throw new IllegalStateException("Only requests are supported");
    }

    @Override
    public boolean hasField(String name) {
        List<String> headers = request.headers(name);
        return !headers.isEmpty();
    }

    @Override
    public String getField(String name) {
        List<String> headers = request.headers(name);
        return ComponentProvider.combineFieldValues(headers);
    }

    @Override
    public boolean hasBody() {
        return request.body() != null;
    }
}
