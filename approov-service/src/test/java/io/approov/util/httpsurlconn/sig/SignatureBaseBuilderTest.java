package io.approov.util.httpsurlconn.sig;

import static org.junit.Assert.assertEquals;

import java.util.logging.Level;
import java.util.logging.Logger;

import okhttp3.Headers;
import okhttp3.Request;

import org.junit.Test;

public class SignatureBaseBuilderTest {
    private static final Logger LOGGER = Logger.getLogger(SignatureBaseBuilderTest.class.getName());

    @Test
    public void createSignatureBase() {
        Headers headers = new Headers.Builder()
                .add("My-Header", "my \tValuE")
                .add("My-Other-Header", "my other\tValuE")
                .build();
        Request request = new Request.Builder()
                .get()
                .url("https://example.com:1234/path/seg%201/seg+2/?param1=&param2=arg%201&param3=Arg+3#fragment")
                .headers(headers)
                .build();

        LOGGER.info(makeLines(
                "Request properties",
                "        toString:" + request.url(),
                "          scheme:" + request.url().scheme(),
                "            host:" + request.url().host(),
                "            port:" + request.url().port(),
                "    encoded path:" + request.url().encodedPath(),
                "           query:" + request.url().query(),
                "   encoded query:" + request.url().encodedQuery(),
                "parameter param1:" + request.url().queryParameter("param1"),
                "parameter param2:" + request.url().queryParameter("param2"),
                "parameter param3:" + request.url().queryParameter("param3"),
                "        fragment:" + request.url().fragment(),
                "encoded fragment:" + request.url().encodedFragment()
        ));

        assertSignatureBase("minimal",
                new SignatureParameters()
                        .setCreated(123L)
                        .setKeyid("my-key")
                        .setAlg("my-alg"),
                request,
                makeLines("\"@signature-params\": ();created=123;keyid=\"my-key\";alg=\"my-alg\"")
        );
        assertSignatureBase("path and authority",
                new SignatureParameters()
                        .setCreated(123L)
                        .setKeyid("my-key")
                        .addComponentIdentifier(ComponentProvider.DC_PATH)
                        .addComponentIdentifier(ComponentProvider.DC_AUTHORITY),
                request,
                makeLines(
                        "\"@path\": /path/seg%201/seg+2/",
                        "\"@authority\": example.com",
                        "\"@signature-params\": (\"@path\" \"@authority\");created=123;keyid=\"my-key\"")
        );
        assertSignatureBase("target-uri",
                new SignatureParameters()
                        .setCreated(123L)
                        .setKeyid("my-key")
                        .addComponentIdentifier(ComponentProvider.DC_TARGET_URI),
                request,
                makeLines(
                        "\"@target-uri\": https://example.com:1234/path/seg%201/seg+2/?param1=&param2=arg%201&param3=Arg+3#fragment",
                        "\"@signature-params\": (\"@target-uri\");created=123;keyid=\"my-key\"")
        );
    }

    private void assertSignatureBase(String name, SignatureParameters params, Request request, String expected) {
        ComponentProvider provider = new TestComponentProvider(request);
        SignatureBaseBuilder baseBuilder = new SignatureBaseBuilder(params, provider);
        String actual = baseBuilder.createSignatureBase();

        LOGGER.log(Level.INFO, "Signature base for - {0}:\n{1}\n", new Object[] { name, actual });

        assertEquals("Signature base failure - " + name, expected, actual);
    }

    private String makeLines(String... lines) {
        StringBuilder builder = new StringBuilder();
        boolean first = true;
        for (String line : lines) {
            if (first) {
                builder.append(line);
                first = false;
            } else {
                builder.append("\n").append(line);
            }
        }
        return builder.toString();
    }
}
