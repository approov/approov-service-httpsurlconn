package io.approov.util.httpsurlconn.sig;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.util.Collections;

import io.approov.util.httpsurlconn.http.sfv.Parameters;
import io.approov.util.httpsurlconn.http.sfv.StringItem;

public class SignatureParametersTest {

    @Test
    public void toComponentValue() {
        assertParams("minimal",
                new SignatureParameters()
                        .setCreated(123L)
                        .setKeyid("my-key")
                        .setAlg("my-alg"),
                "();created=123;keyid=\"my-key\";alg=\"my-alg\""
        );
        assertParams("selective",
                new SignatureParameters()
                        .addComponentIdentifier(ComponentProvider.DC_AUTHORITY)
                        .addComponentIdentifier("Content-Type")
                        .setCreated(123L)
                        .setKeyid("my-key"),
                "(\"@authority\" \"content-type\");created=123;keyid=\"my-key\""
        );
        assertParams("full",
                new SignatureParameters()
                        .addComponentIdentifier("Date")
                        .addComponentIdentifier(ComponentProvider.DC_METHOD)
                        .addComponentIdentifier(ComponentProvider.DC_PATH)
                        .addComponentIdentifier(ComponentProvider.DC_QUERY)
                        .addComponentIdentifier(ComponentProvider.DC_AUTHORITY)
                        .addComponentIdentifier("Content-Type")
                        .addComponentIdentifier("Content-Digest")
                        .addComponentIdentifier("Content-Length")
                        .setCreated(123L)
                        .setKeyid("my-key"),
                "(\"date\" \"@method\" \"@path\" \"@query\" \"@authority\" \"content-type\" \"content-digest\" "
                        + "\"content-length\");created=123;keyid=\"my-key\""
        );
    }

    @Test
    public void eachComponentIsCoveredOnce() {
        assertParams("a repeated field in any case and a repeated derived component",
                new SignatureParameters()
                        .addComponentIdentifier(ComponentProvider.DC_METHOD)
                        .addComponentIdentifier("Authorization")
                        .addComponentIdentifier("authorization")
                        .addComponentIdentifier("AUTHORIZATION")
                        .addComponentIdentifier(ComponentProvider.DC_METHOD),
                "(\"@method\" \"authorization\")"
        );
        SignatureParameters copy = new SignatureParameters(new SignatureParameters()
                .addComponentIdentifier("Approov-Token"))
                .addComponentIdentifier("approov-token");
        assertParams("a component of the base added again", copy, "(\"approov-token\")");
        assertTrue(copy.containsComponentIdentifier("approov-token"));
    }

    @Test
    public void theSameComponentWithOtherParametersIsCoveredSeparately() {
        StringItem first = StringItem.valueOf(ComponentProvider.DC_QUERY_PARAM)
                .withParams(Parameters.valueOf(Collections.<String, Object>singletonMap("name", "a")));
        StringItem second = StringItem.valueOf(ComponentProvider.DC_QUERY_PARAM)
                .withParams(Parameters.valueOf(Collections.<String, Object>singletonMap("name", "b")));
        assertParams("query parameters",
                new SignatureParameters()
                        .addComponentIdentifier(first)
                        .addComponentIdentifier(second)
                        .addComponentIdentifier(first),
                "(\"@query-param\";name=\"a\" \"@query-param\";name=\"b\")"
        );
    }

    private void assertParams(String name, SignatureParameters params, String expected) {
        String actual = params.toComponentValue().serialize();
        assertEquals("Params failure - " + name, expected, actual);
    }
}
