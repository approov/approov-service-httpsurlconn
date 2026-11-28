package io.approov.service.httpsurlconn;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.criticalblue.approovsdk.Approov;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatchers;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import io.approov.util.httpsurlconn.sig.ComponentProvider;
import io.approov.util.httpsurlconn.sig.SignatureParameters;

/**
 * The derived components of a signed request come from the URL in the form Android sends it, parsed with
 * OkHttp's HttpUrl: {@code @target-uri} is that URL without the fragment, which is never sent, and without an
 * explicit default port, and {@code @authority} is the lowercase host with a non-default port. A "|" in the
 * path becomes %7C, a space %20, and a character that is not ASCII its UTF-8 bytes percent-encoded, while a
 * "|" in the query and an existing escape stay as they are. Nothing is parsed with {@code java.net.URI}, which
 * rejects some queries that Android sends.
 */
@RunWith(RobolectricTestRunner.class)
@Config(manifest = Config.NONE)
public class WireUrlComponentProviderTest {
    // the URL as the app wrote it, and the URL Android sends
    private static final String[][] DEVICE_CASES = {
            {"https://h/pipe|path?q=a|b", "https://h/pipe%7Cpath?q=a|b"},
            {"https://h/café?q=über✓", "https://h/caf%C3%A9?q=%C3%BCber%E2%9C%93"},
            {"https://h/a b?c d", "https://h/a%20b?c%20d"},
    };

    // URLs that are already in the form Android sends
    private static final String[] ENCODED = {
            "https://h/pc%25t?q=100%25",
            "https://h/a%20b?q=a%20b",
            "https://h/caf%C3%A9?q=caf%C3%A9",
            "https://h/s?f={%22a%22:1}&c=^`&p=x|y&plus=a+b",
    };

    private MockedStatic<Approov> approov;

    @Before
    public void setUp() {
        approov = Mockito.mockStatic(Approov.class);
        ApproovTestSupport.initializeApproovService(approov);
        ApproovTestSupport.sdkSignsWithBoth(approov);
    }

    @After
    public void tearDown() {
        approov.close();
        ApproovService.reset();
    }

    private static ApproovDefaultMessageSigning.HttpsURLConnectionComponentProvider provider(String url)
            throws Exception {
        return new ApproovDefaultMessageSigning.HttpsURLConnectionComponentProvider(ApproovTestSupport.connection(url));
    }

    // signs a request to the URL with the factory and returns the install signature base
    private String signatureBase(ApproovDefaultMessageSigning signer, String url) throws Exception {
        approov.clearInvocations();
        assertNotNull("the request is signed: " + url,
                ApproovTestSupport.sign(signer, url).getRequestProperty("Signature"));
        ArgumentCaptor<String> base = ArgumentCaptor.forClass(String.class);
        approov.verify(() -> Approov.getInstallMessageSignature(base.capture()));
        return base.getValue();
    }

    private void assertSignedTargetUri(String expected, String url) throws Exception {
        String base = signatureBase(ApproovDefaultMessageSigning.combined(), url);
        String line = "\"@target-uri\": " + expected + "\n";
        assertTrue("target URI " + expected + " for " + url + " in\n" + base, base.contains(line));
        // both signatures are over the same base but for the algorithm
        approov.verify(() -> Approov.getAccountMessageSignature(ArgumentMatchers.contains(line)));
    }

    // ---- the provider

    @Test
    public void targetUriIsTheUrlTheStackSendsForPipeQueries() throws Exception {
        String url = "https://maps.example.com/api/staticmap?path=color:red|weight:5&markers=a|b";
        ApproovDefaultMessageSigning.HttpsURLConnectionComponentProvider p = provider(url);
        assertEquals(url, p.getTargetUri());
        assertEquals("/api/staticmap?path=color:red|weight:5&markers=a|b", p.getRequestTarget());
    }

    @Test
    public void targetUriKeepsTheEncodingOfSpacesPercentAndNonAscii() throws Exception {
        String wire = "https://example.com/caf%C3%A9/a%2Fb?q=a%20b&pct=100%25&name=caf%C3%A9&pipe=x|y&plus=a+b";
        ApproovDefaultMessageSigning.HttpsURLConnectionComponentProvider p = provider(wire);
        assertEquals(wire, p.getTargetUri());
        assertEquals("https", p.getScheme());
        assertEquals("example.com", p.getAuthority());
        assertEquals("/caf%C3%A9/a%2Fb", p.getPath());
        assertEquals("/caf%C3%A9/a%2Fb?q=a%20b&pct=100%25&name=caf%C3%A9&pipe=x|y&plus=a+b", p.getRequestTarget());
    }

    @Test
    public void targetUriForAUrlJavaNetUriRejects() throws Exception {
        String url = "https://example.com/s?f={%22a%22:1}&c=^`&p=x|y";
        try {
            URI.create(url);
            fail("java.net.URI is expected to reject this URL, which the stack sends as is");
        } catch (IllegalArgumentException expected) {
            // the reason the layer must never parse the request URL with java.net.URI
        }
        ApproovDefaultMessageSigning.HttpsURLConnectionComponentProvider p = provider(url);
        assertEquals(url, p.getTargetUri());
        assertEquals("/s?f={%22a%22:1}&c=^`&p=x|y", p.getRequestTarget());
    }

    @Test
    public void targetUriLeavesOutTheFragmentWhichIsNeverSent() throws Exception {
        ApproovDefaultMessageSigning.HttpsURLConnectionComponentProvider p = provider("https://example.com/p?x=1|2#frag|ment");
        assertEquals("https://example.com/p?x=1|2", p.getTargetUri());
        assertEquals("/p?x=1|2", p.getRequestTarget());
        assertEquals("https://example.com/p%2Fx?q=a%20b", provider("https://example.com/p%2Fx?q=a%20b#f").getTargetUri());
    }

    @Test
    public void targetUriLeavesOutAnExplicitDefaultPortOnly() throws Exception {
        assertEquals("https://host/p?a=1", provider("https://host:443/p?a=1").getTargetUri());
        assertEquals("https://host:8443/p", provider("https://host:8443/p").getTargetUri());
        assertEquals("https://host:80/p", provider("https://host:80/p").getTargetUri());
        // the scheme is compared without regard to case, and Android sends it in lowercase
        assertEquals("https://host/p", provider("HTTPS://host:443/p").getTargetUri());
        // a URL with no path or no query
        assertEquals("https://host/", provider("https://host:443/").getTargetUri());
        assertEquals("https://host/?a=1", provider("https://host:443/?a=1#f").getTargetUri());
        assertEquals("https://host/p?", provider("https://host:443/p?").getTargetUri());
        // user info and an IPv6 host
        assertEquals("https://user:pw@host/p", provider("https://user:pw@host:443/p").getTargetUri());
        assertEquals("https://[::1]/p", provider("https://[::1]:443/p").getTargetUri());
        assertEquals("https://[::1]:8443/p", provider("https://[::1]:8443/p").getTargetUri());
        assertEquals("https://[::1]/p", provider("https://[::1]/p").getTargetUri());
        // a colon in the path or query is never taken for a port
        assertEquals("https://host/a:443/b?x=:443", provider("https://host/a:443/b?x=:443").getTargetUri());
    }

    @Test
    public void targetUriOfAUrlWithNoPathHasTheRootPathTheStackSends() throws Exception {
        assertEquals("https://example.com/", provider("https://example.com").getTargetUri());
        assertEquals("https://example.com/?a=1", provider("https://example.com?a=1").getTargetUri());
        assertEquals("/", provider("https://example.com").getPath());
    }

    @Test
    public void authorityHasTheLowercaseHostAndTheNonDefaultPortOnly() throws Exception {
        assertEquals("example.com:8443", provider("https://Example.com:8443/").getAuthority());
        assertEquals("example.com", provider("https://example.com:443/").getAuthority());
        assertEquals("example.com:80", provider("https://example.com:80/").getAuthority());
        assertEquals("[::1]", provider("https://[::1]/").getAuthority());
        assertEquals("[::1]:8443", provider("https://[::1]:8443/").getAuthority());
        assertEquals("example.com", provider("https://user:pw@EXAMPLE.com/").getAuthority());
    }

    @Test
    public void theHostOfAHostFactoryIsLowercaseWithoutAPort() throws Exception {
        assertEquals("example.com", provider("https://Example.COM:8443/p").getHost());
        assertEquals("[::1]", provider("https://[::1]:8443/p").getHost());
        assertEquals("internationalized names are in their ASCII form", "xn--caf-dma.example",
                provider("https://café.example/p").getHost());
    }

    @Test
    public void theDeviceCasesAreInTheFormAndroidSends() throws Exception {
        for (String[] pair : DEVICE_CASES)
            assertEquals(pair[0], pair[1], provider(pair[0]).getTargetUri());
        for (String url : ENCODED)
            assertEquals(url, url, provider(url).getTargetUri());
    }

    @Test
    public void normalisingTwiceIsTheIdentity() {
        List<String> urls = new ArrayList<>();
        for (String[] pair : DEVICE_CASES) {
            urls.add(pair[0]);
            urls.add(pair[1]);
        }
        Collections.addAll(urls, ENCODED);
        Collections.addAll(urls, "HTTPS://Host:443/p?#f", "https://[::1]:8443/a|b", "https://user:pw@h/p");
        for (String url : urls) {
            okhttp3.HttpUrl once = ApproovDefaultMessageSigning.HttpsURLConnectionComponentProvider.parseWireUrl(url);
            assertNotNull(url, once);
            assertEquals(url, once, ApproovDefaultMessageSigning.HttpsURLConnectionComponentProvider
                    .parseWireUrl(once.toString()));
        }
    }

    @Test
    public void aUrlThatCannotBeParsedHasNoWireUrl() throws Exception {
        ApproovDefaultMessageSigning.HttpsURLConnectionComponentProvider p = provider("https://example.com:99999/p");
        assertFalse(p.hasWireUrl());
        try {
            p.getTargetUri();
            fail("a URL that cannot be parsed has no target URI");
        } catch (RuntimeException expected) {
            // inside the fail-open of the signer
        }
    }

    // ---- the signature base

    @Test
    public void theSignedTargetUriIsTheFormAndroidSends() throws Exception {
        for (String[] pair : DEVICE_CASES)
            assertSignedTargetUri(pair[1], pair[0]);
    }

    @Test
    public void aUrlAlreadyInTheSentFormIsSignedUnchanged() throws Exception {
        for (String url : ENCODED)
            assertSignedTargetUri(url, url);
    }

    @Test
    public void anExplicitDefaultPortAndAFragmentAreNotSigned() throws Exception {
        assertSignedTargetUri("https://h/caf%C3%A9?q=a|b", "https://h:443/café?q=a|b#frag|ment");
        assertSignedTargetUri("https://h:8443/a%20b", "https://h:8443/a b#f");
        assertSignedTargetUri("https://host/p%2Fx?q=a%20b", "https://host/p%2Fx?q=a%20b#f");
    }

    @Test
    public void theAuthorityIsSignedWithANonDefaultPortOnly() throws Exception {
        ApproovDefaultMessageSigning signer = new ApproovDefaultMessageSigning().setDefaultFactory(
                ApproovDefaultMessageSigning.generateDefaultSignatureParametersFactory(
                        new SignatureParameters().addComponentIdentifier(ComponentProvider.DC_AUTHORITY)));
        assertTrue(signatureBase(signer, "https://Example.com:443/p").contains("\"@authority\": example.com\n"));
        assertTrue(signatureBase(signer, "https://example.com:8443/p").contains("\"@authority\": example.com:8443\n"));
    }

    @Test
    public void thePathAndTheRequestTargetAreSignedAsSent() throws Exception {
        ApproovDefaultMessageSigning signer = new ApproovDefaultMessageSigning().setDefaultFactory(
                ApproovDefaultMessageSigning.generateDefaultSignatureParametersFactory(new SignatureParameters()
                        .addComponentIdentifier(ComponentProvider.DC_PATH)
                        .addComponentIdentifier(ComponentProvider.DC_REQUEST_TARGET)
                        .addComponentIdentifier(ComponentProvider.DC_SCHEME)
                        .addComponentIdentifier(ComponentProvider.DC_QUERY)));
        String base = signatureBase(signer, "https://h/pipe|path?q=a|b#f");
        assertTrue(base, base.contains("\"@path\": /pipe%7Cpath\n"));
        assertTrue(base, base.contains("\"@request-target\": /pipe%7Cpath?q=a|b\n"));
        assertTrue(base, base.contains("\"@scheme\": https\n"));
        assertTrue(base, base.contains("\"@query\": ?q=a|b\n"));
    }
}
