package io.approov.service.httpsurlconn;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.criticalblue.approovsdk.Approov;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import javax.net.ssl.HttpsURLConnection;

import io.approov.util.httpsurlconn.sig.ComponentProvider;
import io.approov.util.httpsurlconn.sig.SignatureParameters;

/**
 * The signatures a factory selects: the install signature only by default, the account signature only, or
 * both as the members "install" and "account" of the same headers over the same covered components. A
 * subclass that sets the protected flags directly gets the signatures they select.
 */
@RunWith(RobolectricTestRunner.class)
@Config(manifest = Config.NONE)
public class SigningFactoryTest {
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

    private static HttpsURLConnection sign(ApproovDefaultMessageSigning.SignatureParametersFactory factory)
            throws Exception {
        return ApproovTestSupport.sign(new ApproovDefaultMessageSigning().setDefaultFactory(factory),
                "https://api.example.com/data");
    }

    @Test
    public void aDefaultFactoryProducesTheInstallSignatureOnly() throws Exception {
        ApproovDefaultMessageSigning.SignatureParametersFactory factory =
                ApproovDefaultMessageSigning.generateDefaultSignatureParametersFactory();
        assertEquals(Collections.singletonList("ecdsa-p256-sha256"), factory.getAlgs());
        HttpsURLConnection signed = sign(factory);
        assertTrue(signed.getRequestProperty("Signature"), signed.getRequestProperty("Signature").startsWith("install=:"));
        assertFalse(signed.getRequestProperty("Signature"), signed.getRequestProperty("Signature").contains("account="));
        assertFalse(signed.getRequestProperty("Signature-Input"),
                signed.getRequestProperty("Signature-Input").contains("account="));
        approov.verify(() -> Approov.getAccountMessageSignature(Mockito.anyString()), Mockito.never());
    }

    @Test
    public void aBareFactoryProducesTheInstallSignatureOnly() {
        assertEquals(Collections.singletonList("ecdsa-p256-sha256"),
                new ApproovDefaultMessageSigning.SignatureParametersFactory().getAlgs());
    }

    @Test
    public void theAccountSignatureOnly() throws Exception {
        ApproovDefaultMessageSigning.SignatureParametersFactory factory =
                ApproovDefaultMessageSigning.generateDefaultSignatureParametersFactory().setUseAccountMessageSigning();
        assertEquals(Collections.singletonList("hmac-sha256"), factory.getAlgs());
        HttpsURLConnection signed = sign(factory);
        assertTrue(signed.getRequestProperty("Signature"), signed.getRequestProperty("Signature").startsWith("account=:"));
        assertFalse(signed.getRequestProperty("Signature"), signed.getRequestProperty("Signature").contains("install="));
        approov.verify(() -> Approov.getInstallMessageSignature(Mockito.anyString()), Mockito.never());
    }

    @Test
    public void bothSignaturesInOrderOverTheSameComponents() throws Exception {
        ApproovDefaultMessageSigning.SignatureParametersFactory factory =
                ApproovDefaultMessageSigning.generateDefaultSignatureParametersFactory()
                        .setUseInstallAndAccountMessageSigning();
        assertEquals(Arrays.asList("ecdsa-p256-sha256", "hmac-sha256"), factory.getAlgs());
        HttpsURLConnection signed = sign(factory);
        String signature = signed.getRequestProperty("Signature");
        assertTrue(signature, signature.startsWith("install=:") && signature.contains(", account=:"));
        String input = signed.getRequestProperty("Signature-Input");
        String installComponents = input.substring(input.indexOf("install=("), input.indexOf(")", input.indexOf("install=(")));
        String accountComponents = input.substring(input.indexOf("account=("), input.indexOf(")", input.indexOf("account=(")));
        assertEquals(installComponents.substring("install=(".length()), accountComponents.substring("account=(".length()));
    }

    @Test
    public void theSelectionsReplaceOneAnother() {
        ApproovDefaultMessageSigning.SignatureParametersFactory factory =
                new ApproovDefaultMessageSigning.SignatureParametersFactory()
                        .setUseInstallAndAccountMessageSigning();
        assertEquals(Arrays.asList("ecdsa-p256-sha256", "hmac-sha256"), factory.getAlgs());
        assertEquals(Collections.singletonList("hmac-sha256"), factory.setUseAccountMessageSigning().getAlgs());
        assertEquals(Collections.singletonList("ecdsa-p256-sha256"), factory.setUseInstallMessageSigning().getAlgs());
    }

    @Test
    public void aSubclassSettingTheAccountFlagDirectlyProducesBothSignatures() throws Exception {
        ApproovDefaultMessageSigning.SignatureParametersFactory factory =
                new ApproovDefaultMessageSigning.SignatureParametersFactory() {
                    {
                        useAccountMessageSigning = true;
                    }
                }.setBaseParameters(new SignatureParameters().addComponentIdentifier(ComponentProvider.DC_METHOD))
                        .setAddApproovTokenHeader(true);
        assertEquals(Arrays.asList("ecdsa-p256-sha256", "hmac-sha256"), factory.getAlgs());
        String signature = sign(factory).getRequestProperty("Signature");
        assertTrue(signature, signature.startsWith("install=:") && signature.contains(", account=:"));
    }

    @Test
    public void theFactoryParametersSetNoAlgorithm() throws Exception {
        HttpsURLConnection connection = ApproovTestSupport.tokenConnection("https://api.example.com/data");
        SignatureParameters params = ApproovDefaultMessageSigning.generateDefaultSignatureParametersFactory()
                .buildSignatureParameters(
                        new ApproovDefaultMessageSigning.HttpsURLConnectionComponentProvider(connection),
                        ApproovTestSupport.tokenChanges());
        assertNull(params.getAlg());
        assertNotNull(params.getCreated());
        assertEquals(Long.valueOf(params.getCreated() + 15), params.getExpires());
    }

    @Test
    public void aFactoryWithNoAlgorithmLeavesTheRequestUnsigned() throws Exception {
        // a subclass that selects nothing
        ApproovDefaultMessageSigning.SignatureParametersFactory none =
                new ApproovDefaultMessageSigning.SignatureParametersFactory() {
                    @Override
                    public List<String> getAlgs() {
                        throw new IllegalStateException("No message signing algorithm is enabled");
                    }
                }.setBaseParameters(new SignatureParameters().addComponentIdentifier(ComponentProvider.DC_METHOD));
        HttpsURLConnection signed = sign(none);
        assertNull(signed.getRequestProperty("Signature"));
        assertNotNull(signed.getRequestProperty("Approov-Token"));
        assertThrows(IllegalStateException.class, none::getAlgs);

        // and so does one whose flags are both cleared by a subclass
        ApproovDefaultMessageSigning.SignatureParametersFactory cleared =
                new ApproovDefaultMessageSigning.SignatureParametersFactory() {
                    {
                        useInstallMessageSigning = false;
                        useAccountMessageSigning = false;
                    }
                }.setBaseParameters(new SignatureParameters().addComponentIdentifier(ComponentProvider.DC_METHOD));
        assertThrows(IllegalStateException.class, cleared::getAlgs);
        assertNull(sign(cleared).getRequestProperty("Signature"));
    }
}
