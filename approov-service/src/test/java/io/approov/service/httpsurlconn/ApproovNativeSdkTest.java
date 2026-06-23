package io.approov.service.httpsurlconn;

import android.content.Context;
import androidx.test.core.app.ApplicationProvider;
import com.criticalblue.approovsdk.Approov;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

@RunWith(RobolectricTestRunner.class)
@Config(manifest = Config.NONE)
public class ApproovNativeSdkTest {
    private final String config = "#cb-ivol#mAxOF0ekJUOC36J5XWmVmVipOcUoEdMjhPSp2FVtyTo=";
    private final String config2 = "#cb-other#mAxOF0ekJUOC36J5XWmVmVipOcUoEdMjhPSp2FVtyTo=";

    @Test
    public void testApproovInit() {
        Context context = ApplicationProvider.getApplicationContext();

        // First init should succeed.
        Approov.initialize(context, config, "auto", null);

        // Same config should be allowed.
        Approov.initialize(context, config, "auto", null);

        // Different config should be rejected.
        try {
            Approov.initialize(context, config2, "auto", null);
            org.junit.Assert.fail("Expected IllegalStateException when initializing with a different config");
        } catch (IllegalStateException expected) {
            // expected
        }
    }
}
