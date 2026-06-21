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
        Approov.initialize(context, config, "auto", null);
        try {
            Approov.initialize(context, config, "auto", null);
            System.out.println("NATIVE_SDK: Same config allowed");
        } catch (Exception e) {
            System.out.println("NATIVE_SDK: Same config threw " + e.getClass().getName() + ": " + e.getMessage());
        }
        try {
            Approov.initialize(context, config2, "auto", null);
            System.out.println("NATIVE_SDK: Diff config allowed");
        } catch (Exception e) {
            System.out.println("NATIVE_SDK: Diff config threw " + e.getClass().getName() + ": " + e.getMessage());
        }
    }
}
