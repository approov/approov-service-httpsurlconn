package io.approov.util.httpsurlconn.http.sfv;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import java.math.BigDecimal;

public class DecimalItemTest {

    private static String serialized(long permille) {
        return DecimalItem.valueOf(permille).serialize();
    }

    @Test
    public void serializesFractionWithLeadingZeros() {
        assertEquals("1.05", serialized(1050));
        assertEquals("1.005", serialized(1005));
        assertEquals("0.003", serialized(3));
        assertEquals("0.03", serialized(30));
        assertEquals("1.01", serialized(1010));
    }

    @Test
    public void serializesStrippingTrailingZeros() {
        assertEquals("1.5", serialized(1500));
        assertEquals("1.55", serialized(1550));
        assertEquals("2.0", serialized(2000));
        assertEquals("0.0", serialized(0));
    }

    @Test
    public void serializesNegativeValues() {
        assertEquals("-0.05", serialized(-50));
        assertEquals("-1.005", serialized(-1005));
        assertEquals("-2.0", serialized(-2000));
    }

    @Test
    public void serializesExtremes() {
        assertEquals("999999999999.999", serialized(999999999999999L));
        assertEquals("-999999999999.999", serialized(-999999999999999L));
    }

    @Test
    public void roundTripsThroughParser() {
        long[] permilles = {1050, 1005, 3, 30, 1500, 0, -50, -1005, 999999999999999L};
        for (long permille : permilles) {
            String text = serialized(permille);
            DecimalItem reparsed = Parser.parseDecimal(text);
            assertEquals(text, permille, reparsed.getAsLong());
        }
    }

    @Test
    public void bigDecimalFactoryMatchesPermilleFactory() {
        assertEquals("1.05", DecimalItem.valueOf(new BigDecimal("1.05")).serialize());
        assertEquals("0.003", DecimalItem.valueOf(new BigDecimal("0.003")).serialize());
    }
}
