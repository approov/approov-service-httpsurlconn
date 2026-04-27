package io.approov.util.http.sfv;

import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 */
public class DisplayStringItem implements Item<String> {

    private final String value;
    private final Parameters params;

    private DisplayStringItem(String value, Parameters params) {
        this.value = Objects.requireNonNull(value, "value must not be null");
        this.params = Objects.requireNonNull(params, "params must not be null");
    }

    /**
     * Creates a {@link StringItem} instance representing the specified
     * {@code String} value.
     * 
     * @param value
     *            a {@code String} value.
     * @return a {@link StringItem} representing {@code value}.
     */
    public static DisplayStringItem valueOf(String value) {
        return new DisplayStringItem(value, Parameters.EMPTY);
    }

    @Override
    public DisplayStringItem withParams(Parameters params) {
        if (Objects.requireNonNull(params, "params must not be null").isEmpty()) {
            return this;
        } else {
            return new DisplayStringItem(this.value, params);
        }
    }

    @Override
    public Parameters getParams() {
        return params;
    }

    @Override
    public StringBuilder serializeTo(StringBuilder sb) {
        sb.append("%\"");
        byte[] octets = value.getBytes(StandardCharsets.UTF_8);
        for (byte b : octets) {
            int unsigned = b & 0xff;
            if (unsigned == 0x25 || unsigned == 0x22 || unsigned <= 0x1f || unsigned >= 0x7f) {
                sb.append('%');
                sb.append(Character.forDigit((unsigned >> 4) & 0xf, 16));
                sb.append(Character.forDigit(unsigned & 0xf, 16));
            } else {
                sb.append((char) unsigned);
            }
        }
        sb.append('"');
        params.serializeTo(sb);
        return sb;
    }

    @Override
    public String serialize() {
        return serializeTo(new StringBuilder(2 + value.length())).toString();
    }

    @Override
    public String get() {
        return this.value;
    }
}
