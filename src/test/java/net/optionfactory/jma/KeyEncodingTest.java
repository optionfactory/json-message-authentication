package net.optionfactory.jma;

import net.optionfactory.jma.MessageAuthenticationOps.KeyEncoding;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class KeyEncodingTest {

    @Test
    public void canDecodeBase64() {
        final byte[] got = KeyEncoding.BASE_64.decode("AP/MAA==");
        final byte[] expected = new byte[]{
            0x00,
            (byte) 0xff,
            (byte) 0xcc,
            0x00
        };
        Assertions.assertArrayEquals(expected, got);
    }

    @Test
    public void canDecodeUnpaddedBase64() {
        final byte[] got = KeyEncoding.BASE_64.decode("AP/MAA");
        final byte[] expected = new byte[]{
            0x00,
            (byte) 0xff,
            (byte) 0xcc,
            0x00
        };
        Assertions.assertArrayEquals(expected, got);
    }

    @Test
    public void canDecodeUrlSafeBase64() {
        final byte[] got = KeyEncoding.URL_SAFE_BASE_64.decode("AP_MAA==");
        final byte[] expected = new byte[]{
            0x00,
            (byte) 0xff,
            (byte) 0xcc,
            0x00
        };
        Assertions.assertArrayEquals(expected, got);
    }

    @Test
    public void canDecodeUnpaddedUrlSafeBase64() {
        final byte[] got = KeyEncoding.URL_SAFE_BASE_64.decode("AP_MAA");
        final byte[] expected = new byte[]{
            0x00,
            (byte) 0xff,
            (byte) 0xcc,
            0x00
        };
        Assertions.assertArrayEquals(expected, got);

    }

    @Test
    public void canDecodeHexWithMixedCases() {
        final byte[] got = KeyEncoding.HEX.decode("00112233aaFF");
        final byte[] expected = new byte[]{
            0x00,
            0x11,
            0x22,
            0x33,
            (byte) 0xaa,
            (byte) 0xff
        };
        Assertions.assertArrayEquals(expected, got);
    }

    @Test
    public void tryingToDecodeOddLengthHexEncodedYieldException() {
        Assertions.assertThrows(IllegalArgumentException.class, () -> {
            KeyEncoding.HEX.decode("abc");
        });        
    }
}
