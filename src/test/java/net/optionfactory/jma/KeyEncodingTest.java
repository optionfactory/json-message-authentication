package net.optionfactory.jma;

import java.util.Arrays;
import java.util.Base64;
import net.optionfactory.jma.MessageAuthenticationOps.KeyEncoding;
import org.junit.Assert;
import org.junit.Test;

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
        Assert.assertArrayEquals(expected, got);
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
        Assert.assertArrayEquals(expected, got);
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
        Assert.assertArrayEquals(expected, got);
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
        Assert.assertArrayEquals(expected, got);

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
        Assert.assertArrayEquals(expected, got);
    }

    @Test(expected = IllegalArgumentException.class)
    public void tryingToDecodeOddLengthHexEncodedYieldException() {
        final byte[] got = KeyEncoding.HEX.decode("abc");
    }
}
