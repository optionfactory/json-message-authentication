package net.optionfactory.jma;

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.function.Supplier;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class MessageAuthenticationOps {

    private final Base64.Encoder b64enc = Base64.getUrlEncoder().withoutPadding();
    private final Base64.Decoder b64dec = Base64.getUrlDecoder();
    private final SecretKeySpec aesKey;
    private final SecretKeySpec hmacKey;
    private final SecureRandom random;
    private final Supplier<Long> clock;
    private final int ivLength = 16;
    private final int saltLength = 12;

    public MessageAuthenticationOps(SecretKeySpec aesKey, SecretKeySpec hmacKey, SecureRandom random, Supplier<Long> clock) {
        this.aesKey = aesKey;
        this.hmacKey = hmacKey;
        this.random = random;
        this.clock = clock;
    }

    private byte[] randomBytes(int len) {
        final byte[] iv = new byte[len];
        random.nextBytes(iv);
        return iv;
    }

    private Mac initHmacSha256() {
        try {
            final var mac = Mac.getInstance("HmacSHA256");
            mac.init(hmacKey);
            return mac;
        } catch (NoSuchAlgorithmException | InvalidKeyException ex) {
            throw new MessageAuthenticationError(ex.getMessage());
        }
    }

    private Cipher initAesCbcPkcs7(byte[] iv, int mode) {
        try {
            final var cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(mode, aesKey, new IvParameterSpec(iv));
            return cipher;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException ex) {
            throw new MessageAuthenticationError(ex.getMessage());
        }
    }

    public String encryptThenAuthenticate(byte[] clearText) {
        final var iv = randomBytes(ivLength);
        final var createdAt = clock.get();

        try {
            final var cipherText = initAesCbcPkcs7(iv, Cipher.ENCRYPT_MODE).doFinal(clearText);

            final var mac = initHmacSha256();
            mac.update(ByteBuffer.allocate(8).putLong(createdAt).array());
            mac.update(iv);
            final var computedHmac = mac.doFinal(cipherText);

            return String.format("%s.%s.%s.%s",
                    b64enc.encodeToString(iv),
                    createdAt,
                    b64enc.encodeToString(cipherText),
                    b64enc.encodeToString(computedHmac)
            );
        } catch (IllegalBlockSizeException | BadPaddingException ex) {
            throw new MessageAuthenticationError(ex.getMessage());
        }
    }

    public byte[] authenticateThenDecrypt(String value, long validityMs) {
        final var split = value.split("\\.");
        MessageAuthenticationError.enforce(split.length == 4, "invalid parts");

        final var iv = b64dec.decode(split[0]);
        final var createdAt = Long.parseLong(split[1]);
        final var cipherText = b64dec.decode(split[2]);
        final var receivedHmac = b64dec.decode(split[3]);
        final var now = clock.get();

        MessageAuthenticationError.enforce(iv.length == ivLength, "invalid iv");
        MessageAuthenticationError.enforce(validityMs == 0 || createdAt + validityMs > now, "expired");

        final var mac = initHmacSha256();
        mac.update(ByteBuffer.allocate(8).putLong(createdAt).array());
        mac.update(iv);
        final var computedMessageHmac = mac.doFinal(cipherText);
        MessageAuthenticationError.enforce(Arrays.equals(computedMessageHmac, receivedHmac), "tampering");
        try {
            return initAesCbcPkcs7(iv, Cipher.DECRYPT_MODE).doFinal(cipherText);
        } catch (IllegalBlockSizeException | BadPaddingException ex) {
            throw new MessageAuthenticationError(ex.getMessage());
        }
    }

    public String authenticate(byte[] clearText) {

        final var createdAt = clock.get();
        final var salt = randomBytes(saltLength);
        final var mac = initHmacSha256();
        mac.update(ByteBuffer.allocate(8).putLong(createdAt).array());
        mac.update(salt);
        final var computedHmacValue = mac.doFinal(clearText);
        return String.format("%s.%s.%s.%s",
                b64enc.encodeToString(salt),
                createdAt,
                b64enc.encodeToString(computedHmacValue),
                b64enc.encodeToString(clearText)
        );
    }

    public byte[] verifyAndDecode(String authenticated, long validityMs) {

        final var split = authenticated.split("\\.");
        MessageAuthenticationError.enforce(split.length == 4, "invalid parts");

        final var salt = b64dec.decode(split[0]);
        final var createdAt = Long.parseLong(split[1]);
        final var hmacValue = b64dec.decode(split[2]);
        final var clearText = b64dec.decode(split[3]);
        final var now = clock.get();

        MessageAuthenticationError.enforce(salt.length == saltLength, "invalid salt");
        MessageAuthenticationError.enforce(validityMs == 0 || createdAt + validityMs > now, "expired");

        final var sha256 = initHmacSha256();
        sha256.update(ByteBuffer.allocate(8).putLong(createdAt).array());
        sha256.update(salt);
        final var computedHmacValue = sha256.doFinal(clearText);
        MessageAuthenticationError.enforce(Arrays.equals(computedHmacValue, hmacValue), "tampering");
        return clearText;
    }

}
