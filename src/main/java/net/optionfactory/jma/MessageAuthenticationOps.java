package net.optionfactory.jma;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class MessageAuthenticationOps {

    public static byte[] randomBytes(SecureRandom random, int len) {
        final byte[] iv = new byte[len];
        random.nextBytes(iv);
        return iv;
    }

    public static byte[] encrypt(byte[] iv, SecretKeySpec aesKey, long createdAt, String clearText) {
        try {
            final javax.crypto.Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(16 * 8, iv));
            cipher.updateAAD(ByteBuffer.allocate(8).putLong(createdAt).array());
            return cipher.doFinal(clearText.getBytes(StandardCharsets.UTF_8));
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException ex) {
            throw new MessageAuthenticationError(ex.getMessage());
        }
    }

    public static String decrypt(byte[] iv, SecretKeySpec aesKey, long createdAt, byte[] cipherText) {
        try {
            final javax.crypto.Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(16 * 8, iv));
            cipher.updateAAD(ByteBuffer.allocate(8).putLong(createdAt).array());
            return new String(cipher.doFinal(cipherText), StandardCharsets.UTF_8);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException ex) {
            throw new MessageAuthenticationError(ex.getMessage());
        }
    }

    public static byte[] hmac(byte[] salt, SecretKeySpec hmacKey, long createdAt, byte[] clearText) {
        try {
            final var sha256 = Mac.getInstance("HmacSHA256");
            sha256.init(hmacKey);
            sha256.update(ByteBuffer.allocate(8).putLong(createdAt).array());
            sha256.update(salt);
            return sha256.doFinal(clearText);
        } catch (NoSuchAlgorithmException | InvalidKeyException ex) {
            throw new MessageAuthenticationError(ex.getMessage());
        }
    }

    public static boolean verify(byte[] salt, SecretKeySpec hmacKey, long createdAt, byte[] hmac, byte[] clearText) {
        try {
            final var sha256 = Mac.getInstance("HmacSHA256");
            sha256.init(hmacKey);
            sha256.update(ByteBuffer.allocate(8).putLong(createdAt).array());
            sha256.update(salt);
            final var computed = sha256.doFinal(clearText);
            return Arrays.equals(computed, hmac);
        } catch (NoSuchAlgorithmException | InvalidKeyException ex) {
            throw new MessageAuthenticationError(ex.getMessage());
        }
    }

}
