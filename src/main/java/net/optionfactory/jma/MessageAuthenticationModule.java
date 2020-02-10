package net.optionfactory.jma;

import com.fasterxml.jackson.core.Version;
import com.fasterxml.jackson.databind.Module;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.function.Supplier;
import javax.crypto.spec.SecretKeySpec;

public class MessageAuthenticationModule extends Module {

    private final Version version;
    private final SecretKeySpec aesKey;
    private final SecretKeySpec hmacKey;
    private final SecureRandom random;
    private final Base64.Encoder b64enc;
    private final Base64.Decoder b64dec;
    private final Supplier<Long> clock;

    public MessageAuthenticationModule(byte[] aesKey, byte[] hmacKey, Supplier<Long> clock) {
        if (aesKey.length != 32) {
            throw new MessageAuthenticationError("aesKey must be 32B long");
        }
        if (hmacKey.length != 64) {
            throw new MessageAuthenticationError("hmacKey is not 64B long");
        }
        this.version = new Version(1, 0, 0, null, "net.optionfactory", "json-authenticated");
        this.aesKey = new SecretKeySpec(aesKey, "AES");
        this.hmacKey = new SecretKeySpec(hmacKey, "HmacSHA256");
        this.random = new SecureRandom();
        this.b64dec = Base64.getUrlDecoder();
        this.b64enc = Base64.getUrlEncoder().withoutPadding();
        this.clock = clock;
    }

    @Override
    public String getModuleName() {
        return this.getClass().getSimpleName();
    }

    @Override
    public Version version() {
        return version;
    }

    @Override
    public void setupModule(SetupContext ctx) {
        ctx.appendAnnotationIntrospector(new MessageAuthenticationAnnotationIntrospector(version, aesKey, hmacKey, random, b64enc, b64dec, clock));
    }


}
