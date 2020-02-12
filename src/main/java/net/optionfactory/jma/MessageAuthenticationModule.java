package net.optionfactory.jma;

import com.fasterxml.jackson.core.Version;
import com.fasterxml.jackson.databind.Module;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.function.Supplier;
import javax.crypto.spec.SecretKeySpec;

public class MessageAuthenticationModule extends Module {

    private final Version version;
    private final MessageAuthenticationOps ops;

    public MessageAuthenticationModule(byte[] aesKey, byte[] hmacKey, Supplier<Long> clock) {
        if (aesKey.length != 32) {
            throw new MessageAuthenticationError("aesKey must be 32B long");
        }
        if (hmacKey.length != 64) {
            throw new MessageAuthenticationError("hmacKey is not 64B long");
        }
        this.version = new Version(1, 0, 0, null, "net.optionfactory", "json-authenticated");
        this.ops = new MessageAuthenticationOps(
                new SecretKeySpec(aesKey, "AES"),
                new SecretKeySpec(hmacKey, "HmacSHA256"),
                new SecureRandom(),
                clock
        );
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
        ctx.appendAnnotationIntrospector(new MessageAuthenticationAnnotationIntrospector(version, ops));
    }

}
