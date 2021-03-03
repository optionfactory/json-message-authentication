package net.optionfactory.jma;

import com.fasterxml.jackson.core.Version;
import com.fasterxml.jackson.databind.Module;

public class MessageAuthenticationModule extends Module {

    private final Version version;
    private final MessageAuthenticationOps ops;

    public MessageAuthenticationModule(MessageAuthenticationOps ops) {
        this.version = new Version(1, 0, 0, null, "net.optionfactory", "json-authenticated");
        this.ops = ops;
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
