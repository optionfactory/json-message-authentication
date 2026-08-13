package net.optionfactory.jma;

import tools.jackson.core.Version;
import tools.jackson.databind.JacksonModule;

public class MessageAuthenticationModule extends JacksonModule {

    private final Version version;
    private final MessageAuthenticationOps ops;

    public MessageAuthenticationModule(MessageAuthenticationOps ops) {
        this.version = new Version(3, 0, 0, null, "net.optionfactory", "json-authenticated");
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
        ctx.addSerializerModifier(new MessageAuthenticationSerializerModifier(ops));
        ctx.addDeserializerModifier(new MessageAuthenticationDeserializerModifier(ops));
    }
}
