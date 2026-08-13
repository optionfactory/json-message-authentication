package net.optionfactory.jma;

import tools.jackson.databind.BeanDescription;
import tools.jackson.databind.DeserializationConfig;
import tools.jackson.databind.ValueDeserializer;
import tools.jackson.databind.deser.ValueDeserializerModifier;

public class MessageAuthenticationDeserializerModifier extends ValueDeserializerModifier {

    private final MessageAuthenticationOps ops;

    public MessageAuthenticationDeserializerModifier(MessageAuthenticationOps ops) {
        this.ops = ops;
    }

    @Override
    public ValueDeserializer<?> modifyDeserializer(DeserializationConfig config, BeanDescription.Supplier beanDesc, ValueDeserializer<?> deserializer) {
        final var annotation = beanDesc.getClassInfo().getAnnotation(MessageAuthentication.class);
        if (annotation == null) {
            return deserializer;
        }
        final var validity = annotation.unit().getDuration().multipliedBy(annotation.validity());
        final int attempts = annotation.attempts();
        if (annotation.mode() == MessageAuthentication.Mode.AUTHENTICATED) {
            return new MessageAuthenticationDeserializer(ops, validity, attempts, deserializer);
        }
        return new MessageAuthenticationEncryptedDeserializer(ops, validity, attempts, deserializer);
    }

}
