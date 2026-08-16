package net.optionfactory.jma;

import tools.jackson.databind.BeanDescription;
import tools.jackson.databind.SerializationConfig;
import tools.jackson.databind.ValueSerializer;
import tools.jackson.databind.ser.ValueSerializerModifier;

public class MessageAuthenticationSerializerModifier extends ValueSerializerModifier {

    private final MessageAuthenticationOps ops;

    public MessageAuthenticationSerializerModifier(MessageAuthenticationOps ops) {
        this.ops = ops;
    }

    @Override
    public ValueSerializer<?> modifySerializer(SerializationConfig config, BeanDescription.Supplier beanDesc, ValueSerializer<?> serializer) {
        final var annotation = MessageAuthenticationAnnotationIntrospector.find(beanDesc.getClassInfo());
        if (annotation == null) {
            return serializer;
        }
        final var validity = annotation.unit().getDuration().multipliedBy(annotation.validity());
        if (annotation.mode() == MessageAuthentication.Mode.AUTHENTICATED) {
            return new MessageAuthenticationSerializer(ops, validity, serializer);
        }
        return new MessageAuthenticationEncryptedSerializer(ops, validity, serializer);
    }

}
