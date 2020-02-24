package net.optionfactory.jma.message;

import net.optionfactory.jma.MessageAuthentication;

public class EncryptedMessage<T> {

    @MessageAuthentication(mode = MessageAuthentication.Mode.AUTHENTICATED_ENCRYPTED)
    public T value;

    public static <T> EncryptedMessage<T> of(T value) {
        final EncryptedMessage<T> message = new EncryptedMessage<>();
        message.value = value;
        return message;
    }
}
