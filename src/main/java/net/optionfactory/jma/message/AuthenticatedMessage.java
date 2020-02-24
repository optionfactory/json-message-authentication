package net.optionfactory.jma.message;

import net.optionfactory.jma.MessageAuthentication;

public class AuthenticatedMessage<T> {

    @MessageAuthentication(mode = MessageAuthentication.Mode.AUTHENTICATED)
    public T value;

    public static <T> AuthenticatedMessage<T> of(T value) {
        final AuthenticatedMessage<T> message = new AuthenticatedMessage<>();
        message.value = value;
        return message;
    }
}
