package net.optionfactory.jma;

public class MessageAuthenticationError extends IllegalArgumentException {

    public MessageAuthenticationError(String message) {
        super(message);
    }

    public static void enforce(boolean test, String message) {
        if (test) {
            return;
        }
        throw new MessageAuthenticationError(message);
    }

}
