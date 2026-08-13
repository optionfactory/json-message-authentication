package net.optionfactory.jma;

/// Thrown on any token failure: tampering, expiry, replay (already used),
/// malformed encoding, or invalid arguments.
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
