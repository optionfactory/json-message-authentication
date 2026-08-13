package net.optionfactory.jma;

/// The token is past its validity window.
public final class TokenExpired extends MessageAuthenticationError {

    public TokenExpired(String message) {
        super(message);
    }

    public static void enforce(boolean test, String message) {
        if (test) {
            return;
        }
        throw new TokenExpired(message);
    }
}
