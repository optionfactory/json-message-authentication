package net.optionfactory.jma;

/// Recycling was rejected: the token's retry budget is exhausted (all attempts
/// consumed), so it cannot be un-blocked for another decode.
public final class TokenDepleted extends MessageAuthenticationError {

    public TokenDepleted(String message) {
        super(message);
    }

    public static void enforce(boolean test, String message) {
        if (test) {
            return;
        }
        throw new TokenDepleted(message);
    }
}
