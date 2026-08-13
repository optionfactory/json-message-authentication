package net.optionfactory.jma;

/// Consumption was rejected: the token is already blocked (it has been decoded
/// and not recycled — e.g. a replayed or duplicate request).
public final class TokenAlreadyUsed extends MessageAuthenticationError {

    public TokenAlreadyUsed(String message) {
        super(message);
    }

    public static void enforce(boolean test, String message) {
        if (test) {
            return;
        }
        throw new TokenAlreadyUsed(message);
    }
}
