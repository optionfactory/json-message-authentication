package net.optionfactory.jma;

/// The token is malformed or has been tampered with: unparseable structure
/// (wrong part count, bad base64, non-numeric timestamp, wrong nonce length) or
/// an HMAC mismatch (a post-HMAC decryption failure is also reported as this).
public final class TokenMalformed extends MessageAuthenticationError {

    public TokenMalformed(String message) {
        super(message);
    }

    public static void enforce(boolean test, String message) {
        if (test) {
            return;
        }
        throw new TokenMalformed(message);
    }
}
