package net.optionfactory.jma;

/// Base type for token-verification failures produced by this library. Catch
/// this type to handle any token failure; catch a subtype to handle a specific
/// category:
///
/// - [TokenExpired] — past the validity window
/// - [TokenMalformed] — HMAC mismatch or unparseable structure
/// - [TokenAlreadyUsed] — consumption rejected (the token is already blocked)
/// - [TokenDepleted] — recycle rejected (the retry budget is exhausted)
///
/// Programming errors (invalid arguments) are raised as `IllegalArgumentException`
/// and environment/internal failures as `IllegalStateException`; neither is a
/// token condition, so they are deliberately outside this hierarchy.
public abstract sealed class MessageAuthenticationError extends RuntimeException
        permits TokenExpired, TokenMalformed, TokenAlreadyUsed, TokenDepleted {

    protected MessageAuthenticationError(String message) {
        super(message);
    }
}
