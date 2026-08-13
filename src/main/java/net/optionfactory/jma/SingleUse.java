package net.optionfactory.jma;

/// Result of decoding a single-use token. Holds the decoded [ #value() ] and a
/// [ #recycle() ] action the caller may invoke *only* when the operation
/// performed with the value failed and the token should be decodable once more.
///
/// The token is blocked at decode time and each decode consumes one attempt
/// (so concurrent replays are rejected on the happy path). [ #recycle() ] puts
/// the token back into a decodable state so it can be decoded again, and throws
/// [TokenDepleted] when no attempts remain. On success the caller does nothing —
/// the token stays blocked and any further decode is rejected.
public record SingleUse<T>(T value, Recycler recycler) {

    @FunctionalInterface
    public interface Recycler {

        void recycle();
    }

    public void recycle() {
        recycler.recycle();
    }
}
