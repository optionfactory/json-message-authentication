package net.optionfactory.jma.stores;

public interface ConsumedTokenStore {

    boolean consume(String messageId, long expiresAt);

    boolean recycle(String messageId, int attempts);
}
