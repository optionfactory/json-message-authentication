package net.optionfactory.jma.singleuse;

public interface SingleUseStore {

    boolean checkAndStore(String messageId, long expiresAt);
}
