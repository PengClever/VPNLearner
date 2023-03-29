package org.example.HandShakeMsg;

public class ServerHello extends HandShakeMsg{
    private final byte[] random = new byte[32];
    private final byte[] cipherSuite = new byte[2];

    public ServerHello(byte[] inBytes) {
        super(inBytes);
        System.arraycopy(message, 6, random, 0, random.length);
        System.arraycopy(message, 39, cipherSuite, 0, cipherSuite.length);
    }

    public byte[] getRandom() {
        return this.random;
    }

    public byte[] getCipherSuite() {
        return this.cipherSuite;
    }
}
