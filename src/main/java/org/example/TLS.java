package org.example;

import java.util.Arrays;

public class TLS {
    public final static byte CONTENT_TYPE_CHANGE_CIPHER_SPEC = 0x14;
    public final static byte CONTENT_TYPE_ALERT = 0x15;
    public final static byte CONTENT_TYPE_HANDSHAKE = 0x16;
    public final static byte CONTENT_TYPE_APPLICATION = 0x17;
    public final static byte CONTENT_TYPE_HEARTBEAT = 0x18;

    public final static byte HANDSHAKE_MSG_TYPE_HELLO_REQUEST = 0x00;
    public final static byte HANDSHAKE_MSG_TYPE_CLIENT_HELLO = 0x01;
    public final static byte HANDSHAKE_MSG_TYPE_SERVER_HELLO = 0x02;
    public final static byte HANDSHAKE_MSG_TYPE_CERTIFICATE = 0x0B;
    public final static byte HANDSHAKE_MSG_TYPE_SERVER_KEY_EXCHANGE = 0x0C;
    public final static byte HANDSHAKE_MSG_TYPE_CERTIFICATE_REQUEST = 0x0D;
    public final static byte HANDSHAKE_MSG_TYPE_SERVER_HELLO_DONE = 0x0E;
    public final static byte HANDSHAKE_MSG_TYPE_CERTIFICATE_VERIFY = 0x0F;
    public final static byte HANDSHAKE_MSG_TYPE_CLIENT_KEY_EXCHANGE = 0x10;
    public final static byte HANDSHAKE_MSG_TYPE_FINISHED = 0x14;

    public final static byte[] EXTENSION_TYPE_HEARTBEAT = {0x00, 0x0F};
    public final static byte[] EXTENSION_TYPE_RENEGOTIATION_INFO = {(byte)0xFF, 0x01};

    public static byte[] P_SHA256(byte[] secret, byte[] seed) throws Exception {
        byte[] output = {};
        byte[] A = seed;

        for(int i = 0; i < 4; i++) {
            A = Crypto.HMAC_SHA256(secret, A);
            output = Utils.concat(output, Crypto.HMAC_SHA256(secret, Utils.concat(A, seed)));
        }

        return output;
    }

    public static byte[] PRF(byte[] secret, String label, byte[] seed) throws Exception {
        return P_SHA256(secret, Utils.concat(label.getBytes(), seed));
    }

    public static byte[] masterSecret(byte[] preMasterSecret, byte[] serverRandom, byte[] clientRandom) throws Exception {
        return Arrays.copyOf(PRF(preMasterSecret, "master secret", Utils.concat(clientRandom, serverRandom)), 48);
    }

    public static byte[] keyBlock(byte[] masterSecret, byte[] serverRandom, byte[] clientRandom) throws Exception {
        return PRF(masterSecret, "key expansion", Utils.concat(serverRandom, clientRandom));
    }

    public static byte[] verifyDataClient(byte[] masterSecret, byte[] handshakeMessages) throws Exception {
        return Arrays.copyOf(PRF(masterSecret, "client finished", Crypto.SHA256(handshakeMessages)), 12);
    }
}
