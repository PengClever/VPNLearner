package org.example;

import java.security.SecureRandom;
import java.util.Arrays;

public class OpenVPN {
    public final static byte OPCODE_P_CONTROL_HARD_RESET_CLIENT_V1 = 0b00001;
    public final static byte OPCODE_P_CONTROL_HARD_RESET_SERVER_V1 = 0b00010;
    public final static byte OPCODE_P_CONTROL_SOFT_RESET_V1 = 0b00011;
    public final static byte OPCODE_P_CONTROL_V1 = 0b00100;
    public final static byte OPCODE_P_ACK_V1 = 0b00101;
    public final static byte OPCODE_P_DATA_V1 = 0b00110;
    public final static byte OPCODE_P_CONTROL_HARD_RESET_CLIENT_V2 = 0b00111;
    public final static byte OPCODE_P_CONTROL_HARD_RESET_SERVER_V2 = 0b01000;
    public final static byte OPCODE_P_DATA_V2 = 0b01001;

    public final static int CIPHER_KEY_LENGTH = 32;
    public final static int HMAC_KEY_LENGTH = 20;

    public final static String CONFIG_REQUEST = "PUSH_REQUEST";

    private byte[] clientSessionID;
    private byte[] serverSessionID;
    private byte[] clientPacketID;
    private byte[] serverPacketID;
    private byte[] preMasterSecret;
    private byte[] masterSecret;
    byte[] keyExpansion;
    private byte[] clientRandom1;
    private byte[] clientRandom2;
    private byte[] serverRandom1;
    private byte[] serverRandom2;
    private final String clientOptions;
    byte[] clientCipherKey;
    byte[] serverCipherKey;
    byte[] clientHMACKey;
    byte[] serverHMACKey;
    private boolean sendConfigMsg;
    StringBuilder serverReplys;
    StringBuilder serverOptions;

    public OpenVPN(String options) {
        clientOptions = options;
    }

    public void init(SecureRandom secureRandom) {
        clientSessionID = new byte[8];
        secureRandom.nextBytes(clientSessionID);
        serverSessionID = new byte[8];
        clientPacketID = new byte[4];
        serverPacketID = new byte[4];
        preMasterSecret = new byte[48];
        secureRandom.nextBytes(preMasterSecret);
        clientRandom1 = new byte[32];
        secureRandom.nextBytes(clientRandom1);
        clientRandom2 = new byte[32];
        secureRandom.nextBytes(clientRandom2);
        sendConfigMsg = false;
    }

    public void increase() {
        boolean con = true;
        for (int i = 3; con & i >= 0; i--) {
            if (clientPacketID[i] != (byte)0xff) {
                clientPacketID[i]++;
                con = false;
            } else {
                clientPacketID[i] = 0;
            }
        }
    }

    public void setServerSessionID(byte[] serverSessionID) {
        this.serverSessionID = serverSessionID;
    }

    public void setServerPacketID(byte[] serverPacketID) {
        this.serverPacketID = serverPacketID;
    }

    public void setSendConfigMsg(boolean sendConfigMsg) {
        this.sendConfigMsg = sendConfigMsg;
    }

    public byte[] getClientSessionID(){
        return this.clientSessionID;
    }

    public byte[] getServerSessionID(){
        return this.serverSessionID;
    }

    public byte[] getClientPacketID(){
        return this.clientPacketID;
    }

    public byte[] getServerPacketID(){
        return this.serverPacketID;
    }

    public String getClientOptions() {
        return clientOptions;
    }

    public boolean isSendConfigMsg() {
        return sendConfigMsg;
    }

    public byte[] getConfigRequest() {
        return Utils.concat(CONFIG_REQUEST.getBytes(), new byte[]{0x00});
    }

    public void getConfigReply(byte[] recordMsg) {
        byte[] replys = new byte[recordMsg.length - 5];
        System.arraycopy(recordMsg, 5, replys, 0, replys.length);

        serverReplys = new StringBuilder();
        for (byte reply : replys) {
            int v = reply & 0xFF;
            if (v != 0)
                serverReplys.append((char) v);
        }
    }

    public byte[] getClientKeyNegotiateData(String options) {
        return Utils.concat(
                Utils.concat(
                        Utils.concat(new byte[]{0x00, 0x00, 0x00, 0x00, 0x02}, preMasterSecret),
                        Utils.concat(clientRandom1, clientRandom2)
                ),
                Utils.concat(
                        Utils.getBytes16(options.length() + 1),
                        Utils.concat(options.getBytes(), new byte[]{0x00})
                )
        );
    }

    public void getServerKeyNegotiateData(byte[] recordMsg) throws Exception {
        serverRandom1 = new byte[32];
        System.arraycopy(recordMsg, 10, serverRandom1, 0, serverRandom1.length);
        serverRandom2 = new byte[32];
        System.arraycopy(recordMsg, 42, serverRandom2, 0, serverRandom2.length);
        byte[] options = new byte[recordMsg.length - 76];
        System.arraycopy(recordMsg, 76, options, 0, options.length);

        serverOptions = new StringBuilder();
        for (byte option : options) {
            int v = option & 0xFF;
            if (v != 0)
                serverOptions.append((char) v);
        }
        getMasterSecret();
        getKeyExpansion();
    }

    public static byte[] P_MD5(byte[] secret, byte[] seed) throws Exception {
        byte[] output = {};
        byte[] A = seed;

        for(int i = 0; i < 20; i++) {
            A = Crypto.HMAC_MD5(secret, A);
            output = Utils.concat(output, Crypto.HMAC_MD5(secret, Utils.concat(A, seed)));
        }

        return output;
    }

    public static byte[] P_SHA1(byte[] secret, byte[] seed) throws Exception {
        byte[] output = {};
        byte[] A = seed;

        for(int i = 0; i < 16; i++) {
            A = Crypto.HMAC_SHA1(secret, A);
            output = Utils.concat(output, Crypto.HMAC_SHA1(secret, Utils.concat(A, seed)));
        }

        return output;
    }

    public static byte[] PRF(byte[] secret, String label, byte[] seed) throws Exception {
        int L_S1 = (int) Math.ceil((double)secret.length / 2);
        byte[] S1 = Arrays.copyOfRange(secret, 0, L_S1);
        byte[] S2 = Arrays.copyOfRange(secret, secret.length - L_S1, secret.length);

        return Utils.xor(P_MD5(S1, Utils.concat(label.getBytes(), seed)), P_SHA1(S2, Utils.concat(label.getBytes(), seed)));
    }

    public void getMasterSecret() throws Exception {
        masterSecret = new byte[48];
        masterSecret = Arrays.copyOf(PRF(preMasterSecret, "OpenVPN master secret", Utils.concat(clientRandom1, serverRandom1)), 48);
    }

    public void getKeyExpansion() throws Exception {
        keyExpansion = new byte[256];
        keyExpansion = Arrays.copyOf(PRF(masterSecret, "OpenVPN key expansion",
                Utils.concat(
                        Utils.concat(clientRandom2, serverRandom2),
                        Utils.concat(clientSessionID, serverSessionID)
                )
        ), 256);

        int offset = 0;
        clientCipherKey = Arrays.copyOfRange(keyExpansion, offset, offset + CIPHER_KEY_LENGTH);
        offset += 64;
        clientHMACKey = Arrays.copyOfRange(keyExpansion, offset, offset + HMAC_KEY_LENGTH);
        offset += 64;
        serverCipherKey = Arrays.copyOfRange(keyExpansion, offset, offset + CIPHER_KEY_LENGTH);
        offset += 64;
        serverHMACKey = Arrays.copyOfRange(keyExpansion, offset, offset + HMAC_KEY_LENGTH);
    }
}