package org.example.OpenVPNMsg;

import java.io.ByteArrayOutputStream;

public class OpenVPNMsg {
    public final static int TYPE_SIZE = 1;
    public final static int PACKET_LENGTH_SIZE = 2;
    public final static int SESSION_ID_SIZE = 8;
    public final static int PACKET_ID_SIZE = 4;

    protected int length;
    protected byte opcode, keyID;
    protected byte[] sessionID;
    protected byte packetIDArrayLength;
    protected byte[] message;
    protected byte[] messageBody;

    public OpenVPNMsg(byte opcode, byte keyID, byte[] sessionID, byte packetIDArrayLength) {
        this.opcode = opcode;
        this.keyID = keyID;
        this.sessionID = sessionID;
        this.packetIDArrayLength = packetIDArrayLength;
    }

    public OpenVPNMsg(byte[] inBytes) {
        length = inBytes.length;
        messageBody = new byte[this.length];
        System.arraycopy(inBytes, 0, messageBody, 0, length);
        opcode = (byte)(inBytes[0] >> 3);
        keyID = (byte)((inBytes[0] >> 3) & 0x7);
        sessionID = new byte[SESSION_ID_SIZE];
        System.arraycopy(messageBody, 1, sessionID, 0, SESSION_ID_SIZE);
    }

    public void setMessage(ByteArrayOutputStream messageStream) {
        messageBody = messageStream.toByteArray();
        length = messageBody.length;
        message = new byte[length + PACKET_LENGTH_SIZE];
        message[0] = (byte)(0xFF & (length >> 8));
        message[1] = (byte)(0xFF & length);
        System.arraycopy(messageBody, 0, message, PACKET_LENGTH_SIZE, length);
    }

    public byte[] getBytes() {
        return message;
    }

    public byte getOpcode() {
        return opcode;
    }

    public byte[] getSessionID() {
        return sessionID;
    }

}
