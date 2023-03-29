package org.example.HandShakeMsg;

import java.io.ByteArrayOutputStream;

public class HandShakeMsg {
    public final static int HEAD_SIZE = 4;
    protected final byte type;
    protected byte[] message;
    protected byte[] payload;

    public HandShakeMsg(byte type) {
        this.type = type;
    }

    public HandShakeMsg(byte[] inBytes) {
        int messageLength = inBytes.length;
        message = new byte[messageLength];
        System.arraycopy(inBytes, 0, message, 0, messageLength);
        type = message[0];
        payload = new byte[messageLength - HEAD_SIZE];
        System.arraycopy(message, HEAD_SIZE, payload, 0, payload.length);
    }

    public void setMessage(ByteArrayOutputStream messageStream) {
        payload = messageStream.toByteArray();
        int length = payload.length;
        message = new byte[length + HEAD_SIZE];
        message[0] = this.type;
        message[1] = (byte)(0xFF & (length >> 16));
        message[2] = (byte)(0xFF & (length >> 8));
        message[3] = (byte)(0xFF & length);
        System.arraycopy(payload, 0, message, HEAD_SIZE, length);
    }

    public byte[] getBytes() {
        return message;
    }
}
