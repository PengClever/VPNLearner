package org.example;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;
import java.util.Arrays;

public class RecordMsg {
    public final static int HEAD_SIZE = 5;
    private final byte contentType;
    private final byte[] version;
    private int length;
    private byte[] payload;
    private byte[] message;
    private byte[] mac;

    public RecordMsg(byte contentType, byte[] version, byte[] payload) {
        this.contentType = contentType;
        this.version = version;
        this.payload = payload;
        length = this.payload.length;
        getBytes();
    }

    public byte[] getBytes() {
        message = new byte[length + HEAD_SIZE];
        message[0] = this.contentType;
        message[1] = this.version[0];
        message[2] = this.version[1];
        message[3] = (byte)(0xFF & (length >> 8));
        message[4] = (byte)(0xFF & length);
        System.arraycopy(this.payload, 0, message, HEAD_SIZE, length);
        return this.message;
    }

    public byte getContentType() {
        return this.contentType;
    }

    public byte[] getPayload() {
        return this.payload;
    }

    public void addMac(Mac writeMac, int hashSize, long sequenceNumber) throws Exception {
        byte[] tmp = payload;
        payload = new byte[tmp.length + hashSize];
        System.arraycopy(tmp, 0, payload, 0, tmp.length);

        ByteArrayOutputStream macInput = new ByteArrayOutputStream();
        macInput.write(Utils.getBytes64(sequenceNumber));
        macInput.write(message);

        writeMac.reset();
        writeMac.update(macInput.toByteArray());
        writeMac.doFinal(payload, payload.length - hashSize);

        length = payload.length;
        getBytes();
    }

    public boolean checkMac(Mac readMac, long sequenceNumber) {
        readMac.reset();
        readMac.update((byte)(0xFF & (sequenceNumber >>> 56)));
        readMac.update((byte)(0xFF & (sequenceNumber >>> 48)));
        readMac.update((byte)(0xFF & (sequenceNumber >>> 40)));
        readMac.update((byte)(0xFF & (sequenceNumber >>> 32)));
        readMac.update((byte)(0xFF & (sequenceNumber >>> 24)));
        readMac.update((byte)(0xFF & (sequenceNumber >>> 16)));
        readMac.update((byte)(0xFF & (sequenceNumber >>> 8)));
        readMac.update((byte)(0xFF & sequenceNumber));
        readMac.update(contentType);
        readMac.update(version[0]);
        readMac.update(version[1]);
        readMac.update((byte)(0xFF & (length >> 8)));
        readMac.update((byte)(0xFF & length));
        readMac.update(payload);
        byte[] mac = readMac.doFinal();

        for(int i = 0; i < mac.length; i++) {
            if(mac[i] != this.mac[i])
                return false;
        }
        return true;
    }

    public void encrypt(Cipher cipher, SecureRandom random) {
        int newLength = (int)(Math.ceil((double) (payload.length)/ cipher.getBlockSize()) + 2) * cipher.getBlockSize();

        byte[] iv = new byte[cipher.getBlockSize()];
        random.nextBytes(iv);

        byte[] tmp = new byte[newLength];
        System.arraycopy(iv, 0, tmp, 0, iv.length);
        System.arraycopy(payload, 0, tmp, iv.length, payload.length);

        int pad_len = newLength - iv.length - payload.length;
        for(int i = iv.length + payload.length; i < tmp.length; i++)
            tmp[i] = (byte)(pad_len-1);

        payload = cipher.update(tmp);
        length = payload.length;
        getBytes();
    }

    public void decrypt(Cipher cipher, int macSize) throws Exception {
        byte[] tmp = cipher.update(payload, 0, payload.length);

        if(tmp.length < macSize)
            throw new Exception("Error decrypting");

        int padLength = tmp[tmp.length - 1] & 0xFF;
        byte padding = tmp[tmp.length - 1];

        if(padLength >= tmp.length)
            throw new Exception("Error decrypting: padding too long");

        for(int i = tmp.length - padLength - 1; i < tmp.length; i++)
            if(tmp[i] != padding) {
                throw new Exception("Error decrypting: invalid padding");
            }

        if(tmp.length < (cipher.getBlockSize() + macSize + padLength))
            throw new Exception("Error decrypting: data too short");

        payload = Arrays.copyOfRange(tmp, cipher.getBlockSize(), tmp.length - macSize - padLength - 1);
        mac = Arrays.copyOfRange(tmp, tmp.length - macSize - padLength - 1, tmp.length - padLength - 1);
        length = payload.length;
        getBytes();
    }
}
