package org.example;

import javax.crypto.Cipher;
import javax.crypto.Mac;

public class EncryptParameter {
    private boolean CCSOut;
    private boolean CCSIn;
    private Mac writeMAC;
    private Mac readMAC;
    private Cipher writeCipher;
    private Cipher readCipher;
    private long writeMACSeqNr;
    private long readMACSeqNr;

    public void init() {
        CCSOut = false;
        CCSIn = false;
        writeMACSeqNr = 0;
        readMACSeqNr = 0;
    }

    public boolean isCCSOut() {
        return CCSOut;
    }

    public void setCCSOut(boolean CCSOut) {
        this.CCSOut = CCSOut;
    }

    public boolean isCCSIn() {
        return CCSIn;
    }

    public void setCCSIn(boolean CCSIn) {
        this.CCSIn = CCSIn;
    }

    public Mac getWriteMAC() {
        return writeMAC;
    }

    public void setWriteMAC(Mac writeMAC) {
        this.writeMAC = writeMAC;
    }

    public Mac getReadMAC() {
        return readMAC;
    }

    public void setReadMAC(Mac readMAC) {
        this.readMAC = readMAC;
    }

    public Cipher getWriteCipher() {
        return writeCipher;
    }

    public void setWriteCipher(Cipher writeCipher) {
        this.writeCipher = writeCipher;
    }

    public Cipher getReadCipher() {
        return readCipher;
    }

    public void setReadCipher(Cipher readCipher) {
        this.readCipher = readCipher;
    }

    public long getWriteMACSeqNr() {
        return writeMACSeqNr;
    }

    public void increaseWriteMACSeqNr() {
        this.writeMACSeqNr++;
    }

    public long getReadMACSeqNr() {
        return readMACSeqNr;
    }

    public void increaseReadMACSeqNr() {
        this.readMACSeqNr++;
    }
}
