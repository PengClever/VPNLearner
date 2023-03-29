package org.example;

import java.util.Arrays;

public class Utils {
    private static final String CHARS = "0123456789ABCDEF";
    public static byte[] getBytes8(int val) {
        byte[] out = new byte[1];
        out[0] = (byte)(0xFF & val);
        return out;
    }
    public static byte[] getBytes16(int val) {
        byte[] out = new byte[2];
        out[0] = (byte)(0xFF & (val >>> 8));
        out[1] = (byte)(0xFF & val);
        return out;
    }
    public static byte[] getBytes24(int val) {
        byte[] out = new byte[3];
        out[0] = (byte)(0xFF & (val >>> 16));
        out[1] = (byte)(0xFF & (val >>> 8));
        out[2] = (byte)(0xFF & val);
        return out;
    }
    public static byte[] getBytes32(int val) {
        byte[] out = new byte[4];
        out[0] = (byte)(0xFF & (val >>> 24));
        out[1] = (byte)(0xFF & (val >>> 16));
        out[2] = (byte)(0xFF & (val >>> 8));
        out[3] = (byte)(0xFF & val);
        return out;
    }
    public static byte[] getBytes64(long val) {
        byte[] out = new byte[8];
        out[0] = (byte)(0xFF & (val >>> 56));
        out[1] = (byte)(0xFF & (val >>> 48));
        out[2] = (byte)(0xFF & (val >>> 40));
        out[3] = (byte)(0xFF & (val >>> 32));
        out[4] = (byte)(0xFF & (val >>> 24));
        out[5] = (byte)(0xFF & (val >>> 16));
        out[6] = (byte)(0xFF & (val >>> 8));
        out[7] = (byte)(0xFF & val);
        return out;
    }
    public static byte[] concat(byte[] first, byte[] second) {
        if (first == null) return second;
        if(second == null) return first;

        byte[] result = Arrays.copyOf(first, first.length + second.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
    }
    public static String bytesToHex(byte[] bytes) {
        StringBuilder hex = new StringBuilder();

        for (byte aByte : bytes) {
            int n1 = (aByte >> 4) & 0x0F;
            hex.append(CHARS.charAt(n1));
            int n2 = aByte & 0x0F;
            hex.append(CHARS.charAt(n2));
        }

        return hex.toString();
    }
    public static int getLength(byte[] bytes, int length) {
        int temp = 1, result = 0;
        for (int i = length - 1; i >= 0; i--) {
            if (bytes[i] < 0) {
                result += (256 + bytes[i]) * temp;
            } else {
                result += bytes[i] * temp;
            }
            temp *= 256;
        }
        return result;
    }
    public static byte[] xor(byte[] first, byte[] second) throws Exception {
        if(first.length != second.length) throw new Exception("Arguments have different lengths");

        byte[] output = new byte[first.length];

        for(int i = 0; i < first.length; i++) {
            output[i] = (byte)(first[i] ^ second[i]);
        }

        return output;
    }
}
