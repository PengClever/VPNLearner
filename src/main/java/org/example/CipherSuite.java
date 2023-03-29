package org.example;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchAlgorithmException;

public class CipherSuite {
    public final static byte[] TLS_DHE_RSA_WITH_AES_128_CBC_SHA = new byte[]{0x00, 0x33};
    public final static byte[] TLS_EMPTY_RENEGOTIATION_INFO_SCSV = new byte[]{0x00, (byte) 0xFF};
    public final static int MAC_KEY_SIZE = 20;
    public final static int ENCRYPT_KEY_SIZE = 16;
    public final static int FIXED_IV_SIZE = 16;
    public final static String MAC_CIPHER_ALGORITHM = "HmacSHA1";
    public final static String ENCRYPT_CIPHER_ALGORITHM = "AES/CBC/NoPadding";
    public final static String ENCRYPT_CIPHER_KEY_ALGORITHM = "AES";

    public static Mac getMAC() throws NoSuchAlgorithmException {
        return Mac.getInstance(MAC_CIPHER_ALGORITHM);
    }

    public static Cipher getEncCipher() throws NoSuchAlgorithmException, NoSuchPaddingException {
        return Cipher.getInstance(ENCRYPT_CIPHER_ALGORITHM);
    }
}
