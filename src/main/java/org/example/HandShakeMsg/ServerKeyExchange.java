package org.example.HandShakeMsg;

import org.example.*;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

public class ServerKeyExchange extends HandShakeMsg{
    SecurityParameter securityParameter = new SecurityParameter();
    public ServerKeyExchange(byte[] inBytes) throws IOException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, InvalidKeySpecException {
        super(inBytes);

        InputStream input = new ByteArrayInputStream(payload);
        byte[] lengthBytes = new byte[2];
        int length, returnLength;

        returnLength = input.read(lengthBytes, 0, 2);
        length = Utils.getLength(lengthBytes, 2);
        securityParameter.setDHParameterP(new byte[length]);
        returnLength = input.read(securityParameter.getDHParameterP(), 0, length);

        returnLength = input.read(lengthBytes, 0, 2);
        length = Utils.getLength(lengthBytes, 2);
        securityParameter.setDHParameterQ(new byte[length]);
        returnLength = input.read(securityParameter.getDHParameterQ(), 0, length);

        returnLength = input.read(lengthBytes, 0, 2);
        length = Utils.getLength(lengthBytes, 2);
        securityParameter.setDHParameterYs(new byte[length]);
        returnLength = input.read(securityParameter.getDHParameterYs(), 0, length);

        if(input.available() > 0) {
            securityParameter.setHashAlgorithm(input.read());
            securityParameter.setSignatureAlgorithm(input.read());
            returnLength = input.read(lengthBytes, 0, 2);
            length = Utils.getLength(lengthBytes, 2);
            securityParameter.setSignature(new byte[length]);
            returnLength = input.read(securityParameter.getSignature(), 0, length);
        }

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DiffieHellman");
        keyPairGenerator.initialize(new DHParameterSpec(
                new BigInteger(Utils.concat(new byte[] {0x00}, securityParameter.getDHParameterP())),
                new BigInteger(Utils.concat(new byte[] {0x00}, securityParameter.getDHParameterQ()))));
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        securityParameter.setDhPublicKey((DHPublicKey) keyPair.getPublic());

        KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
        keyAgreement.init(keyPair.getPrivate());
        KeyFactory keyFactory = KeyFactory.getInstance("DH");
        DHPublicKeySpec pubKeySpec = new DHPublicKeySpec(
                new BigInteger(Utils.concat(new byte[] {0x00}, securityParameter.getDHParameterYs())),
                new BigInteger(Utils.concat(new byte[] {0x00}, securityParameter.getDHParameterP())),
                new BigInteger(Utils.concat(new byte[] {0x00}, securityParameter.getDHParameterQ())));
        PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);

        keyAgreement.doPhase(pubKey, true);
        securityParameter.setPreMasterSecret(keyAgreement.generateSecret());

        int i;
        for (i = 0; i < securityParameter.getPreMasterSecret().length; i++) {
            if (securityParameter.getPreMasterSecret()[i] != 0x00) break;
        }
        securityParameter.setPreMasterSecret(Arrays.copyOfRange(securityParameter.getPreMasterSecret(), i, securityParameter.getPreMasterSecret().length));
    }

    public SecurityParameter getSecurityParameter() {
        return securityParameter;
    }
}
