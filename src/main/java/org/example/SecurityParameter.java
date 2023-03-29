package org.example;

import javax.crypto.interfaces.DHPublicKey;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class SecurityParameter {
    private byte[] DHParameterP;
    private byte[] DHParameterQ;
    private byte[] DHParameterYs;
    private int hashAlgorithm;
    private int signatureAlgorithm;
    private byte[] signature;
    private byte[] preMasterSecret;
    private byte[] masterSecret;
    private DHPublicKey dhPublicKey;
    private X509Certificate clientCertificate;
    private PrivateKey clientPrivateKey;

    public byte[] getDHParameterP() {
        return DHParameterP;
    }

    public void setDHParameterP(byte[] DHParameterP) {
        this.DHParameterP = DHParameterP;
    }

    public byte[] getDHParameterQ() {
        return DHParameterQ;
    }

    public void setDHParameterQ(byte[] DHParameterQ) {
        this.DHParameterQ = DHParameterQ;
    }

    public byte[] getDHParameterYs() {
        return DHParameterYs;
    }

    public void setDHParameterYs(byte[] DHParameterYs) {
        this.DHParameterYs = DHParameterYs;
    }

    public void setHashAlgorithm(int hashAlgorithm) {
        this.hashAlgorithm = hashAlgorithm;
    }

    public void setSignatureAlgorithm(int signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    public byte[] getSignature() {
        return signature;
    }

    public void setSignature(byte[] signature) {
        this.signature = signature;
    }

    public byte[] getPreMasterSecret() {
        return preMasterSecret;
    }

    public void setPreMasterSecret(byte[] preMasterSecret) {
        this.preMasterSecret = preMasterSecret;
    }

    public byte[] getMasterSecret() {
        return masterSecret;
    }

    public void setMasterSecret(byte[] masterSecret) {
        this.masterSecret = masterSecret;
    }

    public DHPublicKey getDhPublicKey() {
        return dhPublicKey;
    }

    public void setDhPublicKey(DHPublicKey dhPublicKey) {
        this.dhPublicKey = dhPublicKey;
    }

    public X509Certificate getClientCertificate() {
        return clientCertificate;
    }

    public void setClientCertificate(X509Certificate clientCertificate) {
        this.clientCertificate = clientCertificate;
    }

    public PrivateKey getClientPrivateKey() {
        return clientPrivateKey;
    }

    public void setClientPrivateKey(PrivateKey clientPrivateKey) {
        this.clientPrivateKey = clientPrivateKey;
    }

    public void setServerParameter(SecurityParameter sec) {
        DHParameterP = sec.DHParameterP;
        DHParameterQ = sec.DHParameterQ;
        DHParameterYs = sec.DHParameterYs;
        hashAlgorithm = sec.hashAlgorithm;
        signatureAlgorithm = sec.signatureAlgorithm;
        signature = sec.signature;
        masterSecret = new byte[]{};
        dhPublicKey = sec.dhPublicKey;
        preMasterSecret = sec.preMasterSecret;
    }
}
