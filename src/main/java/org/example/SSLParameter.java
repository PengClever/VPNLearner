package org.example;

public class SSLParameter {
    private final byte[] version;
    private byte[] clientRandom;
    private byte[] serverRandom;
    byte[] cipherSuite;

    public SSLParameter(String sslVersion) {
        version = getSSLVersion(sslVersion);
    }

    public void init() {
        clientRandom = new byte[32];
        serverRandom = new byte[32];
        cipherSuite = new byte[2];
    }

    public byte[] getVersion() {
        return version;
    }

    public byte[] getClientRandom() {
        return clientRandom;
    }

    public byte[] getServerRandom() {
        return serverRandom;
    }

    public void setServerRandom(byte[] serverRandom) {
        this.serverRandom = serverRandom;
    }

    public void setCipherSuite(byte[] cipherSuite) {
        this.cipherSuite = cipherSuite;
    }

    private byte[] getSSLVersion(String sslVersion) {
        if (sslVersion.equals("SSL 3.0")){
            return new byte[]{0x3, 0x0};
        } else {
            String[] versions = sslVersion.split(" ");
            if (versions[0].equals("TLS")) {
                switch (versions[1]) {
                    case "1.3":
                        return new byte[]{0x3, 0x4};
                    case "1.2":
                        return new byte[]{0x3, 0x3};
                    case "1.1":
                        return new byte[]{0x3, 0x2};
                    case "1.0":
                        return new byte[]{0x3, 0x1};
                }
            }
        }
        System.out.println("Wrong version!");
        return new byte[]{};
    }
}
