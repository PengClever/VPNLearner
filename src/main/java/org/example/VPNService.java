package org.example;

import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;
import org.example.HandShakeMsg.*;
import org.example.OpenVPNMsg.*;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Objects;

public class VPNService {
    OpenVPN vpn;
    SSLParameter ssl;
    ClientSocket socket;
    SecurityParameter sec;
    SecureRandom rand;
    EncryptParameter enc;
    byte[] handshakeMessages;

    public VPNService(String host, int port, String SSLVersion, String options, String name) throws Exception {
        socket = new ClientSocket(host, port);
        rand = new SecureRandom();
        vpn = new OpenVPN(options);
        ssl = new SSLParameter(SSLVersion);
        sec = new SecurityParameter();
        enc = new EncryptParameter();
        loadKey(name);
        setInitValues();
    }
    
    public VPNService(LearnerConfig config) throws Exception {
        socket = new ClientSocket(config.host, config.port);
        rand = new SecureRandom();
        vpn = new OpenVPN(config.options);
        ssl = new SSLParameter(config.SSLVersion);
        sec = new SecurityParameter();
        enc = new EncryptParameter();
        loadKey(config.cert_name);
        setInitValues();
    }

    public void loadKey(String name) throws Exception {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        FileInputStream fIn = new FileInputStream(Learner.RESOURCES_ROOT + "/cert/" + name + ".crt");
        sec.setClientCertificate((X509Certificate) certificateFactory.generateCertificate(fIn));

        String keyString = new String(Files.readAllBytes(Paths.get(Learner.RESOURCES_ROOT + "/cert/" + name + ".key")));
        keyString = keyString.replace("-----BEGIN PRIVATE KEY-----", "");
        keyString = keyString.replace("-----END PRIVATE KEY-----", "");
        byte[] encoded = Base64.decode(keyString);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        sec.setClientPrivateKey(keyFactory.generatePrivate(keySpec));

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DiffieHellman");
        keyPairGenerator.initialize(new DHParameterSpec(
                new BigInteger(new byte[]{(byte) 0x00, (byte) 0xad, (byte) 0x77, (byte) 0xcd, (byte) 0xb7, (byte) 0x14, (byte) 0x6f, (byte) 0xfe, (byte) 0x08, (byte) 0x1a, (byte) 0xee, (byte) 0xd2, (byte) 0x2c, (byte) 0x18, (byte) 0x29, (byte) 0x62, (byte) 0x5a, (byte) 0xff, (byte) 0x03, (byte) 0x5d, (byte) 0xde, (byte) 0xba, (byte) 0x0d, (byte) 0xd4, (byte) 0x36, (byte) 0x15, (byte) 0x03, (byte) 0x11, (byte) 0x21, (byte) 0x48, (byte) 0xd9, (byte) 0x77, (byte) 0xfb, (byte) 0x67, (byte) 0xb0, (byte) 0x74, (byte) 0x2e, (byte) 0x68, (byte) 0xed, (byte) 0x5a, (byte) 0x3f, (byte) 0x8a, (byte) 0x3e, (byte) 0xdb, (byte) 0x81, (byte) 0xa3, (byte) 0x3b, (byte) 0xaf, (byte) 0x26, (byte) 0xe4, (byte) 0x54, (byte) 0x00, (byte) 0x85, (byte) 0x0d, (byte) 0xfd, (byte) 0x23, (byte) 0x21, (byte) 0xc1, (byte) 0xfe, (byte) 0x69, (byte) 0xe4, (byte) 0xf3, (byte) 0x57, (byte) 0xe6, (byte) 0x0a, (byte) 0x7c, (byte) 0x62, (byte) 0xc0, (byte) 0xd6, (byte) 0x40, (byte) 0x3e, (byte) 0x94, (byte) 0x9e, (byte) 0x49, (byte) 0x72, (byte) 0x5a, (byte) 0x21, (byte) 0x53, (byte) 0xb0, (byte) 0x83, (byte) 0x05, (byte) 0x81, (byte) 0x5a, (byte) 0xde, (byte) 0x17, (byte) 0x31, (byte) 0xbf, (byte) 0xa8, (byte) 0xa9, (byte) 0xe5, (byte) 0x28, (byte) 0x1a, (byte) 0xfc, (byte) 0x06, (byte) 0x1e, (byte) 0x49, (byte) 0xfe, (byte) 0xdc, (byte) 0x08, (byte) 0xe3, (byte) 0x29, (byte) 0xfe, (byte) 0x5b, (byte) 0x88, (byte) 0x66, (byte) 0x39, (byte) 0xa8, (byte) 0x69, (byte) 0x62, (byte) 0x88, (byte) 0x47, (byte) 0x36, (byte) 0xf5, (byte) 0xdd, (byte) 0x92, (byte) 0x8f, (byte) 0xca, (byte) 0x32, (byte) 0x4b, (byte) 0x87, (byte) 0xad, (byte) 0xbf, (byte) 0xab, (byte) 0x4a, (byte) 0x9d, (byte) 0xd5, (byte) 0xb8, (byte) 0x2c, (byte) 0xc4, (byte) 0x43, (byte) 0xb2, (byte) 0x21, (byte) 0xb4, (byte) 0x2a, (byte) 0x9b, (byte) 0x42, (byte) 0x17, (byte) 0x6d, (byte) 0xb6, (byte) 0x86, (byte) 0x42, (byte) 0x41, (byte) 0xb1, (byte) 0xc7, (byte) 0x37, (byte) 0x37, (byte) 0x95, (byte) 0x6d, (byte) 0x62, (byte) 0xca, (byte) 0xa6, (byte) 0x57, (byte) 0x33, (byte) 0x88, (byte) 0xe2, (byte) 0x31, (byte) 0xfe, (byte) 0xd1, (byte) 0x51, (byte) 0xe7, (byte) 0x73, (byte) 0xae, (byte) 0x3c, (byte) 0xa7, (byte) 0x4b, (byte) 0xbc, (byte) 0x8a, (byte) 0x3d, (byte) 0xc5, (byte) 0x9a, (byte) 0x28, (byte) 0x9a, (byte) 0xf9, (byte) 0x57, (byte) 0xb6, (byte) 0xec, (byte) 0xf6, (byte) 0x75, (byte) 0xaa, (byte) 0x56, (byte) 0xc1, (byte) 0x42, (byte) 0x9f, (byte) 0x6a, (byte) 0x7c, (byte) 0x91, (byte) 0x8b, (byte) 0x5e, (byte) 0xea, (byte) 0x54, (byte) 0x32, (byte) 0x90, (byte) 0x8a, (byte) 0x9d, (byte) 0x76, (byte) 0x2a, (byte) 0x29, (byte) 0x1b, (byte) 0x84, (byte) 0x35, (byte) 0xe6, (byte) 0x21, (byte) 0x07, (byte) 0xb2, (byte) 0xcb, (byte) 0x5c, (byte) 0xf9, (byte) 0x5b, (byte) 0xe9, (byte) 0x5e, (byte) 0x1b, (byte) 0x80, (byte) 0xd5, (byte) 0x53, (byte) 0xd7, (byte) 0xa4, (byte) 0x26, (byte) 0x58, (byte) 0xe4, (byte) 0xe9, (byte) 0x3f, (byte) 0xfd, (byte) 0xeb, (byte) 0x78, (byte) 0xf2, (byte) 0x25, (byte) 0x02, (byte) 0x42, (byte) 0xf8, (byte) 0x50, (byte) 0x13, (byte) 0xbb, (byte) 0x01, (byte) 0x39, (byte) 0xf3, (byte) 0xcf, (byte) 0x5c, (byte) 0x51, (byte) 0xdf, (byte) 0xed, (byte) 0xc5, (byte) 0xfa, (byte) 0xd8, (byte) 0x4f, (byte) 0xae, (byte) 0x76, (byte) 0xe8, (byte) 0x30, (byte) 0xfc, (byte) 0x85, (byte) 0xaa, (byte) 0x8c, (byte) 0x91, (byte) 0x02, (byte) 0x2b, (byte) 0x61, (byte) 0x87}),
                new BigInteger(new byte[]{0x05}))
        );
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        sec.setDhPublicKey((DHPublicKey) keyPair.getPublic());
    }

    public void setInitValues() throws IOException {
        sec.setMasterSecret(new byte[]{});
        handshakeMessages = new byte[]{};
        vpn.init(rand);
        ssl.init();
        enc.init();
        socket.init();
    }

    public String sendMessage(OpenVPNMsg msg) throws Exception {
        // send Message
        socket.getOutput().write(msg.getBytes());
        vpn.increase();
        if (vpn.isSendConfigMsg()) {
            StringBuilder out = new StringBuilder();
            vpn.setSendConfigMsg(false);
            out.append(receiveMessage());
            if (Objects.equals(out.toString(), "P_ACK_V1 ")) {
                String result = receiveMessage();
                if (!Objects.equals(result, "Empty")){
                    out.append(" ").append(result);
                }
            }
            return out.toString();
        }
        return receiveMessage();
    }

    public String sendHardResetClient() throws Exception {
        // send P_CONTROL_HARD_RESET_CLIENT_V2
        HardResetClient msg = new HardResetClient((byte)0, vpn.getClientSessionID(), (byte)0, vpn.getClientPacketID());
        return sendMessage(msg);
    }

    public void sendACK() throws Exception {
        // send ACK
        ACKMsg msg = new ACKMsg((byte)0, vpn.getClientSessionID(), (byte)1, vpn.getServerPacketID(), vpn.getServerSessionID());
        socket.getOutput().write(msg.getBytes());
    }

    public String sendHandshake(HandShakeMsg sslMsg, byte packetIDArrayLength) throws Exception {
        // send Handshake
        handshakeMessages = Utils.concat(handshakeMessages, sslMsg.getBytes());
        RecordMsg recordMsg = new RecordMsg(TLS.CONTENT_TYPE_HANDSHAKE, ssl.getVersion(), sslMsg.getBytes());
        return sendRecord(recordMsg, packetIDArrayLength);
    }

    public String sendRecord(RecordMsg recordMsg, byte packetIDArrayLength) throws Exception {
        // send Record
        if (enc.isCCSOut()) {
            recordMsg.addMac(enc.getWriteMAC(), CipherSuite.MAC_KEY_SIZE, enc.getWriteMACSeqNr());
            enc.increaseWriteMACSeqNr();
            recordMsg.encrypt(enc.getWriteCipher(), rand);
        }
        ControlMsg msg = new ControlMsg((byte)0, vpn.getClientSessionID(), packetIDArrayLength, vpn.getServerPacketID(), vpn.getServerSessionID(), vpn.getClientPacketID(), recordMsg.getBytes());
        return sendMessage(msg);
    }

    public String sendClientHello() throws Exception {
        // send P_CONTROL_V1: ClientHello
        rand.nextBytes(ssl.getClientRandom());
        byte[] extensions = new byte[]{};
        Extension renegotiation_extension = new Extension(TLS.EXTENSION_TYPE_RENEGOTIATION_INFO, new byte[]{0x00});
        extensions = Utils.concat(extensions, renegotiation_extension.getBytes());
        Extension heartbeat_extension = new Extension(TLS.EXTENSION_TYPE_HEARTBEAT, new byte[]{0x02});
        extensions = Utils.concat(extensions, heartbeat_extension.getBytes());
        ClientHello sslMsg = new ClientHello(ssl.getVersion(), ssl.getClientRandom(), (byte)0,
                Utils.concat(CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA, CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV),
                new byte[]{0x00}, extensions);
        return sendHandshake(sslMsg, (byte)0);
    }

    public String sendClientCertificate() throws Exception {
        // send P_CONTROL_V1: Certificate
        Certificate sslMsg = new Certificate(sec.getClientCertificate());
        return sendHandshake(sslMsg, (byte)1);
    }

    public String sendClientKeyExchange() throws Exception {
        // send P_CONTROL_V1: ClientKeyExchange
        ClientKeyExchange sslMsg = new ClientKeyExchange(sec.getDhPublicKey().getY().toByteArray());
        return sendHandshake(sslMsg, (byte)1);
    }

    public String sendCertificateVerify() throws Exception {
        // send P_CONTROL_V1: CertificateVerify
        byte[] signature = Crypto.SIGN_RSA_SHA256(sec.getClientPrivateKey(), handshakeMessages);
        CertificateVerify sslMsg = new CertificateVerify(Crypto.HASH_SIGNATURE_ALGORITHM_SHA256RSA, signature);
        return sendHandshake(sslMsg, (byte)1);
    }

    public String sendFinished() throws Exception {
        // send P_CONTROL_V1: Finished
        byte[] verifyData = TLS.verifyDataClient(sec.getMasterSecret(), handshakeMessages);
        Finished sslMsg = new Finished(verifyData);
        return sendHandshake(sslMsg, (byte)1);
    }

    public String sendChangeCipherSpec() throws Exception {
        // send P_CONTROL_V1: Finished
        RecordMsg recordMsg = new RecordMsg(TLS.CONTENT_TYPE_CHANGE_CIPHER_SPEC, ssl.getVersion(), new byte[]{0x01});
        ControlMsg msg = new ControlMsg((byte)0, vpn.getClientSessionID(), (byte)1, vpn.getServerPacketID(), vpn.getServerSessionID(), vpn.getClientPacketID(), recordMsg.getBytes());
        setClientCiphers();
        return sendMessage(msg);
    }

    public String sendKeyNegotiate() throws Exception {
        // send P_CONTROL_V1: ApplicationData.KeyNegotiate
        byte[] applicationData = vpn.getClientKeyNegotiateData(vpn.getClientOptions());
        RecordMsg recordMsg = new RecordMsg(TLS.CONTENT_TYPE_APPLICATION, ssl.getVersion(), applicationData);
        return sendRecord(recordMsg, (byte)1);
    }

    public String sendConfigNegotiate() throws Exception {
        // send P_CONTROL_V1: ApplicationData.ConfigNegotiate
        byte[] applicationData = vpn.getConfigRequest();
        vpn.setSendConfigMsg(true);
        RecordMsg recordMsg = new RecordMsg(TLS.CONTENT_TYPE_APPLICATION, ssl.getVersion(), applicationData);
        return sendRecord(recordMsg, (byte)1);
    }

    public void setClientCiphers() throws Exception {
        byte[] keyBlock = TLS.keyBlock(sec.getMasterSecret(), ssl.getServerRandom(), ssl.getClientRandom());

        int index = 0;
        byte[] writeMacKey = Arrays.copyOfRange(keyBlock, index, index + CipherSuite.MAC_KEY_SIZE);
        index += 2 * CipherSuite.MAC_KEY_SIZE;
        byte[] writeKey = Arrays.copyOfRange(keyBlock, index, index + CipherSuite.ENCRYPT_KEY_SIZE);
        index += 2 * CipherSuite.ENCRYPT_KEY_SIZE;
        byte[] writeIV = Arrays.copyOfRange(keyBlock, index, index + CipherSuite.FIXED_IV_SIZE);

        SecretKey clientCipherKey = new SecretKeySpec(writeKey, CipherSuite.ENCRYPT_CIPHER_KEY_ALGORITHM);
        IvParameterSpec clientCipherIV = new IvParameterSpec(writeIV);

        enc.setWriteMAC(CipherSuite.getMAC());
        enc.getWriteMAC().init(new SecretKeySpec(writeMacKey, CipherSuite.MAC_CIPHER_ALGORITHM));

        enc.setWriteCipher(CipherSuite.getEncCipher());
        enc.getWriteCipher().init(Cipher.ENCRYPT_MODE, clientCipherKey, clientCipherIV);
        enc.setCCSOut(true);
    }

    public void setServerCiphers() throws Exception {
        byte[] keyBlock = TLS.keyBlock(sec.getMasterSecret(), ssl.getServerRandom(), ssl.getClientRandom());

        int index = CipherSuite.MAC_KEY_SIZE;
        byte[] readMacKey = Arrays.copyOfRange(keyBlock, index, index + CipherSuite.MAC_KEY_SIZE);
        index += CipherSuite.MAC_KEY_SIZE + CipherSuite.ENCRYPT_KEY_SIZE;
        byte[] readKey = Arrays.copyOfRange(keyBlock, index, index + CipherSuite.ENCRYPT_KEY_SIZE);
        index += CipherSuite.ENCRYPT_KEY_SIZE + CipherSuite.FIXED_IV_SIZE;
        byte[] readIV = Arrays.copyOfRange(keyBlock, index, index + CipherSuite.FIXED_IV_SIZE);

        SecretKey serverCipherKey = new SecretKeySpec(readKey, CipherSuite.ENCRYPT_CIPHER_KEY_ALGORITHM);
        IvParameterSpec serverCipherIV = new IvParameterSpec(readIV);

        enc.setReadMAC(CipherSuite.getMAC());
        enc.getReadMAC().init(new SecretKeySpec(readMacKey, CipherSuite.MAC_CIPHER_ALGORITHM));

        enc.setReadCipher(CipherSuite.getEncCipher());
        enc.getReadCipher().init(Cipher.DECRYPT_MODE, serverCipherKey, serverCipherIV, rand);
        enc.setCCSIn(true);
    }

    public String receiveMessage() throws Exception {
        // receive
        StringBuilder out = new StringBuilder();
        int returnLength, length;
        byte[] lengthBytes = new byte[2];
        byte[] payload;

        try{
            returnLength = socket.getInput().read(lengthBytes, 0, 2);
        } catch (SocketTimeoutException e) {
            return "Empty";
        }

        if (returnLength != 0) {
            length = Utils.getLength(lengthBytes, 2);
            payload = new byte[length];
            returnLength = socket.getInput().read(payload, 0, length);
            if (returnLength <= 0) {
                socket.close();
                return "ConnectionClosed";
            }
            OpenVPNMsg msg = new OpenVPNMsg(payload);
            switch (msg.getOpcode()) {
                case OpenVPN.OPCODE_P_CONTROL_HARD_RESET_CLIENT_V1:
                    out.append("HardResetClientV1 ");
                    break;

                case OpenVPN.OPCODE_P_CONTROL_HARD_RESET_SERVER_V1:
                    out.append("HardResetServerV1 ");
                    break;

                case OpenVPN.OPCODE_P_CONTROL_SOFT_RESET_V1:
                    out.append("SoftResetV1 ");
                    break;

                case OpenVPN.OPCODE_P_CONTROL_V1:
                    Record record = new Record();
                    RecordMsg recordMsg;
                    boolean sendACK = true;
                    int remainLength = 0;
                    do {
                        if (remainLength != 0) {
                            try{
                                returnLength = socket.getInput().read(lengthBytes, 0, 2);
                            } catch (SocketTimeoutException e) {
                                return "Empty2";
                            }
                            if (returnLength != 0) {
                                length = Utils.getLength(lengthBytes, 2);
                                payload = new byte[length];
                                returnLength = socket.getInput().read(payload, 0, length);
                                if (returnLength <= 0)
                                    return "returnLength <= 0";
                            }
                        }
                        ControlMsg controlMsg = new ControlMsg(payload);
                        record.addMessage(controlMsg.getPayload());
                        remainLength += length - controlMsg.getHeadLength() - 5;

                        while (record.isEnough(remainLength)) {
                            recordMsg = record.getMessage();
                            if (enc.isCCSIn()) {
                                try {
                                    recordMsg.decrypt(enc.getReadCipher(), CipherSuite.MAC_KEY_SIZE);
                                } catch (Exception e) {
                                    e.printStackTrace();
                                    out.append("DecryptError_v1");
                                    break;
                                }
                                if (!recordMsg.checkMac(enc.getReadMAC(), enc.getReadMACSeqNr())) {
                                    enc.increaseReadMACSeqNr();
                                    out.append("DecryptError_v2");
                                    break;
                                }
                                enc.increaseReadMACSeqNr();
                            }
                            switch (recordMsg.getContentType()) {
                                case TLS.CONTENT_TYPE_CHANGE_CIPHER_SPEC:
                                    out.append("ChangeCipherSpec ");
                                    setServerCiphers();
                                    break;
                                case TLS.CONTENT_TYPE_ALERT:
                                    out.append("Alert ");
                                    break;
                                case TLS.CONTENT_TYPE_HANDSHAKE:
                                    byte[] msgBytes = recordMsg.getPayload();
                                    int recordLength = msgBytes.length, sumLength = 0, msgLength;
                                    byte handshakeType;
                                    byte[] handshakeLength = new byte[3], currentMsg;
                                    while (recordLength > sumLength) {
                                        handshakeType = msgBytes[sumLength];
                                        System.arraycopy(msgBytes, sumLength + 1, handshakeLength, 0, 3);
                                        msgLength = Utils.getLength(handshakeLength, 3);
                                        currentMsg = new byte[msgLength + 4];
                                        System.arraycopy(msgBytes, sumLength, currentMsg, 0, currentMsg.length);
                                        handshakeMessages = Utils.concat(handshakeMessages, currentMsg);
                                        switch (handshakeType) {
                                            case TLS.HANDSHAKE_MSG_TYPE_HELLO_REQUEST:
                                                out.append("HelloRequest ");
                                                break;
                                            case TLS.HANDSHAKE_MSG_TYPE_CLIENT_HELLO:
                                                out.append("ClientHello ");
                                                break;
                                            case TLS.HANDSHAKE_MSG_TYPE_SERVER_HELLO:
                                                out.append("ServerHello ");
                                                ServerHello serverHello = new ServerHello(currentMsg);
                                                ssl.setServerRandom(serverHello.getRandom());
                                                ssl.setCipherSuite(serverHello.getCipherSuite());
                                                break;
                                            case TLS.HANDSHAKE_MSG_TYPE_CERTIFICATE:
                                                out.append("Certificate ");
                                                break;
                                            case TLS.HANDSHAKE_MSG_TYPE_SERVER_KEY_EXCHANGE:
                                                out.append("ServerKeyExchange ");
                                                ServerKeyExchange serverKeyExchange = new ServerKeyExchange(currentMsg);
                                                sec.setServerParameter(serverKeyExchange.getSecurityParameter());
                                                sec.setMasterSecret(TLS.masterSecret(sec.getPreMasterSecret(), ssl.getServerRandom(), ssl.getClientRandom()));
                                                break;
                                            case TLS.HANDSHAKE_MSG_TYPE_CERTIFICATE_REQUEST:
                                                out.append("CertificateRequest ");
                                                break;
                                            case TLS.HANDSHAKE_MSG_TYPE_SERVER_HELLO_DONE:
                                                out.append("ServerHelloDone ");
                                                sendACK = false;
                                                break;
                                            case TLS.HANDSHAKE_MSG_TYPE_CERTIFICATE_VERIFY:
                                                out.append("CertificateVerify");
                                                break;
                                            case TLS.HANDSHAKE_MSG_TYPE_CLIENT_KEY_EXCHANGE:
                                                out.append("ClientKeyExchange");
                                                break;
                                            case TLS.HANDSHAKE_MSG_TYPE_FINISHED:
                                                out.append("Finished ");
                                                sendACK = false;
                                                break;
                                            default:
                                                break;
                                        }
                                        sumLength += (msgLength + 4);
                                    }
                                    break;
                                case TLS.CONTENT_TYPE_APPLICATION:
                                    byte[] pad = new byte[4];
                                    System.arraycopy(recordMsg.getBytes(), 5, pad, 0, pad.length);
                                    if (Arrays.equals(pad, new byte[]{0x00, 0x00, 0x00, 0x00})) {
                                        vpn.getServerKeyNegotiateData(recordMsg.getBytes());
                                        out.append("KeyNegotiate ");
                                        break;
                                    }
                                    byte[] config = new byte[10];
                                    System.arraycopy(recordMsg.getBytes(), 5, config, 0, config.length);
                                    if (Arrays.equals(config, "PUSH_REPLY".getBytes())) {
                                        vpn.getConfigReply(recordMsg.getBytes());
                                        out.append("ConfigNegotiate ");
                                        break;
                                    }
                                    out.append("Application ");
                                    break;
                                case TLS.CONTENT_TYPE_HEARTBEAT:
                                    out.append("HeartBeat ");
                                    break;
                                default:
                                    break;
                            }
                            remainLength -= recordMsg.getPayload().length;
                        }
                        vpn.setServerPacketID(controlMsg.getPacketID());
                        if (sendACK)
                            sendACK();
                        else
                            sendACK = true;
                    } while (!record.isEnd());
                    break;

                case OpenVPN.OPCODE_P_ACK_V1:
                    out.append("P_ACK_V1 ");
                    break;

                case OpenVPN.OPCODE_P_DATA_V1:
                    out.append("P_DATA_V1 ");
                    break;

                case OpenVPN.OPCODE_P_CONTROL_HARD_RESET_CLIENT_V2:
                    out.append("HardResetClientV2 ");
                    break;

                case OpenVPN.OPCODE_P_CONTROL_HARD_RESET_SERVER_V2:
                    out.append("HardResetServerV2 ");
                    HardResetServer hrsMsg = new HardResetServer(payload);
                    if (Arrays.equals(hrsMsg.getRemoteSessionID(), vpn.getClientSessionID())) {
                        vpn.setServerSessionID(hrsMsg.getSessionID());
                        vpn.setServerPacketID(hrsMsg.getPacketID());
                        sendACK();
                    } else {
                        out.append("_WRONG");
                    }
                    break;

                case OpenVPN.OPCODE_P_DATA_V2:
                    out.append("P_DATA_V2");
                    break;

                default:
                    out.append("Other");
            }
        }

        return out.toString();
    }
    public String processSymbol(String input) throws Exception{

        if (!socket.getSocket().isConnected() || socket.getSocket().isClosed())
            return "ConnectionClosed";

        try {
            switch (input) {
                case "HardResetClientV2":
                    return sendHardResetClient();
                case "ClientHello":
                    return sendClientHello();
                case "Certificate":
                    return sendClientCertificate();
                case "ClientKeyExchange":
                    return sendClientKeyExchange();
                case "CertificateVerify":
                    return sendCertificateVerify();
                case "ChangeCipherSpec":
                    return sendChangeCipherSpec();
                case "Finished":
                    return sendFinished();
                case "KeyNegotiate":
                    return sendKeyNegotiate();
                case "ConfigNegotiate":
                    return sendConfigNegotiate();
                default:
                    System.out.println("Unknown input symbol (" + input + ")...");
                    throw new RuntimeException("Unknown input Symbol (" + input + ")...");
            }
        } catch (SocketException e) {
            return "ConnectionClosed";
        }
    }

    public void reset() throws IOException {
        socket.close();
        setInitValues();
    }
}
