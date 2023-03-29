package org.example.HandShakeMsg;

import org.example.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class ClientHello extends HandShakeMsg {
    public ClientHello(byte[] version, byte[] random, byte sessionIDLength, byte[] cipherSuites, byte[] compressionMethods, byte[] extension) throws IOException {
        super(TLS.HANDSHAKE_MSG_TYPE_CLIENT_HELLO);

        ByteArrayOutputStream messageStream = new ByteArrayOutputStream();
        messageStream.write(version);
        messageStream.write(random);
        messageStream.write(sessionIDLength);
        messageStream.write(Utils.getBytes16(cipherSuites.length));
        messageStream.write(cipherSuites);
        messageStream.write(Utils.getBytes8(compressionMethods.length));
        messageStream.write(compressionMethods);
        messageStream.write(Utils.getBytes16(extension.length));
        messageStream.write(extension);

        setMessage(messageStream);
    }

}
