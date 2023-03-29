package org.example.HandShakeMsg;

import org.example.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class CertificateVerify extends HandShakeMsg{
    public CertificateVerify(byte[] algorithms, byte[] signature) throws IOException {
        super(TLS.HANDSHAKE_MSG_TYPE_CERTIFICATE_VERIFY);

        ByteArrayOutputStream messageStream = new ByteArrayOutputStream();
        messageStream.write(algorithms);
        messageStream.write(Utils.getBytes16(signature.length));
        messageStream.write(signature);

        setMessage(messageStream);
    }
}
