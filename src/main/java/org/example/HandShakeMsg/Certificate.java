package org.example.HandShakeMsg;

import org.example.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

public class Certificate extends HandShakeMsg{

    public Certificate(X509Certificate cert) throws IOException, CertificateEncodingException {
        super(TLS.HANDSHAKE_MSG_TYPE_CERTIFICATE);

        ByteArrayOutputStream certificateStream = new ByteArrayOutputStream();
        certificateStream.write(Utils.getBytes24(cert.getEncoded().length));
        certificateStream.write(cert.getEncoded());

        byte[] certificates = certificateStream.toByteArray();

        ByteArrayOutputStream messageStream = new ByteArrayOutputStream();
        messageStream.write(Utils.getBytes24(certificates.length));
        messageStream.write(certificates);

        setMessage(messageStream);
    }

}
