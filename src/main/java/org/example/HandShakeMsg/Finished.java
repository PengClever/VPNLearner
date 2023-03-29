package org.example.HandShakeMsg;

import org.example.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class Finished extends HandShakeMsg{
    public Finished(byte[] verifyData) throws IOException {
        super(TLS.HANDSHAKE_MSG_TYPE_FINISHED);

        ByteArrayOutputStream messageStream = new ByteArrayOutputStream();
        messageStream.write(verifyData);

        setMessage(messageStream);
    }
}
