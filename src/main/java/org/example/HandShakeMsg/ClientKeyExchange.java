package org.example.HandShakeMsg;

import org.example.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class ClientKeyExchange extends HandShakeMsg{
    public ClientKeyExchange(byte[] exchangeKeys) throws IOException {
        super(TLS.HANDSHAKE_MSG_TYPE_CLIENT_KEY_EXCHANGE);

        ByteArrayOutputStream messageStream = new ByteArrayOutputStream();
        messageStream.write(Utils.getBytes16(exchangeKeys.length));
        messageStream.write(exchangeKeys);

        setMessage(messageStream);
    }
}
