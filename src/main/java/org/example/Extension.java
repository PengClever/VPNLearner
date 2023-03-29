package org.example;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class Extension {
    byte[] type;
    byte[] payload;

    public Extension(byte[] type, byte[] payload) {
        this.type = type;
        this.payload = payload;
    }

    public byte[] getBytes() throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(type);
        out.write(Utils.getBytes16(payload.length));
        out.write(payload);

        return out.toByteArray();
    }
}
