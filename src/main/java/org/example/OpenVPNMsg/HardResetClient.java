package org.example.OpenVPNMsg;

import org.example.OpenVPN;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class HardResetClient extends OpenVPNMsg {
    public HardResetClient(byte keyID, byte[] sessionID, byte packetIDArrayLength, byte[] packetID) throws IOException {
        super(OpenVPN.OPCODE_P_CONTROL_HARD_RESET_CLIENT_V2, keyID, sessionID, packetIDArrayLength);

        ByteArrayOutputStream messageStream = new ByteArrayOutputStream();
        messageStream.write((byte)((this.opcode << 3) & 0xFF) | this.keyID);
        messageStream.write(this.sessionID);
        messageStream.write(this.packetIDArrayLength);
        messageStream.write(packetID);

        setMessage(messageStream);
    }
}