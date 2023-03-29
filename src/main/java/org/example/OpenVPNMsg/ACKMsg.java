package org.example.OpenVPNMsg;

import org.example.*;

import java.io.ByteArrayOutputStream;

public class ACKMsg extends OpenVPNMsg {
    public ACKMsg(byte keyID, byte[] sessionID, byte packetIDArrayLength, byte[] packetIDElement, byte[] remoteSessionID) {
        super(OpenVPN.OPCODE_P_ACK_V1, keyID, sessionID, packetIDArrayLength);

        ByteArrayOutputStream messageStream = new ByteArrayOutputStream();
        messageStream.write((byte)((this.opcode << 3) & 0xFF) | this.keyID);
        messageStream.write(this.sessionID, 0, 8);
        messageStream.write(this.packetIDArrayLength);
        messageStream.write(packetIDElement, 0, 4);
        messageStream.write(remoteSessionID, 0, 8);

        setMessage(messageStream);
    }
}