package org.example.OpenVPNMsg;

import org.example.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class ControlMsg extends OpenVPNMsg {
    private byte[] packetID = new byte[PACKET_ID_SIZE];
    private final byte[] payload;
    private int headLength;
    public ControlMsg(byte keyID, byte[] sessionID, byte packetIDArrayLength, byte[] element, byte[] remoteSession, byte[] packetID, byte[] payload) throws IOException {
        super(OpenVPN.OPCODE_P_CONTROL_V1, keyID, sessionID, packetIDArrayLength);
        this.packetID = packetID;
        this.payload = payload;

        ByteArrayOutputStream messageStream = new ByteArrayOutputStream();
        messageStream.write((byte)((this.opcode << 3) & 0xFF) | this.keyID);
        messageStream.write(this.sessionID);
        messageStream.write(this.packetIDArrayLength);
        if (this.packetIDArrayLength > 0) {
            messageStream.write(element);
            messageStream.write(remoteSession);
        }
        messageStream.write(this.packetID);
        messageStream.write(this.payload);

        setMessage(messageStream);
    }

    public ControlMsg(byte[] inBytes) {
        super(inBytes);
        int currentPosition = TYPE_SIZE + SESSION_ID_SIZE;
        this.packetIDArrayLength = messageBody[currentPosition++];
        headLength = 14;
        if (this.packetIDArrayLength > 0) {
            currentPosition += this.packetIDArrayLength * PACKET_ID_SIZE + SESSION_ID_SIZE;
            headLength += 12;
        }
        System.arraycopy(messageBody, currentPosition, packetID, 0, PACKET_ID_SIZE);
        currentPosition += PACKET_ID_SIZE;
        payload = new byte[length - currentPosition];
        System.arraycopy(messageBody, currentPosition, payload, 0, length - currentPosition);
    }

    public byte[] getPacketID() {
        return this.packetID;
    }

    public byte[] getPayload() {
        return this.payload;
    }

    public int getHeadLength() {
        return this.headLength;
    }
}
