package org.example.OpenVPNMsg;

public class HardResetServer extends OpenVPNMsg{
    private final byte[] packetID = new byte[PACKET_ID_SIZE];
    private final byte[] remoteSessionID = new byte[SESSION_ID_SIZE];
    public HardResetServer(byte[] inBytes) {
        super(inBytes);
        System.arraycopy(messageBody, 14, remoteSessionID, 0, SESSION_ID_SIZE);
        System.arraycopy(messageBody, 22, packetID, 0, PACKET_ID_SIZE);
    }

    public byte[] getRemoteSessionID() {
        return this.remoteSessionID;
    }

    public byte[] getPacketID() {
        return this.packetID;
    }
}
