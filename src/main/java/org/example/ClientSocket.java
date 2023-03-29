package org.example;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

public class ClientSocket {
    private final String host;
    private final int port;
    private Socket socket;
    private OutputStream output;
    private InputStream input;

    public ClientSocket(String host, int port) {
        this.host = host;
        this.port = port;

    }

    public void init() throws IOException {
        socket = new Socket(host, port);
        socket.setTcpNoDelay(true);
        socket.setSoTimeout(100);
        output = socket.getOutputStream();
        input = socket.getInputStream();
    }

    public void close() throws IOException {
        socket.close();
    }

    public Socket getSocket() {
        return socket;
    }

    public OutputStream getOutput() {
        return output;
    }

    public InputStream getInput() {
        return input;
    }
}
