package org.example;

public class Test {
    public static void main(String[] args) throws Exception {
        String host = "192.168.248.129";
        int port = 1194;
        String options = "V4,dev-type tun,link-mtu 1560,tun-mtu 1500,proto TCPv4_CLIENT,comp-lzo,cipher AES-256-CBC,auth SHA1,keysize 256,key-method 2,tls-client";
        String result;
        System.out.println("Hello Test!");
        VPNService demo = new VPNService(host, port, "TLS 1.2", options, "zhangsan");
        result = demo.processSymbol("HardResetClient");
        System.out.println("\nSend: HardResetClient\nReceive: " + result);
        result = demo.processSymbol("ClientHello");
        System.out.println("\nSend: ClientHello\nReceive: " + result);
        result = demo.processSymbol("Certificate");
        System.out.println("\nSend: Certificate\nReceive: " + result);
        result = demo.processSymbol("ClientKeyExchange");
        System.out.println("\nSend: ClientKeyExchange\nReceive: " + result);
        result = demo.processSymbol("CertificateVerify");
        System.out.println("\nSend: CertificateVerify\nReceive: " + result);
        result = demo.processSymbol("ChangeCipherSpec");
        System.out.println("\nSend: ChangeCipherSpec\nReceive: " + result);
        result = demo.processSymbol("Finished");
        System.out.println("\nSend: Finished\nReceive: " + result);
        result = demo.processSymbol("KeyNegotiate");
        System.out.println("\nSend: KeyNegotiate\nReceive: " + result);
        result = demo.processSymbol("ConfigNegotiate");
        System.out.println("\nSend: ConfigNegotiate\nReceive: " + result);
    }
}
