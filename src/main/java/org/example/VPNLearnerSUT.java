package org.example;

import de.learnlib.api.SUL;
import net.automatalib.words.impl.SimpleAlphabet;

import java.util.Arrays;

public class VPNLearnerSUT implements SUL<String, String> {
    SimpleAlphabet<String> alphabet;
    VPNService vpn;

    // ��ʼ�� SUT
    public VPNLearnerSUT(LearnerConfig config) throws Exception {
        alphabet = new SimpleAlphabet<>(Arrays.asList(config.alphabet.split(" ")));
        vpn = new VPNService(config);
    }
    public SimpleAlphabet<String> getAlphabet() {
        return alphabet;
    }
    // ��дSUL�ӿں������ƶ�ϵͳ��������
    @Override
    public String step(String symbol) {
        String result = null;
        try {
            result = vpn.processSymbol(symbol);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }
    // ��дSUL�ӿں�������ʼ��Ŀ��ϵͳ
    @Override
    public void pre() {
        try {
            vpn.reset();
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }
    // ��дSUL�ӿں���������Ŀ��ϵͳ
    @Override
    public void post() {
    }
}
