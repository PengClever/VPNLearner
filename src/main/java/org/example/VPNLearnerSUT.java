package org.example;

import de.learnlib.api.SUL;
import net.automatalib.words.impl.SimpleAlphabet;

import java.util.Arrays;

public class VPNLearnerSUT implements SUL<String, String> {
    SimpleAlphabet<String> alphabet;
    VPNService vpn;

    // 初始化 SUT
    public VPNLearnerSUT(LearnerConfig config) throws Exception {
        alphabet = new SimpleAlphabet<>(Arrays.asList(config.alphabet.split(" ")));
        vpn = new VPNService(config);
    }
    public SimpleAlphabet<String> getAlphabet() {
        return alphabet;
    }
    // 重写SUL接口函数，推动系统向下运行
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
    // 重写SUL接口函数，初始化目标系统
    @Override
    public void pre() {
        try {
            vpn.reset();
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }
    // 重写SUL接口函数，结束目标系统
    @Override
    public void post() {
    }
}
