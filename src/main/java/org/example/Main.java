package org.example;

public class Main {
    public static void main(String[] args) throws Exception {
        // 配置参数
        LearnerConfig config = new LearnerConfig(Learner.RESOURCES_ROOT + "/config/server.properties");
        // 创建学习者
        Learner learner = new Learner(config);
        // 学习状态机
        learner.learn();
    }
}