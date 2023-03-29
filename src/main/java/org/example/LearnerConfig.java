package org.example;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Properties;

public class LearnerConfig {
    protected Properties properties;
    String output_dir;
    String alphabet;
    public String learning_algorithm;
    public String equivalence_algorithm;
    int max_depth = 10;
    int min_length = 5;
    int max_length = 10;
    int nr_queries = 100;
    int seed = 1;
    String host;
    int port;
    String SSLVersion;
    String options;
    String cert_name;

    // 利用配置文件进行 VPNLearner 初始化
    public LearnerConfig(String filename) throws IOException {
        properties = new Properties();
        InputStream input = Files.newInputStream(Paths.get(filename));
        properties.load(input);
        // 加载配置
        loadProperties();
    }

    private void loadProperties() {
        if(properties.getProperty("output_dir") != null)
            output_dir = properties.getProperty("output_dir");

        if(properties.getProperty("alphabet") != null)
            alphabet = properties.getProperty("alphabet");

        if(properties.getProperty("learning_algorithm").equalsIgnoreCase("lstar")
                || properties.getProperty("learning_algorithm").equalsIgnoreCase("dhc")
                || properties.getProperty("learning_algorithm").equalsIgnoreCase("kv")
                || properties.getProperty("learning_algorithm").equalsIgnoreCase("ttt")
                || properties.getProperty("learning_algorithm").equalsIgnoreCase("mp")
                || properties.getProperty("learning_algorithm").equalsIgnoreCase("rs"))
            learning_algorithm = properties.getProperty("learning_algorithm").toLowerCase();

        if(properties.getProperty("equivalence_algorithm").equalsIgnoreCase("wmethod")
                || properties.getProperty("equivalence_algorithm").equalsIgnoreCase("ruitermethod")
                || properties.getProperty("equivalence_algorithm").equalsIgnoreCase("wpmethod")
                || properties.getProperty("equivalence_algorithm").equalsIgnoreCase("randomwords"))
            equivalence_algorithm = properties.getProperty("equivalence_algorithm").toLowerCase();

        if(properties.getProperty("max_depth") != null)
            max_depth = Integer.parseInt(properties.getProperty("max_depth"));

        if(properties.getProperty("min_length") != null)
            min_length = Integer.parseInt(properties.getProperty("min_length"));

        if(properties.getProperty("max_length") != null)
            max_length = Integer.parseInt(properties.getProperty("max_length"));

        if(properties.getProperty("nr_queries") != null)
            nr_queries = Integer.parseInt(properties.getProperty("nr_queries"));

        if(properties.getProperty("seed") != null)
            seed = Integer.parseInt(properties.getProperty("seed"));

        if(properties.getProperty("ssl_version") != null)
            SSLVersion = properties.getProperty("ssl_version");

        if(properties.getProperty("options") != null)
            options = properties.getProperty("options");

        if(properties.getProperty("host") != null)
            host = properties.getProperty("host");

        if(properties.getProperty("port") != null)
            port = Integer.parseInt(properties.getProperty("port"));

        if(properties.getProperty("cert_name") != null)
            cert_name = properties.getProperty("cert_name");
    }
}
