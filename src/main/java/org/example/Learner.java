package org.example;

import de.learnlib.acex.analyzers.AcexAnalyzers;
import de.learnlib.algorithms.dhc.mealy.MealyDHC;
import de.learnlib.algorithms.kv.mealy.KearnsVaziraniMealy;
import de.learnlib.algorithms.lstargeneric.mealy.ExtensibleLStarMealyBuilder;
import de.learnlib.algorithms.malerpnueli.MalerPnueliMealy;
import de.learnlib.algorithms.rivestschapire.RivestSchapireMealy;
import de.learnlib.algorithms.ttt.mealy.TTTLearnerMealy;
import de.learnlib.api.EquivalenceOracle;
import de.learnlib.api.LearningAlgorithm;
import de.learnlib.counterexamples.AcexLocalSuffixFinder;
import de.learnlib.eqtests.basic.RandomWordsEQOracle;
import de.learnlib.eqtests.basic.WMethodEQOracle;
import de.learnlib.eqtests.basic.WpMethodEQOracle;
import de.learnlib.logging.LearnLogger;
import de.learnlib.oracles.CounterOracle;
import de.learnlib.oracles.DefaultQuery;
import de.learnlib.statistics.Counter;
import de.learnlib.statistics.SimpleProfiler;
import net.automatalib.automata.transout.MealyMachine;
import net.automatalib.util.graphs.dot.GraphDOT;
import net.automatalib.words.Word;
import net.automatalib.words.impl.SimpleAlphabet;

import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Random;
import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.SimpleFormatter;

public class Learner {
    public final static String RESOURCES_ROOT = "D:/Workspace/Maven/VPNLearner/src/main/resources";

    LearnerConfig config;
    VPNLearnerSUT sut;
    SimpleAlphabet<String> alphabet;

    VPNOracle<String, String> vpnMemOracle;
    CounterOracle.MealyCounterOracle<String, String> statsMemOracle;
    CounterOracle.MealyCounterOracle<String, String> statsCachedMemOracle;
    LearningAlgorithm<MealyMachine<?, String, ?, String>, String, Word<String>> learningAlgorithm;

    VPNOracle<String, String> vpnEqOracle;
    CounterOracle.MealyCounterOracle<String, String> statsEqOracle;
    CounterOracle.MealyCounterOracle<String, String> statsCachedEqOracle;
    EquivalenceOracle<MealyMachine<?, String, ?, String>, String, Word<String>> equivalenceAlgorithm;

    public Learner(LearnerConfig config) throws Exception {
        this.config = config;

        Path path = Paths.get(config.output_dir);
        if(Files.notExists(path)) {
            Files.createDirectories(path);
        }

        configureLogging(config.output_dir);

        LearnLogger log = LearnLogger.getLogger(Learner.class.getSimpleName());
        log.log(Level.INFO, "日志初始化");

        sut = new VPNLearnerSUT(config);
        alphabet = sut.getAlphabet();

        loadLearningAlgorithm(config.learning_algorithm, alphabet, sut);
        loadEquivalenceAlgorithm(config.equivalence_algorithm, sut);
    }

    private void loadLearningAlgorithm(String algorithm, SimpleAlphabet<String> alphabet, VPNLearnerSUT sut) throws Exception {
        // 配置 Oracle 输出日志信息
        vpnMemOracle = new VPNOracle<>(sut, LearnLogger.getLogger("learning_queries"));
        // 计数
        statsMemOracle = new CounterOracle.MealyCounterOracle<>(vpnMemOracle, "membership queries to SUL");
        // 设置缓存
        statsCachedMemOracle = new CounterOracle.MealyCounterOracle<>(statsMemOracle, "membership queries to cache");

        switch(algorithm.toLowerCase()) {
            case "lstar":
                learningAlgorithm = new ExtensibleLStarMealyBuilder<String, String>().withAlphabet(alphabet).withOracle(statsCachedMemOracle).create();
                break;

            case "dhc":
                learningAlgorithm = new MealyDHC<>(alphabet, statsCachedMemOracle);
                break;

            case "kv":
                learningAlgorithm = new KearnsVaziraniMealy<>(alphabet, statsCachedMemOracle, true, AcexAnalyzers.BINARY_SEARCH);
                break;

            case "ttt":
                AcexLocalSuffixFinder suffixFinder = new AcexLocalSuffixFinder(AcexAnalyzers.BINARY_SEARCH, true, "Analyzer");
                learningAlgorithm = new TTTLearnerMealy<>(alphabet, statsCachedMemOracle, suffixFinder);
                break;

            case "mp":
                learningAlgorithm = new MalerPnueliMealy<>(alphabet, statsCachedMemOracle);
                break;

            case "rs":
                learningAlgorithm = new RivestSchapireMealy<>(alphabet, statsCachedMemOracle);
                break;

            default:
                throw new Exception("Unknown learning algorithm " + config.learning_algorithm);
        }
    }

    private void loadEquivalenceAlgorithm(String algorithm, VPNLearnerSUT sut) throws Exception {
        vpnEqOracle = new VPNOracle<>(sut, LearnLogger.getLogger("equivalence_queries"));
        statsEqOracle = new CounterOracle.MealyCounterOracle<>(vpnEqOracle, "equivalence queries to SUL");
        statsCachedEqOracle = new CounterOracle.MealyCounterOracle<>(statsEqOracle, "equivalence queries to cache");

        switch(algorithm.toLowerCase()) {
            case "wmethod":
                equivalenceAlgorithm = new WMethodEQOracle.MealyWMethodEQOracle<>(config.max_depth, statsCachedEqOracle);
                break;

            case "ruitermethod":
                equivalenceAlgorithm = new RuiterEQOracle.MealyRuiterEQOracle<>(config.max_depth, statsCachedEqOracle);
                break;

            case "wpmethod":
                equivalenceAlgorithm = new WpMethodEQOracle.MealyWpMethodEQOracle<>(config.max_depth, statsCachedEqOracle);
                break;

            case "randomwords":
                equivalenceAlgorithm = new RandomWordsEQOracle.MealyRandomWordsEQOracle<>(statsCachedEqOracle, config.min_length, config.max_length, config.nr_queries, new Random(config.seed));
                break;

            default:
                throw new Exception("Unknown equivalence algorithm " + config.equivalence_algorithm);
        }
    }

    private void configureLogging(String output_dir) throws SecurityException, IOException {
        // 创建 LearnLogger 实例化对象获取 LearnLib 日志
        LearnLogger loggerLearnlib = LearnLogger.getLogger("de.learnlib");
        loggerLearnlib.setLevel(Level.ALL);
        FileHandler fhLearnlibLog = new FileHandler(output_dir + "/learnlib.log");
        loggerLearnlib.addHandler(fhLearnlibLog);
        fhLearnlibLog.setFormatter(new SimpleFormatter());

        // Learner 日志
        LearnLogger loggerLearner = LearnLogger.getLogger(Learner.class.getSimpleName());
        loggerLearner.setLevel(Level.ALL);
        FileHandler fhLearnerLog = new FileHandler(output_dir + "/learner.log");
        loggerLearner.addHandler(fhLearnerLog);
        fhLearnerLog.setFormatter(new SimpleFormatter());

        // 成员查询日志
        LearnLogger loggerLearningQueries = LearnLogger.getLogger("learning_queries");
        loggerLearningQueries.setLevel(Level.ALL);
        FileHandler fhLearningQueriesLog = new FileHandler(output_dir + "/learning_queries.log");
        loggerLearningQueries.addHandler(fhLearningQueriesLog);
        fhLearningQueriesLog.setFormatter(new SimpleFormatter());

        // 等价性查询日志
        LearnLogger loggerEquivalenceQueries = LearnLogger.getLogger("equivalence_queries");
        loggerEquivalenceQueries.setLevel(Level.ALL);
        FileHandler fhEquivalenceQueriesLog = new FileHandler(output_dir + "/equivalence_queries.log");
        loggerEquivalenceQueries.addHandler(fhEquivalenceQueriesLog);
        fhEquivalenceQueriesLog.setFormatter(new SimpleFormatter());
    }

    // 打印模型
    public static void writeDotModel(MealyMachine<?, String, ?, String> model, SimpleAlphabet<String> alphabet, String filename) throws IOException {
        File dotFile = new File(filename);
        PrintStream psDotFile = new PrintStream(dotFile);
        GraphDOT.write(model, alphabet, psDotFile);
        psDotFile.close();
        Runtime.getRuntime().exec("dot -Tpdf -O " + filename);
    }

    // 学习
    public void learn() throws IOException {
        LearnLogger log = LearnLogger.getLogger(Learner.class.getSimpleName());

        log.log(Level.INFO, "学习算法：" + learningAlgorithm.getClass().getSimpleName());
        log.log(Level.INFO, "一致性测试算法：" + equivalenceAlgorithm.getClass().getSimpleName());
        log.log(Level.INFO, "开始学习...");

        SimpleProfiler.start("总时间");
        boolean learning = true;
        Counter round = new Counter("Rounds", "");
        round.increment();
        log.logPhase("第" + round.getCount() + "轮开始");
        SimpleProfiler.start("学习");
        learningAlgorithm.startLearning();
        SimpleProfiler.stop("学习");
        // 获得假设模型
        MealyMachine<?, String, ?, String> hypothesis = learningAlgorithm.getHypothesisModel();

        while(learning) {
            // 输出当前结果
            writeDotModel(hypothesis, alphabet, config.output_dir + "/hypothesis_" + round.getCount() + ".dot");

            // 利用等价查询寻找反例
            SimpleProfiler.start("查找反例");
            DefaultQuery<String, Word<String>> counterExample = equivalenceAlgorithm.findCounterExample(hypothesis, alphabet);
            SimpleProfiler.stop("查找反例");

            if(counterExample == null) {
                // 未找到反例，说明模型等价结束学习接受模型
                learning = false;

                // 输出最终结果
                writeDotModel(hypothesis, alphabet, config.output_dir + "/learnedModel.dot");
            }
            else {
                // 存在反例，进行下一轮 Membership 查询
                log.logCounterexample("反例：" + counterExample);
                round.increment();
                log.logPhase("第 " + round.getCount() + " 轮开始");

                SimpleProfiler.start("学习");
                learningAlgorithm.refineHypothesis(counterExample);
                SimpleProfiler.stop("学习");

                hypothesis = learningAlgorithm.getHypothesisModel();
            }
        }

        SimpleProfiler.stop("总时间");

        // 输出最终结果
        log.log(Level.INFO, "-------------------------------------------------------");
        log.log(Level.INFO, SimpleProfiler.getResults());
        log.log(Level.INFO, round.getSummary());
        log.log(Level.INFO, statsMemOracle.getStatisticalData().getSummary());
        log.log(Level.INFO, statsCachedMemOracle.getStatisticalData().getSummary());
        log.log(Level.INFO, statsEqOracle.getStatisticalData().getSummary());
        log.log(Level.INFO, statsCachedEqOracle.getStatisticalData().getSummary());
        log.log(Level.INFO, "最终假设模型的状态数：" + hypothesis.size());
    }
}
