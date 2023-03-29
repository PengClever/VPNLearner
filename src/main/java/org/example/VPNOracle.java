package org.example;

import de.learnlib.api.MembershipOracle.MealyMembershipOracle;
import de.learnlib.api.Query;
import de.learnlib.logging.LearnLogger;
import net.automatalib.words.Word;
import net.automatalib.words.WordBuilder;

import java.util.Collection;

public class VPNOracle<I, D> implements MealyMembershipOracle<I, D> {
    LearnLogger logger;
    VPNLearnerSUT sul;
    public VPNOracle(VPNLearnerSUT sul, LearnLogger logger) {
        this.sul = sul;
        this.logger = logger;
    }
    @Override
    public Word<D> answerQuery(Word<I> prefix, Word<I> suffix) {
        WordBuilder<D> wbPrefix = new WordBuilder<>(prefix.length());
        WordBuilder<D> wbSuffix = new WordBuilder<>(suffix.length());

        this.sul.pre();
        try {
            // 处理前缀
            for(I sym : prefix) {
                wbPrefix.add((D) this.sul.step((String) sym));
            }

            // 处理后缀
            for(I sym : suffix) {
                wbSuffix.add((D) this.sul.step((String) sym));
            }

            logger.logQuery("[" + prefix + " | " + suffix +  " / " + wbPrefix.toWord() + " | " + wbSuffix.toWord() + "]");
        }
        finally {
            sul.post();
        }

        return wbSuffix.toWord();
    }
    public void processQueries(Collection<? extends Query<I, Word<D>>> queries) {
        for (Query<I,Word<D>> q : queries) {
            Word<D> output = answerQuery(q.getPrefix(), q.getSuffix());
            q.answer(output);
        }
    }
}
