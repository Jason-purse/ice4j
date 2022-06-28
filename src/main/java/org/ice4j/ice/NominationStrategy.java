/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 *
 * Copyright @ 2015 Atlassian Pty Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.ice4j.ice;


/**
 * Contains the nomination strategies currently supported by this
 * implementation's {@link DefaultNominator} class. Applications can either
 * pick one of these strategies or select <tt>NONE</tt> in case they want to
 * handle nominations themselves.
 *
 * 包含了由当前DefaultNominator 所支持的一个提名策略 ...
 * 应用能够要么 抓取这些策略中的其中一个 或者选择   NONE (如果它们想要自己处理提名) ...
 *
 * 这个策略是ice4j自己的概念,并没有在5245中提及 ...
 * <p>
 * Note that NominationStrategies are an ice4j concept and they are not
 * mentioned in RFC 5245.
 *
 * @author Emil Ivov
 */
public enum NominationStrategy
{
    /**
     * Indicates that ice4j's nominator should nominate valid pairs and that
     * the application will be handling this.
     */
    NONE("None"),

    /**
     * The strategy consists in nominating the first candidate pair that's
     * confirmed as valid.
     *
     * 提名第一个有效的pair ..
     */
    NOMINATE_FIRST_VALID("NominateFirstValid"),

    /**
     * 这个策略会寻找最高优先级的 有效pair ...
     * 一旦一个pair 被验证之后,且没有更高级别的pair 更优秀 ... 那么它将被提名 ..
     * 反之 会通过一个timer 进行巡查(如果在timer 超时之后仍然是最优的,那么这个最高优先级的验证的pair 被提名) ...
     * The strategy consists in nominating the highest priority valid pair.
     * Once a pair is validated, if no higher-priority pairs remain outstanding,
     * it is nominated; otherwise, a timer is armed, and if higher-priority
     * pairs are still outstanding after the timeout, the highest-priority validated
     * pair is nominated.
     */
    NOMINATE_HIGHEST_PRIO("NominateHighestPriority"),

    /**
     * The strategy consists in nominating the first host or server reflexive
     * that's confirmed as valid pair. When a relayed candidate pair is
     * validated first, a timer is armed and only if no host or server
     * reflexive pair gets validated prior to timeout, the relayed ones
     * gets nominated.
     *
     * 这个策略 由 提名第一个中继的候选pair 为第一个有效的,一个timer 将会被启动(如果没有host 或者 server reflexive pair在超时之前得到验证
     * 那么这个中继的pair 将会被提名) ...
     */
    NOMINATE_FIRST_HOST_OR_REFLEXIVE_VALID("NominateFirstHostOrReflexiveValid"),

    /**
     * The strategy consists in nominating the pair that showed the best
     * shortest round trip time once all checks in a list completed.
     *
     * 根据所完成列表进行一次检查,拿取最短往返时间的 pair 提名 ...
     */
    NOMINATE_BEST_RTT("NominateBestRTT");

    /**
     * The name of this strategy.
     */
    private final String strategyName;

    /**
     * Creates a <tt>NominationStrategy</tt> instance with the specified name.
     *
     * @param name the name of the <tt>NominationStrategy</tt> that we'd like
     * to create.
     */
    private NominationStrategy(String name)
    {
        this.strategyName = name;
    }

    /**
     * Returns the name of this <tt>NominationStrategy</tt>.
     *
     * @return the name of this <tt>NominationStrategy</tt>.
     */
    @Override
    public String toString()
    {
        return strategyName;
    }

    /**
     * @return the {@link NominationStrategy} with name equal to the given
     * string, or {@code null} if there is no such strategy.
     * @param string the name of the strategy.
     */
    public static NominationStrategy fromString(String string)
    {
        for (NominationStrategy strategy : NominationStrategy.values())
        {
            if (strategy.strategyName.equals(string))
                return strategy;
        }
        return null;
    }
}
