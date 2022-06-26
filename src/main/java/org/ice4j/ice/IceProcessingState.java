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
 * RFC 5245 mentions that ICE processing across all media streams also has a
 * state associated with it. This state is equal to <tt>Running</tt> while ICE
 * processing is under way. The state is Completed when ICE processing is
 * complete and Failed if it failed without success. For convenience reasons
 * we are also adding two extra states. The first one is the <tt>Waiting</tt>
 * state that reflects the state of an {@link Agent} before it starts
 * processing. This is also an {@link Agent }'s default state. The second one
 * is the "Terminated" state. RFC 5245 says that once ICE processing
 * has reached the Completed state for all peers for media streams using
 * those candidates, the agent SHOULD wait an additional three seconds,
 * and then it MAY cease responding to checks or generating triggered
 * checks on that candidate.  It MAY free the candidate at that time.
 * which reflects the state where an Agent does not need to handle incoming
 * checks any more and is ready for garbage collection. This is the state we
 * refer to with "Terminated".
 *
 * RFC 5245 提到 ICE 处理所有媒体流
 * 这个状态等于 Running (当ICE 正在运行中) ...
 * 等于完成(ICE 处理完成或者失败(如果它没有成功))
 * 为了方便我们也增加了两个额外的状态 , 第一个状态是等待(它在开始处理之前的一个Agent的状态) ..
 * 第二个是 中断状态 (RFC 5245 说一旦ICE 处理已经达到了完成状态(那么所有的peers的媒体流将使用这些候选) ..
 * 这个代理应该等待额外的三秒时间 并且 停止相关的检查 或者生成候选对象的触发检查 ..
 * 此时这个候选也许是自由的(可用的) ..
 * 这反映了 一个代理不需要处理进入的检查并准备好垃圾回收的状态 ... 所以我们指定为中断的 ...状态...
 *
 * @author Emil Ivov
 * @author Lyubomir Marinov
 */
public enum IceProcessingState
{
    /**
     * The state is equal to <tt>Waiting</tt> if ICE processing has not started
     * for the corresponding {@link Agent}.
     */
    WAITING("Waiting"),

    /**
     * The state is equal to <tt>Running</tt> while ICE processing is under way.
     */
    RUNNING("Running"),

    /**
     * The state is Completed when ICE processing is complete.
     */
    COMPLETED("Completed"),

    /**
     * The state is Completed when ICE processing is Failed if processing
     * failed without success.
     */
    FAILED("Failed"),

    /**
     * Once ICE processing has reached the Completed state for all peers for
     * media streams using those candidates, the agent SHOULD wait an
     * additional three seconds, and then it MAY cease responding to checks
     * or generating triggered checks on that candidate.  It MAY free the
     * candidate at that time. This is also when an agent would enter the
     * terminated state.
     */
    TERMINATED("Terminated");

    /**
     * The name of this <tt>IceProcessingState</tt> instance.
     */
    private final String stateName;

    /**
     * Creates an <tt>IceProcessingState</tt> instance with the specified name.
     *
     * @param stateName the name of the <tt>IceProcessingState</tt> instance
     * we'd like to create.
     */
    private IceProcessingState(String stateName)
    {
        this.stateName = stateName;
    }

    /**
     * Returns the name of this <tt>IceProcessingState</tt> (e.g. "Running",
     * "Completed", or "Failed").
     *
     * @return the name of this <tt>IceProcessingState</tt> (e.g. "Running",
     * "Completed", or "Failed").
     */
    @Override
    public String toString()
    {
        return stateName;
    }

    /**
     * Determines whether an {@link Agent} in this state has finished its ICE
     * processing.
     *
     * @return {@code true} if an {@code Agent} in this state has finished its
     * ICE processing; otherwise, {@code false}
     */
    public boolean isOver()
    {
        return
            COMPLETED.equals(this)
                || FAILED.equals(this)
                || TERMINATED.equals(this);
    }

    /**
     * Returns <tt>true</tt> iff the state is one in which a connection
     * has been established, that is either <tt>COMPLETED</tt> or
     * <tt>TERMINATED</tt>.
     *
     * @return <tt>true</tt> iff the state is one in which a connection
     * has been established, that is either <tt>COMPLETED</tt> or
     * <tt>TERMINATED</tt>.
     */
    public boolean isEstablished()
    {
        return this == COMPLETED || this == TERMINATED;
    }
}
