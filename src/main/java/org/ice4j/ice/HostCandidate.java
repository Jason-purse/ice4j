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

import java.net.*;

import org.ice4j.*;
import org.ice4j.socket.*;

/**
 * <tt>HostCandidate</tt>s are obtained by binding to a specific port from an
 * IP address on the host that is running us. This includes IP addresses on
 * physical interfaces and logical ones, such as ones obtained through
 * Virtual Private Networks (VPNs), Mobile IPv6, Realm Specific IP (RSIP) etc.
 * <p>
 * At this point this class only supports UDP candidates. Implementation of
 * support for other transport protocols should mean that this class should
 * become abstract and some transport specific components like to socket for
 * example should be brought down the inheritance chain.
 * </p>
 *
 *
 * HostCandidate 能够通过绑定这个主机的IP 地址上的特定端口(根据正在运行这个程序的主机) 获取 .....
 * 可以包含物理网卡 / 逻辑网卡上的IP 地址,例如包含 VPN(虚拟私有网络 Virtual Private Networks), 移动IPV6 / 特定身份IP(Realm Specific IP) ..
 * 此时这个类仅仅支持 UDP 候选 ... 对于其他传输协议的支持实现 应该将此类作为一个抽象 以及某些特定的传输组件例如 socket(举个例子因为打破这个继承链) ...
 *
 * @author Emil Ivov
 */
public class HostCandidate extends LocalCandidate
{

    /**
     * If this is a local candidate the field contains the socket that is
     * actually associated with the candidate.
     * 如果这是一个本地候选者(这个字段包含了一个与此候选者联系的socket) ...
     */
    private final IceSocketWrapper socket;

    /**
     * Creates a HostCandidate for the specified transport address.
     *
     * @param socket the {@link DatagramSocket} that communication associated
     * with this <tt>Candidate</tt> will be going through.
     * @param parentComponent the <tt>Component</tt> that this candidate
     * belongs to.
     */
    public HostCandidate(IceSocketWrapper socket,
                         Component        parentComponent)
    {
        this(socket,
             parentComponent,
             Transport.UDP);
    }

    /**
     * Creates a HostCandidate for the specified transport address.
     * 组件可以有一个候选对(存在之后,则无法被其他的组件使用) ..
     * @param transportAddress the transport address for the new
     * <tt>HostCandidate</tt>.
     * @param parentComponent the <tt>Component</tt> that this candidate
     * belongs to.
     */
    public HostCandidate(
            TransportAddress transportAddress,
            Component parentComponent)
    {
        super(transportAddress,
              parentComponent,
              CandidateType.HOST_CANDIDATE,
              CandidateExtendedType.HOST_CANDIDATE,
              null);

        this.socket = null;
        setBase(this);
    }

    /**
     * Creates a HostCandidate for the specified transport address.
     *
     * @param socket the {@link DatagramSocket} that communication associated
     * with this <tt>Candidate</tt> will be going through.
     * @param parentComponent the <tt>Component</tt> that this candidate
     * belongs to.
     * @param transport transport protocol used
     */
    public HostCandidate(IceSocketWrapper socket,
                         Component        parentComponent,
                         Transport        transport)
    {
        super(new TransportAddress(socket.getLocalAddress(),
                        socket.getLocalPort(), transport),
              parentComponent,
              CandidateType.HOST_CANDIDATE,
              CandidateExtendedType.HOST_CANDIDATE,
              null);

        this.socket = socket;
        setBase(this);
    }

    /**
     * Creates a new <tt>StunDatagramPacketFilter</tt> which is to capture STUN
     * messages and make them available to the <tt>DatagramSocket</tt> returned
     * by {@link #getStunSocket(TransportAddress)}.
     *
     * @param serverAddress the address of the source we'd like to receive
     * packets from or <tt>null</tt> if we'd like to intercept all STUN packets
     * @return the <tt>StunDatagramPacketFilter</tt> which is to capture STUN
     * messages and make them available to the <tt>DatagramSocket</tt> returned
     * by {@link #getStunSocket(TransportAddress)}
     * @see LocalCandidate#createStunDatagramPacketFilter(TransportAddress)
     */
    @Override
    protected StunDatagramPacketFilter createStunDatagramPacketFilter(
            TransportAddress serverAddress)
    {
        /*
         * Since we support TURN as well, we have to be able to receive TURN
         * messages as well.
         */
        return new TurnDatagramPacketFilter(serverAddress);
    }

    /**
     * {@inheritDoc}
     * SHOULD NOT be used outside ice4j. Only exposed for use in the
     * org.ice4j.socket package.
     */
    @Override
    public IceSocketWrapper getCandidateIceSocketWrapper()
    {
        return socket;
    }
}
