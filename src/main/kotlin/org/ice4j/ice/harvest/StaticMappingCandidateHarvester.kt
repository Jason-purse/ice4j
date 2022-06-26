package org.ice4j.ice.harvest

import org.ice4j.TransportAddress

/**
 * Uses a predefined static mask in order to generate [TransportAddress]es. This harvester is meant for use in
 * situations where servers are deployed behind a NAT or in a DMZ with static port mapping.
 * 使用一个预定义的静态 掩盖 为了生成 TransportAddress ... 这个harvester 打算 使用在服务器部署在NAT 之后 或者 使用静态端口映射的 DMZ(demilitarized zone) ..
 *
 * 每一次 这个 .harvest 方法被调用,那么这个mapping harvester 将会返回 候选者列表(这提供了此组件中的每一个host 候选的掩盖替换 ... 类似于 STUN 服务器) ..
 * 例如:  如果你运行在 192.168.0.1 地址的服务器上,那么 它位于公网IP : 93.184.216.119之后,你能够分配一个主机候选(192.168.0.1/UDP/5000)
 * 这个harvester 将会生成 93.184.216.119/UDP/5000
 * Every time the [.harvest] method is called, the mapping harvester will return a list of candidates that provide
 * masked alternatives for every host candidate in the component. Kind of like a STUN server.
 *
 * Example: You run this on a server with address 192.168.0.1, that is behind a NAT with public IP: 93.184.216.119.
 * You allocate a host candidate 192.168.0.1/UDP/5000. This harvester is going to then generate an address
 * 93.184.216.119/UDP/5000.
 *
 * This harvester is instant and does not introduce any harvesting latency.
 *
 * @author Emil Ivov
 */
class StaticMappingCandidateHarvester @JvmOverloads constructor(
    /** The public address (aka mask - 也有面具的意思) */
    override val mask: TransportAddress,
    /** The local address (aka face - 也有真面目(人脸) ) */
    override val face: TransportAddress,
    name: String? = null,
    matchPort: Boolean = false
) : MappingCandidateHarvester(name ?: "static_mapping", matchPort) {
    override fun toString() = "${javaClass.name}(face=$face, mask=$mask)"
}
