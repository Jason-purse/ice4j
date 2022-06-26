package club.smileboy.app

import org.junit.jupiter.api.Test
import java.net.NetworkInterface
import java.util.*

/**
 * @author FLJ
 * @date 2022/6/22
 * @time 17:18
 * @Description 网卡测试
 */
class NetWorkTests {

    @Test
    fun netWorkUpTest() {
        for (networkInterface in NetworkInterface.getNetworkInterfaces()) {
            println("network interface name ${networkInterface.name} , display name: ${networkInterface.displayName} active status: ${networkInterface.isUp}")
        }
    }

    @Test
    fun findLinkedLocalAddressTest() {

        // 链路本地地址（Link-local address），又称连结本地位址是计算机网络中一类特殊的地址， 它仅供于在网段，或广播域中的主机相互通信使用。这类主机通常不需要外部互联网服务
        for (networkInterface in NetworkInterface.getNetworkInterfaces()) {
            for (interfaceAddress in networkInterface.interfaceAddresses) {
                println("network interface address ${interfaceAddress.address}")
            }

            for (inetAddress in networkInterface.inetAddresses) {
                if(inetAddress.isLinkLocalAddress) {
                    println("inetAddress is link local address , is $inetAddress hostAddress is ${inetAddress.hostAddress}")
                }
            }

            println("inetAddresses of network interface ")
        }

    }
}
