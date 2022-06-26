package club.smileboy.app

import org.ice4j.message.Message
import org.ice4j.stack.TransactionID
import org.junit.jupiter.api.Test

/**
 * @author FLJ
 * @date 2022/6/23
 * @time 11:13
 * @Description 二元操作符 ...
 */
class BinaryOperatorTests {

    @Test
    fun binaryOperator() {

        println("left shift result ${1 shl 8}")
        println(1 shl 8 or (1 shl 8))
        println("0x${(Message.OLD_DATA_INDICATION.code or  0b11).toBigInteger().toString(16)}")

        println(0xFF)
        println(0b11111111)
    }


    @Test
    fun programingInOperator() {

        println("二进制 ${0b11}")
        // 在kotlin 中不支持 8进制 ...
//        println("8进制 ${01223182}")
        println("16进制 ${0x12312}")
    }

    @Test
    fun byteArrayToInt() {

        val value: ByteArray = byteArrayOf(0x12,0x15)

        println("result value ${(value[0].toInt() shl 8) or (value[1].toInt())}")
        println("result value ${(value[0].toInt() shl 8) or (value[1].toInt() and 0xFF) }")


       val one: Byte = -127
        println(one.toInt().toBigInteger().toString(2))
        println(one.toInt() and 0xFF)

        val two: Short = 0xFF

        println("${0x81}")
    }

    @Test
    fun longTests() {

        val value = System.currentTimeMillis();
        val values: ByteArray = ByteArray(6)
        repeat(6) {
            print("${(value shr (it * 8)) and 0xFFL}  ")
            values[it] = ((value shr (it * 8)) and 0xFFL).toByte()
        }

        println()

        println("尝试还原 ............................")
        println("之前的时间毫秒值 $value")
        var result: Long = 0;
        repeat(6) {
            result  = result or ((values[it].toLong() and 0xFFL) shl ((5 -it) * 8))
        }

        var toString = TransactionID.toString(values)
        println("还原结果: $result")
        println("TransactionId结果 ${toString.substring(2).toBigInteger(16)}")
    }
}
