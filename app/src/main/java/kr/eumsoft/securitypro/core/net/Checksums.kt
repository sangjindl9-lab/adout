package kr.eumsoft.securitypro.core.net

/**
 * 인터넷 체크섬(1의 보수 합) 계산. 패킷 경계/홀수 길이를 안전하게 처리한다.
 */
object Checksums {

    fun onesComplementSum(data: ByteArray, offset: Int, length: Int, initial: Long = 0): Long {
        var sum = initial
        var i = offset
        val end = offset + length
        while (i + 1 < end) {
            sum += (((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)).toLong()
            i += 2
        }
        if (i < end) {
            sum += ((data[i].toInt() and 0xFF) shl 8).toLong()
        }
        while (sum shr 16 != 0L) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }
        return sum
    }

    /** 16비트 필드에 쓸 체크섬(1의 보수). */
    fun checksum(data: ByteArray, offset: Int, length: Int): Int =
        (onesComplementSum(data, offset, length).inv() and 0xFFFF).toInt()

    /** 의사 헤더를 포함한 UDP 체크섬. IPv4 는 0 을 허용하지만 일관되게 계산한다. */
    fun udpChecksum(
        ipv6: Boolean,
        srcAddress: ByteArray,
        dstAddress: ByteArray,
        udpSegment: ByteArray,
        udpLength: Int,
    ): Int {
        var sum = 0L
        sum = onesComplementSum(srcAddress, 0, srcAddress.size, sum)
        sum = onesComplementSum(dstAddress, 0, dstAddress.size, sum)
        if (ipv6) {
            sum += ((udpLength ushr 16) and 0xFFFF).toLong()
            sum += (udpLength and 0xFFFF).toLong()
            sum += 17L // next header = UDP
        } else {
            sum += 17L
            sum += (udpLength and 0xFFFF).toLong()
        }
        sum = onesComplementSum(udpSegment, 0, udpLength, sum)
        var folded = sum
        while (folded shr 16 != 0L) {
            folded = (folded and 0xFFFF) + (folded shr 16)
        }
        val result = (folded.inv() and 0xFFFF).toInt()
        // 결과가 0 이면 0xFFFF 로 표기(UDP 규칙)
        return if (result == 0) 0xFFFF else result
    }
}
