package kr.eumsoft.securitypro.core.net

/**
 * TUN 장치에서 읽은 IPv4/IPv6 UDP 패킷의 파싱/생성.
 *
 * VPN 은 DNS(UDP/53)만 처리하므로, DNS 가 아닌 패킷은 [UdpPacketInfo.isDnsQuery] 로
 * 걸러 상위 계층에서 폐기/통계 처리한다. TCP DNS 는 지원하지 않는다(문서화된 제한).
 */
data class UdpPacketInfo(
    val ipv6: Boolean,
    val sourceAddress: ByteArray,
    val destinationAddress: ByteArray,
    val sourcePort: Int,
    val destinationPort: Int,
    val udpLength: Int,
    /** 전체 IP 패킷 길이(헤더 포함). */
    val totalLength: Int,
    val payload: ByteArray,
) {
    val isDnsQuery: Boolean get() = destinationPort == 53
}

object IpPackets {

    const val IPPROTO_UDP = 17
    const val DNS_PORT = 53

    /** TUN 패킷을 UDP 로 해석한다. 실패하면 null. */
    fun parseUdp(packet: ByteArray, length: Int = packet.size): UdpPacketInfo? {
        if (length < 1 || length > packet.size) return null
        return when (packet[0].toInt() ushr 4) {
            4 -> parseIpv4(packet, length)
            6 -> parseIpv6(packet, length)
            else -> null
        }
    }

    private fun parseIpv4(packet: ByteArray, length: Int): UdpPacketInfo? {
        if (length < 28) return null
        val ihl = (packet[0].toInt() and 0x0F) * 4
        if (ihl < 20 || ihl > length) return null
        if (packet[9].toInt() and 0xFF != IPPROTO_UDP) return null
        val totalLength = ((packet[2].toInt() and 0xFF) shl 8) or (packet[3].toInt() and 0xFF)
        if (totalLength < ihl + 8 || totalLength > length) return null
        // 단편화된 패킷은 재조립하지 않는다(오프셋 0 이 아니면 버린다).
        val fragField = ((packet[6].toInt() and 0xFF) shl 8) or (packet[7].toInt() and 0xFF)
        if (fragField and 0x1FFF != 0) return null
        val src = packet.copyOfRange(12, 16)
        val dst = packet.copyOfRange(16, 20)
        val udpOffset = ihl
        val srcPort = ((packet[udpOffset].toInt() and 0xFF) shl 8) or (packet[udpOffset + 1].toInt() and 0xFF)
        val dstPort = ((packet[udpOffset + 2].toInt() and 0xFF) shl 8) or (packet[udpOffset + 3].toInt() and 0xFF)
        val udpLength = ((packet[udpOffset + 4].toInt() and 0xFF) shl 8) or (packet[udpOffset + 5].toInt() and 0xFF)
        if (udpLength < 8 || udpOffset + udpLength > totalLength) return null
        val payload = packet.copyOfRange(udpOffset + 8, udpOffset + udpLength)
        return UdpPacketInfo(
            ipv6 = false,
            sourceAddress = src,
            destinationAddress = dst,
            sourcePort = srcPort,
            destinationPort = dstPort,
            udpLength = udpLength,
            totalLength = totalLength,
            payload = payload,
        )
    }

    private fun parseIpv6(packet: ByteArray, length: Int): UdpPacketInfo? {
        if (length < 48) return null
        if (packet[6].toInt() and 0xFF != IPPROTO_UDP) return null // 확장 헤더 미지원
        val payloadLength = ((packet[4].toInt() and 0xFF) shl 8) or (packet[5].toInt() and 0xFF)
        val totalLength = 40 + payloadLength
        if (totalLength > length || payloadLength < 8) return null
        val src = packet.copyOfRange(8, 24)
        val dst = packet.copyOfRange(24, 40)
        val udpOffset = 40
        val srcPort = ((packet[udpOffset].toInt() and 0xFF) shl 8) or (packet[udpOffset + 1].toInt() and 0xFF)
        val dstPort = ((packet[udpOffset + 2].toInt() and 0xFF) shl 8) or (packet[udpOffset + 3].toInt() and 0xFF)
        val udpLength = ((packet[udpOffset + 4].toInt() and 0xFF) shl 8) or (packet[udpOffset + 5].toInt() and 0xFF)
        if (udpLength < 8 || udpOffset + udpLength > totalLength) return null
        val payload = packet.copyOfRange(udpOffset + 8, udpOffset + udpLength)
        return UdpPacketInfo(
            ipv6 = true,
            sourceAddress = src,
            destinationAddress = dst,
            sourcePort = srcPort,
            destinationPort = dstPort,
            udpLength = udpLength,
            totalLength = totalLength,
            payload = payload,
        )
    }

    /** 앱으로 돌려보낼 IPv4 UDP 패킷 생성(체크섬 포함). */
    fun buildIpv4Udp(
        sourceAddress: ByteArray,
        destinationAddress: ByteArray,
        sourcePort: Int,
        destinationPort: Int,
        payload: ByteArray,
        ttl: Int = 64,
        identification: Int = 0,
    ): ByteArray {
        require(sourceAddress.size == 4) { "IPv4 주소는 4바이트" }
        require(destinationAddress.size == 4) { "IPv4 주소는 4바이트" }
        val udpLength = 8 + payload.size
        val totalLength = 20 + udpLength
        val packet = ByteArray(totalLength)
        packet[0] = 0x45
        packet[1] = 0
        packet[2] = ((totalLength shr 8) and 0xFF).toByte()
        packet[3] = (totalLength and 0xFF).toByte()
        packet[4] = ((identification shr 8) and 0xFF).toByte()
        packet[5] = (identification and 0xFF).toByte()
        packet[6] = 0x40 // DF
        packet[7] = 0
        packet[8] = ttl.toByte()
        packet[9] = IPPROTO_UDP.toByte()
        // checksum(10-11) 는 아래에서 계산
        sourceAddress.copyInto(packet, 12)
        destinationAddress.copyInto(packet, 16)
        val ipChecksum = Checksums.checksum(packet, 0, 20)
        packet[10] = ((ipChecksum shr 8) and 0xFF).toByte()
        packet[11] = (ipChecksum and 0xFF).toByte()

        writeUdpHeader(packet, 20, sourcePort, destinationPort, udpLength, payload)
        val udpChecksum = Checksums.udpChecksum(
            ipv6 = false,
            srcAddress = sourceAddress,
            dstAddress = destinationAddress,
            udpSegment = packet.copyOfRange(20, 20 + udpLength),
            udpLength = udpLength,
        )
        packet[26] = ((udpChecksum shr 8) and 0xFF).toByte()
        packet[27] = (udpChecksum and 0xFF).toByte()
        return packet
    }

    /** 앱으로 돌려보낼 IPv6 UDP 패킷 생성(체크섬 포함). */
    fun buildIpv6Udp(
        sourceAddress: ByteArray,
        destinationAddress: ByteArray,
        sourcePort: Int,
        destinationPort: Int,
        payload: ByteArray,
        hopLimit: Int = 64,
    ): ByteArray {
        require(sourceAddress.size == 16) { "IPv6 주소는 16바이트" }
        require(destinationAddress.size == 16) { "IPv6 주소는 16바이트" }
        val udpLength = 8 + payload.size
        val packet = ByteArray(40 + udpLength)
        packet[0] = 0x60.toByte()
        packet[1] = 0
        packet[2] = 0
        packet[3] = 0
        packet[4] = ((udpLength shr 8) and 0xFF).toByte()
        packet[5] = (udpLength and 0xFF).toByte()
        packet[6] = IPPROTO_UDP.toByte()
        packet[7] = hopLimit.toByte()
        sourceAddress.copyInto(packet, 8)
        destinationAddress.copyInto(packet, 24)
        writeUdpHeader(packet, 40, sourcePort, destinationPort, udpLength, payload)
        val udpChecksum = Checksums.udpChecksum(
            ipv6 = true,
            srcAddress = sourceAddress,
            dstAddress = destinationAddress,
            udpSegment = packet.copyOfRange(40, 40 + udpLength),
            udpLength = udpLength,
        )
        packet[46] = ((udpChecksum shr 8) and 0xFF).toByte()
        packet[47] = (udpChecksum and 0xFF).toByte()
        return packet
    }

    private fun writeUdpHeader(
        packet: ByteArray,
        offset: Int,
        sourcePort: Int,
        destinationPort: Int,
        udpLength: Int,
        payload: ByteArray,
    ) {
        packet[offset] = ((sourcePort shr 8) and 0xFF).toByte()
        packet[offset + 1] = (sourcePort and 0xFF).toByte()
        packet[offset + 2] = ((destinationPort shr 8) and 0xFF).toByte()
        packet[offset + 3] = (destinationPort and 0xFF).toByte()
        packet[offset + 4] = ((udpLength shr 8) and 0xFF).toByte()
        packet[offset + 5] = (udpLength and 0xFF).toByte()
        payload.copyInto(packet, offset + 8)
    }

    /** IPv4 주소 문자열 → 4바이트. */
    fun parseIpv4(text: String): ByteArray? {
        val parts = text.split('.')
        if (parts.size != 4) return null
        val bytes = ByteArray(4)
        parts.forEachIndexed { index, part ->
            val value = part.toIntOrNull() ?: return null
            if (value !in 0..255) return null
            bytes[index] = value.toByte()
        }
        return bytes
    }

    /** IPv6 주소 문자열 → 16바이트(축약형 `::` 지원). */
    fun parseIpv6(text: String): ByteArray? {
        var input = text.trim()
        if (input.isEmpty()) return null
        // IPv4-mapped 형태는 지원하지 않는다.
        if (input.contains('.')) return null
        if (input.contains(":::")) return null
        if (input.count { it == ':' } > 8 && !input.contains("::")) return null
        val hasCompression = input.contains("::")
        val head: List<String>
        val tail: List<String>
        if (hasCompression) {
            val idx = input.indexOf("::")
            head = input.substring(0, idx).split(':').filter { it.isNotEmpty() }
            tail = input.substring(idx + 2).split(':').filter { it.isNotEmpty() }
        } else {
            head = input.split(':').filter { it.isNotEmpty() }
            tail = emptyList()
        }
        if (head.size + tail.size > 8) return null
        val groups = ArrayList<String>(8)
        groups += head
        if (hasCompression) {
            repeat(8 - head.size - tail.size) { groups += "0" }
        }
        groups += tail
        if (groups.size != 8) return null
        val bytes = ByteArray(16)
        groups.forEachIndexed { index, group ->
            val value = group.toIntOrNull(16) ?: return null
            if (value !in 0..0xFFFF) return null
            bytes[index * 2] = ((value shr 8) and 0xFF).toByte()
            bytes[index * 2 + 1] = (value and 0xFF).toByte()
        }
        return bytes
    }

    fun formatIpv4(address: ByteArray): String =
        address.joinToString(".") { (it.toInt() and 0xFF).toString() }

    fun formatIpv6(address: ByteArray): String {
        if (address.size != 16) return "?"
        val groups = (0 until 8).map {
            (((address[it * 2].toInt() and 0xFF) shl 8) or (address[it * 2 + 1].toInt() and 0xFF))
                .toString(16)
        }
        return groups.joinToString(":")
    }
}
