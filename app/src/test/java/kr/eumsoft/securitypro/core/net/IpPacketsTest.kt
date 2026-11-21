package kr.eumsoft.securitypro.core.net

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class IpPacketsTest {

    @Test
    fun `IPv4 UDP 패킷을 만들고 다시 파싱한다`() {
        val payload = byteArrayOf(1, 2, 3, 4, 5)
        val packet = IpPackets.buildIpv4Udp(
            sourceAddress = IpPackets.parseIpv4("10.111.222.2")!!,
            destinationAddress = IpPackets.parseIpv4("10.111.222.1")!!,
            sourcePort = 53,
            destinationPort = 40000,
            payload = payload,
        )
        val parsed = IpPackets.parseUdp(packet)
        assertNotNull(parsed)
        assertEquals(53, parsed!!.sourcePort)
        assertEquals(40000, parsed.destinationPort)
        assertEquals(false, parsed.ipv6)
        assertArrayEquals(payload, parsed.payload)
        assertTrue(parsed.isDnsQuery.not())
    }

    @Test
    fun `IPv4 헤더 체크섬이 유효하다`() {
        val packet = IpPackets.buildIpv4Udp(
            sourceAddress = IpPackets.parseIpv4("1.2.3.4")!!,
            destinationAddress = IpPackets.parseIpv4("5.6.7.8")!!,
            sourcePort = 53,
            destinationPort = 53,
            payload = ByteArray(12) { it.toByte() },
        )
        // 체크섬 필드를 포함해 전체 합이 0xFFFF 여야 한다.
        val sum = Checksums.onesComplementSum(packet, 0, 20)
        assertEquals(0xFFFFL, sum)
    }

    @Test
    fun `IPv6 UDP 패킷과 체크섬`() {
        val src = IpPackets.parseIpv6("fd00:1:0:e222::2")!!
        val dst = IpPackets.parseIpv6("fd00:1:0:e222::1")!!
        val payload = ByteArray(20) { (it * 3).toByte() }
        val packet = IpPackets.buildIpv6Udp(src, dst, 53, 12345, payload)
        val parsed = IpPackets.parseUdp(packet)
        assertNotNull(parsed)
        assertTrue(parsed!!.ipv6)
        assertEquals(12345, parsed.destinationPort)
        assertArrayEquals(payload, parsed.payload)
        // UDP 체크섬은 0 이 아니어야 한다.
        val checksum = ((packet[46].toInt() and 0xFF) shl 8) or (packet[47].toInt() and 0xFF)
        assertTrue(checksum != 0)
    }

    @Test
    fun `TCP 나 단편화 패킷은 UDP 로 해석하지 않는다`() {
        val packet = IpPackets.buildIpv4Udp(
            IpPackets.parseIpv4("1.1.1.1")!!,
            IpPackets.parseIpv4("2.2.2.2")!!,
            53,
            53,
            byteArrayOf(1),
        ).copyOf()
        packet[9] = 6 // TCP
        assertNull(IpPackets.parseUdp(packet))

        val fragmented = IpPackets.buildIpv4Udp(
            IpPackets.parseIpv4("1.1.1.1")!!,
            IpPackets.parseIpv4("2.2.2.2")!!,
            53,
            53,
            byteArrayOf(1),
        ).copyOf()
        fragmented[7] = 0x10 // fragment offset 필드
        assertNull(IpPackets.parseUdp(fragmented))
    }

    @Test
    fun `IPv6 주소 파싱`() {
        assertArrayEquals(
            byteArrayOf(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1),
            IpPackets.parseIpv6("::1"),
        )
        val full = IpPackets.parseIpv6("2001:0db8:0000:0000:0000:ff00:0042:8329")!!
        assertEquals("2001:db8:0:0:0:ff00:42:8329", IpPackets.formatIpv6(full))
        assertNull(IpPackets.parseIpv6(":::1"))
        assertNull(IpPackets.parseIpv6("zzzz::1"))
    }

    @Test
    fun `잘린 패킷은 null`() {
        val packet = IpPackets.buildIpv4Udp(
            IpPackets.parseIpv4("1.1.1.1")!!,
            IpPackets.parseIpv4("2.2.2.2")!!,
            53,
            53,
            ByteArray(10),
        )
        assertNull(IpPackets.parseUdp(packet.copyOf(17)))
        assertNull(IpPackets.parseUdp(ByteArray(0)))
    }
}
