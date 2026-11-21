package kr.eumsoft.securitypro.core.net

import kotlinx.coroutines.runBlocking
import kr.eumsoft.securitypro.core.dns.BlockResponseMode
import kr.eumsoft.securitypro.core.dns.DnsAnswer
import kr.eumsoft.securitypro.core.dns.DnsFilterEngine
import kr.eumsoft.securitypro.core.dns.DnsRcode
import kr.eumsoft.securitypro.core.dns.DnsType
import kr.eumsoft.securitypro.core.dns.DnsWire
import kr.eumsoft.securitypro.core.dns.FilterRuleEntry
import kr.eumsoft.securitypro.core.dns.FilterSnapshot
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class DnsTunHandlerTest {

    private val blockRule = FilterRuleEntry(
        domain = "ads.example.com",
        matchSubdomains = true,
        category = "ADS",
        sourceId = 1L,
        rawRule = "||ads.example.com^",
        priority = 100,
    )

    private val engine = DnsFilterEngine.build(FilterSnapshot(rules = listOf(blockRule)))

    private class FakeUpstream(
        private val responseBytes: (ByteArray) -> ByteArray?,
    ) : DnsUpstream {
        var calls = 0
        override val description = "fake"
        override suspend fun resolve(query: ByteArray): ByteArray? {
            calls++
            return responseBytes(query)
        }
    }

    private fun dnsQueryPacket(domain: String, ipv6: Boolean = false, id: Int = 0x2222): ByteArray {
        val query = buildQuery(domain, id)
        return if (ipv6) {
            IpPackets.buildIpv6Udp(
                IpPackets.parseIpv6("fd00:1:0:e222::1")!!,
                IpPackets.parseIpv6("fd00:1:0:e222::2")!!,
                41000,
                53,
                query,
            )
        } else {
            IpPackets.buildIpv4Udp(
                IpPackets.parseIpv4("10.111.222.1")!!,
                IpPackets.parseIpv4("10.111.222.2")!!,
                41000,
                53,
                query,
            )
        }
    }

    private fun buildQuery(domain: String, id: Int): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        out.write((id shr 8) and 0xFF)
        out.write(id and 0xFF)
        out.write(0x01)
        out.write(0)
        out.write(0); out.write(1)
        repeat(6) { out.write(0) }
        out.write(DnsWire.encodeName(domain))
        out.write(0); out.write(1)
        out.write(0); out.write(1)
        return out.toByteArray()
    }

    private fun okResponse(query: ByteArray): ByteArray {
        val parsed = DnsWire.parseQuery(query)!!
        return DnsWire.buildResponse(
            parsed,
            DnsRcode.NO_ERROR,
            listOf(DnsAnswer(DnsType.A, 120, byteArrayOf(93.toByte(), 184.toByte(), 216.toByte(), 34))),
        )
    }

    @Test
    fun `차단 도메인은 NXDOMAIN 으로 응답하고 업스트림을 호출하지 않는다`() = runBlocking {
        val upstream = FakeUpstream { okResponse(it) }
        val events = mutableListOf<DnsEvent>()
        val handler = DnsTunHandler(
            engineProvider = { engine },
            upstream = upstream,
            onEvent = { events += it },
            clock = { 1000L },
        )
        val response = handler.handle(dnsQueryPacket("ads.example.com"))
        assertNotNull(response)
        val info = IpPackets.parseUdp(response!!)!!
        assertEquals(53, info.sourcePort)
        assertEquals(41000, info.destinationPort)
        assertEquals(DnsRcode.NXDOMAIN, DnsWire.rcodeOf(info.payload))
        assertEquals(0, upstream.calls)
        assertEquals(1, events.size)
        assertTrue(events[0].blocked)
        assertEquals("ADS", events[0].category)
    }

    @Test
    fun `허용 도메인은 업스트림 응답을 재포장한다`() = runBlocking {
        val upstream = FakeUpstream { okResponse(it) }
        val handler = DnsTunHandler(engineProvider = { engine }, upstream = upstream)
        val response = handler.handle(dnsQueryPacket("news.example.org"))
        assertNotNull(response)
        val info = IpPackets.parseUdp(response!!)!!
        assertEquals(DnsRcode.NO_ERROR, DnsWire.rcodeOf(info.payload))
        assertEquals(1, upstream.calls)
        assertEquals(93.toByte(), info.payload.takeLast(4)[0])
    }

    @Test
    fun `IPv6 질의도 같은 방식으로 처리한다`() = runBlocking {
        val handler = DnsTunHandler(engineProvider = { engine }, upstream = FakeUpstream { okResponse(it) })
        val response = handler.handle(dnsQueryPacket("ads.example.com", ipv6 = true))
        assertNotNull(response)
        assertTrue(response!![0].toInt() ushr 4 == 6)
        val info = IpPackets.parseUdp(response)!!
        assertEquals(DnsRcode.NXDOMAIN, DnsWire.rcodeOf(info.payload))
    }

    @Test
    fun `업스트림 실패는 SERVFAIL 로 응답한다`() = runBlocking {
        val handler = DnsTunHandler(engineProvider = { engine }, upstream = FakeUpstream { null })
        val response = handler.handle(dnsQueryPacket("news.example.org"))
        val info = IpPackets.parseUdp(response!!)!!
        assertEquals(DnsRcode.SERVFAIL, DnsWire.rcodeOf(info.payload))
    }

    @Test
    fun `DNS 가 아닌 UDP 패킷은 버린다`() = runBlocking {
        val handler = DnsTunHandler(engineProvider = { engine }, upstream = FakeUpstream { okResponse(it) })
        val packet = IpPackets.buildIpv4Udp(
            IpPackets.parseIpv4("10.111.222.1")!!,
            IpPackets.parseIpv4("93.184.216.34")!!,
            40000,
            443,
            ByteArray(10),
        )
        assertNull(handler.handle(packet))
    }

    @Test
    fun `같은 도메인 두 번째 질의는 캐시로 응답한다`() = runBlocking {
        var now = 5_000L
        val upstream = FakeUpstream { okResponse(it) }
        val handler = DnsTunHandler(
            engineProvider = { null },
            upstream = upstream,
            clock = { now },
        )
        handler.handle(dnsQueryPacket("news.example.org"))
        now += 1_000
        val second = handler.handle(dnsQueryPacket("news.example.org"))
        assertNotNull(second)
        assertEquals(1, upstream.calls)
        val info = IpPackets.parseUdp(second!!)!!
        assertEquals(DnsRcode.NO_ERROR, DnsWire.rcodeOf(info.payload))
    }

    @Test
    fun `차단 스위치가 꺼지면 차단하지 않는다`() = runBlocking {
        val upstream = FakeUpstream { okResponse(it) }
        val handler = DnsTunHandler(
            engineProvider = { engine },
            blockingEnabled = { false },
            upstream = upstream,
            responseMode = { BlockResponseMode.NULL_IP },
        )
        val response = handler.handle(dnsQueryPacket("ads.example.com"))
        val info = IpPackets.parseUdp(response!!)!!
        assertEquals(DnsRcode.NO_ERROR, DnsWire.rcodeOf(info.payload))
        assertEquals(1, upstream.calls)
    }

    @Test
    fun `응답 모드를 0_0_0_0 으로 바꿀 수 있다`() = runBlocking {
        val handler = DnsTunHandler(
            engineProvider = { engine },
            upstream = FakeUpstream { okResponse(it) },
            responseMode = { BlockResponseMode.NULL_IP },
        )
        val response = handler.handle(dnsQueryPacket("ads.example.com"))
        val info = IpPackets.parseUdp(response!!)!!
        assertEquals(DnsRcode.NO_ERROR, DnsWire.rcodeOf(info.payload))
        assertTrue(info.payload.takeLast(4).all { it == 0.toByte() })
    }
}
