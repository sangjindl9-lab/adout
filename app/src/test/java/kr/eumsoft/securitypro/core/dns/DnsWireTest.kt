package kr.eumsoft.securitypro.core.dns

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class DnsWireTest {

    private fun query(id: Int, name: String, type: Int = DnsType.A): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        out.write((id shr 8) and 0xFF)
        out.write(id and 0xFF)
        out.write(0x01)
        out.write(0x00) // RD=1
        out.write(0)
        out.write(1)
        out.write(0); out.write(0)
        out.write(0); out.write(0)
        out.write(0); out.write(0)
        out.write(DnsWire.encodeName(name))
        out.write((type shr 8) and 0xFF); out.write(type and 0xFF)
        out.write(0); out.write(1)
        return out.toByteArray()
    }

    @Test
    fun `질의를 파싱한다`() {
        val parsed = DnsWire.parseQuery(query(0x1234, "Ads.Example.COM"))
        assertNotNull(parsed)
        assertEquals(0x1234, parsed!!.id)
        assertEquals(1, parsed.questions.size)
        assertEquals("ads.example.com", parsed.questions[0].name)
        assertEquals(DnsType.A, parsed.questions[0].type)
        assertTrue(parsed.isRecursionDesired)
    }

    @Test
    fun `NXDOMAIN 차단 응답을 만든다`() {
        val q = DnsWire.parseQuery(query(7, "blocked.example.com"))!!
        val response = DnsWire.buildBlockResponse(q, BlockResponseMode.NXDOMAIN)
        assertEquals(DnsRcode.NXDOMAIN, DnsWire.rcodeOf(response))
        assertEquals(7, ((response[0].toInt() and 0xFF) shl 8) or (response[1].toInt() and 0xFF))
        // QDCOUNT=1, ANCOUNT=0
        assertEquals(1, ((response[4].toInt() and 0xFF) shl 8) or (response[5].toInt() and 0xFF))
        assertEquals(0, ((response[6].toInt() and 0xFF) shl 8) or (response[7].toInt() and 0xFF))
        // 응답 플래그 QR=1
        assertTrue((response[2].toInt() and 0x80) != 0)
    }

    @Test
    fun `0_0_0_0 차단 응답은 A 레코드를 돌려준다`() {
        val q = DnsWire.parseQuery(query(9, "tracker.example.com"))!!
        val response = DnsWire.buildBlockResponse(q, BlockResponseMode.NULL_IP)
        assertEquals(DnsRcode.NO_ERROR, DnsWire.rcodeOf(response))
        val anCount = ((response[6].toInt() and 0xFF) shl 8) or (response[7].toInt() and 0xFF)
        assertEquals(1, anCount)
        // 마지막 4바이트는 0.0.0.0
        val tail = response.takeLast(4)
        assertTrue(tail.all { it == 0.toByte() })
    }

    @Test
    fun `압축 포인터 이름을 읽는다`() {
        // 헤더 + 질의(example.com) + 추가 레코드 이름이 첫 질의를 가리키는 포인터
        val queryBytes = query(1, "example.com")
        val extra = byteArrayOf(0xC0.toByte(), 0x0C)
        val message = queryBytes + extra
        val (name, after) = DnsWire.readName(message, queryBytes.size, message.size)!!
        assertEquals("example.com", name)
        assertEquals(queryBytes.size + 2, after)
    }

    @Test
    fun `손상된 입력은 null 을 돌려준다`() {
        assertNull(DnsWire.parseQuery(ByteArray(5)))
        assertNull(DnsWire.parseQuery(query(1, "example.com").copyOf(10)))
        // 응답(QR=1)은 질의로 파싱하지 않는다.
        val response = byteArrayOf(0, 1, 0x81.toByte(), 0x80.toByte(), 0, 0, 0, 0, 0, 0, 0, 0)
        assertNull(DnsWire.parseQuery(response))
    }

    @Test
    fun `최소 TTL 을 계산한다`() {
        val q = DnsWire.parseQuery(query(3, "ttl.example.com"))!!
        val answer = DnsAnswer(DnsType.A, 300, byteArrayOf(1, 2, 3, 4))
        val response = DnsWire.buildResponse(q, DnsRcode.NO_ERROR, listOf(answer))
        assertEquals(300, DnsWire.minTtl(response))
        // 실패 응답은 캐시 대상이 아니다.
        assertEquals(0, DnsWire.minTtl(DnsWire.buildBlockResponse(q, BlockResponseMode.NXDOMAIN)))
    }

    @Test
    fun `이름 인코딩과 정규화`() {
        val encoded = DnsWire.encodeName("A.Example.com.")
        // 1 + 'a' + 1 + 'example' + 1 + 'com' + 0
        assertEquals(1 + 1 + 1 + 7 + 1 + 3 + 1, encoded.size)
        assertEquals(0, encoded.last().toInt())
        assertEquals("example.com", DnsWire.normalizeDomain(" Example.COM. "))
    }

    @Test
    fun `트랜잭션 ID 재작성`() {
        val q = DnsWire.parseQuery(query(1, "id.example.com"))!!
        val response = DnsWire.buildResponse(q, DnsRcode.NO_ERROR)
        val rewritten = DnsWire.rewriteId(response, 0xBEEF)
        assertEquals(0xBEEF, ((rewritten[0].toInt() and 0xFF) shl 8) or (rewritten[1].toInt() and 0xFF))
    }
}
