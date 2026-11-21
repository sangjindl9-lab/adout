package kr.eumsoft.securitypro.core.dns

import kr.eumsoft.securitypro.core.net.DnsResponseCache
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class DnsFilterTest {

    private fun engine(
        vararg lines: String,
        allowed: Set<String> = emptySet(),
        blocked: Set<String> = emptySet(),
        category: String = "ADS",
        priority: Int = 100,
    ): DnsFilterEngine {
        val meta = FilterSourceMeta(sourceId = 1, name = "test", category = category, priority = priority)
        val parsed = RuleParser.parse(lines.asSequence(), meta)
        return DnsFilterEngine.build(FilterSnapshot(parsed.rules, allowed, blocked))
    }

    @Test
    fun `hosts 형식과 AdGuard 규칙을 해석한다`() {
        val meta = FilterSourceMeta(1, "test", "ADS", 100)
        val result = RuleParser.parse(
            sequenceOf(
                "! 주석",
                "# hosts 주석",
                "0.0.0.0 ads.example.com",
                "127.0.0.1 tracker.example.net",
                "||banner.example.org^",
                "@@||allow.example.org^",
                "||video.example.kr^\$dnstype=AAAA",
                "/regex-unsupported/",
                "example##.cosmetic",
            ),
            meta,
        )
        assertEquals(5, result.stats.parsed)
        assertEquals(2, result.stats.skippedComment)
        assertEquals(2, result.stats.skippedUnsupported)
        assertTrue(result.rules.any { it.isException })
        assertTrue(result.rules.any { it.dnsTypes == setOf(DnsType.AAAA) })
    }

    @Test
    fun `서브도메인까지 차단한다`() {
        val engine = engine("||ads.example.com^")
        assertTrue(engine.evaluate("ads.example.com").blocked)
        assertTrue(engine.evaluate("cdn.ads.example.com").blocked)
        assertFalse(engine.evaluate("example.com").blocked)
        assertFalse(engine.evaluate("notads.example.com").blocked)
    }

    @Test
    fun `사용자 허용 목록이 항상 우선한다`() {
        val engine = engine("||ads.example.com^", allowed = setOf("ads.example.com"))
        val decision = engine.evaluate("ads.example.com")
        assertFalse(decision.blocked)
        assertEquals(DecisionReason.USER_ALLOW, decision.reason)
    }

    @Test
    fun `사용자 차단 목록이 예외 규칙보다 우선한다`() {
        val engine = engine("@@||ads.example.com^", blocked = setOf("ads.example.com"))
        val decision = engine.evaluate("ads.example.com")
        assertTrue(decision.blocked)
        assertEquals(DecisionReason.USER_BLOCK, decision.reason)
    }

    @Test
    fun `예외 규칙이 차단 규칙을 이긴다`() {
        val engine = engine("||example.com^", "@@||safe.example.com^")
        assertTrue(engine.evaluate("ads.example.com").blocked)
        assertFalse(engine.evaluate("safe.example.com").blocked)
        assertEquals(DecisionReason.EXCEPTION_RULE, engine.evaluate("safe.example.com").reason)
    }

    @Test
    fun `dnstype 수정자를 존중한다`() {
        val engine = engine("||img.example.com^\$dnstype=AAAA")
        assertTrue(engine.evaluate("img.example.com", DnsType.AAAA).blocked)
        assertFalse(engine.evaluate("img.example.com", DnsType.A).blocked)
    }

    @Test
    fun `최상위 공용 접미사는 차단하지 않는다`() {
        val engine = engine("||co.kr^", "||com^", "||localhost^")
        assertFalse(engine.evaluate("co.kr").blocked)
        assertFalse(engine.evaluate("com").blocked)
        assertFalse(engine.evaluate("localhost").blocked)
        assertEquals(DecisionReason.NOT_BLOCKABLE, engine.evaluate("com").reason)
    }

    @Test
    fun `와일드카드 규칙`() {
        val engine = engine("*ads*.example.com")
        assertTrue(engine.evaluate("cdn-ads1.example.com").blocked)
        assertFalse(engine.evaluate("cdn.example.com").blocked)
    }

    @Test
    fun `우선순위가 높은 규칙의 범주를 쓴다`() {
        val metaLow = FilterSourceMeta(1, "ads", "ADS", priority = 100)
        val metaHigh = FilterSourceMeta(2, "phish", "PHISHING", priority = 10)
        val rules = RuleParser.parse(sequenceOf("||evil.example.com^"), metaLow).rules +
            RuleParser.parse(sequenceOf("||evil.example.com^"), metaHigh).rules
        val engine = DnsFilterEngine.build(FilterSnapshot(rules))
        val decision = engine.evaluate("evil.example.com")
        assertTrue(decision.blocked)
        assertEquals("PHISHING", decision.category)
    }

    @Test
    fun `유니코드 도메인을 punycode 로 정규화한다`() {
        assertNotNull(RuleParser.normalizeHost("한글도메인.kr"))
        val punycode = RuleParser.normalizeHost("한글도메인.kr")!!
        assertTrue(punycode.startsWith("xn--"))
        assertTrue(punycode.endsWith(".kr"))
        assertEquals(null, RuleParser.normalizeHost("127.0.0.1"))
        assertEquals(null, RuleParser.normalizeHost("not a domain"))
    }

    @Test
    fun `응답 캐시는 TTL 동안만 유효하다`() {
        val cache = DnsResponseCache(maxEntries = 4)
        val query = buildQuery("cache.example.com")
        val parsed = DnsWire.parseQuery(query)!!
        val response = DnsWire.buildResponse(
            parsed,
            DnsRcode.NO_ERROR,
            listOf(DnsAnswer(DnsType.A, 60, byteArrayOf(1, 1, 1, 1))),
        )
        val now = 1_000_000L
        assertTrue(cache.put("cache.example.com", DnsType.A, response, now))
        assertNotNull(cache.get("cache.example.com", DnsType.A, now + 10_000))
        // TTL 60초 뒤에는 만료
        assertEquals(null, cache.get("cache.example.com", DnsType.A, now + 61_000))
    }

    private fun buildQuery(name: String): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        out.write(0); out.write(1)
        out.write(0x01); out.write(0)
        out.write(0); out.write(1)
        repeat(6) { out.write(0) }
        out.write(DnsWire.encodeName(name))
        out.write(0); out.write(1)
        out.write(0); out.write(1)
        return out.toByteArray()
    }
}
