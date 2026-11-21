package kr.eumsoft.securitypro.core.net

import kr.eumsoft.securitypro.core.dns.DnsWire

/**
 * DNS 응답 캐시(LRU + TTL).
 *
 * 캐시 키는 (정규화 도메인, 타입)이며, 응답의 최소 TTL 을 사용한다.
 * 실패 응답·빈 응답은 캐시하지 않는다.
 */
class DnsResponseCache(
    private val maxEntries: Int = 512,
    private val minTtlSeconds: Int = 30,
    private val maxTtlSeconds: Int = 3600,
) {

    private data class Entry(val response: ByteArray, val expiresAt: Long)

    private val map = object : LinkedHashMap<String, Entry>(maxEntries, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Entry>?): Boolean =
            size > maxEntries
    }

    private var hits = 0L
    private var misses = 0L

    @Synchronized
    fun get(domain: String, type: Int, now: Long): ByteArray? {
        val key = key(domain, type)
        val entry = map[key]
        if (entry == null) {
            misses++
            return null
        }
        if (entry.expiresAt <= now) {
            map.remove(key)
            misses++
            return null
        }
        hits++
        return entry.response
    }

    @Synchronized
    fun put(domain: String, type: Int, response: ByteArray, now: Long): Boolean {
        val ttl = DnsWire.minTtl(response)
        if (ttl <= 0) return false
        val clamped = ttl.coerceIn(minTtlSeconds, maxTtlSeconds)
        map[key(domain, type)] = Entry(response, now + clamped * 1000L)
        return true
    }

    @Synchronized
    fun clear() {
        map.clear()
        hits = 0
        misses = 0
    }

    @Synchronized
    fun size(): Int = map.size

    @Synchronized
    fun stats(): Pair<Long, Long> = hits to misses

    private fun key(domain: String, type: Int): String =
        DnsWire.normalizeDomain(domain) + "|" + type
}
