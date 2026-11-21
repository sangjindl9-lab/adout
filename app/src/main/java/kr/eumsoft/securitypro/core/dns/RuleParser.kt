package kr.eumsoft.securitypro.core.dns

/**
 * 필터 규칙 한 줄을 해석한 결과.
 */
data class FilterRuleEntry(
    /** 소문자 정규화된 도메인(또는 와일드카드 패턴 원문). */
    val domain: String,
    /** true 면 하위 도메인까지 차단한다(`||domain^`). */
    val matchSubdomains: Boolean,
    /** ADS, TRACKING, PHISHING, MALWARE, USER */
    val category: String,
    val sourceId: Long?,
    val rawRule: String,
    /** 작을수록 우선순위가 높다. */
    val priority: Int = 100,
    /** 예외 규칙(@@)이면 true. */
    val isException: Boolean = false,
    /** 와일드카드가 포함된 패턴이면 정규식으로 매칭한다. */
    val wildcard: Boolean = false,
    /** $dnstype= 수정자로 제한된 레코드 타입. null 이면 모든 타입. */
    val dnsTypes: Set<Int>? = null,
)

/** 한 필터 소스의 메타데이터. */
data class FilterSourceMeta(
    val sourceId: Long?,
    val name: String,
    val category: String,
    val priority: Int,
)

/** 규칙 파싱 통계(지원하지 않는 문법은 조용히 버리지 않고 집계한다). */
data class RuleParseStats(
    val parsed: Int,
    val skippedComment: Int,
    val skippedUnsupported: Int,
    val skippedInvalid: Int,
    val unsupportedExamples: List<String> = emptyList(),
)

data class RuleParseResult(
    val rules: List<FilterRuleEntry>,
    val stats: RuleParseStats,
)

/**
 * Hosts 형식과 AdGuard DNS 필터 문법의 부분집합을 해석한다.
 *
 * 지원:
 *  - `0.0.0.0 example.com`, `127.0.0.1 example.com`, `::1 example.com`
 *  - `||example.com^` (하위 도메인 포함 차단)
 *  - `@@||example.com^` (허용 예외)
 *  - `|https://example.com^`, `||example.com^$dnstype=AAAA`
 *  - `*.example.com` 형태의 와일드카드
 *  - `!` / `#` 주석, `[Adblock Plus 2.0]` 헤더
 *
 * 지원하지 않는 문법(정규식 `/.../`, `$replace`, `$badfilter`, 코스메틱 규칙 `##`)은
 * 건너뛰고 통계로 보고한다.
 */
object RuleParser {

    private val hostsPrefixes = listOf("0.0.0.0", "127.0.0.1", "::1", "::", "255.255.255.255")
    private val domainRegex = Regex("^[a-z0-9]([a-z0-9_-]{0,62})(\\.[a-z0-9_]([a-z0-9_-]{0,62}))*\\.[a-z]{2,63}$")
    private val ipv4Regex = Regex("^\\d{1,3}(\\.\\d{1,3}){3}$")

    fun parse(
        lines: Sequence<String>,
        meta: FilterSourceMeta,
        maxRules: Int = 500_000,
    ): RuleParseResult {
        var comments = 0
        var unsupported = 0
        var invalid = 0
        val unsupportedExamples = ArrayList<String>(8)
        val rules = ArrayList<FilterRuleEntry>(minOf(maxRules, 4096))

        for (rawLine in lines) {
            if (rules.size >= maxRules) break
            val line = rawLine.trim().trimStart('\uFEFF')
            if (line.isEmpty()) continue
            if (line.startsWith("!") || line.startsWith("#") || line.startsWith("[")) {
                comments++
                continue
            }
            if (line.contains("##") || line.contains("#@#") || line.contains("#?#")) {
                unsupported++
                if (unsupportedExamples.size < 5) unsupportedExamples += line.take(80)
                continue
            }
            if (line.startsWith("/") && line.endsWith("/")) {
                unsupported++
                if (unsupportedExamples.size < 5) unsupportedExamples += line.take(80)
                continue
            }
            val entry = parseLine(line, meta)
            when {
                entry != null -> rules += entry
                line.isEmpty() -> Unit
                else -> {
                    // 호스트 형식이지만 IP 만 있는 줄 등은 무효로 집계
                    if (line.split(' ').size >= 2) invalid++ else invalid++
                }
            }
        }
        val stats = RuleParseStats(
            parsed = rules.size,
            skippedComment = comments,
            skippedUnsupported = unsupported,
            skippedInvalid = invalid,
            unsupportedExamples = unsupportedExamples,
        )
        return RuleParseResult(rules, stats)
    }

    private fun parseLine(line: String, meta: FilterSourceMeta): FilterRuleEntry? {
        // 1) hosts 형식: IP 도메인 [도메인...]
        val parts = line.split(' ', '\t').filter { it.isNotBlank() }
        if (parts.size >= 2 && parts[0].lowercase() in hostsPrefixes) {
            val domain = normalizeHost(parts[1]) ?: return null
            return FilterRuleEntry(
                domain = domain,
                matchSubdomains = true,
                category = meta.category,
                sourceId = meta.sourceId,
                rawRule = line,
                priority = meta.priority,
            )
        }

        // 2) AdGuard/AdBlock DNS 문법
        var body = line
        var isException = false
        if (body.startsWith("@@")) {
            isException = true
            body = body.substring(2)
        }
        if (body.isEmpty()) return null

        var dnsTypes: Set<Int>? = null
        val dollar = body.lastIndexOf('$')
        if (dollar > 0) {
            val modifiers = body.substring(dollar + 1)
            body = body.substring(0, dollar)
            dnsTypes = parseDnsTypeModifier(modifiers)
        }

        // 앵커/스킴 정리
        body = body.removePrefix("||").removePrefix("|").removePrefix("https://")
            .removePrefix("http://").removePrefix("*.")
        body = body.trimEnd('^')
        if (body.isEmpty()) return null
        if (body.contains('/')) return null

        val wildcard = body.contains('*')
        val domain = if (wildcard) {
            body.lowercase().trim('.')
        } else {
            normalizeHost(body) ?: return null
        }

        return FilterRuleEntry(
            domain = domain,
            matchSubdomains = line.startsWith("||") || line.startsWith("|") || wildcard,
            category = meta.category,
            sourceId = meta.sourceId,
            rawRule = line,
            priority = meta.priority,
            isException = isException,
            wildcard = wildcard,
            dnsTypes = dnsTypes,
        )
    }

    /** `$dnstype=A,AAAA` → {1,28}. 지원하지 않는 수정자는 무시한다. */
    internal fun parseDnsTypeModifier(modifiers: String): Set<Int>? {
        modifiers.split(',').forEach { modifier ->
            val m = modifier.trim()
            if (m.startsWith("dnstype=", ignoreCase = true)) {
                val values = m.substringAfter('=').split('|')
                val types = values.mapNotNull { typeNameToCode(it.trim()) }.toSet()
                return types.ifEmpty { null }
            }
        }
        return null
    }

    private fun typeNameToCode(name: String): Int? = when (name.uppercase()) {
        "A" -> DnsType.A
        "AAAA" -> DnsType.AAAA
        "CNAME" -> DnsType.CNAME
        "TXT" -> DnsType.TXT
        "MX" -> DnsType.MX
        "NS" -> DnsType.NS
        "SRV" -> DnsType.SRV
        "HTTPS" -> DnsType.HTTPS
        "ANY" -> DnsType.ANY
        else -> name.toIntOrNull()
    }

    /** 호스트 문자열 검증/정규화. IP 주소나 잘못된 이름은 null. */
    fun normalizeHost(raw: String): String? {
        var host = raw.trim().trimEnd('.').lowercase()
        if (host.isEmpty() || host.length > DNS_MAX_NAME_LENGTH) return null
        if (host.startsWith(".")) host = host.trimStart('.')
        if (ipv4Regex.matches(host)) return null
        if (host.contains(':')) return null // IPv6
        val labels = host.split('.')
        if (labels.any { it.isEmpty() }) return null
        // 유니코드 도메인은 punycode 로 변환 시도
        val ascii = try {
            java.net.IDN.toASCII(host, java.net.IDN.ALLOW_UNASSIGNED)
        } catch (_: Exception) {
            return null
        }.lowercase()
        if (!domainRegex.matches(ascii)) {
            // 내부 도메인(single-label)은 규칙으로 허용하지 않는다(오탐 방지)
            return null
        }
        return ascii
    }
}
