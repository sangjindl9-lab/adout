package kr.eumsoft.securitypro.core.dns

/** 필터 판정 근거. */
enum class DecisionReason {
    NONE,
    USER_ALLOW,
    USER_BLOCK,
    EXCEPTION_RULE,
    BLOCK_RULE,
    NOT_BLOCKABLE,
}

data class FilterDecision(
    val blocked: Boolean,
    val category: String? = null,
    val sourceId: Long? = null,
    val matchedRule: String? = null,
    val reason: DecisionReason = DecisionReason.NONE,
)

/** 엔진이 요구하는 규칙 묶음(DB에서 읽어 만든 스냅샷). */
data class FilterSnapshot(
    val rules: List<FilterRuleEntry> = emptyList(),
    val userAllowed: Set<String> = emptySet(),
    val userBlocked: Set<String> = emptySet(),
) {
    val size: Int get() = rules.size
}

/**
 * 메모리 상주 DNS 필터 엔진.
 *
 * 매칭 순서(AdGuard 와 동일한 우선순위 원칙):
 *  1. 사용자 허용 목록
 *  2. 사용자 차단 목록
 *  3. 예외 규칙(@@)
 *  4. 차단 규칙
 *
 * 도메인은 라벨 역순 없이 "자기 자신 + 상위 도메인" 을 순차 조회하는 suffix map 으로
 * 찾는다. 라벨 수가 최대 10개로 제한되므로 조회 비용은 O(라벨 수)다.
 */
class DnsFilterEngine private constructor(
    private val suffixRules: Map<String, List<FilterRuleEntry>>,
    private val wildcardRules: List<Pair<Regex, FilterRuleEntry>>,
    private val userAllowed: Set<String>,
    private val userBlocked: Set<String>,
    val ruleCount: Int,
) {

    fun evaluate(domain: String, recordType: Int = DnsType.A): FilterDecision {
        val normalized = DnsWire.normalizeDomain(domain)
        if (!isBlockable(normalized)) {
            return FilterDecision(blocked = false, reason = DecisionReason.NOT_BLOCKABLE)
        }
        if (matchesDomainOrParent(normalized, userAllowed)) {
            return FilterDecision(
                blocked = false,
                category = "USER",
                matchedRule = normalized,
                reason = DecisionReason.USER_ALLOW,
            )
        }
        if (matchesDomainOrParent(normalized, userBlocked)) {
            return FilterDecision(
                blocked = true,
                category = "USER",
                matchedRule = normalized,
                reason = DecisionReason.USER_BLOCK,
            )
        }

        val suffixChain = suffixes(normalized)

        // 예외 규칙이 먼저다.
        for (name in suffixChain) {
            val entries = suffixRules[name] ?: continue
            entries.firstOrNull { it.isException && accepts(it, recordType) }?.let { rule ->
                return FilterDecision(
                    blocked = false,
                    category = rule.category,
                    sourceId = rule.sourceId,
                    matchedRule = rule.rawRule,
                    reason = DecisionReason.EXCEPTION_RULE,
                )
            }
        }
        for ((regex, rule) in wildcardRules) {
            if (!rule.isException || !accepts(rule, recordType)) continue
            if (regex.matches(normalized)) {
                return FilterDecision(
                    blocked = false,
                    category = rule.category,
                    sourceId = rule.sourceId,
                    matchedRule = rule.rawRule,
                    reason = DecisionReason.EXCEPTION_RULE,
                )
            }
        }

        // 차단 규칙: 우선순위(작을수록 우선) → 더 구체적인 규칙 순.
        var best: FilterRuleEntry? = null
        for (name in suffixChain) {
            val entries = suffixRules[name] ?: continue
            for (entry in entries) {
                if (entry.isException || !accepts(entry, recordType)) continue
                if (best == null || entry.priority < best.priority) best = entry
            }
        }
        if (best == null) {
            for ((regex, rule) in wildcardRules) {
                if (rule.isException || !accepts(rule, recordType)) continue
                if (regex.matches(normalized)) {
                    if (best == null || rule.priority < best.priority) best = rule
                }
            }
        }
        return if (best != null) {
            FilterDecision(
                blocked = true,
                category = best.category,
                sourceId = best.sourceId,
                matchedRule = best.rawRule,
                reason = DecisionReason.BLOCK_RULE,
            )
        } else {
            FilterDecision(blocked = false, reason = DecisionReason.NONE)
        }
    }

    private fun accepts(rule: FilterRuleEntry, recordType: Int): Boolean {
        val types = rule.dnsTypes ?: return true
        if (recordType == 0) return true
        return recordType in types
    }

    private fun matchesDomainOrParent(domain: String, set: Set<String>): Boolean {
        if (set.isEmpty()) return false
        return suffixes(domain).any { it in set }
    }

    /** [domain] 자기 자신과 상위 도메인 목록(최대 10단계). */
    private fun suffixes(domain: String): List<String> {
        val result = ArrayList<String>(8)
        result += domain
        var index = domain.indexOf('.')
        var guard = 0
        while (index >= 0 && guard < 10) {
            val parent = domain.substring(index + 1)
            if (parent.isNotEmpty()) result += parent
            index = domain.indexOf('.', index + 1)
            guard++
        }
        return result
    }

    /** 최상위 도메인/내부 도메인은 차단하지 않는다(인터넷 전체 차단 방지). */
    internal fun isBlockable(domain: String): Boolean {
        if (domain.isEmpty()) return false
        if (domain.length > DNS_MAX_NAME_LENGTH) return false
        val labels = domain.split('.')
        if (labels.size < 2) return false
        if (labels.any { it.isEmpty() }) return false
        val tld = labels.last()
        if (tld.length < 2) return false
        if (labels.size == 2) {
            // 'co.kr', 'com.au' 같은 2단계 공용 접미사는 차단 대상에서 제외
            val second = labels.first()
            if (second in PUBLIC_SUFFIX_GUARDS && tld in COUNTRY_TLDS) return false
        }
        return true
    }

    companion object {
        private val PUBLIC_SUFFIX_GUARDS = setOf("co", "or", "ne", "go", "ac", "com", "net", "org", "gov", "edu")
        private val COUNTRY_TLDS = setOf("kr", "jp", "cn", "uk", "au", "nz", "jp", "tw", "th", "vn", "id", "my", "sg", "ph", "hk")

        /** 와일드카드 정규식 최대 개수(ReDoS/메모리 보호). */
        private const val MAX_WILDCARDS = 2000

        fun build(snapshot: FilterSnapshot): DnsFilterEngine {
            val suffixMap = HashMap<String, MutableList<FilterRuleEntry>>(snapshot.rules.size / 2)
            val wildcards = ArrayList<Pair<Regex, FilterRuleEntry>>()
            var wildcardSkipped = 0

            snapshot.rules.forEach { rule ->
                if (rule.wildcard) {
                    if (wildcards.size >= MAX_WILDCARDS) {
                        wildcardSkipped++
                        return@forEach
                    }
                    val regex = wildcardToRegex(rule.domain) ?: return@forEach
                    wildcards += regex to rule
                } else {
                    suffixMap.getOrPut(rule.domain) { ArrayList(2) } += rule
                }
            }

            val userAllowed = snapshot.userAllowed
                .mapNotNull { RuleParser.normalizeHost(it) }
                .toSet()
            val userBlocked = snapshot.userBlocked
                .mapNotNull { RuleParser.normalizeHost(it) }
                .toSet()

            return DnsFilterEngine(
                suffixRules = suffixMap,
                wildcardRules = wildcards,
                userAllowed = userAllowed,
                userBlocked = userBlocked,
                ruleCount = snapshot.rules.size,
            )
        }

        /** `*` 만 허용하는 안전한 정규식 변환(다른 메타문자는 이스케이프). */
        internal fun wildcardToRegex(pattern: String): Regex? {
            if (pattern.length > 200) return null
            if (pattern.count { it == '*' } > 8) return null
            val sb = StringBuilder("^")
            pattern.forEach { c ->
                when (c) {
                    '*' -> sb.append(".*")
                    '.' -> sb.append("\\.")
                    '-' -> sb.append("\\-")
                    '_' -> sb.append('_')
                    else -> if (c.isLetterOrDigit()) sb.append(c) else sb.append(Regex.escape(c.toString()))
                }
            }
            sb.append("$")
            return try {
                Regex(sb.toString())
            } catch (_: Exception) {
                null
            }
        }
    }
}
