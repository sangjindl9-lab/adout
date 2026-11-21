package kr.eumsoft.securitypro.core.yara

/**
 * YARA 규칙의 부분집합 컴파일러/매처.
 *
 * 지원 문법:
 *  - `rule 이름 [: 태그] { meta: ... strings: $a = "텍스트" ascii wide nocase fullword
 *    $b = { 4D 5A ?? } condition: ... }`
 *  - 조건식: `all of them`, `any of them`, `N of them`, `$a`, `$a and $b`,
 *    `$a or not $b`, 괄호, `true`/`false`
 *
 * 지원하지 않는 문법(정규식 문자열, filesize, uint16(), #count, for 문)은 컴파일 오류로
 * 보고하고 해당 규칙만 건너뛴다. YARA-X 네이티브 모듈 미연결 상태의 대체 엔진이며,
 * 탐지 결과는 악성코드 "확정"이 아니라 의심 근거로 취급한다.
 */
data class YaraString(
    val id: String,
    val pattern: ByteArray,
    val mask: ByteArray? = null, // hex 와일드카드
    val nocase: Boolean = false,
    val wide: Boolean = false,
    /** 실제 매칭에 사용할 바이트 시퀀스 목록(ascii/wide 변형 포함). */
    val variants: List<ByteArray> = emptyList(),
    val fullword: Boolean = false,
)

sealed interface YaraCondition {
    data class HasString(val id: String) : YaraCondition
    data class AllOfThem(val negated: Boolean = false) : YaraCondition
    data class AnyOfThem(val negated: Boolean = false) : YaraCondition
    data class NOfThem(val n: Int, val negated: Boolean = false) : YaraCondition
    data class And(val left: YaraCondition, val right: YaraCondition) : YaraCondition
    data class Or(val left: YaraCondition, val right: YaraCondition) : YaraCondition
    data class Not(val inner: YaraCondition) : YaraCondition
    data object Always : YaraCondition
}

data class YaraRule(
    val name: String,
    val tags: List<String>,
    val meta: Map<String, String>,
    val strings: List<YaraString>,
    val condition: YaraCondition,
)

data class YaraCompileError(val ruleName: String, val reason: String)

data class YaraCompileResult(
    val rules: List<YaraRule>,
    val errors: List<YaraCompileError>,
)

data class YaraMatch(
    val rule: YaraRule,
    val matchedStrings: Map<String, Int>,
    val firstOffsets: Map<String, Int>,
)

object YaraEngine {

    private const val MAX_RULES = 2000
    private const val MAX_STRING_LENGTH = 4096
    private const val MAX_RULE_SIZE = 64 * 1024

    fun compile(source: String): YaraCompileResult {
        val rules = ArrayList<YaraRule>()
        val errors = ArrayList<YaraCompileError>()
        val stripped = stripComments(source)
        var index = 0
        while (true) {
            val ruleStart = stripped.indexOf("rule", index, ignoreCase = true)
            if (ruleStart < 0) break
            // 단어 경계 확인
            if (ruleStart > 0 && (stripped[ruleStart - 1].isLetterOrDigit() || stripped[ruleStart - 1] == '_')) {
                index = ruleStart + 4
                continue
            }
            val braceOpen = stripped.indexOf('{', ruleStart)
            if (braceOpen < 0) break
            val header = stripped.substring(ruleStart + 4, braceOpen).trim()
            if (header.length > MAX_RULE_SIZE) {
                errors += YaraCompileError(header.take(40), "규칙 헤더가 너무 큽니다.")
                break
            }
            val braceClose = findMatchingBrace(stripped, braceOpen)
            if (braceClose < 0) {
                errors += YaraCompileError(header.substringBefore(':').trim(), "닫는 중괄호가 없습니다.")
                break
            }
            val body = stripped.substring(braceOpen + 1, braceClose)
            val name = header.substringBefore(':').trim()
            try {
                val rule = parseRule(name, header, body)
                if (rules.size >= MAX_RULES) {
                    errors += YaraCompileError(name, "규칙 수 상한 초과")
                } else {
                    rules += rule
                }
            } catch (e: YaraCompileException) {
                errors += YaraCompileError(name, e.message ?: "컴파일 오류")
            } catch (e: Exception) {
                errors += YaraCompileError(name, e.javaClass.simpleName + ": " + (e.message ?: ""))
            }
            index = braceClose + 1
        }
        return YaraCompileResult(rules, errors)
    }

    private fun parseRule(name: String, header: String, body: String): YaraRule {
        val tags = header.substringAfter(':', "").trim().split(' ').filter { it.isNotEmpty() }
        var metaSection = ""
        var stringsSection = ""
        var conditionSection = ""
        var section = ""
        val stringsBuilder = StringBuilder()
        val metaBuilder = StringBuilder()
        val conditionBuilder = StringBuilder()
        body.lineSequence().forEach { line ->
            val trimmed = line.trim()
            when {
                trimmed.startsWith("meta:", ignoreCase = true) -> section = "meta"
                trimmed.startsWith("strings:", ignoreCase = true) -> section = "strings"
                trimmed.startsWith("condition:", ignoreCase = true) -> {
                    section = "condition"
                    conditionBuilder.append(trimmed.removePrefix("condition:").removePrefix("Condition:"))
                        .append('\n')
                }
                else -> when (section) {
                    "meta" -> metaBuilder.append(trimmed).append('\n')
                    "strings" -> stringsBuilder.append(trimmed).append('\n')
                    "condition" -> conditionBuilder.append(trimmed).append('\n')
                }
            }
        }
        metaSection = metaBuilder.toString()
        stringsSection = stringsBuilder.toString()
        conditionSection = conditionBuilder.toString().trim()

        val meta = HashMap<String, String>()
        metaSection.lineSequence().forEach { line ->
            val t = line.trim()
            if (t.isEmpty()) return@forEach
            val eq = t.indexOf('=')
            if (eq > 0) {
                meta[t.substring(0, eq).trim()] = t.substring(eq + 1).trim().trim('"')
            }
        }

        val strings = ArrayList<YaraString>()
        stringsSection.lineSequence().forEach { line ->
            val t = line.trim()
            if (t.isEmpty()) return@forEach
            if (!t.startsWith("$")) throw YaraCompileException("문자열 정의 형식 오류: ${t.take(30)}")
            val id = t.substringBefore('=').trim().removePrefix("$").substringBefore(' ')
            if (id.isEmpty()) throw YaraCompileException("문자열 식별자가 없습니다.")
            val eq = t.indexOf('=')
            if (eq < 0) throw YaraCompileException("'=' 가 없습니다: ${t.take(30)}")
            val rest = t.substring(eq + 1).trim()
            strings += parseString(id, rest)
        }

        val tokens = tokenizeCondition(conditionSection)
        if (tokens.isEmpty()) throw YaraCompileException("조건식이 비어 있습니다.")
        val parser = ConditionParser(tokens, strings.map { it.id }.toSet())
        val condition = parser.parse()
        if (!parser.finished()) throw YaraCompileException("조건식에 남은 토큰이 있습니다.")

        return YaraRule(name, tags, meta, strings, condition)
    }

    private fun parseString(id: String, rest: String): YaraString {
        if (rest.startsWith("/")) throw YaraCompileException("정규식 문자열은 지원하지 않습니다.")
        if (rest.startsWith("{")) {
            val end = rest.indexOf('}')
            if (end < 0) throw YaraCompileException("hex 문자열이 닫히지 않았습니다.")
            val hex = rest.substring(1, end)
            val modifiers = rest.substring(end + 1)
            val (pattern, mask) = parseHex(hex)
            if (pattern.isEmpty()) throw YaraCompileException("hex 문자열이 비어 있습니다.")
            val nocase = modifiers.contains("nocase", true)
            val wide = modifiers.contains("wide", true)
            return YaraString(
                id = id,
                pattern = pattern,
                mask = mask,
                nocase = nocase,
                wide = wide,
                variants = buildVariants(pattern, nocase, wide),
            )
        }
        if (!rest.startsWith("\"")) throw YaraCompileException("문자열은 \" 로 시작해야 합니다: ${rest.take(20)}")
        val end = findStringEnd(rest, 1)
        if (end < 0) throw YaraCompileException("문자열이 닫히지 않았습니다.")
        val raw = unescape(rest.substring(1, end))
        val modifiers = rest.substring(end + 1)
        val bytes = raw.toByteArray(Charsets.ISO_8859_1)
        if (bytes.isEmpty()) throw YaraCompileException("빈 문자열은 지원하지 않습니다.")
        if (bytes.size > MAX_STRING_LENGTH) throw YaraCompileException("문자열이 너무 깁니다.")
        val nocase = modifiers.contains("nocase", true)
        val wide = modifiers.contains("wide", true)
        val fullword = modifiers.contains("fullword", true)
        return YaraString(
            id = id,
            pattern = bytes,
            nocase = nocase,
            wide = wide,
            fullword = fullword,
            variants = buildVariants(bytes, nocase, wide),
        )
    }

    private fun buildVariants(pattern: ByteArray, nocase: Boolean, wide: Boolean): List<ByteArray> {
        val variants = ArrayList<ByteArray>(4)
        if (wide) {
            val wideBytes = ByteArray(pattern.size * 2)
            pattern.forEachIndexed { i, b ->
                wideBytes[i * 2] = b
                wideBytes[i * 2 + 1] = 0
            }
            variants += wideBytes
        }
        variants += pattern
        if (nocase) {
            variants.map { it.copyOf() }.forEach { variant ->
                variants += lowercase(variant)
            }
        }
        return variants.distinctBy { it.joinToString(",") }
    }

    private fun lowercase(bytes: ByteArray): ByteArray {
        val out = bytes.copyOf()
        for (i in out.indices) {
            val c = out[i].toInt() and 0xFF
            if (c in 0x41..0x5A) out[i] = (c + 32).toByte()
        }
        return out
    }

    private fun parseHex(hex: String): Pair<ByteArray, ByteArray> {
        val tokens = hex.trim().split(Regex("\\s+")).filter { it.isNotEmpty() }
        val pattern = ByteArray(tokens.size)
        val mask = ByteArray(tokens.size)
        tokens.forEachIndexed { index, token ->
            if (token.length != 2) throw YaraCompileException("hex 바이트 형식 오류: $token")
            val hi = hexNibble(token[0])
            val lo = hexNibble(token[1])
            var byte = 0
            var m = 0
            if (hi >= 0) {
                byte = byte or (hi shl 4)
                m = m or 0xF0
            }
            if (lo >= 0) {
                byte = byte or lo
                m = m or 0x0F
            }
            pattern[index] = byte.toByte()
            mask[index] = m.toByte()
        }
        return pattern to mask
    }

    private fun hexNibble(c: Char): Int = when (c) {
        in '0'..'9' -> c - '0'
        in 'a'..'f' -> c - 'a' + 10
        in 'A'..'F' -> c - 'A' + 10
        '?' -> -1
        else -> throw YaraCompileException("hex 문자가 아닙니다: $c")
    }

    private fun unescape(text: String): String {
        val sb = StringBuilder(text.length)
        var i = 0
        while (i < text.length) {
            val c = text[i]
            if (c == '\\' && i + 1 < text.length) {
                when (val n = text[i + 1]) {
                    'n' -> sb.append('\n')
                    't' -> sb.append('\t')
                    'r' -> sb.append('\r')
                    '\\' -> sb.append('\\')
                    '"' -> sb.append('"')
                    'x' -> {
                        if (i + 3 < text.length) {
                            val hex = text.substring(i + 2, i + 4)
                            val value = hex.toIntOrNull(16)
                            if (value != null) {
                                sb.append(value.toChar())
                                i += 4
                                continue
                            }
                        }
                        sb.append(n)
                    }
                    else -> sb.append(n)
                }
                i += 2
            } else {
                sb.append(c)
                i++
            }
        }
        return sb.toString()
    }

    private fun findStringEnd(text: String, start: Int): Int {
        var i = start
        while (i < text.length) {
            when (text[i]) {
                '\\' -> i += 2
                '"' -> return i
                else -> i++
            }
        }
        return -1
    }

    private fun findMatchingBrace(text: String, open: Int): Int {
        var depth = 0
        var i = open
        var inString = false
        while (i < text.length) {
            val c = text[i]
            when {
                inString -> {
                    if (c == '\\') i++
                    else if (c == '"') inString = false
                }
                c == '"' -> inString = true
                c == '{' -> depth++
                c == '}' -> {
                    depth--
                    if (depth == 0) return i
                }
            }
            i++
        }
        return -1
    }

    private fun stripComments(source: String): String {
        val sb = StringBuilder(source.length)
        var i = 0
        var inString = false
        while (i < source.length) {
            val c = source[i]
            when {
                inString -> {
                    sb.append(c)
                    if (c == '\\' && i + 1 < source.length) {
                        sb.append(source[i + 1])
                        i++
                    } else if (c == '"') {
                        inString = false
                    }
                }
                c == '"' -> {
                    inString = true
                    sb.append(c)
                }
                c == '/' && i + 1 < source.length && source[i + 1] == '/' -> {
                    while (i < source.length && source[i] != '\n') i++
                }
                c == '/' && i + 1 < source.length && source[i + 1] == '*' -> {
                    i += 2
                    while (i + 1 < source.length && !(source[i] == '*' && source[i + 1] == '/')) i++
                    i += 2
                }
                else -> sb.append(c)
            }
            i++
        }
        return sb.toString()
    }

    // ---------------- 조건식 토큰/파서 ----------------

    private sealed interface Token {
        data class Word(val text: String) : Token
        data class StrId(val id: String) : Token
        data class Number(val value: Int) : Token
        data object LParen : Token
        data object RParen : Token
    }

    private fun tokenizeCondition(text: String): List<Token> {
        val tokens = ArrayList<Token>()
        var i = 0
        while (i < text.length) {
            val c = text[i]
            when {
                c.isWhitespace() -> i++
                c == '(' -> {
                    tokens += Token.LParen
                    i++
                }
                c == ')' -> {
                    tokens += Token.RParen
                    i++
                }
                c == '$' -> {
                    val start = i + 1
                    var j = start
                    while (j < text.length && (text[j].isLetterOrDigit() || text[j] == '_')) j++
                    tokens += Token.StrId(text.substring(start, j))
                    i = j
                }
                c.isDigit() -> {
                    var j = i
                    while (j < text.length && text[j].isDigit()) j++
                    tokens += Token.Number(text.substring(i, j).toInt())
                    i = j
                }
                c.isLetter() || c == '_' -> {
                    var j = i
                    while (j < text.length && (text[j].isLetterOrDigit() || text[j] == '_')) j++
                    tokens += Token.Word(text.substring(i, j))
                    i = j
                }
                else -> throw YaraCompileException("조건식에 지원하지 않는 문자: '$c'")
            }
        }
        return tokens
    }

    private class ConditionParser(
        private val tokens: List<Token>,
        private val stringIds: Set<String>,
    ) {
        private var position = 0

        fun finished(): Boolean = position >= tokens.size

        fun parse(): YaraCondition = parseOr()

        private fun peek(): Token? = tokens.getOrNull(position)

        private fun next(): Token? = tokens.getOrNull(position++)

        private fun parseOr(): YaraCondition {
            var left = parseAnd()
            while (true) {
                val token = peek() as? Token.Word ?: break
                if (!token.text.equals("or", true)) break
                position++
                left = YaraCondition.Or(left, parseAnd())
            }
            return left
        }

        private fun parseAnd(): YaraCondition {
            var left = parseUnary()
            while (true) {
                val token = peek() as? Token.Word ?: break
                if (!token.text.equals("and", true)) break
                position++
                left = YaraCondition.And(left, parseUnary())
            }
            return left
        }

        private fun parseUnary(): YaraCondition {
            val token = peek() ?: throw YaraCompileException("조건식이 예상보다 일찍 끝났습니다.")
            if (token is Token.Word && token.text.equals("not", true)) {
                position++
                return YaraCondition.Not(parseUnary())
            }
            if (token is Token.LParen) {
                position++
                val inner = parseOr()
                val close = next()
                if (close != Token.RParen) throw YaraCompileException("괄호가 닫히지 않았습니다.")
                return inner
            }
            if (token is Token.StrId) {
                position++
                if (token.id !in stringIds) throw YaraCompileException("정의되지 않은 문자열: \$${token.id}")
                return YaraCondition.HasString(token.id)
            }
            if (token is Token.Number) {
                position++
                val of = next() as? Token.Word
                val them = next() as? Token.Word
                if (of == null || !of.text.equals("of", true) || them == null || !them.text.equals("them", true)) {
                    throw YaraCompileException("'N of them' 형식이 아닙니다.")
                }
                return YaraCondition.NOfThem(token.value)
            }
            if (token is Token.Word) {
                when {
                    token.text.equals("all", true) || token.text.equals("any", true) -> {
                        position++
                        val of = next() as? Token.Word
                        val them = next() as? Token.Word
                        if (of == null || !of.text.equals("of", true) || them == null || !them.text.equals("them", true)) {
                            throw YaraCompileException("'all|any of them' 형식이 아닙니다.")
                        }
                        return if (token.text.equals("all", true)) {
                            YaraCondition.AllOfThem()
                        } else {
                            YaraCondition.AnyOfThem()
                        }
                    }
                    token.text.equals("true", true) -> {
                        position++
                        return YaraCondition.Always
                    }
                    token.text.equals("false", true) -> {
                        position++
                        return YaraCondition.Not(YaraCondition.Always)
                    }
                    else -> throw YaraCompileException("지원하지 않는 조건 토큰: ${token.text}")
                }
            }
            throw YaraCompileException("조건식을 해석할 수 없습니다.")
        }
    }

    // ---------------- 매칭 ----------------

    fun match(rule: YaraRule, data: ByteArray, maxMatchesPerString: Int = 4): YaraMatch? {
        val counts = HashMap<String, Int>()
        val offsets = HashMap<String, Int>()
        rule.strings.forEach { string ->
            var count = 0
            var first = -1
            for (variant in string.variants) {
                val found = findAll(data, variant, string.nocase, string.mask, maxMatchesPerString)
                if (found.isNotEmpty()) {
                    if (first < 0) first = found.first()
                    count += found.size
                }
                if (count >= maxMatchesPerString) break
            }
            if (count > 0) {
                counts[string.id] = count
                offsets[string.id] = first
            }
        }
        val matched = evaluate(rule.condition, counts, rule.strings.size)
        return if (matched) YaraMatch(rule, counts, offsets) else null
    }

    private fun evaluate(condition: YaraCondition, counts: Map<String, Int>, totalStrings: Int): Boolean =
        when (condition) {
            is YaraCondition.HasString -> (counts[condition.id] ?: 0) > 0
            is YaraCondition.AllOfThem -> {
                val all = totalStrings > 0 && counts.size == totalStrings
                if (condition.negated) !all else all
            }
            is YaraCondition.AnyOfThem -> {
                val any = counts.isNotEmpty()
                if (condition.negated) !any else any
            }
            is YaraCondition.NOfThem -> {
                val ok = counts.size >= condition.n
                if (condition.negated) !ok else ok
            }
            is YaraCondition.And -> evaluate(condition.left, counts, totalStrings) &&
                evaluate(condition.right, counts, totalStrings)
            is YaraCondition.Or -> evaluate(condition.left, counts, totalStrings) ||
                evaluate(condition.right, counts, totalStrings)
            is YaraCondition.Not -> !evaluate(condition.inner, counts, totalStrings)
            YaraCondition.Always -> true
        }

    /** Boyer-Moore-Horspool 바이트 검색(대소문자 무시 지원). */
    internal fun findAll(
        haystack: ByteArray,
        needle: ByteArray,
        nocase: Boolean,
        mask: ByteArray? = null,
        limit: Int = 4,
    ): List<Int> {
        if (needle.isEmpty() || haystack.size < needle.size) return emptyList()
        val results = ArrayList<Int>(limit)
        if (mask != null) {
            var i = 0
            val last = haystack.size - needle.size
            while (i <= last) {
                var matched = true
                for (j in needle.indices) {
                    val m = mask[j].toInt() and 0xFF
                    val a = haystack[i + j].toInt() and 0xFF
                    val b = needle[j].toInt() and 0xFF
                    if ((a and m) != (b and m)) {
                        matched = false
                        break
                    }
                }
                if (matched) {
                    results += i
                    if (results.size >= limit) return results
                }
                i++
            }
            return results
        }
        if (nocase) {
            var i = 0
            val last = haystack.size - needle.size
            while (i <= last) {
                var matched = true
                for (j in needle.indices) {
                    if (lower(haystack[i + j]) != lower(needle[j])) {
                        matched = false
                        break
                    }
                }
                if (matched) {
                    results += i
                    if (results.size >= limit) return results
                }
                i++
            }
            return results
        }
        // BMH
        val skip = IntArray(256) { needle.size }
        for (j in 0 until needle.size - 1) {
            skip[needle[j].toInt() and 0xFF] = needle.size - 1 - j
        }
        var i = 0
        val last = haystack.size - needle.size
        while (i <= last) {
            var j = needle.size - 1
            while (j >= 0 && haystack[i + j] == needle[j]) j--
            if (j < 0) {
                results += i
                if (results.size >= limit) return results
                i += 1
            } else {
                i += skip[haystack[i + needle.size - 1].toInt() and 0xFF].coerceAtLeast(1)
            }
        }
        return results
    }

    private fun lower(b: Byte): Byte {
        val v = b.toInt() and 0xFF
        return if (v in 0x41..0x5A) (v + 32).toByte() else b
    }
}

class YaraCompileException(message: String) : Exception(message)
