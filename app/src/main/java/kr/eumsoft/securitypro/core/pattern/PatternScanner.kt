package kr.eumsoft.securitypro.core.pattern

import kr.eumsoft.securitypro.core.risk.Finding
import kr.eumsoft.securitypro.core.risk.ScanEngine
import kr.eumsoft.securitypro.core.risk.Severity
import kr.eumsoft.securitypro.core.yara.BuiltInRules
import kr.eumsoft.securitypro.core.yara.YaraCompileResult
import kr.eumsoft.securitypro.core.yara.YaraEngine
import kr.eumsoft.securitypro.core.yara.YaraRule

/**
 * DEX / .so / 스크립트 내부의 의심 문자열·명령 패턴 검사.
 *
 * 두 계층으로 동작한다.
 *  1) YARA 부분집합 규칙(내장 + DB 규칙)
 *  2) 단순 문자열 규칙(셸 명령, 원시 IP URL, 인코딩된 페이로드 등)
 *
 * 코드를 실행하지 않고 바이트만 읽는다.
 */
class PatternScanner(
    private val yaraRules: List<YaraRule> = BuiltInRules.compiledRules().rules,
    private val compileErrors: List<String> = BuiltInRules.compiledRules().errors.map { "${it.ruleName}: ${it.reason}" },
) {

    data class Content(val name: String, val bytes: ByteArray)

    private data class SimpleRule(
        val id: String,
        val needles: List<String>,
        val required: Int,
        val category: String,
        val severity: Severity,
        val confidence: Int,
        val titleKey: String,
    )

    private val simpleRules = listOf(
        SimpleRule(
            id = "raw_ip_url",
            needles = listOf("http://", "https://"),
            required = 1,
            category = "suspicious_pattern",
            severity = Severity.LOW,
            confidence = 25,
            titleKey = "finding_url_strings",
        ),
        SimpleRule(
            id = "shell_command",
            needles = listOf("/system/bin/", "/system/xbin/", "busybox"),
            required = 2,
            category = "suspicious_pattern",
            severity = Severity.MEDIUM,
            confidence = 40,
            titleKey = "finding_shell_strings",
        ),
    )

    fun scan(contents: List<Content>, onProgress: ((String) -> Unit)? = null): List<Finding> {
        val findings = ArrayList<Finding>()
        contents.forEach { content ->
            onProgress?.invoke(content.name)
            yaraRules.forEach { rule ->
                val match = try {
                    YaraEngine.match(rule, content.bytes)
                } catch (_: Exception) {
                    null
                }
                if (match != null) {
                    findings += toFinding(rule, match.matchedStrings, match.firstOffsets, content.name)
                }
            }
            findings += simpleScan(content)
        }
        return findings
    }

    private fun toFinding(
        rule: YaraRule,
        matched: Map<String, Int>,
        offsets: Map<String, Int>,
        fileName: String,
    ): Finding {
        val severity = runCatching { Severity.valueOf(rule.meta["severity"] ?: "MEDIUM") }
            .getOrDefault(Severity.MEDIUM)
        val confidence = rule.meta["confidence"]?.toIntOrNull() ?: 40
        val category = rule.meta["category"] ?: "suspicious_pattern"
        val detail = matched.entries.sortedBy { it.key }
            .joinToString(", ") { (id, count) -> "\$$id(${count}회 @${offsets[id] ?: -1})" }
        return Finding(
            engine = ScanEngine.YARA_SUBSET,
            ruleId = rule.name,
            category = category,
            severity = severity,
            confidence = confidence,
            titleKey = "finding_pattern_" + rule.name.lowercase(),
            evidence = "파일: $fileName · 일치: $detail · 규칙: ${rule.meta["description"] ?: rule.name}",
            adviceKey = "advice_review_app",
        )
    }

    private fun simpleScan(content: Content): List<Finding> {
        val findings = ArrayList<Finding>()
        val text = runCatching { String(content.bytes, Charsets.ISO_8859_1) }.getOrNull() ?: return findings
        simpleRules.forEach { rule ->
            val hits = rule.needles.filter { text.contains(it, ignoreCase = true) }
            if (hits.size >= rule.required) {
                findings += Finding(
                    engine = ScanEngine.PATTERN,
                    ruleId = rule.id,
                    category = rule.category,
                    severity = rule.severity,
                    confidence = rule.confidence,
                    titleKey = rule.titleKey,
                    evidence = "파일: ${content.name} · 문자열: ${hits.joinToString(", ")}",
                    adviceKey = "advice_review_app",
                )
            }
        }
        return findings
    }

    fun diagnostics(): List<String> = compileErrors

    companion object {
        fun withExtraRules(source: String): PatternScanner {
            val base = BuiltInRules.compiledRules()
            val extra = YaraEngine.compile(source)
            return PatternScanner(
                yaraRules = base.rules + extra.rules,
                compileErrors = (base.errors + extra.errors).map { "${it.ruleName}: ${it.reason}" },
            )
        }

        fun fromCompileResult(result: YaraCompileResult): PatternScanner =
            PatternScanner(result.rules, result.errors.map { "${it.ruleName}: ${it.reason}" })
    }
}
