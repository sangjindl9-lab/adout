package kr.eumsoft.securitypro.data.updater

import java.io.ByteArrayInputStream
import java.util.zip.GZIPInputStream
import kr.eumsoft.securitypro.core.dns.FilterSourceMeta
import kr.eumsoft.securitypro.core.dns.RuleParser
import kr.eumsoft.securitypro.core.dns.RuleParseStats
import kr.eumsoft.securitypro.data.db.entity.AdFilterRuleEntity
import kr.eumsoft.securitypro.data.db.entity.ThreatHashEntity
import kr.eumsoft.securitypro.data.db.entity.ThreatRuleEntity
import org.json.JSONArray
import org.json.JSONObject

/**
 * 업데이트 페이로드 JSON 해석.
 *
 * 형식:
 *  - THREAT_HASH  : [{"sha256","threatName","family","category","severity","confidence","source","firstSeen","lastSeen"}]
 *  - YARA_RULES   : {"engine":"YARA_SUBSET","rules":[{"name","category","severity","content","source","version"}]}
 *  - AD_FILTER    : {"source":"이름","rules":["||ads.example.com^", ...], "category":"ADS"}
 */
object UpdatePayloadParser {

    private const val MAX_RECORDS = 1_000_000

    fun maybeGunzip(bytes: ByteArray): ByteArray {
        if (bytes.size < 2) return bytes
        val magic0 = bytes[0].toInt() and 0xFF
        val magic1 = bytes[1].toInt() and 0xFF
        if (magic0 != 0x1f || magic1 != 0x8b) return bytes
        return GZIPInputStream(ByteArrayInputStream(bytes)).use { it.readBytes() }
    }

    fun parseHashes(json: String): List<ThreatHashEntity> {
        val array = try {
            JSONArray(json)
        } catch (e: Exception) {
            throw UpdateRejection(UpdateErrorCode.MALFORMED, "해시 페이로드가 JSON 배열이 아닙니다.")
        }
        if (array.length() > MAX_RECORDS) {
            throw UpdateRejection(UpdateErrorCode.MALFORMED, "레코드 수 초과: ${array.length()}")
        }
        val hashes = ArrayList<ThreatHashEntity>(array.length())
        for (i in 0 until array.length()) {
            val item = array.optJSONObject(i) ?: continue
            val sha = item.optString("sha256", "").lowercase()
            if (!sha.matches(Regex("^[0-9a-f]{64}$"))) {
                throw UpdateRejection(UpdateErrorCode.MALFORMED, "해시 형식 오류: ${sha.take(12)}")
            }
            hashes += ThreatHashEntity(
                sha256 = sha,
                threatName = item.optString("threatName", "Unknown"),
                threatFamily = item.optString("family").ifEmpty { null },
                category = item.optString("category", "malware"),
                severity = item.optString("severity", "HIGH").uppercase(),
                confidence = item.optInt("confidence", 70).coerceIn(0, 100),
                source = item.optString("source", "unknown"),
                firstSeen = item.optLong("firstSeen").takeIf { it > 0 },
                lastSeen = item.optLong("lastSeen").takeIf { it > 0 },
                updatedAt = System.currentTimeMillis(),
            )
        }
        return hashes
    }

    fun parseRules(json: String): List<ThreatRuleEntity> {
        val root = try {
            JSONObject(json)
        } catch (e: Exception) {
            throw UpdateRejection(UpdateErrorCode.MALFORMED, "규칙 페이로드가 JSON 객체가 아닙니다.")
        }
        val engine = root.optString("engine", "YARA_SUBSET")
        val array = root.optJSONArray("rules") ?: JSONArray()
        if (array.length() > MAX_RECORDS) {
            throw UpdateRejection(UpdateErrorCode.MALFORMED, "규칙 수 초과")
        }
        val rules = ArrayList<ThreatRuleEntity>(array.length())
        for (i in 0 until array.length()) {
            val item = array.optJSONObject(i) ?: continue
            val name = item.optString("name", "").trim()
            val content = item.optString("content", "")
            if (name.isEmpty() || content.isEmpty()) {
                throw UpdateRejection(UpdateErrorCode.MALFORMED, "규칙 이름/본문 누락")
            }
            rules += ThreatRuleEntity(
                engine = engine,
                ruleName = name,
                category = item.optString("category", "suspicious_pattern"),
                severity = item.optString("severity", "MEDIUM").uppercase(),
                content = content,
                source = item.optString("source", "update"),
                version = item.optString("version", "0"),
                enabled = item.optBoolean("enabled", true),
                updatedAt = System.currentTimeMillis(),
            )
        }
        return rules
    }

    fun parseFilterRules(json: String, sourceId: Long): Triple<List<AdFilterRuleEntity>, String, RuleParseStats> {
        val root = try {
            JSONObject(json)
        } catch (e: Exception) {
            throw UpdateRejection(UpdateErrorCode.MALFORMED, "필터 페이로드가 JSON 객체가 아닙니다.")
        }
        val array = root.optJSONArray("rules") ?: JSONArray()
        val category = root.optString("category", "ADS")
        val sourceName = root.optString("source", "update")
        if (array.length() > MAX_RECORDS) {
            throw UpdateRejection(UpdateErrorCode.MALFORMED, "규칙 수 초과")
        }
        val lines = ArrayList<String>(array.length())
        for (i in 0 until array.length()) {
            lines += array.optString(i, "")
        }
        val meta = FilterSourceMeta(
            sourceId = sourceId,
            name = sourceName,
            category = category,
            priority = root.optInt("priority", 100),
        )
        val parsed = RuleParser.parse(lines.asSequence(), meta)
        val entities = parsed.rules.map { rule ->
            AdFilterRuleEntity(
                sourceId = sourceId,
                domain = rule.domain,
                ruleType = if (rule.wildcard) "WILDCARD" else if (rule.matchSubdomains) "SUFFIX" else "EXACT",
                category = rule.category,
                rawRule = rule.rawRule,
                enabled = true,
            )
        }
        return Triple(entities, sourceName, parsed.stats)
    }
}
