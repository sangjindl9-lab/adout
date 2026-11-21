package kr.eumsoft.securitypro.data.updater

import org.json.JSONObject

/**
 * 매니페스트 JSON 파서/정규화기.
 *
 * 서명 대상은 "manifest" 객체의 정규화(canonical) JSON 이다. 필드 순서와 공백을
 * 고정해, 전송 과정에서 형식이 바뀌어도 같은 서명이 검증되게 한다.
 */
object UpdateManifestCodec {

    fun parse(json: String): Pair<UpdateManifest, ByteArray> {
        val root = try {
            JSONObject(json)
        } catch (e: Exception) {
            throw UpdateRejection(UpdateErrorCode.MALFORMED, "JSON 파싱 실패: ${e.message}")
        }
        val body = root.optJSONObject("manifest")
            ?: throw UpdateRejection(UpdateErrorCode.MALFORMED, "manifest 객체가 없습니다.")
        val signatureBase64 = root.optString("signature", "")
        if (signatureBase64.isBlank()) {
            throw UpdateRejection(UpdateErrorCode.SIGNATURE, "signature 필드가 없습니다.")
        }
        val targetName = body.optString("target", "")
        val target = UpdateTarget.entries.firstOrNull { it.name == targetName }
            ?: throw UpdateRejection(UpdateErrorCode.MALFORMED, "알 수 없는 target: $targetName")
        val manifest = UpdateManifest(
            target = target,
            version = body.optLong("version", -1),
            versionLabel = body.optString("versionLabel", ""),
            publishedAt = body.optLong("publishedAt", 0),
            payloadUrl = body.optString("payloadUrl", ""),
            payloadSha256 = body.optString("payloadSha256", "").lowercase(),
            payloadSize = body.optLong("payloadSize", 0),
            entryCount = body.optInt("entryCount", 0),
            isTestData = body.optBoolean("isTestData", false),
            canonicalBytes = canonicalBytes(
                target = target,
                version = body.optLong("version", -1),
                versionLabel = body.optString("versionLabel", ""),
                publishedAt = body.optLong("publishedAt", 0),
                payloadUrl = body.optString("payloadUrl", ""),
                payloadSha256 = body.optString("payloadSha256", "").lowercase(),
                payloadSize = body.optLong("payloadSize", 0),
                entryCount = body.optInt("entryCount", 0),
                isTestData = body.optBoolean("isTestData", false),
            ),
        )
        if (manifest.version < 1) {
            throw UpdateRejection(UpdateErrorCode.MALFORMED, "version 값이 올바르지 않습니다.")
        }
        if (!manifest.payloadUrl.startsWith("https://")) {
            throw UpdateRejection(UpdateErrorCode.MALFORMED, "payloadUrl 은 https 여야 합니다.")
        }
        if (!manifest.payloadSha256.matches(Regex("^[0-9a-f]{64}$"))) {
            throw UpdateRejection(UpdateErrorCode.MALFORMED, "payloadSha256 형식 오류")
        }
        val signature = try {
            java.util.Base64.getDecoder().decode(signatureBase64)
        } catch (e: Exception) {
            throw UpdateRejection(UpdateErrorCode.SIGNATURE, "서명 base64 해석 실패")
        }
        return manifest to signature
    }

    /** 서명 대상 정규화 바이트. 필드 순서 고정, 공백 없음. */
    fun canonicalBytes(
        target: UpdateTarget,
        version: Long,
        versionLabel: String,
        publishedAt: Long,
        payloadUrl: String,
        payloadSha256: String,
        payloadSize: Long,
        entryCount: Int,
        isTestData: Boolean,
    ): ByteArray {
        val sb = StringBuilder(256)
        sb.append('{')
        sb.append("\"target\":\"").append(target.name).append("\",")
        sb.append("\"version\":").append(version).append(',')
        sb.append("\"versionLabel\":\"").append(escape(versionLabel)).append("\",")
        sb.append("\"publishedAt\":").append(publishedAt).append(',')
        sb.append("\"payloadUrl\":\"").append(escape(payloadUrl)).append("\",")
        sb.append("\"payloadSha256\":\"").append(payloadSha256).append("\",")
        sb.append("\"payloadSize\":").append(payloadSize).append(',')
        sb.append("\"entryCount\":").append(entryCount).append(',')
        sb.append("\"isTestData\":").append(isTestData)
        sb.append('}')
        return sb.toString().toByteArray(Charsets.UTF_8)
    }

    /** 서버/테스트용: 매니페스트 JSON 문자열 생성. */
    fun encode(
        manifest: UpdateManifest,
        signatureBase64: String,
    ): String {
        val body = String(manifest.canonicalBytes, Charsets.UTF_8)
        return "{\"manifest\":$body,\"signature\":\"$signatureBase64\"}"
    }

    private fun escape(value: String): String {
        val sb = StringBuilder(value.length + 8)
        value.forEach { c ->
            when (c) {
                '"' -> sb.append("\\\"")
                '\\' -> sb.append("\\\\")
                '\n' -> sb.append("\\n")
                '\r' -> sb.append("\\r")
                '\t' -> sb.append("\\t")
                else -> if (c.code < 0x20) sb.append("\\u%04x".format(c.code)) else sb.append(c)
            }
        }
        return sb.toString()
    }
}
