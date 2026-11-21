package kr.eumsoft.securitypro.data.updater

/** 업데이트 대상(독립적으로 버전이 매겨진다). */
enum class UpdateTarget(val dbType: String, val pathSegment: String) {
    AD_FILTER("AD_FILTER", "ad-filter"),
    THREAT_HASH("THREAT_HASH", "threat-hash"),
    YARA_RULES("YARA_RULES", "yara-rules"),
}

/**
 * 서명된 업데이트 매니페스트.
 *
 * [canonicalBytes] 는 서명 대상 바이트다(전송 공백/키 순서와 무관하게 재구성).
 */
data class UpdateManifest(
    val target: UpdateTarget,
    val version: Long,
    val versionLabel: String,
    val publishedAt: Long,
    val payloadUrl: String,
    val payloadSha256: String,
    val payloadSize: Long,
    val entryCount: Int,
    val isTestData: Boolean,
    val canonicalBytes: ByteArray,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is UpdateManifest) return false
        return target == other.target && version == other.version &&
            versionLabel == other.versionLabel && payloadUrl == other.payloadUrl &&
            payloadSha256 == other.payloadSha256 && isTestData == other.isTestData
    }

    override fun hashCode(): Int = version.hashCode() * 31 + target.hashCode()
}

enum class UpdateErrorCode {
    NOT_CONFIGURED,
    SIGNATURE,
    SHA256,
    ROLLBACK,
    TOO_LARGE,
    MALFORMED,
    HTTP,
    IO,
    UNKNOWN,
}

class UpdateRejection(val code: UpdateErrorCode, val detail: String) :
    Exception("$code: $detail")

/** 업데이트 실행 결과. UI/이력에 그대로 표시한다. */
sealed interface UpdateOutcome {
    val target: UpdateTarget

    data class Success(
        override val target: UpdateTarget,
        val version: Long,
        val versionLabel: String,
        val records: Int,
        val isTestData: Boolean,
        val signatureVerified: Boolean,
    ) : UpdateOutcome

    data class UpToDate(
        override val target: UpdateTarget,
        val currentVersion: Long,
    ) : UpdateOutcome

    data class NotConfigured(override val target: UpdateTarget, val detail: String) : UpdateOutcome

    data class Rejected(
        override val target: UpdateTarget,
        val code: UpdateErrorCode,
        val detail: String,
    ) : UpdateOutcome

    data class Failed(
        override val target: UpdateTarget,
        val detail: String,
        val httpStatus: Int? = null,
    ) : UpdateOutcome
}
