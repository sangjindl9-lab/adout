package kr.eumsoft.securitypro.data.updater

import java.security.MessageDigest

/**
 * 업데이트 검증기: Ed25519 서명 → SHA-256 무결성 → 롤백(다운그레이드) 차단.
 */
class UpdateVerifier(
    private val publicKeyHex: String,
) {

    fun isConfigured(): Boolean = publicKeyHex.isNotBlank() && Ed25519.isValidPublicKey(publicKeyHex)

    /** 매니페스트 서명 검증 후 매니페스트를 돌려준다. */
    fun verifyManifest(manifestJson: String): UpdateManifest {
        if (!isConfigured()) {
            throw UpdateRejection(UpdateErrorCode.NOT_CONFIGURED, "업데이트 공개키가 설정되지 않았습니다.")
        }
        val (manifest, signature) = UpdateManifestCodec.parse(manifestJson)
        val key = Ed25519.hexToBytes(publicKeyHex)
        if (!Ed25519.verify(key, manifest.canonicalBytes, signature)) {
            throw UpdateRejection(UpdateErrorCode.SIGNATURE, "Ed25519 서명이 일치하지 않습니다.")
        }
        return manifest
    }

    /** 내려받은 페이로드의 SHA-256 과 크기를 확인한다. */
    fun verifyPayload(payload: ByteArray, manifest: UpdateManifest) {
        if (manifest.payloadSize > 0 && payload.size.toLong() != manifest.payloadSize) {
            throw UpdateRejection(
                UpdateErrorCode.SHA256,
                "페이로드 크기 불일치: ${payload.size} != ${manifest.payloadSize}",
            )
        }
        val digest = MessageDigest.getInstance("SHA-256").digest(payload)
        val hex = digest.joinToString("") { "%02x".format(it) }
        if (!hex.equals(manifest.payloadSha256, ignoreCase = true)) {
            throw UpdateRejection(UpdateErrorCode.SHA256, "SHA-256 불일치")
        }
    }

    /** 같은 버전 재적용과 다운그레이드를 모두 막는다(롤백 공격 방지). */
    fun checkRollback(currentVersion: Long, incomingVersion: Long) {
        if (incomingVersion <= currentVersion) {
            throw UpdateRejection(
                UpdateErrorCode.ROLLBACK,
                "현재 버전($currentVersion) 이하의 매니페스트($incomingVersion)는 적용하지 않습니다.",
            )
        }
    }
}
