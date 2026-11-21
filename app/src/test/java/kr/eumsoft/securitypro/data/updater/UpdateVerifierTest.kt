package kr.eumsoft.securitypro.data.updater

import kr.eumsoft.securitypro.core.crypto.Sha256
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class UpdateVerifierTest {

    private val keys = Ed25519TestKeys.generate()

    private fun manifestJson(
        version: Long = 5,
        payload: ByteArray = """[{"sha256":"${"a".repeat(64)}"}]""".toByteArray(),
        target: UpdateTarget = UpdateTarget.THREAT_HASH,
        isTestData: Boolean = true,
        keyPair: Ed25519TestKeys.KeyPair = keys,
    ): String {
        val canonical = UpdateManifestCodec.canonicalBytes(
            target = target,
            version = version,
            versionLabel = "2026.11.$version",
            publishedAt = 1_800_000_000_000L,
            payloadUrl = "https://example.invalid/payload.json",
            payloadSha256 = Sha256.of(payload),
            payloadSize = payload.size.toLong(),
            entryCount = 1,
            isTestData = isTestData,
        )
        val signature = Ed25519TestKeys.sign(keyPair, canonical)
        val body = String(canonical, Charsets.UTF_8)
        return "{\"manifest\":$body,\"signature\":\"${Ed25519TestKeys.base64(signature)}\"}"
    }

    @Test
    fun `올바른 서명은 검증을 통과한다`() {
        val verifier = UpdateVerifier(keys.publicKeyHex)
        val manifest = verifier.verifyManifest(manifestJson())
        assertEquals(5L, manifest.version)
        assertEquals(UpdateTarget.THREAT_HASH, manifest.target)
        assertTrue(manifest.isTestData)
    }

    @Test
    fun `본문을 변조하면 서명 검증에 실패한다`() {
        val verifier = UpdateVerifier(keys.publicKeyHex)
        val json = manifestJson().replace("\"version\":5", "\"version\":6")
        try {
            verifier.verifyManifest(json)
            fail("변조된 매니페스트가 통과했습니다.")
        } catch (e: UpdateRejection) {
            assertEquals(UpdateErrorCode.SIGNATURE, e.code)
        }
    }

    @Test
    fun `다른 키로 서명하면 실패한다`() {
        val otherKeys = Ed25519TestKeys.generate(seed = ByteArray(32) { (it * 11 + 5).toByte() })
        val verifier = UpdateVerifier(keys.publicKeyHex)
        try {
            verifier.verifyManifest(manifestJson(keyPair = otherKeys))
            fail("다른 키의 서명이 통과했습니다.")
        } catch (e: UpdateRejection) {
            assertEquals(UpdateErrorCode.SIGNATURE, e.code)
        }
    }

    @Test
    fun `공개키가 없으면 설정 안 됨`() {
        val verifier = UpdateVerifier("")
        assertFalse(verifier.isConfigured())
        try {
            verifier.verifyManifest(manifestJson())
            fail("공개키 없이 통과했습니다.")
        } catch (e: UpdateRejection) {
            assertEquals(UpdateErrorCode.NOT_CONFIGURED, e.code)
        }
    }

    @Test
    fun `페이로드 해시와 크기를 확인한다`() {
        val payload = """[{"sha256":"${"b".repeat(64)}"}]""".toByteArray()
        val verifier = UpdateVerifier(keys.publicKeyHex)
        val manifest = verifier.verifyManifest(manifestJson(payload = payload))
        verifier.verifyPayload(payload, manifest)
        try {
            verifier.verifyPayload(payload + "x".toByteArray(), manifest)
            fail("변조된 페이로드가 통과했습니다.")
        } catch (e: UpdateRejection) {
            assertEquals(UpdateErrorCode.SHA256, e.code)
        }
    }

    @Test
    fun `롤백과 동일 버전 재적용을 막는다`() {
        val verifier = UpdateVerifier(keys.publicKeyHex)
        verifier.checkRollback(currentVersion = 3, incomingVersion = 4)
        listOf(3L, 2L, 1L).forEach { incoming ->
            try {
                verifier.checkRollback(currentVersion = 3, incomingVersion = incoming)
                fail("롤백($incoming)이 통과했습니다.")
            } catch (e: UpdateRejection) {
                assertEquals(UpdateErrorCode.ROLLBACK, e.code)
            }
        }
    }

    @Test
    fun `https 가 아닌 페이로드 URL 은 거부한다`() {
        val canonical = UpdateManifestCodec.canonicalBytes(
            target = UpdateTarget.AD_FILTER,
            version = 2,
            versionLabel = "v2",
            publishedAt = 0,
            payloadUrl = "http://insecure.invalid/payload.json",
            payloadSha256 = Sha256.of("x"),
            payloadSize = 1,
            entryCount = 0,
            isTestData = false,
        )
        val signature = Ed25519TestKeys.sign(keys, canonical)
        val json = "{\"manifest\":${String(canonical)}, \"signature\":\"${Ed25519TestKeys.base64(signature)}\"}"
        try {
            UpdateVerifier(keys.publicKeyHex).verifyManifest(json)
            fail("http URL 이 통과했습니다.")
        } catch (e: UpdateRejection) {
            assertEquals(UpdateErrorCode.MALFORMED, e.code)
        }
    }
}
