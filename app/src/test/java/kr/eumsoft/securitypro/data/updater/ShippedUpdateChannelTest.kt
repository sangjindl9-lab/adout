package kr.eumsoft.securitypro.data.updater

import java.io.File
import kr.eumsoft.securitypro.BuildConfig
import kr.eumsoft.securitypro.core.crypto.Sha256
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 저장소에 커밋된 테스트 업데이트 채널(testdata/update)이 앱에 내장된 공개키와 맞는지 검증한다.
 *
 * 실제 기기에서는 이 파일들이 HTTPS 로 내려받아지며, 이 테스트는 그 데이터가
 * (1) 올바른 Ed25519 서명을 가지고 (2) 페이로드 해시가 일치하며
 * (3) 앱의 파서가 기대하는 형식인지 확인한다.
 */
class ShippedUpdateChannelTest {

    private val root: File = sequenceOf(
        File("../testdata/update"),
        File("testdata/update"),
    ).firstOrNull { it.isDirectory }
        ?: error("testdata/update 를 찾을 수 없습니다.")

    private val verifier = UpdateVerifier(BuildConfig.UPDATE_PUBLIC_KEY)

    @Test
    fun `채널 공개키가 앱에 설정되어 있다`() {
        assertTrue("BuildConfig.UPDATE_PUBLIC_KEY 가 비어 있습니다.", BuildConfig.UPDATE_PUBLIC_KEY.isNotBlank())
        assertTrue(Ed25519.isValidPublicKey(BuildConfig.UPDATE_PUBLIC_KEY))
        assertTrue(
            "BuildConfig.UPDATE_BASE_URL 이 https 여야 합니다: ${BuildConfig.UPDATE_BASE_URL}",
            BuildConfig.UPDATE_BASE_URL.startsWith("https://"),
        )
    }

    @Test
    fun `세 대상의 매니페스트 서명과 페이로드가 유효하다`() {
        UpdateTarget.entries.forEach { target ->
            val dir = File(root, target.pathSegment)
            val manifestJson = File(dir, "manifest.json").readText()
            val manifest = verifier.verifyManifest(manifestJson)
            assertEquals(target, manifest.target)
            assertTrue("테스트 데이터 표시가 필요합니다.", manifest.isTestData)
            assertTrue(manifest.payloadUrl.startsWith("https://"))

            val payloadFile = File(dir, manifest.payloadUrl.substringAfterLast('/'))
            assertTrue("페이로드 파일 없음: ${payloadFile.name}", payloadFile.isFile)
            val payload = payloadFile.readBytes()
            verifier.verifyPayload(payload, manifest)
            assertEquals(Sha256.of(payload), manifest.payloadSha256)

            val parsed = when (target) {
                UpdateTarget.THREAT_HASH -> UpdatePayloadParser.parseHashes(String(payload)).size
                UpdateTarget.YARA_RULES -> UpdatePayloadParser.parseRules(String(payload)).size
                UpdateTarget.AD_FILTER ->
                    UpdatePayloadParser.parseFilterRules(String(payload), sourceId = 1).first.size
            }
            assertEquals("레코드 수 불일치($target)", manifest.entryCount, parsed)
        }
    }

    @Test
    fun `테스트 채널의 해시는 고유하고 형식이 올바르다`() {
        val payload = File(root, "threat-hash/data-1.json").readText()
        val hashes = UpdatePayloadParser.parseHashes(payload)
        assertEquals(3, hashes.size)
        assertEquals(hashes.size, hashes.map { it.sha256 }.distinct().size)
        hashes.forEach { assertTrue(Sha256.isValidHex(it.sha256)) }
    }

    @Test
    fun `테스트 채널 필터 규칙이 매칭 가능한 형태다`() {
        val payload = File(root, "ad-filter/data-1.json").readText()
        val (rules, _, stats) = UpdatePayloadParser.parseFilterRules(payload, sourceId = 1)
        assertEquals(6, rules.size)
        assertEquals(0, stats.skippedInvalid)
        assertTrue(rules.any { it.rawRule.startsWith("@@") })
    }
}
