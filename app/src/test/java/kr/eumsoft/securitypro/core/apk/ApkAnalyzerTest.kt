package kr.eumsoft.securitypro.core.apk

import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kr.eumsoft.securitypro.core.risk.RiskLevel
import kr.eumsoft.securitypro.core.risk.ScanEngine
import kr.eumsoft.securitypro.core.risk.Severity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ApkAnalyzerTest {

    private val analyzer = ApkStaticAnalyzer()

    private fun fixture(name: String): File {
        val url = checkNotNull(javaClass.classLoader?.getResource("fixtures/$name")) {
            "테스트 픽스처를 찾을 수 없습니다: $name"
        }
        return File(url.toURI())
    }

    @Test
    fun `정상 APK 의 매니페스트를 파싱한다`() {
        val analysis = analyzer.analyze(fixture("normal.apk.fixture"))
        assertNull(analysis.errorKey)
        val manifest = analysis.manifest
        assertNotNull(manifest)
        assertEquals("com.example.eumfixture", manifest!!.packageName)
        assertEquals("1.2.3", manifest.versionName)
        assertEquals(7L, manifest.versionCode)
        assertEquals(35, manifest.targetSdk)
        assertTrue(manifest.permissions.contains("android.permission.INTERNET"))
        assertEquals("EUM Fixture", manifest.applicationLabel)
        assertFalse(manifest.debuggable)
        val activity = manifest.components.first { it.type == "activity" }
        assertEquals("com.example.eumfixture.MainActivity", activity.name)
        assertTrue(activity.exported)
        assertTrue(activity.actions.contains("android.intent.action.MAIN"))
    }

    @Test
    fun `서명 인증서 SHA-256 을 읽는다`() {
        val analysis = analyzer.analyze(fixture("normal.apk.fixture"))
        // apksigner --print-certs 로 확인한 디버그 키 지문
        assertEquals(
            "dc45cfba13f65d3a378e751fbbdce8eb12eeb9ab55df39fb3a1f7c60fdf642da",
            analysis.certSha256,
        )
        assertTrue(analysis.signature.scheme == "v2" || analysis.signature.scheme == "v3")
    }

    @Test
    fun `SHA-256 은 파일 해시와 일치한다`() {
        val file = fixture("normal.apk.fixture")
        val analysis = analyzer.analyze(file)
        assertEquals(kr.eumsoft.securitypro.core.crypto.Sha256.ofFile(file), analysis.sha256)
        assertEquals(
            "daaf11d2a358f5b30aad6281bc416b4c9bfc56dd25ad444aa0f9c782e9325796",
            analysis.sha256,
        )
    }

    @Test
    fun `위험 APK 에서 권한과 컴포넌트 근거를 찾는다`() {
        val analysis = analyzer.analyze(fixture("risky.apk.fixture"))
        val manifest = analysis.manifest!!
        assertEquals("com.example.eumrisky", manifest.packageName)
        assertEquals(28, manifest.targetSdk)
        assertTrue(manifest.debuggable)
        assertTrue(manifest.permissions.contains("android.permission.SEND_SMS"))
        val findings = analysis.findings
        assertTrue(findings.any { it.ruleId == "debuggable" })
        assertTrue(findings.any { it.category == "dangerous_permission" })
        assertTrue(findings.any { it.titleKey == "finding_sms_plus_internet" })
        assertTrue(findings.any { it.ruleId == "accessibility_service" })
        assertTrue(findings.any { it.ruleId == "device_admin" })
    }

    @Test
    fun `위험 APK 판정은 주의 단계이며 확정 악성으로 표시하지 않는다`() {
        val analysis = analyzer.analyze(fixture("risky.apk.fixture"))
        val verdict = analyzer.verdictFor(analysis, emptyList())
        assertEquals(RiskLevel.WARNING, verdict.level)
        assertTrue(verdict.findings.none { it.engine == ScanEngine.HASH })
    }

    @Test
    fun `해시 일치 시에만 위험으로 판정한다`() {
        val analysis = analyzer.analyze(fixture("normal.apk.fixture"))
        val hashFinding = kr.eumsoft.securitypro.core.risk.Finding(
            engine = ScanEngine.HASH,
            ruleId = analysis.sha256,
            category = "malware",
            severity = Severity.CRITICAL,
            confidence = 95,
            titleKey = "finding_known_malware",
            evidence = "SHA-256: ${analysis.sha256}",
        )
        val verdict = analyzer.verdictFor(analysis, listOf(hashFinding))
        assertEquals(RiskLevel.DANGER, verdict.level)
        assertTrue(verdict.reasonKeys.contains("reason_confirmed_hash"))
    }

    @Test
    fun `손상된 APK 는 예외 없이 분석 실패로 보고된다`() {
        val analysis = analyzer.analyze(fixture("corrupt.apk.fixture"))
        assertNotNull(analysis)
        assertNull(analysis.manifest)
        assertTrue(analysis.truncated || analysis.errorKey != null)
    }

    @Test
    fun `압축 폭탄은 한도에서 차단된다`() {
        val file = File.createTempFile("bomb", ".fixture")
        try {
            ZipOutputStream(file.outputStream()).use { zip ->
                zip.putNextEntry(ZipEntry("classes.dex"))
                val block = ByteArray(256 * 1024)
                repeat(48) { zip.write(block) }
                zip.closeEntry()
            }
            val analysis = analyzer.analyze(file)
            assertTrue("폭탄 감지 실패", analysis.bombSuspected)
            assertTrue(analysis.findings.any { it.ruleId == "zip_bomb" })
        } finally {
            file.delete()
        }
    }

    @Test
    fun `경로 이탈 엔트리를 가진 ZIP 을 탐지한다`() {
        val file = File.createTempFile("slip", ".fixture")
        try {
            ZipOutputStream(file.outputStream()).use { zip ->
                zip.putNextEntry(ZipEntry("../../evil.txt"))
                zip.write("x".toByteArray())
                zip.closeEntry()
                zip.putNextEntry(ZipEntry("AndroidManifest.xml"))
                zip.write(byteArrayOf(1, 2, 3))
                zip.closeEntry()
            }
            val analysis = analyzer.analyze(file)
            assertTrue(analysis.findings.any { it.ruleId == "zip_path_traversal" })
        } finally {
            file.delete()
        }
    }

    @Test
    fun `DEX 안의 패턴을 찾아 근거로 남긴다`() {
        val file = File.createTempFile("dex", ".fixture")
        try {
            ZipOutputStream(file.outputStream()).use { zip ->
                zip.putNextEntry(ZipEntry("classes.dex"))
                zip.write(
                    ("Ldalvik/system/DexClassLoader; Ldalvik/system/PathClassLoader; " +
                        "Ldalvik/system/InMemoryDexClassLoader;").toByteArray()
                )
                zip.closeEntry()
            }
            val analysis = analyzer.analyze(file)
            val pattern = analysis.findings.filter { it.engine == ScanEngine.YARA_SUBSET }
            assertTrue(pattern.isNotEmpty())
            assertTrue(pattern.first().evidence.contains("classes.dex"))
        } finally {
            file.delete()
        }
    }
}
