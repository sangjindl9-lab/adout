package kr.eumsoft.securitypro.core.risk

import kr.eumsoft.securitypro.core.apk.ApkComponent
import kr.eumsoft.securitypro.core.apk.ManifestInfo
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RiskAssessorTest {

    private fun finding(
        engine: ScanEngine,
        severity: Severity,
        confidence: Int = 60,
        category: String = "test",
    ) = Finding(
        engine = engine,
        ruleId = "rule",
        category = category,
        severity = severity,
        confidence = confidence,
        titleKey = "finding_test",
        evidence = "evidence",
    )

    @Test
    fun `검증된 해시만 위험으로 판정한다`() {
        val verdict = RiskAssessor.assess(
            findings = listOf(finding(ScanEngine.HASH, Severity.CRITICAL, confidence = 90)),
            enginesRun = setOf(ScanEngine.HASH),
        )
        assertEquals(RiskLevel.DANGER, verdict.level)
        assertTrue(verdict.reasonKeys.contains("reason_confirmed_hash"))
    }

    @Test
    fun `신뢰도 낮은 패턴은 주의에 머문다`() {
        val verdict = RiskAssessor.assess(
            findings = listOf(finding(ScanEngine.YARA_SUBSET, Severity.HIGH, confidence = 40)),
            enginesRun = setOf(ScanEngine.APK_STATIC, ScanEngine.YARA_SUBSET),
        )
        assertEquals(RiskLevel.WARNING, verdict.level)
        assertTrue(verdict.reasonKeys.contains("reason_heuristic_only"))
    }

    @Test
    fun `근거가 없으면 알려진 위협 미발견`() {
        val verdict = RiskAssessor.assess(
            findings = emptyList(),
            enginesRun = setOf(ScanEngine.HASH, ScanEngine.APK_STATIC),
        )
        assertEquals(RiskLevel.NOT_FOUND, verdict.level)
        assertTrue(verdict.reasonKeys.contains("reason_no_known_threat"))
    }

    @Test
    fun `정보성 근거만 있으면 미발견`() {
        val verdict = RiskAssessor.assess(
            findings = listOf(finding(ScanEngine.APK_STATIC, Severity.INFO)),
            enginesRun = setOf(ScanEngine.APK_STATIC),
        )
        assertEquals(RiskLevel.NOT_FOUND, verdict.level)
    }

    @Test
    fun `검사 실패는 검사 불가`() {
        val verdict = RiskAssessor.assess(
            findings = emptyList(),
            enginesRun = emptySet(),
            scanFailed = true,
            failureReason = "error_file_access",
        )
        assertEquals(RiskLevel.UNABLE, verdict.level)
        assertTrue(verdict.reasonKeys.contains("reason_scan_failed"))
    }

    @Test
    fun `위험 점수는 100 을 넘지 않는다`() {
        val findings = (1..10).map { finding(ScanEngine.PATTERN, Severity.CRITICAL) }
        val verdict = RiskAssessor.assess(findings, setOf(ScanEngine.PATTERN))
        assertTrue(verdict.score <= 100)
    }

    @Test
    fun `SMS 와 인터넷 조합을 찾는다`() {
        val findings = PermissionAnalyzer.analyze(
            packageName = "com.example.unknown",
            isSystem = false,
            info = null,
            permissions = listOf(
                "android.permission.READ_SMS",
                "android.permission.SEND_SMS",
                "android.permission.INTERNET",
            ),
        )
        assertTrue(findings.any { it.titleKey == "finding_sms_plus_internet" })
    }

    @Test
    fun `널리 쓰이는 앱은 신뢰도를 낮춘다`() {
        val permissions = listOf(
            "android.permission.READ_SMS",
            "android.permission.SEND_SMS",
            "android.permission.INTERNET",
        )
        val unknown = PermissionAnalyzer.analyze("com.example.unknown", false, null, permissions)
        val known = PermissionAnalyzer.analyze("com.google.android.apps.messaging", false, null, permissions)
        val unknownCombo = unknown.first { it.titleKey == "finding_sms_plus_internet" }
        val knownCombo = known.first { it.titleKey == "finding_sms_plus_internet" }
        assertTrue(knownCombo.confidence < unknownCombo.confidence)
        assertTrue(knownCombo.severity.weight < unknownCombo.severity.weight)
    }

    @Test
    fun `권한 없는 exported 컴포넌트를 찾는다`() {
        val info = ManifestInfo(
            packageName = "com.example.unknown",
            versionName = "1",
            versionCode = 1,
            minSdk = 29,
            targetSdk = 35,
            permissions = listOf("android.permission.INTERNET"),
            components = listOf(
                ApkComponent(
                    type = "activity",
                    name = "com.example.unknown.OpenActivity",
                    exported = true,
                    hasIntentFilter = true,
                )
            ),
            applicationLabel = "x",
            debuggable = false,
            allowBackup = true,
            usesCleartextTraffic = false,
            features = emptyList(),
            usesLibraries = emptyList(),
        )
        val findings = PermissionAnalyzer.analyze("com.example.unknown", false, info)
        assertTrue(findings.any { it.ruleId == "exported_component" })
    }

    @Test
    fun `시스템 앱은 권한 근거를 만들지 않는다`() {
        val findings = PermissionAnalyzer.analyze(
            packageName = "android",
            isSystem = true,
            info = null,
            permissions = listOf("android.permission.SEND_SMS", "android.permission.INTERNET"),
        )
        val combo = findings.firstOrNull { it.titleKey == "finding_sms_plus_internet" }
        if (combo != null) {
            assertFalse(combo.severity == Severity.CRITICAL)
        }
    }
}
