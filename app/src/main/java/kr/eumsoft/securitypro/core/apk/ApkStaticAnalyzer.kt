package kr.eumsoft.securitypro.core.apk

import java.io.File
import kr.eumsoft.securitypro.core.crypto.Sha256
import kr.eumsoft.securitypro.core.pattern.PatternScanner
import kr.eumsoft.securitypro.core.risk.Finding
import kr.eumsoft.securitypro.core.risk.PermissionAnalyzer
import kr.eumsoft.securitypro.core.risk.RiskLevel
import kr.eumsoft.securitypro.core.risk.RiskVerdict
import kr.eumsoft.securitypro.core.risk.RiskAssessor
import kr.eumsoft.securitypro.core.risk.ScanEngine
import kr.eumsoft.securitypro.core.risk.Severity

/** APK 정적 분석 결과. */
data class ApkAnalysis(
    val filePath: String,
    val fileSize: Long,
    val sha256: String?,
    val manifest: ManifestInfo?,
    val signature: ApkSignatureReader.Result,
    val dexFiles: List<String> = emptyList(),
    val nativeLibs: List<String> = emptyList(),
    val scriptFiles: List<String> = emptyList(),
    val suspiciousAssetFiles: List<String> = emptyList(),
    val entryCount: Int = 0,
    val findings: List<Finding> = emptyList(),
    val unscanned: List<String> = emptyList(),
    val errorKey: String? = null,
    val truncated: Boolean = false,
    val bombSuspected: Boolean = false,
    val patternCompileErrors: List<String> = emptyList(),
) {
    val packageName: String? get() = manifest?.packageName
    val versionName: String? get() = manifest?.versionName
    val versionCode: Long get() = manifest?.versionCode ?: 0
    val certSha256: String? get() = signature.certSha256
    val isSuccessful: Boolean get() = errorKey == null && manifest != null
}

/**
 * 기기 안에서 동작하는 APK 정적 분석기.
 *
 * - APK 코드를 실행하지 않는다(ZIP 해제 + 바이너리 XML/서명/바이트 패턴만 읽는다).
 * - 압축 폭탄/손상 파일/과대 엔트리를 한도 내에서 안전하게 처리한다.
 * - 분석에 쓰는 메모리를 제한하기 위해 패턴 검사 대상은 개별/전체 한도를 둔다.
 */
class ApkStaticAnalyzer(
    private val limits: ArchiveLimits = ArchiveLimits(),
    private val maxEntryScanBytes: Long = 24L * 1024 * 1024,
    private val maxTotalScanBytes: Long = 48L * 1024 * 1024,
    private val patternScanner: PatternScanner = PatternScanner(),
) {

    fun analyze(file: File, onProgress: ((String) -> Unit)? = null): ApkAnalysis {
        if (!file.isFile || !file.canRead()) {
            return ApkAnalysis(
                filePath = file.absolutePath,
                fileSize = 0,
                sha256 = null,
                manifest = null,
                signature = ApkSignatureReader.Result(null, null, 0, "파일을 읽을 수 없음"),
                errorKey = "error_file_access",
                unscanned = listOf("파일 접근 불가"),
            )
        }
        val size = file.length()
        val sha256 = Sha256.ofFile(file)
        var manifestBytes: ByteArray? = null
        var manifestEntryMissing = true
        val dexFiles = ArrayList<String>()
        val nativeLibs = ArrayList<String>()
        val scriptFiles = ArrayList<String>()
        val suspiciousAssets = ArrayList<String>()
        val toScan = ArrayList<PatternScanner.Content>()
        var scanBytes = 0L
        val unscanned = ArrayList<String>()
        val pathWarnings = ArrayList<String>()

        val stats = try {
            ApkArchive.read(
                file = file,
                limits = limits,
                select = { name, _ ->
                    if (name.contains("..") || name.startsWith("/")) pathWarnings += name
                    shouldRead(name)
                },
                onEntry = { name, bytes ->
                    when {
                        name == "AndroidManifest.xml" -> {
                            manifestEntryMissing = false
                            manifestBytes = bytes
                        }
                        name.startsWith("classes") && name.endsWith(".dex") -> {
                            dexFiles += name
                            if (bytes.size <= maxEntryScanBytes && scanBytes + bytes.size <= maxTotalScanBytes) {
                                toScan += PatternScanner.Content(name, bytes)
                                scanBytes += bytes.size
                            } else {
                                unscanned += "$name (크기 한도 초과)"
                            }
                        }
                        name.endsWith(".so") -> {
                            nativeLibs += name
                            if (bytes.size <= maxEntryScanBytes && scanBytes + bytes.size <= maxTotalScanBytes) {
                                toScan += PatternScanner.Content(name, bytes)
                                scanBytes += bytes.size
                            }
                        }
                        isScript(name) -> {
                            scriptFiles += name
                            if (bytes.size <= maxEntryScanBytes && scanBytes + bytes.size <= maxTotalScanBytes) {
                                toScan += PatternScanner.Content(name, bytes)
                                scanBytes += bytes.size
                            }
                        }
                        else -> Unit
                    }
                    if (name.contains("..") || name.startsWith("/")) {
                        pathWarnings += name
                    }
                    if (name.matches(Regex("assets/.*\\.(dex|jar|so|apk)$"))) {
                        suspiciousAssets += name
                    }
                    onProgress?.invoke(name)
                },
            )
        } catch (e: ArchiveLimitException) {
            return ApkAnalysis(
                filePath = file.absolutePath,
                fileSize = size,
                sha256 = sha256,
                manifest = null,
                signature = ApkSignatureReader.Result(null, null, 0, null),
                errorKey = "error_archive_limit",
                unscanned = listOf("압축 해제 한도 초과"),
            )
        }

        val manifest = if (manifestBytes != null) {
            ManifestParser.parse(Axml.parse(manifestBytes!!), file.nameWithoutExtension.removePrefix("base"))
        } else {
            null
        }

        val signature = ApkSignatureReader.read(file)

        val findings = ArrayList<Finding>()
        if (manifest == null) {
            findings += Finding(
                engine = ScanEngine.APK_STATIC,
                ruleId = "manifest_missing",
                category = "analysis_limited",
                severity = Severity.INFO,
                confidence = 100,
                titleKey = "finding_manifest_missing",
                evidence = if (manifestEntryMissing) "AndroidManifest.xml 엔트리 없음" else "AndroidManifest.xml 해석 실패",
                adviceKey = null,
            )
        }
        manifest?.let { info ->
            if (info.debuggable) {
                findings += Finding(
                    engine = ScanEngine.APK_STATIC,
                    ruleId = "debuggable",
                    category = "insecure_setting",
                    severity = Severity.MEDIUM,
                    confidence = 90,
                    titleKey = "finding_debuggable",
                    evidence = "android:debuggable=\"true\"",
                    adviceKey = "advice_review_app",
                )
            }
            if (info.usesCleartextTraffic) {
                findings += Finding(
                    engine = ScanEngine.APK_STATIC,
                    ruleId = "cleartext",
                    category = "insecure_setting",
                    severity = Severity.LOW,
                    confidence = 70,
                    titleKey = "finding_cleartext",
                    evidence = "usesCleartextTraffic 허용 (targetSdk=${info.targetSdk ?: "?"})",
                    adviceKey = "advice_review_app",
                )
            }
            val lowTarget = info.targetSdk ?: 0
            if (lowTarget in 1..28) {
                findings += Finding(
                    engine = ScanEngine.APK_STATIC,
                    ruleId = "low_target_sdk",
                    category = "outdated_app",
                    severity = Severity.LOW,
                    confidence = 80,
                    titleKey = "finding_low_target_sdk",
                    evidence = "targetSdkVersion=$lowTarget",
                    adviceKey = "advice_update_app",
                )
            }
            findings += PermissionAnalyzer.analyze(
                packageName = info.packageName,
                isSystem = false,
                info = info,
            )
        }
        if (signature.certSha256 == null) {
            findings += Finding(
                engine = ScanEngine.APK_STATIC,
                ruleId = "unsigned",
                category = "signature",
                severity = Severity.MEDIUM,
                confidence = 70,
                titleKey = "finding_unsigned",
                evidence = signature.error ?: "서명 블록 없음",
                adviceKey = "advice_check_install_source",
            )
        }
        if (pathWarnings.isNotEmpty()) {
            findings += Finding(
                engine = ScanEngine.APK_STATIC,
                ruleId = "zip_path_traversal",
                category = "malformed_apk",
                severity = Severity.HIGH,
                confidence = 85,
                titleKey = "finding_path_traversal",
                evidence = pathWarnings.take(3).joinToString(", "),
                adviceKey = "advice_delete_file",
            )
        }
        if (suspiciousAssets.isNotEmpty()) {
            findings += Finding(
                engine = ScanEngine.APK_STATIC,
                ruleId = "hidden_payload",
                category = "hidden_payload",
                severity = Severity.HIGH,
                confidence = 70,
                titleKey = "finding_hidden_payload",
                evidence = suspiciousAssets.take(5).joinToString(", "),
                adviceKey = "advice_review_app",
            )
        }
        if (dexFiles.isEmpty() && manifest != null) {
            findings += Finding(
                engine = ScanEngine.APK_STATIC,
                ruleId = "no_dex",
                category = "analysis_limited",
                severity = Severity.INFO,
                confidence = 90,
                titleKey = "finding_no_dex",
                evidence = "classes*.dex 없음(리소스 전용 APK 또는 분할 APK)",
                adviceKey = null,
            )
        }
        if (stats.bombSuspected) {
            findings += Finding(
                engine = ScanEngine.APK_STATIC,
                ruleId = "zip_bomb",
                category = "malformed_apk",
                severity = Severity.HIGH,
                confidence = 80,
                titleKey = "finding_zip_bomb",
                evidence = "압축비/엔트리 수 한도 초과(엔트리 ${stats.entries}개)",
                adviceKey = "advice_delete_file",
            )
            unscanned += "압축 폭탄 의심 — 나머지 엔트리 미검사"
        }
        if (stats.truncated) unscanned += "손상된 ZIP 구조 — 일부 엔트리 미검사"
        if (stats.skippedLargeEntries > 0) unscanned += "크기 한도 초과 엔트리 ${stats.skippedLargeEntries}개"

        findings += patternScanner.scan(toScan)
        if (nativeLibs.isEmpty() && manifest != null) {
            unscanned += "native 라이브러리 없음(해당 없음)"
        }

        return ApkAnalysis(
            filePath = file.absolutePath,
            fileSize = size,
            sha256 = sha256,
            manifest = manifest,
            signature = signature,
            dexFiles = dexFiles,
            nativeLibs = nativeLibs,
            scriptFiles = scriptFiles,
            suspiciousAssetFiles = suspiciousAssets,
            entryCount = stats.entries,
            findings = findings,
            unscanned = unscanned.distinct(),
            errorKey = null,
            truncated = stats.truncated,
            bombSuspected = stats.bombSuspected,
            patternCompileErrors = patternScanner.diagnostics(),
        )
    }

    /** 분석 결과에 해시 DB 일치 여부를 합쳐 최종 판정을 만든다. */
    fun verdictFor(analysis: ApkAnalysis, hashFindings: List<Finding>): RiskVerdict {
        val findings = analysis.findings + hashFindings
        val engines = buildSet {
            add(ScanEngine.APK_STATIC)
            if (hashFindings.isNotEmpty() || analysis.sha256 != null) add(ScanEngine.HASH)
            if (findings.any { it.engine == ScanEngine.YARA_SUBSET }) add(ScanEngine.YARA_SUBSET)
            if (findings.any { it.engine == ScanEngine.PATTERN }) add(ScanEngine.PATTERN)
            if (findings.any { it.engine == ScanEngine.PERMISSION }) add(ScanEngine.PERMISSION)
        }
        return RiskAssessor.assess(
            findings = findings,
            enginesRun = engines,
            unscanned = analysis.unscanned,
            scanFailed = analysis.errorKey != null,
            failureReason = analysis.errorKey,
        )
    }

    private fun shouldRead(name: String): Boolean = when {
        name == "AndroidManifest.xml" -> true
        name.startsWith("classes") && name.endsWith(".dex") -> true
        name.endsWith(".so") -> true
        isScript(name) -> true
        else -> false
    }

    private fun isScript(name: String): Boolean {
        val lower = name.lowercase()
        if (!lower.startsWith("assets/") && !lower.startsWith("res/raw/")) return false
        return lower.endsWith(".js") || lower.endsWith(".json") || lower.endsWith(".sh") ||
            lower.endsWith(".html") || lower.endsWith(".txt") || lower.endsWith(".dex") ||
            lower.endsWith(".jar") || lower.endsWith(".bin")
    }

    companion object {
        /** 설치 앱에서 읽은 APK 경로로 분석한다. 실패하면 null 대신 errorKey 결과. */
        fun riskLevelOf(verdict: RiskVerdict): RiskLevel = verdict.level
    }
}
