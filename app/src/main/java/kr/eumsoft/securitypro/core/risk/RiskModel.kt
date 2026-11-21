package kr.eumsoft.securitypro.core.risk

/** 검사 결과 4단계. */
enum class RiskLevel {
    /** 검증된 악성 해시 또는 신뢰도 높은 악성 패턴. */
    DANGER,

    /** 위험 권한 조합/의심 패턴 — 악성 확정 아님. */
    WARNING,

    /** 실행된 검사 범위에서 알려진 위협 미발견. */
    NOT_FOUND,

    /** 접근 제한/오류로 검사를 끝내지 못함. */
    UNABLE,
}

enum class Severity(val weight: Int) {
    INFO(1),
    LOW(4),
    MEDIUM(12),
    HIGH(25),
    CRITICAL(45),
}

enum class ScanEngine(val label: String) {
    HASH("SHA-256"),
    APK_STATIC("APK 정적 분석"),
    PATTERN("패턴 검사"),
    YARA_SUBSET("YARA 부분집합"),
    PERMISSION("권한 분석"),
}

/**
 * 탐지 근거 1건.
 *
 * [titleKey] 는 UI 번역 키, [evidence] 는 실제 값(패키지명/권한/파일명/도메인)을 담은
 * 기술 근거다. 근거 없는 "악성" 표시는 만들지 않는다.
 */
data class Finding(
    val engine: ScanEngine,
    val ruleId: String?,
    val category: String,
    val severity: Severity,
    val confidence: Int,
    val titleKey: String,
    val evidence: String,
    val adviceKey: String? = null,
)

/** 종합 판정. */
data class RiskVerdict(
    val level: RiskLevel,
    val score: Int,
    val findings: List<Finding>,
    val reasonKeys: List<String>,
    val unscanned: List<String>,
) {
    val dangerCount: Int get() = if (level == RiskLevel.DANGER) 1 else 0
    val warningCount: Int get() = if (level == RiskLevel.WARNING) 1 else 0
}
