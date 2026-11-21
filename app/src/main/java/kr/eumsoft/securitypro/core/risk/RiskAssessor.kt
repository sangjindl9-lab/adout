package kr.eumsoft.securitypro.core.risk

/**
 * 종합 위험 판정 엔진.
 *
 * 등급 규칙:
 *  - DANGER  : 검증된 악성 해시 일치(신뢰도 ≥ 80) 또는 "확정" 표시된 규칙
 *  - WARNING : MEDIUM 이상 근거가 있으나 악성 확정 근거는 없음
 *  - NOT_FOUND: 실행된 범위에서 위험 근거 없음(미검사 항목은 별도 표기)
 *  - UNABLE  : 검사를 수행할 수 없었음
 *
 * 검증되지 않은 "100% 안전" 류의 표현은 만들지 않는다.
 */
object RiskAssessor {

    private const val CONFIRMED_HASH_CONFIDENCE = 80

    fun assess(
        findings: List<Finding>,
        enginesRun: Set<ScanEngine>,
        unscanned: List<String> = emptyList(),
        scanFailed: Boolean = false,
        failureReason: String? = null,
    ): RiskVerdict {
        if (scanFailed) {
            return RiskVerdict(
                level = RiskLevel.UNABLE,
                score = 0,
                findings = findings,
                reasonKeys = listOf("reason_scan_failed") + (failureReason?.let { listOf(it) } ?: emptyList()),
                unscanned = unscanned,
            )
        }

        val confirmedMalware = findings.any { finding ->
            finding.engine == ScanEngine.HASH &&
                finding.severity == Severity.CRITICAL &&
                finding.confidence >= CONFIRMED_HASH_CONFIDENCE
        }
        val serious = findings.filter { it.severity.weight >= Severity.MEDIUM.weight }

        val score = findings.sumOf { it.severity.weight }
            .coerceAtMost(100)

        val level = when {
            confirmedMalware -> RiskLevel.DANGER
            serious.isNotEmpty() -> RiskLevel.WARNING
            enginesRun.isEmpty() -> RiskLevel.UNABLE
            else -> RiskLevel.NOT_FOUND
        }

        val reasons = ArrayList<String>()
        when (level) {
            RiskLevel.DANGER -> reasons += "reason_confirmed_hash"
            RiskLevel.WARNING -> reasons += "reason_heuristic_only"
            RiskLevel.NOT_FOUND -> reasons += "reason_no_known_threat"
            RiskLevel.UNABLE -> reasons += "reason_not_scanned"
        }
        val engines = enginesRun.joinToString(", ") { it.label }
        if (engines.isNotEmpty()) reasons += "엔진: $engines"
        if (unscanned.isNotEmpty()) reasons += "reason_partial_scope"

        return RiskVerdict(
            level = level,
            score = score,
            findings = findings.sortedByDescending { it.severity.weight },
            reasonKeys = reasons,
            unscanned = unscanned,
        )
    }
}
