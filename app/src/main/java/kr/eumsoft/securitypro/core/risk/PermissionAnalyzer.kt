package kr.eumsoft.securitypro.core.risk

import kr.eumsoft.securitypro.core.apk.ApkComponent
import kr.eumsoft.securitypro.core.apk.ManifestInfo

/**
 * 위험 권한/컴포넌트 조합 분석.
 *
 * 원칙: 권한만으로 악성코드를 확정하지 않는다. 널리 쓰이는 앱(시스템/대형 서비스)에는
 * 신뢰도 하향 규칙을 적용해 오탐을 줄인다. 모든 판정은 권한 이름과 같은 검증 가능한 근거를 남긴다.
 */
object PermissionAnalyzer {

    data class DangerousPermission(val name: String, val severity: Severity, val whyKey: String)

    private val DANGEROUS: List<DangerousPermission> = listOf(
        DangerousPermission("android.permission.READ_SMS", Severity.HIGH, "why_read_sms"),
        DangerousPermission("android.permission.SEND_SMS", Severity.CRITICAL, "why_send_sms"),
        DangerousPermission("android.permission.RECEIVE_SMS", Severity.HIGH, "why_receive_sms"),
        DangerousPermission("android.permission.RECEIVE_MMS", Severity.MEDIUM, "why_receive_mms"),
        DangerousPermission("android.permission.READ_CONTACTS", Severity.MEDIUM, "why_read_contacts"),
        DangerousPermission("android.permission.WRITE_CONTACTS", Severity.MEDIUM, "why_write_contacts"),
        DangerousPermission("android.permission.CALL_PHONE", Severity.HIGH, "why_call_phone"),
        DangerousPermission("android.permission.READ_CALL_LOG", Severity.HIGH, "why_read_call_log"),
        DangerousPermission("android.permission.RECORD_AUDIO", Severity.HIGH, "why_record_audio"),
        DangerousPermission("android.permission.CAMERA", Severity.MEDIUM, "why_camera"),
        DangerousPermission("android.permission.ACCESS_FINE_LOCATION", Severity.MEDIUM, "why_fine_location"),
        DangerousPermission("android.permission.ACCESS_BACKGROUND_LOCATION", Severity.HIGH, "why_bg_location"),
        DangerousPermission("android.permission.SYSTEM_ALERT_WINDOW", Severity.HIGH, "why_overlay"),
        DangerousPermission("android.permission.REQUEST_INSTALL_PACKAGES", Severity.HIGH, "why_install_packages"),
        DangerousPermission("android.permission.BIND_DEVICE_ADMIN", Severity.CRITICAL, "why_device_admin"),
        DangerousPermission("android.permission.BIND_ACCESSIBILITY_SERVICE", Severity.HIGH, "why_accessibility"),
        DangerousPermission("android.permission.BIND_NOTIFICATION_LISTENER_SERVICE", Severity.HIGH, "why_notification_access"),
        DangerousPermission("android.permission.PACKAGE_USAGE_STATS", Severity.MEDIUM, "why_usage_stats"),
        DangerousPermission("android.permission.MANAGE_EXTERNAL_STORAGE", Severity.MEDIUM, "why_manage_storage"),
        DangerousPermission("android.permission.READ_PHONE_STATE", Severity.LOW, "why_phone_state"),
        DangerousPermission("android.permission.WRITE_SETTINGS", Severity.MEDIUM, "why_write_settings"),
    )

    /** 여러 권한이 함께 있을 때만 의미가 생기는 조합. */
    private data class Combo(
        val required: List<String>,
        val severity: Severity,
        val confidence: Int,
        val titleKey: String,
        val adviceKey: String,
        val category: String = "risky_permission_combo",
    )

    private val COMBOS: List<Combo> = listOf(
        Combo(
            required = listOf("android.permission.READ_SMS", "android.permission.SEND_SMS", "android.permission.INTERNET"),
            severity = Severity.CRITICAL,
            confidence = 80,
            titleKey = "finding_sms_plus_internet",
            adviceKey = "advice_check_sms_app",
        ),
        Combo(
            required = listOf("android.permission.SEND_SMS", "android.permission.CALL_PHONE"),
            severity = Severity.HIGH,
            confidence = 65,
            titleKey = "finding_premium_sms_risk",
            adviceKey = "advice_check_billing",
        ),
        Combo(
            required = listOf("android.permission.RECORD_AUDIO", "android.permission.READ_CONTACTS", "android.permission.INTERNET"),
            severity = Severity.HIGH,
            confidence = 55,
            titleKey = "finding_audio_contacts_upload",
            adviceKey = "advice_review_permissions",
        ),
        Combo(
            required = listOf("android.permission.SYSTEM_ALERT_WINDOW", "android.permission.BIND_ACCESSIBILITY_SERVICE"),
            severity = Severity.CRITICAL,
            confidence = 75,
            titleKey = "finding_overlay_accessibility",
            adviceKey = "advice_disable_accessibility",
        ),
        Combo(
            required = listOf("android.permission.REQUEST_INSTALL_PACKAGES", "android.permission.INTERNET"),
            severity = Severity.MEDIUM,
            confidence = 50,
            titleKey = "finding_silent_install",
            adviceKey = "advice_review_install_source",
        ),
        Combo(
            required = listOf("android.permission.BIND_DEVICE_ADMIN", "android.permission.INTERNET"),
            severity = Severity.HIGH,
            confidence = 60,
            titleKey = "finding_device_admin_internet",
            adviceKey = "advice_check_device_admin",
        ),
        Combo(
            required = listOf("android.permission.READ_CALL_LOG", "android.permission.INTERNET"),
            severity = Severity.MEDIUM,
            confidence = 45,
            titleKey = "finding_call_log_upload",
            adviceKey = "advice_review_permissions",
        ),
    )

    /** 널리 알려진 신뢰 패키지 접두사 — 오탐 완화용(사용자가 무시 가능). */
    private val TRUSTED_PREFIXES = listOf(
        "android",
        "com.android.",
        "com.google.",
        "com.samsung.",
        "com.sec.",
        "com.lge.",
        "com.kakao.",
        "com.nhn.",
        "com.naver.",
        "com.sktelecom.",
        "com.kt.",
        "com.lguplus.",
        "kr.co.",
    )

    fun isWellKnownPackage(packageName: String?, isSystem: Boolean): Boolean {
        if (isSystem) return true
        val name = packageName?.lowercase() ?: return false
        return TRUSTED_PREFIXES.any { name == it || name.startsWith(it) }
    }

    /**
     * @param installed true 면 설치 앱(PackageManager 로 실제 권한 확인), false 면 APK 파일 분석.
     */
    fun analyze(
        packageName: String?,
        isSystem: Boolean,
        info: ManifestInfo?,
        permissions: List<String> = info?.permissions ?: emptyList(),
        components: List<ApkComponent> = info?.components ?: emptyList(),
    ): List<Finding> {
        val findings = ArrayList<Finding>()
        val wellKnown = isWellKnownPackage(packageName, isSystem)
        val confidencePenalty = if (wellKnown) 30 else 0

        // 1) 고위험 단일 권한
        DANGEROUS.filter { dangerous ->
            permissions.any { it.equals(dangerous.name, ignoreCase = true) }
        }.forEach { dangerous ->
            val severity = if (wellKnown && dangerous.severity.weight >= Severity.HIGH.weight) {
                Severity.MEDIUM
            } else {
                dangerous.severity
            }
            findings += Finding(
                engine = ScanEngine.PERMISSION,
                ruleId = dangerous.name.substringAfterLast('.'),
                category = "dangerous_permission",
                severity = severity,
                confidence = (70 - confidencePenalty).coerceAtLeast(20),
                titleKey = dangerous.whyKey,
                evidence = "권한: ${dangerous.name}",
                adviceKey = "advice_review_permissions",
            )
        }

        // 2) 조합
        COMBOS.forEach { combo ->
            if (combo.required.all { required -> permissions.any { it.equals(required, true) } }) {
                findings += Finding(
                    engine = ScanEngine.PERMISSION,
                    ruleId = combo.titleKey,
                    category = combo.category,
                    severity = if (wellKnown && combo.severity == Severity.CRITICAL) Severity.MEDIUM else combo.severity,
                    confidence = (combo.confidence - confidencePenalty).coerceAtLeast(15),
                    titleKey = combo.titleKey,
                    evidence = "권한 조합: " + combo.required.joinToString(", ") { it.substringAfterLast('.') },
                    adviceKey = combo.adviceKey,
                )
            }
        }

        // 3) 컴포넌트 노출
        val exportedWithoutPermission = components.filter {
            it.exported && it.hasIntentFilter && it.permission.isNullOrBlank()
        }
        if (exportedWithoutPermission.isNotEmpty()) {
            findings += Finding(
                engine = ScanEngine.APK_STATIC,
                ruleId = "exported_component",
                category = "exposed_component",
                severity = if (exportedWithoutPermission.size >= 3) Severity.MEDIUM else Severity.LOW,
                confidence = 45,
                titleKey = "finding_exported_component",
                evidence = exportedWithoutPermission.take(5)
                    .joinToString("\n") { "${it.type}: ${it.name}" },
                adviceKey = "advice_review_component",
            )
        }

        // 4) 접근성 서비스 선언
        val accessibilityService = components.firstOrNull { component ->
            component.type == "service" && (
                component.permission.equals("android.permission.BIND_ACCESSIBILITY_SERVICE", true) ||
                    component.actions.any { it == "android.accessibilityservice.AccessibilityService" }
                )
        }
        if (accessibilityService != null) {
            findings += Finding(
                engine = ScanEngine.APK_STATIC,
                ruleId = "accessibility_service",
                category = "powerful_capability",
                severity = if (wellKnown) Severity.LOW else Severity.MEDIUM,
                confidence = (50 - confidencePenalty).coerceAtLeast(10),
                titleKey = "finding_accessibility_service",
                evidence = "서비스: ${accessibilityService.name}",
                adviceKey = "advice_disable_accessibility",
            )
        }

        // 5) 기기 관리자
        val deviceAdmin = components.firstOrNull { component ->
            component.type == "receiver" &&
                component.actions.any { it == "android.app.action.DEVICE_ADMIN_ENABLED" }
        }
        if (deviceAdmin != null) {
            findings += Finding(
                engine = ScanEngine.APK_STATIC,
                ruleId = "device_admin",
                category = "powerful_capability",
                severity = if (wellKnown) Severity.LOW else Severity.MEDIUM,
                confidence = (50 - confidencePenalty).coerceAtLeast(10),
                titleKey = "finding_device_admin",
                evidence = "리시버: ${deviceAdmin.name}",
                adviceKey = "advice_check_device_admin",
            )
        }

        return findings
    }
}
