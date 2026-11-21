package kr.eumsoft.securitypro.core.yara

/**
 * 앱에 내장되는 기본 패턴 규칙(YARA 부분집합 문법).
 *
 * - 자체 작성 규칙이며 특정 상용 시그니처를 복제하지 않는다.
 * - 탐지 결과는 "악성 확정"이 아니라 의심 근거로만 사용한다.
 */
object BuiltInRules {

    const val VERSION = "2026.11.1-builtin"
    const val LICENSE = "자체 작성(EUM SECURITY PRO) — Apache-2.0"

    val SOURCE: String = """
        // EUM SECURITY PRO 내장 패턴 규칙 v1
        rule EUM_Dynamic_Code_Loading
        {
            meta:
                description = "런타임 동적 코드 로딩 흔적"
                category = "dynamic_code"
                severity = "MEDIUM"
                confidence = "55"
            strings:
                ${'$'}dex = "Ldalvik/system/DexClassLoader;" ascii
                ${'$'}inmem = "Ldalvik/system/InMemoryDexClassLoader;" ascii
                ${'$'}path = "Ldalvik/system/PathClassLoader;" ascii
                ${'$'}load = "loadDex" ascii
            condition:
                2 of them
        }

        rule EUM_Hidden_Sms_Api
        {
            meta:
                description = "SMS 전송 API 사용"
                category = "premium_sms"
                severity = "HIGH"
                confidence = "60"
            strings:
                ${'$'}send = "sendTextMessage" ascii
                ${'$'}mgr = "Landroid/telephony/SmsManager;" ascii
                ${'$'}multipart = "sendMultipartTextMessage" ascii
            condition:
                all of them
        }

        rule EUM_Accessibility_Keylogging
        {
            meta:
                description = "접근성 이벤트 수집 흔적"
                category = "accessibility_abuse"
                severity = "HIGH"
                confidence = "60"
            strings:
                ${'$'}svc = "Landroid/accessibilityservice/AccessibilityService;" ascii
                ${'$'}event = "onAccessibilityEvent" ascii
                ${'$'}text = "getText" ascii
            condition:
                all of them
        }

        rule EUM_Overlay_Phishing
        {
            meta:
                description = "화면 위 덮기(오버레이) + 웹뷰 조합"
                category = "overlay_phishing"
                severity = "HIGH"
                confidence = "50"
            strings:
                ${'$'}overlay = "TYPE_APPLICATION_OVERLAY" ascii
                ${'$'}perm = "SYSTEM_ALERT_WINDOW" ascii
                ${'$'}web = "Landroid/webkit/WebView;" ascii
            condition:
                2 of them
        }

        rule EUM_Device_Admin_Abuse
        {
            meta:
                description = "기기 관리자 기능 사용"
                category = "device_admin"
                severity = "MEDIUM"
                confidence = "45"
            strings:
                ${'$'}admin = "Landroid/app/admin/DeviceAdminReceiver;" ascii
                ${'$'}policy = "Landroid/app/admin/DevicePolicyManager;" ascii
                ${'$'}lock = "setPasswordQuality" ascii
            condition:
                2 of them
        }

        rule EUM_Anti_Analysis
        {
            meta:
                description = "에뮬레이터/분석 환경 탐지"
                category = "anti_analysis"
                severity = "MEDIUM"
                confidence = "40"
            strings:
                ${'$'}qemu = "ro.kernel.qemu" ascii
                ${'$'}emu = "isEmulator" ascii
                ${'$'}frida = "frida" ascii
                ${'$'}xposed = "de.robv.android.xposed" ascii
            condition:
                2 of them
        }

        rule EUM_Shell_Execution
        {
            meta:
                description = "셸 실행/권한 상승 시도"
                category = "shell_execution"
                severity = "HIGH"
                confidence = "50"
            strings:
                ${'$'}su = "su -c" ascii
                ${'$'}sh = "/system/bin/sh" ascii
                ${'$'}chmod = "chmod 777" ascii
                ${'$'}pm = "pm install" ascii
            condition:
                2 of them
        }

        rule EUM_Reflection_Hide
        {
            meta:
                description = "리플렉션 기반 은닉 호출"
                category = "obfuscation"
                severity = "LOW"
                confidence = "35"
            strings:
                ${'$'}reflect = "java/lang/reflect/Method" ascii
                ${'$'}setAccessible = "setAccessible" ascii
                ${'$'}classForName = "Class.forName" ascii
            condition:
                2 of them
        }

        rule EUM_Crypto_File_Encryption
        {
            meta:
                description = "파일 암호화 + 외부 저장소 조합(랜섬웨어 유사)"
                category = "ransomware_like"
                severity = "MEDIUM"
                confidence = "40"
            strings:
                ${'$'}aes = "AES/CBC/PKCS5Padding" ascii
                ${'$'}ext = "getExternalStorageDirectory" ascii
                ${'$'}walk = "listFiles" ascii
            condition:
                all of them
        }

        rule EUM_Tracking_Sdk
        {
            meta:
                description = "광고/추적 SDK 포함"
                category = "tracking_sdk"
                severity = "LOW"
                confidence = "30"
            strings:
                ${'$'}admob = "com/google/android/gms/ads" ascii
                ${'$'}fb = "com/facebook/ads" ascii
                ${'$'}unity = "com/unity3d/ads" ascii
                ${'$'}applovin = "com/applovin" ascii
            condition:
                any of them
        }
    """.trimIndent()

    @Volatile
    private var compiled: YaraCompileResult? = null

    fun compiledRules(): YaraCompileResult {
        compiled?.let { return it }
        val result = YaraEngine.compile(SOURCE)
        compiled = result
        return result
    }
}
