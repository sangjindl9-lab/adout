package kr.eumsoft.securitypro.core.apk

/** APK 안의 컴포넌트 하나. */
data class ApkComponent(
    /** activity, activity-alias, service, receiver, provider */
    val type: String,
    val name: String,
    val exported: Boolean,
    val permission: String? = null,
    val actions: List<String> = emptyList(),
    val hasIntentFilter: Boolean = false,
    val authorities: String? = null,
)

/** AndroidManifest.xml 에서 뽑아낸 핵심 정보. */
data class ManifestInfo(
    val packageName: String?,
    val versionName: String?,
    val versionCode: Long,
    val minSdk: Int?,
    val targetSdk: Int?,
    val permissions: List<String>,
    val components: List<ApkComponent>,
    val applicationLabel: String?,
    val debuggable: Boolean,
    val allowBackup: Boolean,
    val usesCleartextTraffic: Boolean,
    val features: List<String>,
    val usesLibraries: List<String>,
    val warnings: List<String> = emptyList(),
) {
    val exportedComponents: List<ApkComponent> get() = components.filter { it.exported }

    fun hasPermission(name: String): Boolean =
        permissions.any { it.equals(name, ignoreCase = true) || it.endsWith(".$name") }
}

object ManifestParser {

    private val COMPONENT_TYPES = setOf("activity", "activity-alias", "service", "receiver", "provider")

    fun parse(root: Axml.Element?, fallbackPackage: String? = null): ManifestInfo {
        if (root == null) {
            return ManifestInfo(
                packageName = fallbackPackage,
                versionName = null,
                versionCode = 0,
                minSdk = null,
                targetSdk = null,
                permissions = emptyList(),
                components = emptyList(),
                applicationLabel = null,
                debuggable = false,
                allowBackup = true,
                usesCleartextTraffic = false,
                features = emptyList(),
                usesLibraries = emptyList(),
                warnings = listOf("AndroidManifest.xml 을 해석하지 못했습니다."),
            )
        }
        val warnings = ArrayList<String>()
        val packageName = root.attr("package")?.stringValue ?: fallbackPackage
        val versionCode = root.attr("versionCode")?.let { attr ->
            attr.intValue?.toLong() ?: attr.stringValue?.toLongOrNull()
        } ?: 0L
        val versionName = root.attr("versionName")?.stringValue

        val usesSdk = root.child("uses-sdk")
        val minSdk = usesSdk?.attr("minSdkVersion")?.let { it.intValue ?: it.stringValue?.toIntOrNull() }
        val targetSdk = usesSdk?.attr("targetSdkVersion")?.let { it.intValue ?: it.stringValue?.toIntOrNull() }

        val permissions = ArrayList<String>()
        root.childrenNamed("uses-permission").forEach { element ->
            element.attr("name")?.stringValue?.let { permissions += it }
        }
        root.childrenNamed("uses-permission-sdk-23").forEach { element ->
            element.attr("name")?.stringValue?.let { permissions += it }
        }

        val features = root.childrenNamed("uses-feature")
            .mapNotNull { it.attr("name")?.stringValue }

        val usesLibraries = root.childrenNamed("uses-library")
            .mapNotNull { it.attr("name")?.stringValue }

        val application = root.child("application")
        if (application == null) {
            warnings += "application 엘리먼트가 없습니다."
        }
        val components = ArrayList<ApkComponent>()
        application?.children?.forEach { child ->
            if (child.name !in COMPONENT_TYPES) return@forEach
            val rawName = child.attr("name")?.stringValue
            if (rawName.isNullOrEmpty()) {
                warnings += "${child.name} 컴포넌트 이름이 비어 있습니다."
                return@forEach
            }
            val fullName = when {
                rawName.startsWith(".") -> (packageName ?: "") + rawName
                !rawName.contains('.') && packageName != null -> "$packageName.$rawName"
                else -> rawName
            }
            val actions = child.childrenNamed("intent-filter")
                .flatMap { it.childrenNamed("action") }
                .mapNotNull { it.attr("name")?.stringValue }
            val exportedAttr = child.attr("exported")?.boolValue
            val exported = exportedAttr ?: (child.children.any { it.name == "intent-filter" } && minSdk == null)
            if (exportedAttr == null && child.children.any { it.name == "intent-filter" }) {
                warnings += "${child.name} $fullName 의 exported 값이 명시되지 않았습니다."
            }
            components += ApkComponent(
                type = child.name,
                name = fullName,
                exported = exported,
                permission = child.attr("permission")?.stringValue,
                actions = actions,
                hasIntentFilter = child.children.any { it.name == "intent-filter" },
                authorities = child.attr("authorities")?.stringValue,
            )
        }

        val debuggable = application?.attr("debuggable")?.boolValue ?: false
        val allowBackup = application?.attr("allowBackup")?.boolValue ?: true
        val cleartext = application?.attr("usesCleartextTraffic")?.boolValue
            ?: ((targetSdk ?: 35) < 28)

        return ManifestInfo(
            packageName = packageName,
            versionName = versionName,
            versionCode = versionCode,
            minSdk = minSdk,
            targetSdk = targetSdk,
            permissions = permissions.distinct(),
            components = components,
            applicationLabel = application?.attr("label")?.stringValue,
            debuggable = debuggable,
            allowBackup = allowBackup,
            usesCleartextTraffic = cleartext,
            features = features,
            usesLibraries = usesLibraries,
            warnings = warnings,
        )
    }
}
