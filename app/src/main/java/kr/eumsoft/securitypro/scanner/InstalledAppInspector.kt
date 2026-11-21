package kr.eumsoft.securitypro.scanner

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import dagger.hilt.android.qualifiers.ApplicationContext
import java.io.File
import javax.inject.Inject
import javax.inject.Singleton
import kr.eumsoft.securitypro.core.crypto.Sha256

/** 설치 앱 1건의 메타데이터(파일 접근 가능 여부 포함). */
data class InstalledAppTarget(
    val packageName: String,
    val label: String,
    val versionName: String?,
    val versionCode: Long,
    val firstInstallTime: Long,
    val lastUpdateTime: Long,
    val installerPackage: String?,
    val isSystem: Boolean,
    val apkFile: File?,
    val permissions: List<String>,
    val certSha256: String?,
    val uid: Int,
)

/**
 * PackageManager 로 설치 앱 정보를 수집한다.
 *
 * 다른 앱의 APK 파일에 접근할 수 없는 경우(파일 권한 제한)에는 파일 대신
 * 메타데이터만 검사하고, 그 사실을 결과에 명시한다.
 */
@Singleton
class InstalledAppInspector @Inject constructor(
    @ApplicationContext private val context: Context,
) {

    private val packageManager: PackageManager get() = context.packageManager

    fun listTargets(
        includeSystem: Boolean = false,
        limit: Int = 300,
    ): List<InstalledAppTarget> {
        val flags = PackageManager.GET_PERMISSIONS or
            PackageManager.GET_SIGNING_CERTIFICATES
        val packages: List<PackageInfo> = try {
            packageManager.getInstalledPackages(flags)
        } catch (_: Exception) {
            return emptyList()
        }
        return packages.asSequence()
            .mapNotNull { runCatching { toTarget(it) }.getOrNull() }
            .filter { includeSystem || !it.isSystem }
            .sortedByDescending { it.lastUpdateTime }
            .take(limit)
            .toList()
    }

    fun inspect(packageName: String): InstalledAppTarget? = try {
        val info = packageManager.getPackageInfo(
            packageName,
            PackageManager.GET_PERMISSIONS or PackageManager.GET_SIGNING_CERTIFICATES,
        )
        toTarget(info)
    } catch (_: Exception) {
        null
    }

    private fun toTarget(info: PackageInfo): InstalledAppTarget {
        val app: ApplicationInfo = info.applicationInfo ?: throw IllegalStateException("applicationInfo null")
        val isSystem = (app.flags and ApplicationInfo.FLAG_SYSTEM) != 0 ||
            (app.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
        val apkPath = app.sourceDir ?: app.publicSourceDir
        val apkFile = apkPath?.let { File(it) }?.takeIf { it.canRead() && it.isFile }
        return InstalledAppTarget(
            packageName = info.packageName,
            label = runCatching { packageManager.getApplicationLabel(app).toString() }
                .getOrDefault(info.packageName),
            versionName = info.versionName,
            versionCode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                info.longVersionCode
            } else {
                @Suppress("DEPRECATION")
                info.versionCode.toLong()
            },
            firstInstallTime = info.firstInstallTime,
            lastUpdateTime = info.lastUpdateTime,
            installerPackage = runCatching {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    packageManager.getInstallSourceInfo(info.packageName).installingPackageName
                } else {
                    @Suppress("DEPRECATION")
                    packageManager.getInstallerPackageName(info.packageName)
                }
            }.getOrNull(),
            isSystem = isSystem,
            apkFile = apkFile,
            permissions = info.requestedPermissions?.toList() ?: emptyList(),
            certSha256 = signingCertSha256(info),
            uid = app.uid,
        )
    }

    private fun signingCertSha256(info: PackageInfo): String? = runCatching {
        val signingInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            info.signingInfo
        } else {
            null
        }
        val signatures = if (signingInfo != null) {
            signingInfo.apkContentsSigners
        } else {
            @Suppress("DEPRECATION")
            info.signatures
        }
        signatures?.firstOrNull()?.toByteArray()?.let { Sha256.of(it) }
    }.getOrNull()
}
