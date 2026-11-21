package kr.eumsoft.securitypro.data.db.entity

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.ForeignKey
import androidx.room.Index
import androidx.room.PrimaryKey

/**
 * 검사 세션 — 빠른 검사 / 설치 앱 검사 / APK 파일 검사 한 번의 실행 단위.
 */
@Entity(
    tableName = "scan_sessions",
    indices = [
        Index(value = ["startedAt"]),
        Index(value = ["status"]),
    ],
)
data class ScanSessionEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    /** QUICK, INSTALLED_APPS, APK_FILE */
    val type: String,
    /** RUNNING, COMPLETED, CANCELLED, FAILED */
    val status: String,
    val targetLabel: String? = null,
    val totalTargets: Int = 0,
    val scannedTargets: Int = 0,
    val dangerCount: Int = 0,
    val warningCount: Int = 0,
    /** 실행된 엔진 이름 csv */
    val engines: String = "",
    val startedAt: Long,
    val finishedAt: Long? = null,
    val errorMessage: String? = null,
    val createdAt: Long = startedAt,
    val updatedAt: Long = startedAt,
)

/**
 * 검사 대상 1건의 결과(APK 파일 또는 설치 앱).
 */
@Entity(
    tableName = "scan_results",
    foreignKeys = [
        ForeignKey(
            entity = ScanSessionEntity::class,
            parentColumns = ["id"],
            childColumns = ["sessionId"],
            onDelete = ForeignKey.CASCADE,
        ),
    ],
    indices = [
        Index(value = ["sessionId"]),
        Index(value = ["sha256"]),
        Index(value = ["riskLevel"]),
    ],
)
data class ScanResultEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val sessionId: Long,
    /** APK_FILE, INSTALLED_APP */
    val targetType: String,
    val packageName: String? = null,
    val label: String? = null,
    val filePath: String? = null,
    val fileSize: Long = 0,
    val sha256: String? = null,
    /** DANGER, WARNING, NOT_FOUND, UNABLE */
    val riskLevel: String,
    val riskScore: Int = 0,
    val summary: String? = null,
    val enginesRun: String = "",
    val unscannedItems: String? = null,
    val createdAt: Long = System.currentTimeMillis(),
)

/**
 * 검사 결과의 개별 탐지 근거.
 */
@Entity(
    tableName = "scan_findings",
    foreignKeys = [
        ForeignKey(
            entity = ScanResultEntity::class,
            parentColumns = ["id"],
            childColumns = ["resultId"],
            onDelete = ForeignKey.CASCADE,
        ),
    ],
    indices = [
        Index(value = ["resultId"]),
        Index(value = ["engine"]),
        Index(value = ["category"]),
    ],
)
data class ScanFindingEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val resultId: Long,
    /** HASH, APK_STATIC, PATTERN, YARA_SUBSET, PERMISSION */
    val engine: String,
    val ruleId: String? = null,
    /** malware, phishing, adware, risky_permission, suspicious_pattern ... */
    val category: String,
    /** INFO, LOW, MEDIUM, HIGH, CRITICAL */
    val severity: String,
    val confidence: Int = 0,
    val title: String,
    val evidence: String,
    val advice: String? = null,
    val createdAt: Long = System.currentTimeMillis(),
)

/**
 * 기기에 설치된 앱의 메타데이터 사본(검사 이력 포함).
 */
@Entity(
    tableName = "installed_apps",
    indices = [
        Index(value = ["packageName"], unique = true),
        Index(value = ["riskLevel"]),
        Index(value = ["lastScannedAt"]),
    ],
)
data class InstalledAppEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val packageName: String,
    val label: String,
    val versionName: String? = null,
    val versionCode: Long = 0,
    val firstInstallTime: Long = 0,
    val lastUpdateTime: Long = 0,
    /** 설치 출처(설치자 패키지). 시스템 설치면 null. */
    val installerPackage: String? = null,
    val isSystemApp: Boolean = false,
    val certSha256: String? = null,
    /** 요청한 위험 권한 csv */
    val dangerousPermissions: String = "",
    val riskLevel: String? = null,
    @ColumnInfo(name = "lastScannedAt") val lastScannedAt: Long? = null,
    val createdAt: Long = System.currentTimeMillis(),
    val updatedAt: Long = System.currentTimeMillis(),
)
