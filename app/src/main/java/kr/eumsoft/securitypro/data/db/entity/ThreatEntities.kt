package kr.eumsoft.securitypro.data.db.entity

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

/**
 * 알려진 악성 파일 SHA-256 데이터베이스.
 */
@Entity(
    tableName = "threat_hashes",
    indices = [
        Index(value = ["category"]),
        Index(value = ["threatFamily"]),
        Index(value = ["source"]),
    ],
)
data class ThreatHashEntity(
    @PrimaryKey val sha256: String,
    val threatName: String,
    val threatFamily: String? = null,
    val category: String,
    /** INFO, LOW, MEDIUM, HIGH, CRITICAL */
    val severity: String,
    /** 0-100 신뢰도 */
    val confidence: Int,
    val source: String,
    val firstSeen: Long? = null,
    val lastSeen: Long? = null,
    val updatedAt: Long = System.currentTimeMillis(),
)

/**
 * 패턴 탐지 규칙(YARA 부분집합 또는 내장 위험 패턴).
 */
@Entity(
    tableName = "threat_rules",
    indices = [
        Index(value = ["engine", "ruleName"], unique = true),
        Index(value = ["category"]),
    ],
)
data class ThreatRuleEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    /** YARA_SUBSET, BUILTIN_PATTERN */
    val engine: String,
    val ruleName: String,
    val category: String,
    val severity: String,
    /** 규칙 원문(텍스트) */
    val content: String,
    val source: String,
    val version: String,
    val enabled: Boolean = true,
    val updatedAt: Long = System.currentTimeMillis(),
)

/**
 * 위협 데이터 출처(라이선스/신뢰도 메타데이터 포함).
 */
@Entity(
    tableName = "threat_sources",
    indices = [Index(value = ["name"], unique = true)],
)
data class ThreatSourceEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val name: String,
    val url: String? = null,
    val license: String,
    /** HASH, YARA, HOSTS, ADGUARD_DNS */
    val type: String,
    val enabled: Boolean = true,
    val recordCount: Int = 0,
    val lastFetchedAt: Long? = null,
    val updatedAt: Long = System.currentTimeMillis(),
)

/**
 * 설치된 위협 DB 버전(해시/규칙/필터 각각).
 */
@Entity(
    tableName = "threat_db_versions",
    indices = [
        Index(value = ["dbType"], unique = true),
        Index(value = ["installedAt"]),
    ],
)
data class ThreatDbVersionEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    /** AD_FILTER, THREAT_HASH, YARA_RULES */
    val dbType: String,
    /** 단조 증가 버전 번호(롤백 방지 기준) */
    val version: Long,
    val versionLabel: String,
    val recordCount: Int = 0,
    val publishedAt: Long? = null,
    val installedAt: Long = System.currentTimeMillis(),
    val sha256: String? = null,
    /** VERIFIED, UNSIGNED_TEST, FAILED */
    val signatureStatus: String = "UNSIGNED_TEST",
    /** true 면 테스트 데이터(운영 탐지 데이터 아님) */
    val isTestData: Boolean = true,
)
