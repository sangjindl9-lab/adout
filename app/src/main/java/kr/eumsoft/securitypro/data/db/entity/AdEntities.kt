package kr.eumsoft.securitypro.data.db.entity

import androidx.room.Entity
import androidx.room.ForeignKey
import androidx.room.Index
import androidx.room.PrimaryKey

/**
 * 광고·추적·피싱 필터 출처.
 */
@Entity(
    tableName = "ad_filter_sources",
    indices = [
        Index(value = ["name"], unique = true),
        Index(value = ["category"]),
    ],
)
data class AdFilterSourceEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val name: String,
    val url: String? = null,
    val license: String,
    /** ADS, TRACKING, PHISHING, MALWARE, USER */
    val category: String,
    val enabled: Boolean = true,
    val priority: Int = 100,
    val ruleCount: Int = 0,
    val lastUpdatedAt: Long? = null,
    /** NEVER, SUCCESS, FAILED, NOT_CONFIGURED */
    val lastUpdateStatus: String = "NEVER",
    val isBuiltin: Boolean = true,
    val isTestData: Boolean = false,
    /** HTTP 조건부 요청용 ETag(증분 업데이트). 2.0 스키마에서 추가. */
    val etag: String? = null,
    val updatedAt: Long = System.currentTimeMillis(),
)

/**
 * 개별 DNS 차단 규칙. domain 은 매칭 성능을 위해 소문자/역순 없이 저장하고
 * 런타임 인덱스가 역순 라벨 트라이를 만든다.
 */
@Entity(
    tableName = "ad_filter_rules",
    foreignKeys = [
        ForeignKey(
            entity = AdFilterSourceEntity::class,
            parentColumns = ["id"],
            childColumns = ["sourceId"],
            onDelete = ForeignKey.CASCADE,
        ),
    ],
    indices = [
        Index(value = ["sourceId"]),
        Index(value = ["domain"]),
        Index(value = ["ruleType"]),
        Index(value = ["category"]),
    ],
)
data class AdFilterRuleEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val sourceId: Long,
    val domain: String,
    val ruleType: String,
    /** ADS, TRACKING, PHISHING, MALWARE */
    val category: String,
    /** 규칙 원문(감사/표시용) */
    val rawRule: String,
    val enabled: Boolean = true,
    val createdAt: Long = System.currentTimeMillis(),
)

/**
 * 차단된(또는 차단 판정된) DNS 요청 이벤트.
 */
@Entity(
    tableName = "blocked_dns_events",
    indices = [
        Index(value = ["domain"]),
        Index(value = ["blockedAt"]),
        Index(value = ["category"]),
        Index(value = ["appUid"]),
    ],
)
data class BlockedDnsEventEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val domain: String,
    val category: String,
    val sourceId: Long? = null,
    val ruleMatched: String? = null,
    /** BLOCKED, ALLOWED_BY_USER */
    val action: String,
    val appUid: Int? = null,
    val blockedAt: Long = System.currentTimeMillis(),
)

/**
 * 사용자가 허용한 도메인(항상 우선).
 */
@Entity(
    tableName = "allowed_domains",
    indices = [Index(value = ["domain"], unique = true)],
)
data class AllowedDomainEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val domain: String,
    val note: String? = null,
    val createdAt: Long = System.currentTimeMillis(),
)

/**
 * 사용자가 추가로 차단한 도메인.
 */
@Entity(
    tableName = "blocked_domains",
    indices = [Index(value = ["domain"], unique = true)],
)
data class BlockedDomainEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val domain: String,
    val note: String? = null,
    val createdAt: Long = System.currentTimeMillis(),
)
