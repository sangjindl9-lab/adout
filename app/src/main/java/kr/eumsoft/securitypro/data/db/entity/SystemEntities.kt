package kr.eumsoft.securitypro.data.db.entity

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

/**
 * VPN 세션 기록(연결/해제, 처리량).
 */
@Entity(
    tableName = "vpn_sessions",
    indices = [Index(value = ["startedAt"])],
)
data class VpnSessionEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val startedAt: Long,
    val endedAt: Long? = null,
    val queryCount: Long = 0,
    val blockedCount: Long = 0,
    val bytesFromApps: Long = 0,
    val bytesToApps: Long = 0,
    /** USER_STOP, REVOKED, ERROR, NETWORK_LOST */
    val endReason: String? = null,
)

/**
 * DB/규칙/앱 업데이트 이력.
 */
@Entity(
    tableName = "update_history",
    indices = [
        Index(value = ["targetType"]),
        Index(value = ["startedAt"]),
    ],
)
data class UpdateHistoryEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    /** AD_FILTER, THREAT_HASH, YARA_RULES */
    val targetType: String,
    val fromVersion: Long = 0,
    val toVersion: Long = 0,
    /** SUCCESS, FAILED, REJECTED_ROLLBACK, REJECTED_INTEGRITY, NOT_CONFIGURED */
    val status: String,
    val bytes: Long = 0,
    val sha256: String? = null,
    val signatureOk: Boolean = false,
    val startedAt: Long = System.currentTimeMillis(),
    val finishedAt: Long? = null,
    val message: String? = null,
    /** 업데이트 서버 응답 코드(0 이면 미수신). 2.0 스키마에서 추가. */
    val httpStatus: Int? = null,
)

/**
 * 보안 설정(key-value). DataStore 는 사용자 환경설정, 이 테이블은
 * 마지막 검사/알림 상태처럼 DB 트랜잭션에 묶여야 하는 값을 보관한다.
 */
@Entity(
    tableName = "security_settings",
    indices = [Index(value = ["updatedAt"])],
)
data class SecuritySettingEntity(
    @PrimaryKey val key: String,
    val value: String,
    val updatedAt: Long = System.currentTimeMillis(),
)
