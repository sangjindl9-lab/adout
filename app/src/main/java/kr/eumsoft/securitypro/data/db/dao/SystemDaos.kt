package kr.eumsoft.securitypro.data.db.dao

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.Query
import androidx.room.Upsert
import kotlinx.coroutines.flow.Flow
import kr.eumsoft.securitypro.data.db.entity.SecuritySettingEntity
import kr.eumsoft.securitypro.data.db.entity.UpdateHistoryEntity
import kr.eumsoft.securitypro.data.db.entity.VpnSessionEntity

@Dao
interface VpnSessionDao {

    @Insert
    suspend fun startSession(session: VpnSessionEntity): Long

    @Query(
        """
        UPDATE vpn_sessions
           SET endedAt = :endedAt, queryCount = :queries, blockedCount = :blocked,
               bytesFromApps = :bytesIn, bytesToApps = :bytesOut, endReason = :reason
         WHERE id = :id
        """
    )
    suspend fun endSession(
        id: Long,
        endedAt: Long,
        queries: Long,
        blocked: Long,
        bytesIn: Long,
        bytesOut: Long,
        reason: String?,
    )

    @Query("SELECT * FROM vpn_sessions ORDER BY startedAt DESC LIMIT 1")
    fun lastSession(): Flow<VpnSessionEntity?>

    @Query("SELECT * FROM vpn_sessions WHERE endedAt IS NULL ORDER BY startedAt DESC LIMIT 1")
    suspend fun openSession(): VpnSessionEntity?
}

@Dao
interface UpdateHistoryDao {

    @Insert
    suspend fun insert(history: UpdateHistoryEntity): Long

    @Query("UPDATE update_history SET status = :status, toVersion = :toVersion, finishedAt = :finishedAt, message = :message, signatureOk = :signatureOk, sha256 = :sha256, bytes = :bytes, httpStatus = :httpStatus WHERE id = :id")
    suspend fun finish(
        id: Long,
        status: String,
        toVersion: Long,
        finishedAt: Long,
        message: String?,
        signatureOk: Boolean,
        sha256: String?,
        bytes: Long,
        httpStatus: Int?,
    )

    @Query("SELECT * FROM update_history ORDER BY startedAt DESC LIMIT :limit")
    fun recent(limit: Int = 50): Flow<List<UpdateHistoryEntity>>

    @Query("SELECT * FROM update_history ORDER BY startedAt DESC LIMIT 1")
    fun latest(): Flow<UpdateHistoryEntity?>
}

@Dao
interface SettingsDao {

    @Upsert
    suspend fun put(setting: SecuritySettingEntity)

    @Query("SELECT value FROM security_settings WHERE key = :key")
    suspend fun get(key: String): String?

    @Query("SELECT value FROM security_settings WHERE key = :key")
    fun observe(key: String): Flow<String?>
}
