package kr.eumsoft.securitypro.data.db.dao

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.Query
import androidx.room.Transaction
import kotlinx.coroutines.flow.Flow
import kr.eumsoft.securitypro.data.db.ScanSessionDetail
import kr.eumsoft.securitypro.data.db.entity.ScanFindingEntity
import kr.eumsoft.securitypro.data.db.entity.ScanResultEntity
import kr.eumsoft.securitypro.data.db.entity.ScanSessionEntity

@Dao
interface ScanDao {

    @Insert
    suspend fun insertSession(session: ScanSessionEntity): Long

    @Query(
        """
        UPDATE scan_sessions
           SET scannedTargets = :scanned, totalTargets = :total, dangerCount = :danger,
               warningCount = :warning, updatedAt = :now
         WHERE id = :sessionId
        """
    )
    suspend fun updateProgress(
        sessionId: Long,
        scanned: Int,
        total: Int,
        danger: Int,
        warning: Int,
        now: Long = System.currentTimeMillis(),
    )

    @Query(
        """
        UPDATE scan_sessions
           SET status = :status, dangerCount = :danger, warningCount = :warning,
               scannedTargets = :scanned, finishedAt = :finishedAt,
               errorMessage = :error, updatedAt = :finishedAt
         WHERE id = :sessionId
        """
    )
    suspend fun finishSession(
        sessionId: Long,
        status: String,
        danger: Int,
        warning: Int,
        scanned: Int,
        finishedAt: Long = System.currentTimeMillis(),
        error: String? = null,
    )

    @Insert
    suspend fun insertResult(result: ScanResultEntity): Long

    @Insert
    suspend fun insertFindings(findings: List<ScanFindingEntity>)

    @Transaction
    @Query("SELECT * FROM scan_sessions WHERE id = :sessionId")
    suspend fun sessionDetail(sessionId: Long): ScanSessionDetail?

    @Transaction
    @Query("SELECT * FROM scan_sessions ORDER BY startedAt DESC LIMIT :limit")
    fun recentSessions(limit: Int = 20): Flow<List<ScanSessionDetail>>

    @Query("SELECT * FROM scan_sessions ORDER BY startedAt DESC LIMIT :limit")
    fun recentSessionHeaders(limit: Int = 20): Flow<List<ScanSessionEntity>>

    @Query("SELECT * FROM scan_sessions WHERE status = 'COMPLETED' ORDER BY finishedAt DESC LIMIT 1")
    fun latestCompletedSession(): Flow<ScanSessionEntity?>

    @Query("SELECT * FROM scan_sessions WHERE status = 'COMPLETED' ORDER BY finishedAt DESC LIMIT 1")
    suspend fun latestCompletedSessionOnce(): ScanSessionEntity?

    @Query("SELECT COALESCE(SUM(dangerCount), 0) FROM scan_sessions WHERE status = 'COMPLETED'")
    fun totalDangerFindings(): Flow<Int>

    @Query("SELECT * FROM scan_results WHERE sha256 = :sha256 ORDER BY createdAt DESC LIMIT 1")
    suspend fun cachedResultByHash(sha256: String): ScanResultEntity?

    @Query("DELETE FROM scan_sessions")
    suspend fun deleteAllSessions()

    @Query("DELETE FROM scan_sessions WHERE id = :sessionId")
    suspend fun deleteSession(sessionId: Long)

    @Query("DELETE FROM scan_sessions WHERE startedAt < :cutoff")
    suspend fun deleteSessionsOlderThan(cutoff: Long): Int
}
