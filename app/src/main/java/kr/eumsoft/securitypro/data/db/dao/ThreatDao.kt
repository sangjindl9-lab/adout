package kr.eumsoft.securitypro.data.db.dao

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Transaction
import androidx.room.Upsert
import kotlinx.coroutines.flow.Flow
import kr.eumsoft.securitypro.data.db.entity.InstalledAppEntity
import kr.eumsoft.securitypro.data.db.entity.ThreatDbVersionEntity
import kr.eumsoft.securitypro.data.db.entity.ThreatHashEntity
import kr.eumsoft.securitypro.data.db.entity.ThreatRuleEntity
import kr.eumsoft.securitypro.data.db.entity.ThreatSourceEntity

@Dao
abstract class ThreatDao {

    @Query("SELECT * FROM threat_hashes WHERE sha256 = :sha256 LIMIT 1")
    abstract suspend fun findHash(sha256: String): ThreatHashEntity?

    @Query("SELECT * FROM threat_hashes WHERE sha256 IN (:hashes)")
    abstract suspend fun findHashes(hashes: List<String>): List<ThreatHashEntity>

    @Query("SELECT COUNT(*) FROM threat_hashes")
    abstract fun countHashes(): Flow<Int>

    @Query("SELECT COUNT(*) FROM threat_hashes")
    abstract suspend fun countHashesOnce(): Int

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    abstract suspend fun insertHashes(hashes: List<ThreatHashEntity>)

    @Query("DELETE FROM threat_hashes")
    abstract suspend fun deleteAllHashes()

    /** 업데이트 적용: 전체 교체를 한 트랜잭션으로 수행(실패 시 기존 데이터 유지). */
    @Transaction
    open suspend fun replaceAllHashes(hashes: List<ThreatHashEntity>) {
        deleteAllHashes()
        insertHashes(hashes)
    }

    @Query("SELECT * FROM threat_rules WHERE engine = :engine AND enabled = 1 ORDER BY ruleName")
    abstract suspend fun rulesForEngine(engine: String): List<ThreatRuleEntity>

    @Query("SELECT COUNT(*) FROM threat_rules WHERE engine = :engine")
    abstract fun countRulesForEngine(engine: String): Flow<Int>

    @Query("SELECT COUNT(*) FROM threat_rules WHERE engine = :engine")
    abstract suspend fun countRulesForEngineOnce(engine: String): Int

    @Upsert
    abstract suspend fun upsertRules(rules: List<ThreatRuleEntity>)

    @Query("DELETE FROM threat_rules WHERE engine = :engine")
    abstract suspend fun deleteRulesForEngine(engine: String)

    @Transaction
    open suspend fun replaceRulesForEngine(engine: String, rules: List<ThreatRuleEntity>) {
        deleteRulesForEngine(engine)
        if (rules.isNotEmpty()) upsertRules(rules)
    }

    @Query("SELECT * FROM threat_sources ORDER BY name")
    abstract fun sources(): Flow<List<ThreatSourceEntity>>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    abstract suspend fun upsertSources(sources: List<ThreatSourceEntity>): List<Long>

    @Query("SELECT * FROM threat_db_versions WHERE dbType = :dbType LIMIT 1")
    abstract suspend fun dbVersion(dbType: String): ThreatDbVersionEntity?

    @Query("SELECT * FROM threat_db_versions WHERE dbType = :dbType LIMIT 1")
    abstract fun dbVersionFlow(dbType: String): Flow<ThreatDbVersionEntity?>

    /** 롤백 공격 방지: 현재 버전보다 큰 버전만 기록한다. */
    @Query("SELECT COALESCE(MAX(version), 0) FROM threat_db_versions WHERE dbType = :dbType")
    abstract suspend fun currentVersionNumber(dbType: String): Long

    @Upsert
    abstract suspend fun upsertDbVersion(version: ThreatDbVersionEntity)

    @Query("SELECT * FROM installed_apps WHERE packageName = :packageName LIMIT 1")
    abstract suspend fun installedApp(packageName: String): InstalledAppEntity?

    @Query("SELECT * FROM installed_apps ORDER BY label")
    abstract fun installedApps(): Flow<List<InstalledAppEntity>>

    @Query("SELECT * FROM installed_apps WHERE riskLevel = 'DANGER'")
    abstract fun dangerousApps(): Flow<List<InstalledAppEntity>>

    @Upsert
    abstract suspend fun upsertInstalledApps(apps: List<InstalledAppEntity>)

    @Query("DELETE FROM installed_apps WHERE packageName NOT IN (:keep)")
    abstract suspend fun pruneInstalledApps(keep: List<String>)
}
