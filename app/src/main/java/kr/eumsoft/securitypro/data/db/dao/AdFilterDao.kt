package kr.eumsoft.securitypro.data.db.dao

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Transaction
import androidx.room.Upsert
import kotlinx.coroutines.flow.Flow
import kr.eumsoft.securitypro.data.db.CategoryCount
import kr.eumsoft.securitypro.data.db.DayBucket
import kr.eumsoft.securitypro.data.db.HourBucket
import kr.eumsoft.securitypro.data.db.entity.AdFilterRuleEntity
import kr.eumsoft.securitypro.data.db.entity.AdFilterSourceEntity
import kr.eumsoft.securitypro.data.db.entity.AllowedDomainEntity
import kr.eumsoft.securitypro.data.db.entity.BlockedDnsEventEntity
import kr.eumsoft.securitypro.data.db.entity.BlockedDomainEntity

/** 런타임 필터 인덱스를 만들 때 쓰는 활성 규칙 행. */
data class ActiveRuleRow(
    val domain: String,
    val category: String,
    val sourceId: Long,
    val rawRule: String,
    val priority: Int,
)

/** 도메인별 집계. */
data class DomainCount(
    val domain: String,
    val count: Int,
)

@Dao
abstract class AdFilterDao {

    @Query("SELECT * FROM ad_filter_sources ORDER BY priority, name")
    abstract fun sources(): Flow<List<AdFilterSourceEntity>>

    @Query("SELECT * FROM ad_filter_sources ORDER BY priority, name")
    abstract suspend fun sourcesOnce(): List<AdFilterSourceEntity>

    @Upsert
    abstract suspend fun upsertSources(sources: List<AdFilterSourceEntity>): List<Long>

    @Query("SELECT id FROM ad_filter_sources WHERE name = :name LIMIT 1")
    abstract suspend fun sourceIdByName(name: String): Long?

    @Query("SELECT COUNT(*) FROM ad_filter_rules")
    abstract fun totalRuleCount(): Flow<Int>

    @Query("SELECT COUNT(*) FROM ad_filter_rules WHERE sourceId = :sourceId")
    abstract suspend fun ruleCount(sourceId: Long): Int

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    abstract suspend fun insertRules(rules: List<AdFilterRuleEntity>)

    @Query("DELETE FROM ad_filter_rules WHERE sourceId = :sourceId")
    abstract suspend fun deleteRulesForSource(sourceId: Long)

    /** 필터 업데이트 적용을 한 트랜잭션으로 처리한다. */
    @Transaction
    open suspend fun replaceRulesForSource(sourceId: Long, rules: List<AdFilterRuleEntity>) {
        deleteRulesForSource(sourceId)
        rules.chunked(2000).forEach { insertRules(it) }
    }

    @Query(
        """
        SELECT r.domain AS domain, r.category AS category, r.sourceId AS sourceId,
               r.rawRule AS rawRule, s.priority AS priority
          FROM ad_filter_rules r
          JOIN ad_filter_sources s ON s.id = r.sourceId
         WHERE r.enabled = 1 AND s.enabled = 1
        """
    )
    abstract suspend fun activeRules(): List<ActiveRuleRow>

    @Query("SELECT domain FROM allowed_domains")
    abstract suspend fun allowedDomainsOnce(): List<String>

    @Query("SELECT domain FROM blocked_domains")
    abstract suspend fun blockedDomainsOnce(): List<String>

    @Query("SELECT * FROM allowed_domains ORDER BY createdAt DESC")
    abstract fun allowedDomains(): Flow<List<AllowedDomainEntity>>

    @Query("SELECT * FROM blocked_domains ORDER BY createdAt DESC")
    abstract fun blockedDomains(): Flow<List<BlockedDomainEntity>>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    abstract suspend fun addAllowedDomain(domain: AllowedDomainEntity)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    abstract suspend fun addBlockedDomain(domain: BlockedDomainEntity)

    @Query("DELETE FROM allowed_domains WHERE domain = :domain")
    abstract suspend fun removeAllowedDomain(domain: String)

    @Query("DELETE FROM blocked_domains WHERE domain = :domain")
    abstract suspend fun removeBlockedDomain(domain: String)

    @Insert
    abstract suspend fun insertEvent(event: BlockedDnsEventEntity): Long

    @Insert
    abstract suspend fun insertEvents(events: List<BlockedDnsEventEntity>)

    @Query("SELECT * FROM blocked_dns_events ORDER BY blockedAt DESC LIMIT :limit")
    abstract fun recentEvents(limit: Int = 100): Flow<List<BlockedDnsEventEntity>>

    @Query("SELECT COUNT(*) FROM blocked_dns_events WHERE action = 'BLOCKED' AND blockedAt >= :since")
    abstract fun blockedCountSince(since: Long): Flow<Int>

    @Query("SELECT COUNT(*) FROM blocked_dns_events WHERE action = 'BLOCKED' AND blockedAt >= :since")
    abstract suspend fun blockedCountSinceOnce(since: Long): Int

    @Query("SELECT COUNT(*) FROM blocked_dns_events WHERE action = 'BLOCKED'")
    abstract fun blockedCountTotal(): Flow<Int>

    @Query(
        """
        SELECT (blockedAt / 3600000) * 3600000 AS hourStart, COUNT(*) AS count
          FROM blocked_dns_events
         WHERE action = 'BLOCKED' AND blockedAt >= :since
         GROUP BY hourStart
         ORDER BY hourStart
        """
    )
    abstract suspend fun hourBuckets(since: Long): List<HourBucket>

    @Query(
        """
        SELECT (blockedAt / 86400000) * 86400000 AS dayStart, COUNT(*) AS count
          FROM blocked_dns_events
         WHERE action = 'BLOCKED' AND blockedAt >= :since
         GROUP BY dayStart
         ORDER BY dayStart
        """
    )
    abstract suspend fun dayBuckets(since: Long): List<DayBucket>

    @Query(
        """
        SELECT category AS category, COUNT(*) AS count
          FROM blocked_dns_events
         WHERE action = 'BLOCKED' AND blockedAt >= :since
         GROUP BY category
        """
    )
    abstract suspend fun categoryCounts(since: Long): List<CategoryCount>

    @Query(
        """
        SELECT domain AS domain, COUNT(*) AS count
          FROM blocked_dns_events
         WHERE action = 'BLOCKED' AND blockedAt >= :since
         GROUP BY domain
         ORDER BY count DESC
         LIMIT :limit
        """
    )
    abstract suspend fun topBlockedDomains(since: Long, limit: Int = 10): List<DomainCount>

    @Query("DELETE FROM blocked_dns_events WHERE blockedAt < :cutoff")
    abstract suspend fun pruneEventsBefore(cutoff: Long): Int

    @Query("DELETE FROM blocked_dns_events")
    abstract suspend fun clearEvents()

    @Query("SELECT COUNT(*) FROM blocked_dns_events")
    abstract suspend fun eventCount(): Int
}
