package kr.eumsoft.securitypro.data.repo

import android.content.Context
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kr.eumsoft.securitypro.core.dns.DnsFilterEngine
import kr.eumsoft.securitypro.core.dns.FilterRuleEntry
import kr.eumsoft.securitypro.core.dns.FilterSnapshot
import kr.eumsoft.securitypro.core.dns.FilterSourceMeta
import kr.eumsoft.securitypro.core.dns.RuleParser
import kr.eumsoft.securitypro.data.db.dao.AdFilterDao
import kr.eumsoft.securitypro.data.db.entity.AdFilterRuleEntity
import kr.eumsoft.securitypro.data.db.entity.AdFilterSourceEntity
import kr.eumsoft.securitypro.data.db.entity.AllowedDomainEntity
import kr.eumsoft.securitypro.data.db.entity.BlockedDomainEntity
import kr.eumsoft.securitypro.data.prefs.SettingsRepository

/**
 * 필터 데이터 + 런타임 엔진 스냅샷 관리.
 *
 * VPN 서비스는 [snapshot] 만 읽으므로 DB 접근이 DNS 경로를 막지 않는다.
 */
@Singleton
class AdFilterRepository @Inject constructor(
    @ApplicationContext private val context: Context,
    private val dao: AdFilterDao,
    private val settingsRepository: SettingsRepository,
    private val scope: CoroutineScope,
) {

    private val _snapshot = MutableStateFlow(FilterSnapshot())
    val snapshot: StateFlow<FilterSnapshot> = _snapshot.asStateFlow()

    val sources: Flow<List<AdFilterSourceEntity>> = dao.sources()
    val allowedDomains: Flow<List<AllowedDomainEntity>> = dao.allowedDomains()
    val blockedDomains: Flow<List<BlockedDomainEntity>> = dao.blockedDomains()
    val recentEvents = dao.recentEvents(200)
    val totalRuleCount = dao.totalRuleCount()

    /** 내장 필터를 최초 1회 적재한다. */
    suspend fun seedIfNeeded() = withContext(Dispatchers.IO) {
        val existing = dao.sourceIdByName(ADS_SOURCE_NAME)
        if (existing != null) {
            reload()
            return@withContext
        }
        val sourceId = dao.upsertSources(
            listOf(
                AdFilterSourceEntity(
                    name = ADS_SOURCE_NAME,
                    url = "https://github.com/StevenBlack/hosts",
                    license = "MIT (Copyright (c) 2026 Steven Black)",
                    category = "ADS",
                    isBuiltin = true,
                    isTestData = false,
                    lastUpdateStatus = "NEVER",
                )
            )
        ).first()

        val lines = readAsset("filters/stevenblack_adhoc.txt")
        val meta = FilterSourceMeta(sourceId, ADS_SOURCE_NAME, "ADS", priority = 100)
        val parsed = RuleParser.parse(lines.asSequence(), meta)
        val entities = parsed.rules.map { rule ->
            AdFilterRuleEntity(
                sourceId = sourceId,
                domain = rule.domain,
                ruleType = if (rule.wildcard) "WILDCARD" else if (rule.matchSubdomains) "SUFFIX" else "EXACT",
                category = rule.category,
                rawRule = rule.rawRule,
            )
        }
        dao.replaceRulesForSource(sourceId, entities)
        dao.upsertSources(listOf(
            AdFilterSourceEntity(
                id = sourceId,
                name = ADS_SOURCE_NAME,
                url = "https://github.com/StevenBlack/hosts",
                license = "MIT (Copyright (c) 2026 Steven Black)",
                category = "ADS",
                isBuiltin = true,
                isTestData = false,
                ruleCount = entities.size,
                lastUpdatedAt = System.currentTimeMillis(),
                lastUpdateStatus = "SUCCESS",
            )
        ))

        seedExampleThreatDomains()

        reload()
        settingsRepository.markSeeded()
    }

    private suspend fun seedExampleThreatDomains() {
        val name = PHISHING_SOURCE_NAME
        if (dao.sourceIdByName(name) != null) return
        val sourceId = dao.upsertSources(
            listOf(
                AdFilterSourceEntity(
                    name = name,
                    url = null,
                    license = "자체 작성(Apache-2.0)",
                    category = "PHISHING",
                    isBuiltin = true,
                    isTestData = true,
                    lastUpdateStatus = "NEVER",
                )
            )
        ).first()
        val lines = readAsset("filters/eum_phishing_examples.txt")
        val meta = FilterSourceMeta(sourceId, name, "PHISHING", priority = 10)
        val parsed = RuleParser.parse(lines.asSequence(), meta)
        val entities = parsed.rules.map { rule ->
            AdFilterRuleEntity(
                sourceId = sourceId,
                domain = rule.domain,
                ruleType = if (rule.wildcard) "WILDCARD" else "SUFFIX",
                category = rule.category,
                rawRule = rule.rawRule,
            )
        }
        dao.replaceRulesForSource(sourceId, entities)
        dao.upsertSources(listOf(
            AdFilterSourceEntity(
                id = sourceId,
                name = name,
                url = null,
                license = "자체 작성(Apache-2.0)",
                category = "PHISHING",
                isBuiltin = true,
                isTestData = true,
                ruleCount = entities.size,
                lastUpdatedAt = System.currentTimeMillis(),
                lastUpdateStatus = "NEVER",
            )
        ))
    }

    /** DB 규칙을 읽어 엔진 스냅샷을 만든다(서비스 시작/규칙 변경 시). */
    suspend fun reload() = withContext(Dispatchers.IO) {
        val settings = settingsRepository.settings.first()
        val enabledCategories = settings.categories
        val rows = dao.activeRules().filter { it.category in enabledCategories }
        val rules = rows.map { row ->
            val wildcard = row.rawRule.contains('*') || row.rawRule.contains("wildcard", true)
            FilterRuleEntry(
                domain = row.domain,
                matchSubdomains = true,
                category = row.category,
                sourceId = row.sourceId,
                rawRule = row.rawRule,
                priority = row.priority,
                wildcard = wildcard,
            )
        }
        val userAllowed = dao.allowedDomainsOnce().toSet()
        val userBlocked = dao.blockedDomainsOnce().toSet()
        _snapshot.value = FilterSnapshot(rules, userAllowed, userBlocked)
    }

    fun scheduleReload() {
        scope.launch { runCatching { reload() } }
    }

    /** 엔진을 즉시 만들어 준다(테스트/진단용). */
    fun engine(): DnsFilterEngine = DnsFilterEngine.build(snapshot.value)

    suspend fun setSourceEnabled(sourceId: Long, enabled: Boolean) {
        val source = dao.sourcesOnce().firstOrNull { it.id == sourceId } ?: return
        dao.upsertSources(listOf(source.copy(enabled = enabled, updatedAt = System.currentTimeMillis())))
        reload()
    }

    suspend fun allowDomain(domain: String, note: String? = null): Boolean {
        val normalized = RuleParser.normalizeHost(domain) ?: return false
        dao.addAllowedDomain(AllowedDomainEntity(domain = normalized, note = note))
        reload()
        return true
    }

    suspend fun removeAllowedDomain(domain: String) {
        dao.removeAllowedDomain(domain)
        reload()
    }

    suspend fun blockDomain(domain: String, note: String? = null): Boolean {
        val normalized = RuleParser.normalizeHost(domain) ?: return false
        dao.addBlockedDomain(BlockedDomainEntity(domain = normalized, note = note))
        reload()
        return true
    }

    suspend fun removeBlockedDomain(domain: String) {
        dao.removeBlockedDomain(domain)
        reload()
    }

    suspend fun recordBlockedEvent(
        domain: String,
        category: String,
        sourceId: Long?,
        rule: String?,
        appUid: Int?,
        blockedAt: Long = System.currentTimeMillis(),
    ) {
        dao.insertEvent(
            kr.eumsoft.securitypro.data.db.entity.BlockedDnsEventEntity(
                domain = domain,
                category = category,
                sourceId = sourceId,
                ruleMatched = rule,
                action = "BLOCKED",
                appUid = appUid,
                blockedAt = blockedAt,
            )
        )
    }

    suspend fun pruneOldEvents(retentionDays: Int) {
        val cutoff = System.currentTimeMillis() - retentionDays * 86_400_000L
        dao.pruneEventsBefore(cutoff)
    }

    private fun readAsset(path: String): List<String> {
        return runCatching {
            context.assets.open(path).bufferedReader().useLines { lines -> lines.toList() }
        }.getOrDefault(emptyList())
    }

    companion object {
        const val ADS_SOURCE_NAME = "EUM 기본 광고·추적 차단 목록"
        const val PHISHING_SOURCE_NAME = "EUM 피싱·악성 도메인 (예시 데이터)"
    }
}
