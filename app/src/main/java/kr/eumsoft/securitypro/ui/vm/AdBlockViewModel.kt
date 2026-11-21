package kr.eumsoft.securitypro.ui.vm

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import javax.inject.Inject
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kr.eumsoft.securitypro.data.db.CategoryCount
import kr.eumsoft.securitypro.data.db.HourBucket
import kr.eumsoft.securitypro.data.db.dao.AdFilterDao
import kr.eumsoft.securitypro.data.db.entity.AdFilterSourceEntity
import kr.eumsoft.securitypro.data.db.entity.AllowedDomainEntity
import kr.eumsoft.securitypro.data.db.entity.BlockedDnsEventEntity
import kr.eumsoft.securitypro.data.db.entity.BlockedDomainEntity
import kr.eumsoft.securitypro.data.prefs.AppSettings
import kr.eumsoft.securitypro.data.prefs.SettingsRepository
import kr.eumsoft.securitypro.data.repo.AdFilterRepository
import kr.eumsoft.securitypro.scanner.InstalledAppInspector
import kr.eumsoft.securitypro.service.VpnController
import kr.eumsoft.securitypro.service.VpnState
import kr.eumsoft.securitypro.service.VpnStateHolder
import kr.eumsoft.securitypro.ui.util.startOfToday

data class AppEntry(val packageName: String, val label: String)

data class AdBlockUiState(
    val settings: AppSettings = AppSettings(),
    val vpn: VpnState = VpnState(),
    val sources: List<AdFilterSourceEntity> = emptyList(),
    val allowed: List<AllowedDomainEntity> = emptyList(),
    val blockedDomains: List<BlockedDomainEntity> = emptyList(),
    val events: List<BlockedDnsEventEntity> = emptyList(),
    val todayBlocked: Int = 0,
    val totalBlocked: Int = 0,
    val categories: List<CategoryCount> = emptyList(),
    val hours: List<HourBucket> = emptyList(),
    val installedApps: List<AppEntry> = emptyList(),
    val message: String? = null,
)

@HiltViewModel
class AdBlockViewModel @Inject constructor(
    private val settingsRepository: SettingsRepository,
    private val filterRepository: AdFilterRepository,
    private val adFilterDao: AdFilterDao,
    private val vpnController: VpnController,
    private val inspector: InstalledAppInspector,
) : ViewModel() {

    private val extra = MutableStateFlow(ExtraStats())
    private val apps = MutableStateFlow<List<AppEntry>>(emptyList())
    private val message = MutableStateFlow<String?>(null)
    private val dayStart = startOfToday()

    private data class ExtraStats(
        val today: Int = 0,
        val total: Int = 0,
        val categories: List<CategoryCount> = emptyList(),
        val hours: List<HourBucket> = emptyList(),
    )

    val state: StateFlow<AdBlockUiState> = combine(
        settingsRepository.settings,
        VpnStateHolder.state,
        filterRepository.sources,
        filterRepository.allowedDomains,
        filterRepository.blockedDomains,
    ) { settings, vpn, sources, allowed, blocked ->
        Partial(settings, vpn, sources, allowed, blocked)
    }.combine(filterRepository.recentEvents) { partial, events ->
        partial to events
    }.combine(extra) { (partial, events), extraStats ->
        partial to (events to extraStats)
    }.combine(apps) { (partial, pair), appsList ->
        partial to (pair to appsList)
    }.combine(message) { (partial, nested), msg ->
        val (events, stats) = nested.first
        val appsList = nested.second
        AdBlockUiState(
            settings = partial.settings,
            vpn = partial.vpn,
            sources = partial.sources,
            allowed = partial.allowed,
            blockedDomains = partial.blocked,
            events = events,
            todayBlocked = stats.today,
            totalBlocked = stats.total,
            categories = stats.categories,
            hours = stats.hours,
            installedApps = appsList,
            message = msg,
        )
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), AdBlockUiState())

    private data class Partial(
        val settings: AppSettings,
        val vpn: VpnState,
        val sources: List<AdFilterSourceEntity>,
        val allowed: List<AllowedDomainEntity>,
        val blocked: List<BlockedDomainEntity>,
    )

    init {
        refreshStats()
        loadApps()
    }

    fun refreshStats() {
        viewModelScope.launch(Dispatchers.IO) {
            val today = adFilterDao.blockedCountSinceOnce(dayStart)
            val total = adFilterDao.blockedCountTotal().first()
            val categories = adFilterDao.categoryCounts(dayStart)
            val hours = adFilterDao.hourBuckets(dayStart)
            extra.value = ExtraStats(today, total, categories, hours)
        }
    }

    fun loadApps() {
        viewModelScope.launch(Dispatchers.IO) {
            apps.value = inspector.listTargets(includeSystem = false, limit = 200)
                .map { AppEntry(it.packageName, it.label) }
        }
    }

    fun setAdBlock(enabled: Boolean) = update { settingsRepository.setAdBlockEnabled(enabled) }

    fun setTracking(enabled: Boolean) = update { settingsRepository.setBlockTracking(enabled) }

    fun setPhishing(enabled: Boolean) = update { settingsRepository.setBlockPhishing(enabled) }

    fun setMalware(enabled: Boolean) = update { settingsRepository.setBlockMalware(enabled) }

    fun startVpn() {
        if (vpnController.consentIntent() == null) vpnController.start()
        else message.value = "VPN_PERMISSION"
    }

    /** Activity 동의 화면을 띄우기 위해 필요하다(null 이면 이미 동의됨). */
    fun consentIntentForUi(): android.content.Intent? = vpnController.consentIntent()

    fun stopVpn() = vpnController.stop()

    fun pause(minutes: Int) {
        viewModelScope.launch { vpnController.pause(minutes) }
    }

    fun resume() {
        viewModelScope.launch { vpnController.resume() }
    }

    fun allowDomain(domain: String) {
        viewModelScope.launch {
            val ok = filterRepository.allowDomain(domain)
            message.value = if (ok) null else "INVALID_DOMAIN"
        }
    }

    fun removeAllowed(domain: String) {
        viewModelScope.launch { filterRepository.removeAllowedDomain(domain) }
    }

    fun blockDomain(domain: String) {
        viewModelScope.launch {
            val ok = filterRepository.blockDomain(domain)
            message.value = if (ok) null else "INVALID_DOMAIN"
        }
    }

    fun removeBlocked(domain: String) {
        viewModelScope.launch { filterRepository.removeBlockedDomain(domain) }
    }

    fun setSourceEnabled(sourceId: Long, enabled: Boolean) {
        viewModelScope.launch { filterRepository.setSourceEnabled(sourceId, enabled) }
    }

    fun setAppExcluded(packageName: String, excluded: Boolean) {
        viewModelScope.launch {
            val current = settingsRepository.settings.first().excludedPackages.toMutableSet()
            if (excluded) current += packageName else current -= packageName
            settingsRepository.setExcludedPackages(current)
            if (VpnStateHolder.state.value.running) {
                // 라우팅 규칙은 VPN 재시작 시 적용된다.
                message.value = "EXCLUSION_RESTART"
            }
        }
    }

    fun clearMessage() {
        message.value = null
    }

    private fun update(block: suspend () -> Unit) {
        viewModelScope.launch {
            block()
            filterRepository.reload()
        }
    }
}
