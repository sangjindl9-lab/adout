package kr.eumsoft.securitypro.ui.vm

import android.net.Uri
import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import javax.inject.Inject
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kr.eumsoft.securitypro.data.db.ScanSessionDetail
import kr.eumsoft.securitypro.data.db.dao.ScanDao
import kr.eumsoft.securitypro.data.db.entity.ScanSessionEntity
import kr.eumsoft.securitypro.data.db.entity.ThreatDbVersionEntity
import kr.eumsoft.securitypro.data.prefs.AppSettings
import kr.eumsoft.securitypro.data.prefs.SettingsRepository
import kr.eumsoft.securitypro.data.updater.UpdateClient
import kr.eumsoft.securitypro.data.updater.UpdateOutcome
import kr.eumsoft.securitypro.data.updater.UpdateTarget
import kr.eumsoft.securitypro.scanner.MalwareScanManager
import kr.eumsoft.securitypro.scanner.ScanRequest
import kr.eumsoft.securitypro.scanner.ScanState
import kr.eumsoft.securitypro.worker.WorkScheduler

data class ScanUiState(
    val scan: ScanState = ScanState(),
    val sessions: List<ScanSessionEntity> = emptyList(),
)

@HiltViewModel
class ScanViewModel @Inject constructor(
    private val scanManager: MalwareScanManager,
    private val scanDao: ScanDao,
) : ViewModel() {

    val state: StateFlow<ScanUiState> = combine(
        scanManager.state,
        scanDao.recentSessionHeaders(20),
    ) { scan, sessions -> ScanUiState(scan, sessions) }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), ScanUiState())

    fun startQuick() = scanManager.start(ScanRequest.Quick)

    fun startInstalled() = scanManager.start(ScanRequest.InstalledApps)

    fun startApk(uri: Uri) = scanManager.start(ScanRequest.ApkFile(uri))

    fun cancel() = scanManager.cancel()
}

/** 검사 결과 상세. */
@HiltViewModel
class ResultViewModel @Inject constructor(
    savedStateHandle: SavedStateHandle,
    private val scanDao: ScanDao,
    private val scanManager: MalwareScanManager,
) : ViewModel() {

    private val sessionId: Long = savedStateHandle.get<String>("sessionId")?.toLongOrNull() ?: -1L
    private val _detail = MutableStateFlow<ScanSessionDetail?>(null)
    val detail: StateFlow<ScanSessionDetail?> = _detail.asStateFlow()

    init {
        load()
    }

    fun load() {
        viewModelScope.launch {
            _detail.value = withContext(Dispatchers.IO) { scanDao.sessionDetail(sessionId) }
        }
    }

    fun rescan() {
        scanManager.start(ScanRequest.Quick)
    }
}

data class DatabaseUiState(
    val settings: AppSettings = AppSettings(),
    val filterVersion: ThreatDbVersionEntity? = null,
    val hashVersion: ThreatDbVersionEntity? = null,
    val yaraVersion: ThreatDbVersionEntity? = null,
    val history: List<kr.eumsoft.securitypro.data.db.entity.UpdateHistoryEntity> = emptyList(),
    val updating: Boolean = false,
    val message: String? = null,
)

@HiltViewModel
class DatabaseViewModel @Inject constructor(
    private val threatDao: kr.eumsoft.securitypro.data.db.dao.ThreatDao,
    private val updateHistoryDao: kr.eumsoft.securitypro.data.db.dao.UpdateHistoryDao,
    private val updateClient: UpdateClient,
    private val settingsRepository: SettingsRepository,
    private val workScheduler: WorkScheduler,
) : ViewModel() {

    private val updating = MutableStateFlow(false)
    private val message = MutableStateFlow<String?>(null)

    val state: StateFlow<DatabaseUiState> = combine(
        threatDao.dbVersionFlow(UpdateTarget.AD_FILTER.dbType),
        threatDao.dbVersionFlow(UpdateTarget.THREAT_HASH.dbType),
        threatDao.dbVersionFlow(UpdateTarget.YARA_RULES.dbType),
        updateHistoryDao.recent(30),
        updating,
    ) { filter, hash, yara, history, busy ->
        DatabaseUiState(
            filterVersion = filter,
            hashVersion = hash,
            yaraVersion = yara,
            history = history,
            updating = busy,
        )
    }.combine(message) { state, msg -> state.copy(message = msg) }
        .combine(settingsRepository.settings) { state, settings -> state.copy(settings = settings) }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), DatabaseUiState())

    fun update(target: UpdateTarget? = null) {
        viewModelScope.launch {
            updating.value = true
            message.value = null
            val outcomes = if (target == null) updateClient.updateAll() else listOf(updateClient.update(target))
            updating.value = false
            val successes = outcomes.filterIsInstance<UpdateOutcome.Success>()
            val notConfigured = outcomes.any { it is UpdateOutcome.NotConfigured }
            message.value = when {
                notConfigured -> "NOT_CONFIGURED"
                successes.isNotEmpty() -> "SUCCESS"
                else -> "FAILED"
            }
            settingsRepository.markUpdateCheck(System.currentTimeMillis())
        }
    }

    fun clearMessage() {
        message.value = null
    }
}

data class SettingsUiState(
    val settings: AppSettings = AppSettings(),
    val patternDiagnostics: List<String> = emptyList(),
    val versionName: String = "",
    val message: String? = null,
)

@HiltViewModel
class SettingsViewModel @Inject constructor(
    private val settingsRepository: SettingsRepository,
    private val scanDao: ScanDao,
    private val adFilterDao: kr.eumsoft.securitypro.data.db.dao.AdFilterDao,
    private val patternScanner: kr.eumsoft.securitypro.core.pattern.PatternScanner,
) : ViewModel() {

    private val message = MutableStateFlow<String?>(null)

    val state: StateFlow<SettingsUiState> = settingsRepository.settings
        .combine(message) { settings, msg ->
            SettingsUiState(
                settings = settings,
                patternDiagnostics = patternScanner.diagnostics(),
                versionName = kr.eumsoft.securitypro.BuildConfig.VERSION_NAME,
                message = msg,
            )
        }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), SettingsUiState())

    fun setAutoScan(value: Boolean) = launchUpdate { settingsRepository.setAutoScan(value) }

    fun setAutoUpdate(value: Boolean) = launchUpdate { settingsRepository.setAutoUpdate(value) }

    fun setNotifications(value: Boolean) = launchUpdate { settingsRepository.setNotifications(value) }

    fun setTheme(mode: kr.eumsoft.securitypro.data.prefs.ThemeMode) =
        launchUpdate { settingsRepository.setThemeMode(mode) }

    fun setLanguage(language: String) = launchUpdate { settingsRepository.setLanguage(language) }

    fun setDnsMode(mode: kr.eumsoft.securitypro.data.prefs.DnsMode) =
        launchUpdate { settingsRepository.setDnsMode(mode) }

    fun setDnsProvider(provider: String) = launchUpdate { settingsRepository.setDnsProvider(provider) }

    fun setCustomDns(host: String) = launchUpdate { settingsRepository.setCustomDnsName(host) }

    fun setBlockMode(mode: kr.eumsoft.securitypro.core.dns.BlockResponseMode) =
        launchUpdate { settingsRepository.setBlockResponseMode(mode) }

    fun setRetention(days: Int) = launchUpdate { settingsRepository.setLogRetentionDays(days) }

    fun clearHistory() {
        viewModelScope.launch(Dispatchers.IO) {
            runCatching {
                scanDao.deleteAllSessions()
                adFilterDao.clearEvents()
            }
            message.value = "CLEARED"
        }
    }

    fun clearMessage() {
        message.value = null
    }

    private fun launchUpdate(block: suspend () -> Unit) {
        viewModelScope.launch { block() }
    }
}
