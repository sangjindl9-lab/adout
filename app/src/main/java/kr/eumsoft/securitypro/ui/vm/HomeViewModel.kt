package kr.eumsoft.securitypro.ui.vm

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import javax.inject.Inject
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kr.eumsoft.securitypro.data.db.dao.ThreatDao
import kr.eumsoft.securitypro.data.db.dao.AdFilterDao
import kr.eumsoft.securitypro.data.db.dao.ScanDao
import kr.eumsoft.securitypro.data.db.entity.ScanSessionEntity
import kr.eumsoft.securitypro.data.db.entity.ThreatDbVersionEntity
import kr.eumsoft.securitypro.data.prefs.AppSettings
import kr.eumsoft.securitypro.data.prefs.SettingsRepository
import kr.eumsoft.securitypro.scanner.MalwareScanManager
import kr.eumsoft.securitypro.scanner.ScanState
import kr.eumsoft.securitypro.service.VpnController
import kr.eumsoft.securitypro.service.VpnState
import kr.eumsoft.securitypro.service.VpnStateHolder
import kr.eumsoft.securitypro.ui.util.startOfToday
import kr.eumsoft.securitypro.worker.WorkScheduler

data class HomeUiState(
    val settings: AppSettings = AppSettings(),
    val vpn: VpnState = VpnState(),
    val scan: ScanState = ScanState(),
    val latestSession: ScanSessionEntity? = null,
    val todayBlocked: Int = 0,
    val totalBlocked: Int = 0,
    val dangerApps: Int = 0,
    val dbVersion: ThreatDbVersionEntity? = null,
)

@HiltViewModel
class HomeViewModel @Inject constructor(
    private val settingsRepository: SettingsRepository,
    private val vpnController: VpnController,
    private val scanManager: MalwareScanManager,
    private val scanDao: ScanDao,
    private val adFilterDao: AdFilterDao,
    private val threatDao: ThreatDao,
    private val workScheduler: WorkScheduler,
) : ViewModel() {

    private val dayStart = startOfToday()

    val state: StateFlow<HomeUiState> = combine(
        settingsRepository.settings,
        VpnStateHolder.state,
        scanManager.state,
        scanDao.latestCompletedSession(),
        adFilterDao.blockedCountSince(dayStart),
    ) { settings, vpn, scan, session, today ->
        Partial(settings, vpn, scan, session, today)
    }.combine(adFilterDao.blockedCountTotal()) { partial, total ->
        partial to total
    }.combine(threatDao.dangerousApps().map { it.size }) { (partial, total), danger ->
        Triple(partial, total, danger)
    }.combine(threatDao.dbVersionFlow("AD_FILTER")) { (partial, total, danger), dbVersion ->
        HomeUiState(
            settings = partial.settings,
            vpn = partial.vpn,
            scan = partial.scan,
            latestSession = partial.session,
            todayBlocked = partial.today,
            totalBlocked = total,
            dangerApps = danger,
            dbVersion = dbVersion,
        )
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), HomeUiState())

    private data class Partial(
        val settings: AppSettings,
        val vpn: VpnState,
        val scan: ScanState,
        val session: ScanSessionEntity?,
        val today: Int,
    )

    fun setAdBlockEnabled(enabled: Boolean) {
        viewModelScope.launch {
            settingsRepository.setAdBlockEnabled(enabled)
            if (enabled) {
                if (vpnController.consentIntent() == null) vpnController.start()
            } else {
                vpnController.stop()
            }
        }
    }

    fun startQuickScan() {
        scanManager.start(kr.eumsoft.securitypro.scanner.ScanRequest.Quick)
    }

    /** null 이면 동의가 이미 되어 있다. */
    fun consentIntent(): android.content.Intent? = vpnController.consentIntent()

    fun startVpn() = vpnController.start()

    fun stopVpn() = vpnController.stop()

    fun updateDatabases() {
        workScheduler.requestUpdateNow()
    }
}
