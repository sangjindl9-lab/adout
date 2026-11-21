package kr.eumsoft.securitypro.service

import android.content.Context
import android.content.Intent
import android.net.VpnService
import androidx.core.content.ContextCompat
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.coroutines.flow.StateFlow
import kr.eumsoft.securitypro.data.prefs.SettingsRepository

/** UI 에서 VPN 을 제어하는 진입점. 동의 화면(Intent) 처리를 돕는다. */
@Singleton
class VpnController @Inject constructor(
    @ApplicationContext private val context: Context,
    private val settingsRepository: SettingsRepository,
) {

    val state: StateFlow<VpnState> = VpnStateHolder.state

    /** null 이면 이미 동의됨. 아니면 Activity 에서 startActivityForResult 로 띄운다. */
    fun consentIntent(): Intent? = try {
        VpnService.prepare(context)
    } catch (_: Exception) {
        null
    }

    fun start() {
        val intent = Intent(context, EumVpnService::class.java).setAction(EumVpnService.ACTION_START)
        runCatching { ContextCompat.startForegroundService(context, intent) }
    }

    fun stop() {
        val intent = Intent(context, EumVpnService::class.java).setAction(EumVpnService.ACTION_STOP)
        runCatching { context.startService(intent) }
    }

    suspend fun pause(minutes: Int) {
        settingsRepository.pauseFor(System.currentTimeMillis(), minutes)
        VpnStateHolder.update { it.copy(paused = true) }
    }

    suspend fun resume() {
        settingsRepository.resume()
        VpnStateHolder.update { it.copy(paused = false) }
    }
}
