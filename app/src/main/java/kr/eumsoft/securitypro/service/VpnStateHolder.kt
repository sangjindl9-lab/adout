package kr.eumsoft.securitypro.service

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/** VPN 상태(UI 관찰용). */
data class VpnState(
    val running: Boolean = false,
    val starting: Boolean = false,
    val needsPermission: Boolean = false,
    val startedAt: Long = 0L,
    val queries: Long = 0L,
    val blocked: Long = 0L,
    val upstream: String = "",
    val message: String? = null,
    val lastEventDomain: String? = null,
    val paused: Boolean = false,
)

/**
 * 서비스와 UI 사이의 상태 홀더. 서비스가 살아있는 동안 프로세스 전역으로 공유된다.
 */
object VpnStateHolder {
    private val _state = MutableStateFlow(VpnState())
    val state: StateFlow<VpnState> = _state.asStateFlow()

    fun update(transform: (VpnState) -> VpnState) {
        _state.value = transform(_state.value)
    }

    fun reset() {
        _state.value = VpnState()
    }

    fun recordQuery(blocked: Boolean, domain: String) {
        _state.value = _state.value.copy(
            queries = _state.value.queries + 1,
            blocked = _state.value.blocked + if (blocked) 1 else 0,
            lastEventDomain = if (blocked) domain else _state.value.lastEventDomain,
        )
    }
}
