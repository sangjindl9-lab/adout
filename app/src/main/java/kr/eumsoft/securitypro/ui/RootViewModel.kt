package kr.eumsoft.securitypro.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import javax.inject.Inject
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kr.eumsoft.securitypro.data.prefs.AppSettings
import kr.eumsoft.securitypro.data.prefs.SettingsRepository

@HiltViewModel
class RootViewModel @Inject constructor(
    settingsRepository: SettingsRepository,
) : ViewModel() {

    data class UiState(val settings: AppSettings = AppSettings())

    val state: StateFlow<UiState> = settingsRepository.settings
        .map { UiState(it) }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), UiState())
}
