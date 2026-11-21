package kr.eumsoft.securitypro.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Slider
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import kr.eumsoft.securitypro.R
import kr.eumsoft.securitypro.core.dns.BlockResponseMode
import kr.eumsoft.securitypro.data.prefs.DnsMode
import kr.eumsoft.securitypro.data.prefs.ThemeMode
import kr.eumsoft.securitypro.ui.components.KeyValueRow
import kr.eumsoft.securitypro.ui.components.LabeledSwitchRow
import kr.eumsoft.securitypro.ui.components.SectionCard
import kr.eumsoft.securitypro.ui.vm.SettingsViewModel

@Composable
fun SettingsScreen(viewModel: SettingsViewModel = hiltViewModel()) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val settings = state.settings
    val context = LocalContext.current
    var showClearDialog by remember { mutableStateOf(false) }
    var showPolicy by remember { mutableStateOf(false) }
    var showLicenses by remember { mutableStateOf(false) }
    var showDiagnostics by remember { mutableStateOf(false) }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        item {
            Text(
                text = stringResource(R.string.settings_title),
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.Bold,
            )
        }

        item {
            SectionCard(title = stringResource(R.string.settings_section_scan)) {
                LabeledSwitchRow(
                    title = stringResource(R.string.settings_auto_scan),
                    checked = settings.autoScan,
                    onCheckedChange = viewModel::setAutoScan,
                )
                LabeledSwitchRow(
                    title = stringResource(R.string.settings_auto_update),
                    checked = settings.autoUpdate,
                    onCheckedChange = viewModel::setAutoUpdate,
                )
                LabeledSwitchRow(
                    title = stringResource(R.string.settings_notifications),
                    checked = settings.notificationsEnabled,
                    onCheckedChange = viewModel::setNotifications,
                )
            }
        }

        item {
            SectionCard(title = stringResource(R.string.settings_section_display)) {
                Text(
                    text = stringResource(R.string.settings_theme),
                    style = MaterialTheme.typography.titleMedium,
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Chip(
                        label = stringResource(R.string.settings_theme_system),
                        selected = settings.themeMode == ThemeMode.SYSTEM,
                        onClick = { viewModel.setTheme(ThemeMode.SYSTEM) },
                    )
                    Chip(
                        label = stringResource(R.string.settings_theme_light),
                        selected = settings.themeMode == ThemeMode.LIGHT,
                        onClick = { viewModel.setTheme(ThemeMode.LIGHT) },
                    )
                    Chip(
                        label = stringResource(R.string.settings_theme_dark),
                        selected = settings.themeMode == ThemeMode.DARK,
                        onClick = { viewModel.setTheme(ThemeMode.DARK) },
                    )
                }
                Spacer(Modifier.height(12.dp))
                Text(
                    text = stringResource(R.string.settings_language),
                    style = MaterialTheme.typography.titleMedium,
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    LangChip("system", settings.language, stringResource(R.string.settings_language_system), viewModel)
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    LangChip("ko", settings.language, "한국어", viewModel)
                    LangChip("en", settings.language, "English", viewModel)
                    LangChip("ja", settings.language, "日本語", viewModel)
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    LangChip("zh-CN", settings.language, "简体中文", viewModel)
                    LangChip("es", settings.language, "Español", viewModel)
                }
            }
        }

        item {
            SectionCard(title = stringResource(R.string.settings_section_network)) {
                Text(
                    text = stringResource(R.string.settings_dns_mode),
                    style = MaterialTheme.typography.titleMedium,
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Chip(
                        label = stringResource(R.string.settings_dns_system),
                        selected = settings.dnsMode == DnsMode.SYSTEM,
                        onClick = { viewModel.setDnsMode(DnsMode.SYSTEM) },
                    )
                    Chip(
                        label = "DoH",
                        selected = settings.dnsMode == DnsMode.DOH,
                        onClick = { viewModel.setDnsMode(DnsMode.DOH) },
                    )
                    Chip(
                        label = "DoT",
                        selected = settings.dnsMode == DnsMode.DOT,
                        onClick = { viewModel.setDnsMode(DnsMode.DOT) },
                    )
                }
                if (settings.dnsMode != DnsMode.SYSTEM) {
                    Spacer(Modifier.height(10.dp))
                    Text(
                        text = stringResource(R.string.settings_dns_provider),
                        style = MaterialTheme.typography.titleMedium,
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Chip(
                            label = stringResource(R.string.settings_dns_provider_cloudflare),
                            selected = settings.dnsProvider == "cloudflare",
                            onClick = { viewModel.setDnsProvider("cloudflare") },
                        )
                        Chip(
                            label = stringResource(R.string.settings_dns_provider_google),
                            selected = settings.dnsProvider == "google",
                            onClick = { viewModel.setDnsProvider("google") },
                        )
                        Chip(
                            label = stringResource(R.string.settings_dns_provider_adguard),
                            selected = settings.dnsProvider == "adguard",
                            onClick = { viewModel.setDnsProvider("adguard") },
                        )
                    }
                    if (settings.dnsProvider == "custom") {
                        OutlinedTextField(
                            value = settings.customDnsName,
                            onValueChange = viewModel::setCustomDns,
                            label = { Text(stringResource(R.string.settings_dns_custom_hint)) },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth(),
                        )
                    } else {
                        TextButton(onClick = { viewModel.setDnsProvider("custom") }) {
                            Text(stringResource(R.string.settings_dns_provider_custom))
                        }
                    }
                }
                Spacer(Modifier.height(12.dp))
                Text(
                    text = stringResource(R.string.settings_block_mode),
                    style = MaterialTheme.typography.titleMedium,
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Chip(
                        label = stringResource(R.string.settings_block_nxdomain),
                        selected = settings.blockResponseMode == BlockResponseMode.NXDOMAIN,
                        onClick = { viewModel.setBlockMode(BlockResponseMode.NXDOMAIN) },
                    )
                    Chip(
                        label = stringResource(R.string.settings_block_null),
                        selected = settings.blockResponseMode == BlockResponseMode.NULL_IP,
                        onClick = { viewModel.setBlockMode(BlockResponseMode.NULL_IP) },
                    )
                }
            }
        }

        item {
            SectionCard(title = stringResource(R.string.settings_section_privacy)) {
                Text(
                    text = stringResource(R.string.settings_retention) + ": " +
                        stringResource(R.string.settings_retention_value, settings.logRetentionDays),
                    style = MaterialTheme.typography.titleMedium,
                )
                Slider(
                    value = settings.logRetentionDays.toFloat(),
                    onValueChange = { viewModel.setRetention(it.toInt().coerceIn(1, 365)) },
                    valueRange = 1f..365f,
                    steps = 0,
                )
                Spacer(Modifier.height(8.dp))
                OutlinedButton(onClick = { showPolicy = true }) {
                    Text(stringResource(R.string.settings_privacy_policy))
                }
                Spacer(Modifier.height(8.dp))
                OutlinedButton(onClick = { showClearDialog = true }) {
                    Text(stringResource(R.string.settings_clear_history))
                }
            }
        }

        item {
            SectionCard(title = stringResource(R.string.settings_section_about)) {
                KeyValueRow(key = stringResource(R.string.settings_version), value = state.versionName)
                KeyValueRow(key = stringResource(R.string.home_db_status), value = settings.dnsMode.name)
                TextButton(onClick = { showLicenses = true }) {
                    Text(stringResource(R.string.settings_licenses))
                }
                TextButton(onClick = { showDiagnostics = true }) {
                    Text(stringResource(R.string.settings_health))
                }
            }
        }
    }

    if (showClearDialog) {
        AlertDialog(
            onDismissRequest = { showClearDialog = false },
            title = { Text(stringResource(R.string.settings_clear_history)) },
            text = { Text(stringResource(R.string.settings_clear_confirm)) },
            confirmButton = {
                TextButton(onClick = {
                    viewModel.clearHistory()
                    showClearDialog = false
                }) { Text(stringResource(R.string.delete)) }
            },
            dismissButton = {
                TextButton(onClick = { showClearDialog = false }) { Text(stringResource(R.string.cancel)) }
            },
        )
    }

    if (showPolicy) {
        TextDialog(
            title = stringResource(R.string.settings_privacy_policy),
            body = readAsset(context, "legal/privacy_policy_ko.md"),
            onClose = { showPolicy = false },
        )
    }
    if (showLicenses) {
        TextDialog(
            title = stringResource(R.string.settings_licenses),
            body = readAsset(context, "legal/third_party_licenses.md"),
            onClose = { showLicenses = false },
        )
    }
    if (showDiagnostics) {
        TextDialog(
            title = stringResource(R.string.settings_health),
            body = if (state.patternDiagnostics.isEmpty()) {
                "규칙 컴파일 오류 없음"
            } else {
                state.patternDiagnostics.joinToString("\n")
            },
            onClose = { showDiagnostics = false },
        )
    }
}

@Composable
private fun Chip(label: String, selected: Boolean, onClick: () -> Unit) {
    FilterChip(selected = selected, onClick = onClick, label = { Text(label) })
}

@Composable
private fun LangChip(code: String, current: String, label: String, viewModel: SettingsViewModel) {
    Chip(label = label, selected = current == code, onClick = { viewModel.setLanguage(code) })
}

@Composable
private fun TextDialog(title: String, body: String, onClose: () -> Unit) {
    AlertDialog(
        onDismissRequest = onClose,
        title = { Text(title) },
        text = {
            Column(
                modifier = Modifier
                    .height(420.dp)
                    .verticalScroll(rememberScrollState()),
            ) {
                Text(text = body, style = MaterialTheme.typography.bodyMedium)
            }
        },
        confirmButton = {
            TextButton(onClick = onClose) { Text(stringResource(R.string.close)) }
        },
    )
}

private fun readAsset(context: android.content.Context, path: String): String = runCatching {
    context.assets.open(path).bufferedReader().use { it.readText() }
}.getOrDefault("문서를 불러올 수 없습니다: $path")
