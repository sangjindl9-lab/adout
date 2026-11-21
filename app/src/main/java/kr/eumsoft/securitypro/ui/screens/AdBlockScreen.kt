package kr.eumsoft.securitypro.ui.screens

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import kr.eumsoft.securitypro.R
import kr.eumsoft.securitypro.ui.components.KeyValueRow
import kr.eumsoft.securitypro.ui.components.LabeledSwitchRow
import kr.eumsoft.securitypro.ui.components.SectionCard
import kr.eumsoft.securitypro.ui.components.StatTile
import kr.eumsoft.securitypro.ui.components.StatusPill
import kr.eumsoft.securitypro.ui.theme.DangerRed
import kr.eumsoft.securitypro.ui.theme.SafeGreen
import kr.eumsoft.securitypro.ui.theme.WarnAmber
import kr.eumsoft.securitypro.ui.util.formatDateTime
import kr.eumsoft.securitypro.ui.util.formatNumber
import kr.eumsoft.securitypro.ui.vm.AdBlockViewModel

@Composable
fun AdBlockScreen(viewModel: AdBlockViewModel = hiltViewModel()) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val consentLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == android.app.Activity.RESULT_OK) viewModel.startVpn()
    }
    var showAllowDialog by remember { mutableStateOf(false) }
    var showBlockDialog by remember { mutableStateOf(false) }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        item {
            Text(
                text = stringResource(R.string.adblock_title),
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.Bold,
            )
        }

        item {
            SectionCard(title = stringResource(R.string.adblock_vpn_state)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    StatusPill(
                        text = when {
                            state.vpn.running && state.vpn.paused -> stringResource(R.string.adblock_vpn_paused)
                            state.vpn.running -> stringResource(R.string.adblock_vpn_running)
                            else -> stringResource(R.string.adblock_vpn_stopped)
                        },
                        color = when {
                            state.vpn.running && !state.vpn.paused -> SafeGreen
                            state.vpn.running -> WarnAmber
                            else -> DangerRed
                        },
                    )
                    Spacer(Modifier.width(10.dp))
                    Text(
                        text = state.vpn.message ?: "",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Spacer(Modifier.height(10.dp))
                KeyValueRow(
                    key = stringResource(R.string.adblock_upstream),
                    value = state.vpn.upstream.ifEmpty { stringResource(R.string.notif_vpn_upstream_default) },
                )
                KeyValueRow(
                    key = stringResource(R.string.adblock_stats_total),
                    value = formatNumber(state.vpn.queries),
                )
                Spacer(Modifier.height(10.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    if (state.vpn.running) {
                        OutlinedButton(onClick = { viewModel.stopVpn() }) {
                            Text(stringResource(R.string.adblock_vpn_stop))
                        }
                        OutlinedButton(onClick = {
                            if (state.vpn.paused) viewModel.resume() else viewModel.pause(15)
                        }) {
                            Text(
                                stringResource(
                                    if (state.vpn.paused) R.string.adblock_resume else R.string.adblock_pause_15
                                )
                            )
                        }
                    } else {
                        Button(onClick = {
                            val intent = viewModel.consentIntentForUi()
                            if (intent != null) consentLauncher.launch(intent) else viewModel.startVpn()
                        }) {
                            Text(stringResource(R.string.adblock_vpn_start))
                        }
                    }
                }
            }
        }

        item {
            SectionCard {
                LabeledSwitchRow(
                    title = stringResource(R.string.adblock_toggle_ads),
                    checked = state.settings.adBlockEnabled,
                    onCheckedChange = { enabled ->
                        viewModel.setAdBlock(enabled)
                        if (enabled) {
                            val intent = viewModel.consentIntentForUi()
                            if (intent != null) consentLauncher.launch(intent)
                        }
                    },
                )
                LabeledSwitchRow(
                    title = stringResource(R.string.adblock_toggle_tracking),
                    checked = state.settings.blockTracking,
                    onCheckedChange = viewModel::setTracking,
                )
                LabeledSwitchRow(
                    title = stringResource(R.string.adblock_toggle_phishing),
                    checked = state.settings.blockPhishing,
                    onCheckedChange = viewModel::setPhishing,
                )
                LabeledSwitchRow(
                    title = stringResource(R.string.adblock_toggle_malware),
                    checked = state.settings.blockMalware,
                    onCheckedChange = viewModel::setMalware,
                )
            }
        }

        item {
            SectionCard(title = stringResource(R.string.adblock_filters)) {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    state.sources.forEach { source ->
                        Column {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(source.name, style = MaterialTheme.typography.titleMedium)
                                    Text(
                                        text = stringResource(R.string.adblock_filter_rules, source.ruleCount),
                                        style = MaterialTheme.typography.bodyMedium,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    )
                                    Text(
                                        text = stringResource(R.string.adblock_filter_license, source.license),
                                        style = MaterialTheme.typography.bodyMedium,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    )
                                    Text(
                                        text = stringResource(
                                            R.string.adblock_filter_updated,
                                            if (source.lastUpdatedAt != null) {
                                                formatDateTime(source.lastUpdatedAt)
                                            } else {
                                                stringResource(R.string.adblock_filter_never)
                                            },
                                        ),
                                        style = MaterialTheme.typography.bodyMedium,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    )
                                }
                                Switch(
                                    checked = source.enabled,
                                    onCheckedChange = { viewModel.setSourceEnabled(source.id, it) },
                                    modifier = Modifier.semantics {
                                        contentDescription = source.name
                                    },
                                )
                            }
                            if (source.isTestData) {
                                StatusPill(text = stringResource(R.string.test_data_badge), color = WarnAmber)
                            }
                            Spacer(Modifier.height(6.dp))
                        }
                    }
                }
            }
        }

        item {
            SectionCard(title = stringResource(R.string.adblock_stats)) {
                Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    StatTile(
                        label = stringResource(R.string.adblock_stats_today),
                        value = formatNumber(state.todayBlocked),
                        modifier = Modifier.weight(1f),
                    )
                    StatTile(
                        label = stringResource(R.string.adblock_stats_total),
                        value = formatNumber(state.totalBlocked),
                        modifier = Modifier.weight(1f),
                    )
                    StatTile(
                        label = stringResource(R.string.adblock_stats_tracking),
                        value = formatNumber(
                            state.categories.firstOrNull { it.category == "TRACKING" }?.count ?: 0
                        ),
                        modifier = Modifier.weight(1f),
                    )
                }
                Spacer(Modifier.height(12.dp))
                Text(
                    text = stringResource(R.string.adblock_hourly),
                    style = MaterialTheme.typography.titleMedium,
                )
                Spacer(Modifier.height(6.dp))
                HourlyBars(state.hours.map { it.count })
                Spacer(Modifier.height(8.dp))
                Text(
                    text = stringResource(R.string.adblock_limit_note),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }

        item {
            SectionCard(title = stringResource(R.string.adblock_recent_blocks)) {
                if (state.events.isEmpty()) {
                    Text(
                        text = stringResource(R.string.adblock_empty_blocks),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                } else {
                    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        state.events.take(20).forEach { event ->
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(event.domain, style = MaterialTheme.typography.bodyLarge)
                                    Text(
                                        text = event.category + " · " + formatDateTime(event.blockedAt),
                                        style = MaterialTheme.typography.bodyMedium,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    )
                                }
                                TextButton(onClick = { viewModel.allowDomain(event.domain) }) {
                                    Text(stringResource(R.string.adblock_allow_this))
                                }
                            }
                            HorizontalDivider()
                        }
                    }
                }
            }
        }

        item {
            SectionCard(title = stringResource(R.string.adblock_allowlist)) {
                state.allowed.forEach { domain ->
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(domain.domain, modifier = Modifier.weight(1f))
                        TextButton(onClick = { viewModel.removeAllowed(domain.domain) }) {
                            Text(stringResource(R.string.delete))
                        }
                    }
                }
                if (state.allowed.isEmpty()) {
                    Text(
                        text = stringResource(R.string.adblock_empty_allow),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                TextButton(onClick = { showAllowDialog = true }) {
                    Text(stringResource(R.string.adblock_add_domain))
                }
            }
        }

        item {
            SectionCard(title = stringResource(R.string.adblock_blocklist)) {
                state.blockedDomains.forEach { domain ->
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(domain.domain, modifier = Modifier.weight(1f))
                        TextButton(onClick = { viewModel.removeBlocked(domain.domain) }) {
                            Text(stringResource(R.string.delete))
                        }
                    }
                }
                if (state.blockedDomains.isEmpty()) {
                    Text(
                        text = stringResource(R.string.adblock_empty_block),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                TextButton(onClick = { showBlockDialog = true }) {
                    Text(stringResource(R.string.adblock_add_domain))
                }
            }
        }

        item {
            SectionCard(
                title = stringResource(R.string.adblock_excluded_apps),
                subtitle = stringResource(R.string.adblock_excluded_desc),
            ) {
                state.installedApps.take(40).forEach { app ->
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(app.label, style = MaterialTheme.typography.titleMedium)
                            Text(
                                text = app.packageName,
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                        Switch(
                            checked = app.packageName in state.settings.excludedPackages,
                            onCheckedChange = { excluded ->
                                viewModel.setAppExcluded(app.packageName, excluded)
                            },
                            modifier = Modifier.semantics { contentDescription = app.label },
                        )
                    }
                }
            }
        }

        item {
            Text(
                text = stringResource(R.string.adblock_limit_note),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(4.dp),
            )
        }
    }

    if (showAllowDialog) {
        DomainDialog(
            title = stringResource(R.string.adblock_allowlist),
            onDismiss = { showAllowDialog = false },
            onConfirm = { domain ->
                viewModel.allowDomain(domain)
                showAllowDialog = false
            },
        )
    }
    if (showBlockDialog) {
        DomainDialog(
            title = stringResource(R.string.adblock_blocklist),
            onDismiss = { showBlockDialog = false },
            onConfirm = { domain ->
                viewModel.blockDomain(domain)
                showBlockDialog = false
            },
        )
    }
}

@Composable
private fun DomainDialog(
    title: String,
    onDismiss: () -> Unit,
    onConfirm: (String) -> Unit,
) {
    var value by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            OutlinedTextField(
                value = value,
                onValueChange = { value = it },
                label = { Text(stringResource(R.string.adblock_domain_hint)) },
                singleLine = true,
            )
        },
        confirmButton = {
            TextButton(
                onClick = { onConfirm(value.trim()) },
                enabled = value.isNotBlank(),
            ) { Text(stringResource(R.string.add)) }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) }
        },
    )
}

@Composable
private fun HourlyBars(values: List<Int>) {
    val max = values.maxOrNull() ?: 0
    if (max <= 0) {
        Text(
            text = stringResource(R.string.adblock_no_stats),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        return
    }
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .height(96.dp)
            .semantics { contentDescription = "hourly-chart" },
        verticalAlignment = Alignment.Bottom,
        horizontalArrangement = Arrangement.spacedBy(3.dp),
    ) {
        values.takeLast(24).forEach { value ->
            val fraction = (value.toFloat() / max).coerceIn(0.02f, 1f)
            Box(
                modifier = Modifier
                    .weight(1f)
                    .height((88 * fraction).dp)
                    .background(MaterialTheme.colorScheme.primary, RoundedCornerShape(3.dp)),
            )
        }
    }
}
