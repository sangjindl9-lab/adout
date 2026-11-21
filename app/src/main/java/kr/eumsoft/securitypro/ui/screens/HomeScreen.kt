package kr.eumsoft.securitypro.ui.screens

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
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
import kr.eumsoft.securitypro.core.risk.RiskLevel
import kr.eumsoft.securitypro.ui.components.LabeledSwitchRow
import kr.eumsoft.securitypro.ui.components.KeyValueRow
import kr.eumsoft.securitypro.ui.components.SectionCard
import kr.eumsoft.securitypro.ui.components.StatTile
import kr.eumsoft.securitypro.ui.components.StatusPill
import kr.eumsoft.securitypro.ui.components.localized
import kr.eumsoft.securitypro.ui.components.riskColor
import kr.eumsoft.securitypro.ui.theme.SafeGreen
import kr.eumsoft.securitypro.ui.theme.WarnAmber
import kr.eumsoft.securitypro.ui.util.formatDateTime
import kr.eumsoft.securitypro.ui.util.formatNumber
import kr.eumsoft.securitypro.ui.vm.HomeViewModel

@Composable
fun HomeScreen(
    onOpenAdBlock: () -> Unit,
    onOpenResult: (Long) -> Unit,
    viewModel: HomeViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val consentLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == android.app.Activity.RESULT_OK) viewModel.startVpn()
    }

    val level = when {
        state.dangerApps > 0 -> RiskLevel.DANGER
        (state.latestSession?.warningCount ?: 0) > 0 -> RiskLevel.WARNING
        state.latestSession != null -> RiskLevel.NOT_FOUND
        else -> RiskLevel.UNABLE
    }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        item {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    imageVector = Icons.Filled.CheckCircle,
                    contentDescription = stringResource(R.string.cd_app_logo),
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(32.dp),
                )
                Spacer(Modifier.size(10.dp))
                Column {
                    Text(
                        text = stringResource(R.string.app_name),
                        style = MaterialTheme.typography.titleLarge,
                        fontWeight = FontWeight.Bold,
                    )
                    Text(
                        text = stringResource(R.string.home_title),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }

        item {
            SectionCard {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = if (level == RiskLevel.DANGER) Icons.Filled.Warning else Icons.Filled.CheckCircle,
                        contentDescription = stringResource(R.string.cd_status_shield),
                        tint = riskColor(level),
                        modifier = Modifier.size(40.dp),
                    )
                    Spacer(Modifier.size(12.dp))
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = when (level) {
                                RiskLevel.DANGER -> stringResource(R.string.home_state_danger)
                                RiskLevel.WARNING -> stringResource(R.string.home_state_warning)
                                RiskLevel.NOT_FOUND -> stringResource(R.string.home_state_safe)
                                RiskLevel.UNABLE -> stringResource(R.string.home_state_unknown)
                            },
                            style = MaterialTheme.typography.headlineSmall,
                            color = riskColor(level),
                        )
                        Text(
                            text = when (level) {
                                RiskLevel.DANGER -> stringResource(R.string.home_subtitle_danger)
                                RiskLevel.WARNING -> stringResource(R.string.home_subtitle_warning)
                                RiskLevel.NOT_FOUND -> stringResource(R.string.home_subtitle_safe)
                                RiskLevel.UNABLE -> stringResource(R.string.home_subtitle_unknown)
                            },
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
                Spacer(Modifier.height(14.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    StatTile(
                        label = stringResource(R.string.home_today_blocked),
                        value = formatNumber(state.todayBlocked),
                        modifier = Modifier.weight(1f),
                    )
                    StatTile(
                        label = stringResource(R.string.home_danger_apps),
                        value = formatNumber(state.dangerApps),
                        tint = if (state.dangerApps > 0) riskColor(RiskLevel.DANGER) else SafeGreen,
                        modifier = Modifier.weight(1f),
                    )
                    StatTile(
                        label = stringResource(R.string.home_db_status),
                        value = state.dbVersion?.versionLabel ?: "-",
                        tint = MaterialTheme.colorScheme.onSurface,
                        modifier = Modifier.weight(1f),
                    )
                }
            }
        }

        item {
            SectionCard(title = stringResource(R.string.home_adblock_title)) {
                LabeledSwitchRow(
                    title = if (state.settings.adBlockEnabled) {
                        stringResource(R.string.home_adblock_on)
                    } else {
                        stringResource(R.string.home_adblock_off)
                    },
                    checked = state.settings.adBlockEnabled,
                    onCheckedChange = { enabled ->
                        if (enabled) {
                            val intent = viewModel.consentIntent()
                            if (intent != null) consentLauncher.launch(intent) else viewModel.startVpn()
                        } else {
                            viewModel.setAdBlockEnabled(false)
                        }
                        viewModel.setAdBlockEnabled(enabled)
                    },
                    contentDescriptionText = stringResource(R.string.cd_switch_adblock),
                    description = when {
                        state.vpn.running && state.vpn.paused -> stringResource(R.string.adblock_vpn_paused)
                        state.vpn.running -> stringResource(R.string.adblock_vpn_running)
                        else -> stringResource(R.string.adblock_vpn_stopped)
                    },
                )
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    KeyValueRow(
                        key = stringResource(R.string.home_dns_label),
                        value = state.vpn.upstream.ifEmpty { stringResource(R.string.notif_vpn_upstream_default) },
                        modifier = Modifier.weight(1f),
                    )
                    OutlinedButton(onClick = onOpenAdBlock) {
                        Text(stringResource(R.string.nav_adblock))
                    }
                }
            }
        }

        item {
            Button(
                onClick = {
                    if (state.scan.running) onOpenResult(state.scan.sessionId)
                    else viewModel.startQuickScan()
                },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(64.dp)
                    .semantics { contentDescription = "scan" },
                colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.primary),
            ) {
                Icon(Icons.Filled.PlayArrow, contentDescription = null)
                Spacer(Modifier.size(8.dp))
                Text(
                    text = if (state.scan.running) {
                        stringResource(R.string.home_scan_running)
                    } else {
                        stringResource(R.string.home_scan_button)
                    },
                    style = MaterialTheme.typography.titleMedium,
                )
            }
        }

        item {
            val session = state.latestSession
            SectionCard(
                title = stringResource(R.string.home_last_scan),
                subtitle = formatDateTime(session?.finishedAt),
                modifier = Modifier.clickable(enabled = session != null) {
                    session?.let { onOpenResult(it.id) }
                },
            ) {
                if (session == null) {
                    Text(
                        text = stringResource(R.string.home_last_scan_none),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                } else {
                    Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                        StatTile(
                            label = stringResource(R.string.result_apps_count, session.scannedTargets),
                            value = formatNumber(session.scannedTargets),
                            modifier = Modifier.weight(1f),
                        )
                        StatTile(
                            label = stringResource(R.string.result_risk_danger),
                            value = formatNumber(session.dangerCount),
                            tint = if (session.dangerCount > 0) riskColor(RiskLevel.DANGER) else SafeGreen,
                            modifier = Modifier.weight(1f),
                        )
                        StatTile(
                            label = stringResource(R.string.result_risk_warning),
                            value = formatNumber(session.warningCount),
                            tint = if (session.warningCount > 0) WarnAmber else SafeGreen,
                            modifier = Modifier.weight(1f),
                        )
                    }
                    Spacer(Modifier.height(8.dp))
                    Text(
                        text = session.summaryText(),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }

        item {
            SectionCard(
                title = stringResource(R.string.home_db_status),
                subtitle = state.dbVersion?.let { localized("db_installed_at") + ": " + formatDateTime(it.installedAt) }
                    ?: stringResource(R.string.home_db_never),
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = state.dbVersion?.versionLabel ?: "-",
                            style = MaterialTheme.typography.titleMedium,
                        )
                        if (state.dbVersion?.isTestData == true) {
                            Spacer(Modifier.height(4.dp))
                            StatusPill(
                                text = stringResource(R.string.test_data_badge),
                                color = WarnAmber,
                            )
                        }
                    }
                    OutlinedButton(onClick = { viewModel.updateDatabases() }) {
                        Text(stringResource(R.string.home_db_update_button))
                    }
                }
            }
        }

        item {
            Text(
                text = stringResource(R.string.home_privacy_note),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(horizontal = 4.dp, vertical = 8.dp),
            )
        }
    }
}

private fun kr.eumsoft.securitypro.data.db.entity.ScanSessionEntity.summaryText(): String =
    when {
        dangerCount > 0 -> "위험 $dangerCount · 주의 $warningCount"
        warningCount > 0 -> "주의 $warningCount"
        else -> "알려진 위협 미발견"
    }
