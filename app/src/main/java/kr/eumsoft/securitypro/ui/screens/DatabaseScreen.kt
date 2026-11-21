package kr.eumsoft.securitypro.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import kr.eumsoft.securitypro.R
import kr.eumsoft.securitypro.data.db.entity.ThreatDbVersionEntity
import kr.eumsoft.securitypro.data.db.entity.UpdateHistoryEntity
import kr.eumsoft.securitypro.data.updater.UpdateTarget
import kr.eumsoft.securitypro.ui.components.KeyValueRow
import kr.eumsoft.securitypro.ui.components.SectionCard
import kr.eumsoft.securitypro.ui.components.StatusPill
import kr.eumsoft.securitypro.ui.theme.SafeGreen
import kr.eumsoft.securitypro.ui.theme.WarnAmber
import kr.eumsoft.securitypro.ui.util.formatDateTime
import kr.eumsoft.securitypro.ui.util.formatNumber
import kr.eumsoft.securitypro.ui.vm.DatabaseViewModel

@Composable
fun DatabaseScreen(viewModel: DatabaseViewModel = hiltViewModel()) {
    val state by viewModel.state.collectAsStateWithLifecycle()

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        item {
            Text(
                text = stringResource(R.string.db_title),
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.Bold,
            )
        }

        if (state.message == "NOT_CONFIGURED") {
            item {
                SectionCard {
                    Text(
                        text = stringResource(R.string.db_not_configured),
                        style = MaterialTheme.typography.bodyMedium,
                        color = WarnAmber,
                    )
                }
            }
        }

        item {
            VersionCard(
                title = stringResource(R.string.db_filter_db),
                version = state.filterVersion,
                onUpdate = { viewModel.update(UpdateTarget.AD_FILTER) },
                busy = state.updating,
            )
        }
        item {
            VersionCard(
                title = stringResource(R.string.db_hash_db),
                version = state.hashVersion,
                onUpdate = { viewModel.update(UpdateTarget.THREAT_HASH) },
                busy = state.updating,
            )
        }
        item {
            VersionCard(
                title = stringResource(R.string.db_yara_db),
                version = state.yaraVersion,
                onUpdate = { viewModel.update(UpdateTarget.YARA_RULES) },
                busy = state.updating,
            )
        }

        item {
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                Button(
                    onClick = { viewModel.update(null) },
                    enabled = !state.updating,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    if (state.updating) {
                        CircularProgressIndicator(
                            modifier = Modifier.height(18.dp),
                            strokeWidth = 2.dp,
                        )
                        Spacer(Modifier.height(4.dp))
                    }
                    Text(
                        text = if (state.updating) {
                            stringResource(R.string.db_updating)
                        } else {
                            stringResource(R.string.db_update_now)
                        }
                    )
                }
            }
        }

        item {
            Text(
                text = stringResource(R.string.db_history),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold,
            )
        }

        if (state.history.isEmpty()) {
            item {
                Text(
                    text = stringResource(R.string.db_history_empty),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        items(state.history, key = { it.id }) { entry ->
            HistoryRow(entry)
        }
    }
}

@Composable
private fun VersionCard(
    title: String,
    version: ThreatDbVersionEntity?,
    onUpdate: () -> Unit,
    busy: Boolean,
) {
    SectionCard(title = title) {
        if (version == null) {
            Text(
                text = stringResource(R.string.db_not_installed),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        } else {
            KeyValueRow(key = stringResource(R.string.version_label), value = version.versionLabel + " (${version.version})")
            KeyValueRow(key = stringResource(R.string.records_label), value = formatNumber(version.recordCount))
            KeyValueRow(key = stringResource(R.string.db_installed_at), value = formatDateTime(version.installedAt))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                StatusPill(
                    text = if (version.signatureStatus == "VERIFIED") {
                        stringResource(R.string.db_signature_verified)
                    } else {
                        stringResource(R.string.db_signature_unsigned)
                    },
                    color = if (version.signatureStatus == "VERIFIED") SafeGreen else WarnAmber,
                )
                if (version.isTestData) {
                    StatusPill(text = stringResource(R.string.test_data_badge), color = WarnAmber)
                }
            }
        }
        Spacer(Modifier.height(8.dp))
        OutlinedButton(onClick = onUpdate, enabled = !busy) {
            Text(stringResource(R.string.db_update_now))
        }
    }
}

@Composable
private fun HistoryRow(entry: UpdateHistoryEntity) {
    SectionCard {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = entry.targetType,
                    style = MaterialTheme.typography.titleMedium,
                )
                Text(
                    text = formatDateTime(entry.startedAt) + " · " + entry.status,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            StatusPill(
                text = statusText(entry.status),
                color = when (entry.status) {
                    "SUCCESS" -> SafeGreen
                    "RUNNING" -> MaterialTheme.colorScheme.primary
                    "UP_TO_DATE" -> SafeGreen
                    else -> WarnAmber
                },
            )
        }
        if (!entry.message.isNullOrBlank()) {
            Text(
                text = entry.message!!,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        if (entry.toVersion > 0) {
            Text(
                text = "v${entry.toVersion}",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        HorizontalDivider()
    }
}

@Composable
private fun statusText(status: String): String = when (status) {
    "SUCCESS" -> stringResource(R.string.db_status_success)
    "FAILED" -> stringResource(R.string.db_status_failed)
    "RUNNING" -> stringResource(R.string.db_status_running)
    "REJECTED_ROLLBACK" -> stringResource(R.string.db_status_rollback)
    "REJECTED_INTEGRITY" -> stringResource(R.string.db_status_integrity)
    "NOT_CONFIGURED" -> stringResource(R.string.db_status_not_configured)
    "UP_TO_DATE" -> stringResource(R.string.db_status_up_to_date)
    else -> stringResource(R.string.db_status_unknown)
}
