package kr.eumsoft.securitypro.ui.screens

import android.net.Uri
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
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
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
import kr.eumsoft.securitypro.data.db.entity.ScanSessionEntity
import kr.eumsoft.securitypro.ui.components.SectionCard
import kr.eumsoft.securitypro.ui.components.StatTile
import kr.eumsoft.securitypro.ui.components.localized
import kr.eumsoft.securitypro.ui.theme.DangerRed
import kr.eumsoft.securitypro.ui.theme.SafeGreen
import kr.eumsoft.securitypro.ui.theme.WarnAmber
import kr.eumsoft.securitypro.ui.util.formatDateTime
import kr.eumsoft.securitypro.ui.util.formatNumber
import kr.eumsoft.securitypro.ui.vm.ScanViewModel

@Composable
fun ScanScreen(
    onOpenResult: (Long) -> Unit,
    viewModel: ScanViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val apkPicker = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        if (uri != null) viewModel.startApk(uri)
    }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        item {
            Text(
                text = stringResource(R.string.scan_title),
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.Bold,
            )
        }

        if (state.scan.running) {
            item {
                SectionCard(title = stringResource(R.string.scan_progress)) {
                    LinearProgressIndicator(
                        progress = { state.scan.progress },
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(10.dp)
                            .semantics { contentDescription = "scan-progress" },
                    )
                    Spacer(Modifier.height(8.dp))
                    Text(
                        text = stringResource(
                            R.string.scan_target_count,
                            state.scan.total,
                        ) + " · " + state.scan.scanned + "/" + state.scan.total,
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Text(
                        text = stringResource(R.string.scan_current) + ": " + state.scan.currentTarget,
                        style = MaterialTheme.typography.bodyLarge,
                    )
                    Spacer(Modifier.height(8.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                        StatTile(
                            label = stringResource(R.string.result_risk_danger),
                            value = formatNumber(state.scan.dangers),
                            tint = if (state.scan.dangers > 0) DangerRed else SafeGreen,
                            modifier = Modifier.weight(1f),
                        )
                        StatTile(
                            label = stringResource(R.string.result_risk_warning),
                            value = formatNumber(state.scan.warnings),
                            tint = if (state.scan.warnings > 0) WarnAmber else SafeGreen,
                            modifier = Modifier.weight(1f),
                        )
                    }
                    Spacer(Modifier.height(10.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                        OutlinedButton(onClick = { viewModel.cancel() }) {
                            Text(stringResource(R.string.scan_stop))
                        }
                        Button(onClick = { onOpenResult(state.scan.sessionId) }) {
                            Text(stringResource(R.string.scan_results))
                        }
                    }
                }
            }
        } else {
            item {
                SectionCard(title = stringResource(R.string.scan_quick)) {
                    Text(
                        text = stringResource(R.string.scan_quick_desc),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Spacer(Modifier.height(10.dp))
                    Button(
                        onClick = { viewModel.startQuick() },
                        modifier = Modifier.fillMaxWidth().height(56.dp),
                    ) {
                        Icon(Icons.Filled.PlayArrow, contentDescription = null)
                        Spacer(Modifier.size(8.dp))
                        Text(stringResource(R.string.scan_quick))
                    }
                }
            }

            item {
                SectionCard(title = stringResource(R.string.scan_installed)) {
                    Text(
                        text = stringResource(R.string.scan_installed_desc),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Spacer(Modifier.height(10.dp))
                    OutlinedButton(
                        onClick = { viewModel.startInstalled() },
                        modifier = Modifier.fillMaxWidth().height(56.dp),
                    ) {
                        Icon(Icons.Filled.Search, contentDescription = null)
                        Spacer(Modifier.size(8.dp))
                        Text(stringResource(R.string.scan_installed))
                    }
                }
            }

            item {
                SectionCard(title = stringResource(R.string.scan_apk)) {
                    Text(
                        text = stringResource(R.string.scan_apk_desc),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Spacer(Modifier.height(10.dp))
                    OutlinedButton(
                        onClick = { apkPicker.launch(arrayOf("application/vnd.android.package-archive", "*/*")) },
                        modifier = Modifier.fillMaxWidth().height(56.dp),
                    ) {
                        Text(stringResource(R.string.scan_apk))
                    }
                    Spacer(Modifier.height(8.dp))
                    Text(
                        text = stringResource(R.string.scan_permission_note),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }

        item {
            Text(
                text = stringResource(R.string.scan_history),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold,
            )
        }

        if (state.sessions.isEmpty()) {
            item {
                Text(
                    text = stringResource(R.string.scan_empty_history),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        } else {
            items(state.sessions, key = { it.id }) { session ->
                SessionRow(session = session, onClick = { onOpenResult(session.id) })
            }
        }
    }
}

@Composable
private fun SessionRow(session: ScanSessionEntity, onClick: () -> Unit) {
    SectionCard(modifier = Modifier.clickable(onClick = onClick)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = session.targetLabel ?: session.type,
                    style = MaterialTheme.typography.titleMedium,
                )
                Text(
                    text = formatDateTime(session.finishedAt ?: session.startedAt) +
                        " · " + localized(session.typeLabelKey()),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Text(
                text = session.scannedTargets.toString(),
                style = MaterialTheme.typography.titleMedium,
            )
        }
        Spacer(Modifier.height(6.dp))
        Text(
            text = "위험 ${session.dangerCount} · 주의 ${session.warningCount}",
            style = MaterialTheme.typography.bodyMedium,
            color = if (session.dangerCount > 0) DangerRed else MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
    HorizontalDivider()
}

private fun ScanSessionEntity.typeLabelKey(): String = when (type) {
    "QUICK" -> "scan_quick"
    "INSTALLED_APPS" -> "scan_installed"
    "APK_FILE" -> "scan_apk"
    else -> "scan_title"
}
