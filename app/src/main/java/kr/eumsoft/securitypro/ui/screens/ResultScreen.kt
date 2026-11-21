package kr.eumsoft.securitypro.ui.screens

import android.content.Intent
import android.net.Uri
import android.provider.Settings
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
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import kr.eumsoft.securitypro.R
import kr.eumsoft.securitypro.core.risk.RiskLevel
import kr.eumsoft.securitypro.data.db.ScanResultWithFindings
import kr.eumsoft.securitypro.data.db.entity.ScanFindingEntity
import kr.eumsoft.securitypro.ui.components.KeyValueRow
import kr.eumsoft.securitypro.ui.components.RiskBadge
import kr.eumsoft.securitypro.ui.components.SectionCard
import kr.eumsoft.securitypro.ui.components.localized
import kr.eumsoft.securitypro.ui.util.formatDateTime
import kr.eumsoft.securitypro.ui.vm.ResultViewModel

@Composable
fun ResultScreen(
    sessionId: Long,
    onBack: () -> Unit,
    viewModel: ResultViewModel = hiltViewModel(),
) {
    val detail by viewModel.detail.collectAsStateWithLifecycle()
    val context = LocalContext.current

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = stringResource(R.string.result_title),
                        style = MaterialTheme.typography.headlineSmall,
                        fontWeight = FontWeight.Bold,
                    )
                    Text(
                        text = detail?.session?.targetLabel ?: "#$sessionId",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                TextButton(onClick = onBack) { Text(stringResource(R.string.close)) }
            }
        }

        val session = detail?.session
        if (session == null) {
            item {
                Text(
                    text = stringResource(R.string.loading),
                    style = MaterialTheme.typography.bodyLarge,
                )
            }
        } else {
            item {
                SectionCard(title = stringResource(R.string.result_summary)) {
                    KeyValueRow(
                        key = stringResource(R.string.result_scanned_at),
                        value = formatDateTime(session.finishedAt ?: session.startedAt),
                    )
                    KeyValueRow(
                        key = stringResource(R.string.result_apps_count, session.scannedTargets),
                        value = "${session.scannedTargets}/${session.totalTargets}",
                    )
                    KeyValueRow(
                        key = stringResource(R.string.result_engines),
                        value = session.engines,
                    )
                    KeyValueRow(
                        key = stringResource(R.string.result_risk_danger),
                        value = session.dangerCount.toString(),
                    )
                    KeyValueRow(
                        key = stringResource(R.string.result_risk_warning),
                        value = session.warningCount.toString(),
                    )
                    if (!session.errorMessage.isNullOrBlank()) {
                        KeyValueRow(key = stringResource(R.string.result_unscanned), value = session.errorMessage!!)
                    }
                    Spacer(Modifier.height(8.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(onClick = { viewModel.rescan() }) {
                            Text(stringResource(R.string.result_rescan))
                        }
                    }
                }
            }

            val noisy = detail?.results.orEmpty()
                .sortedBy { result -> riskOrder(result.result.riskLevel) }
            items(noisy, key = { it.result.id }) { item ->
                ResultItem(
                    item = item,
                    onOpenAppInfo = { packageName ->
                        runCatching {
                            context.startActivity(
                                Intent(
                                    Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                                    Uri.parse("package:$packageName"),
                                ).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                            )
                        }
                    },
                    onUninstall = { packageName ->
                        runCatching {
                            context.startActivity(
                                Intent(Intent.ACTION_DELETE, Uri.parse("package:$packageName"))
                                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                            )
                        }
                    },
                    onReport = { packageName, level, evidence ->
                        runCatching {
                            val intent = Intent(Intent.ACTION_SENDTO).apply {
                                data = Uri.parse("mailto:${context.getString(R.string.support_email)}")
                                putExtra(
                                    Intent.EXTRA_SUBJECT,
                                    context.getString(R.string.result_report_subject),
                                )
                                putExtra(
                                    Intent.EXTRA_TEXT,
                                    context.getString(
                                        R.string.result_report_body,
                                        packageName ?: "-",
                                        level,
                                        evidence,
                                    ),
                                )
                            }
                            context.startActivity(intent)
                        }
                    },
                )
            }

            if ((detail?.results?.size ?: 0) == 0) {
                item {
                    Text(
                        text = stringResource(R.string.result_no_findings),
                        style = MaterialTheme.typography.bodyLarge,
                    )
                }
            }
        }
    }
}

private fun riskOrder(level: String): Int = when (level) {
    RiskLevel.DANGER.name -> 0
    RiskLevel.WARNING.name -> 1
    RiskLevel.UNABLE.name -> 2
    else -> 3
}

@Composable
private fun ResultItem(
    item: ScanResultWithFindings,
    onOpenAppInfo: (String) -> Unit,
    onUninstall: (String) -> Unit,
    onReport: (String?, String, String) -> Unit,
) {
    val result = item.result
    val level = runCatching { RiskLevel.valueOf(result.riskLevel) }.getOrDefault(RiskLevel.UNABLE)
    SectionCard {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = result.label ?: result.packageName ?: result.targetType,
                    style = MaterialTheme.typography.titleMedium,
                )
                Text(
                    text = result.packageName ?: result.filePath ?: "",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            RiskBadge(level = level)
        }
        Spacer(Modifier.height(8.dp))
        KeyValueRow(key = stringResource(R.string.result_score), value = result.riskScore.toString())
        if (!result.sha256.isNullOrBlank()) {
            KeyValueRow(key = "SHA-256", value = result.sha256!!.take(32) + "…")
        }
        if (!result.unscannedItems.isNullOrBlank()) {
            KeyValueRow(
                key = stringResource(R.string.result_unscanned),
                value = result.unscannedItems!!,
            )
        }
        if (item.findings.isNotEmpty()) {
            Spacer(Modifier.height(8.dp))
            Text(
                text = stringResource(R.string.result_found),
                style = MaterialTheme.typography.titleMedium,
            )
            item.findings.forEach { finding ->
                FindingRow(finding)
            }
        } else {
            Text(
                text = stringResource(R.string.result_no_findings),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Spacer(Modifier.height(10.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            val packageName = result.packageName
            if (!packageName.isNullOrBlank()) {
                OutlinedButton(onClick = { onOpenAppInfo(packageName) }) {
                    Text(stringResource(R.string.result_open_app_info))
                }
                OutlinedButton(onClick = { onUninstall(packageName) }) {
                    Text(stringResource(R.string.result_uninstall))
                }
                TextButton(onClick = {
                    onReport(
                        packageName,
                        level.name,
                        item.findings.joinToString("; ") { it.title },
                    )
                }) {
                    Text(stringResource(R.string.result_report))
                }
            }
        }
        HorizontalDivider()
    }
}

@Composable
private fun FindingRow(finding: ScanFindingEntity) {
    Column(modifier = Modifier.padding(vertical = 6.dp)) {
        Row {
            Text(
                text = localized(finding.title),
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier.weight(1f),
            )
            Text(
                text = finding.severity,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Text(
            text = finding.evidence,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        if (!finding.advice.isNullOrBlank()) {
            Text(
                text = stringResource(R.string.result_advice) + ": " + localized(finding.advice),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.primary,
            )
        }
        Text(
            text = "${finding.engine} · " + formatDateTime(finding.createdAt),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}
