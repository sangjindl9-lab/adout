package kr.eumsoft.securitypro.worker

import android.content.Context
import androidx.hilt.work.HiltWorker
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.ExistingWorkPolicy
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import androidx.work.Constraints
import androidx.work.NetworkType
import dagger.assisted.Assisted
import dagger.assisted.AssistedInject
import dagger.hilt.android.qualifiers.ApplicationContext
import java.util.concurrent.TimeUnit
import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.coroutines.flow.first
import kr.eumsoft.securitypro.data.prefs.SettingsRepository

/**
 * 주기 작업 예약. 사용자가 끈 자동 검사는 예약하지 않는다.
 */
@Singleton
class WorkScheduler @Inject constructor(
    @ApplicationContext private val context: Context,
    private val settingsRepository: SettingsRepository,
) {

    fun ensurePeriodicWork() {
        val constraints = Constraints.Builder()
            .setRequiredNetworkType(NetworkType.CONNECTED)
            .build()

        val updateRequest = PeriodicWorkRequestBuilder<DatabaseUpdateWorker>(1, TimeUnit.DAYS)
            .setConstraints(constraints)
            .setInitialDelay(1, TimeUnit.HOURS)
            .build()
        runCatching {
            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                UPDATE_WORK,
                ExistingPeriodicWorkPolicy.KEEP,
                updateRequest,
            )
        }

        val scanRequest = PeriodicWorkRequestBuilder<AutoScanWorker>(7, TimeUnit.DAYS)
            .setConstraints(constraints)
            .build()
        runCatching {
            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                SCAN_WORK,
                ExistingPeriodicWorkPolicy.KEEP,
                scanRequest,
            )
        }
    }

    /** 수동 업데이트(즉시 실행). */
    fun requestUpdateNow() {
        val request = OneTimeWorkRequestBuilder<DatabaseUpdateWorker>()
            .setConstraints(
                Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build()
            )
            .build()
        runCatching {
            WorkManager.getInstance(context).enqueueUniqueWork(
                UPDATE_NOW,
                ExistingWorkPolicy.REPLACE,
                request,
            )
        }
    }

    fun requestScanNow() {
        val request = OneTimeWorkRequestBuilder<AutoScanWorker>()
            .setConstraints(
                Constraints.Builder().setRequiredNetworkType(NetworkType.NOT_REQUIRED).build()
            )
            .build()
        runCatching {
            WorkManager.getInstance(context).enqueueUniqueWork(
                SCAN_NOW,
                ExistingWorkPolicy.REPLACE,
                request,
            )
        }
    }

    suspend fun autoScanEnabled(): Boolean = settingsRepository.settings.let { flow ->
        flow.first().autoScan
    }

    companion object {
        const val UPDATE_WORK = "eum_periodic_update"
        const val SCAN_WORK = "eum_periodic_scan"
        const val UPDATE_NOW = "eum_update_now"
        const val SCAN_NOW = "eum_scan_now"
    }
}

/** 매일 1회 위협 DB/필터 업데이트(서명 검증 실패 시 기존 데이터 유지). */
@HiltWorker
class DatabaseUpdateWorker @AssistedInject constructor(
    @Assisted appContext: Context,
    @Assisted params: WorkerParameters,
    private val updateClient: kr.eumsoft.securitypro.data.updater.UpdateClient,
    private val settingsRepository: SettingsRepository,
) : CoroutineWorker(appContext, params) {

    override suspend fun doWork(): Result {
        val settings = settingsRepository.settings.first()
        if (!settings.autoUpdate && runAttemptCount == 0 && inputData.getBoolean("manual", false).not()) {
            // 자동 업데이트가 꺼져 있고 수동 요청도 아니면 아무것도 하지 않는다.
            return Result.success()
        }
        val outcomes = updateClient.updateAll()
        settingsRepository.markUpdateCheck(System.currentTimeMillis())
        val success = outcomes.count { it is kr.eumsoft.securitypro.data.updater.UpdateOutcome.Success }
        val failed = outcomes.count {
            it is kr.eumsoft.securitypro.data.updater.UpdateOutcome.Failed ||
                it is kr.eumsoft.securitypro.data.updater.UpdateOutcome.Rejected
        }
        return when {
            failed == 0 -> Result.success()
            success > 0 -> Result.success()
            runAttemptCount < 2 -> Result.retry()
            else -> Result.success()
        }
    }
}

/** 정기 악성코드 검사(설정에서 켠 경우에만 실제 실행). */
@HiltWorker
class AutoScanWorker @AssistedInject constructor(
    @Assisted appContext: Context,
    @Assisted params: WorkerParameters,
    private val scanManager: kr.eumsoft.securitypro.scanner.MalwareScanManager,
    private val settingsRepository: SettingsRepository,
) : CoroutineWorker(appContext, params) {

    override suspend fun doWork(): Result {
        val settings = settingsRepository.settings.first()
        if (!settings.autoScan) return Result.success()
        scanManager.runQuickScanNow()
        return Result.success()
    }
}
