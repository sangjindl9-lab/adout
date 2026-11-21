package kr.eumsoft.securitypro

import android.app.Application
import androidx.hilt.work.HiltWorkerFactory
import androidx.work.Configuration
import dagger.hilt.android.HiltAndroidApp
import javax.inject.Inject
import kr.eumsoft.securitypro.worker.WorkScheduler

@HiltAndroidApp
class EumApplication : Application(), Configuration.Provider {

    @Inject
    lateinit var workerFactory: HiltWorkerFactory

    @Inject
    lateinit var workScheduler: WorkScheduler

    override val workManagerConfiguration: Configuration
        get() = Configuration.Builder()
            .setWorkerFactory(workerFactory)
            .setMinimumLoggingLevel(android.util.Log.INFO)
            .build()

    override fun onCreate() {
        super.onCreate()
        // 주기 작업(필터/위협 DB 업데이트, 자동 검사)을 예약한다. 이미 있으면 갱신만 한다.
        workScheduler.ensurePeriodicWork()
    }
}
