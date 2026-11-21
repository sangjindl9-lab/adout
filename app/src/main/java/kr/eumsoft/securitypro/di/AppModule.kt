package kr.eumsoft.securitypro.di

import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kr.eumsoft.securitypro.BuildConfig
import kr.eumsoft.securitypro.core.apk.ApkStaticAnalyzer
import kr.eumsoft.securitypro.core.pattern.PatternScanner
import kr.eumsoft.securitypro.data.db.AppDatabase
import kr.eumsoft.securitypro.data.updater.AppClock
import kr.eumsoft.securitypro.data.updater.Fetcher
import kr.eumsoft.securitypro.data.updater.HttpUrlConnectionFetcher
import kr.eumsoft.securitypro.data.updater.UpdateClient
import kr.eumsoft.securitypro.data.updater.UpdateConfiguration

@Module
@InstallIn(SingletonComponent::class)
object AppModule {

    @Provides
    @Singleton
    fun provideAppScope(): CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    @Provides
    @Singleton
    fun provideClock(): AppClock = AppClock()

    @Provides
    @Singleton
    fun provideFetcher(): Fetcher = HttpUrlConnectionFetcher()

    @Provides
    @Singleton
    fun provideUpdateConfiguration(): UpdateConfiguration = UpdateConfiguration(
        baseUrl = BuildConfig.UPDATE_BASE_URL,
        publicKeyHex = BuildConfig.UPDATE_PUBLIC_KEY,
    )

    @Provides
    @Singleton
    fun provideUpdateClient(
        db: AppDatabase,
        fetcher: Fetcher,
        configuration: UpdateConfiguration,
        clock: AppClock,
    ): UpdateClient = UpdateClient(db, fetcher, configuration, clock)

    @Provides
    @Singleton
    fun provideApkAnalyzer(): ApkStaticAnalyzer = ApkStaticAnalyzer()

    @Provides
    @Singleton
    fun providePatternScanner(): PatternScanner = PatternScanner()
}
