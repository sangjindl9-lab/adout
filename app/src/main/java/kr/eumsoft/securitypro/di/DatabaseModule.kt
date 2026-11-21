package kr.eumsoft.securitypro.di

import android.content.Context
import androidx.room.Room
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton
import kr.eumsoft.securitypro.data.db.AppDatabase
import kr.eumsoft.securitypro.data.db.dao.AdFilterDao
import kr.eumsoft.securitypro.data.db.dao.ScanDao
import kr.eumsoft.securitypro.data.db.dao.SettingsDao
import kr.eumsoft.securitypro.data.db.dao.ThreatDao
import kr.eumsoft.securitypro.data.db.dao.UpdateHistoryDao
import kr.eumsoft.securitypro.data.db.dao.VpnSessionDao

@Module
@InstallIn(SingletonComponent::class)
object DatabaseModule {

    @Provides
    @Singleton
    fun provideDatabase(@ApplicationContext context: Context): AppDatabase =
        Room.databaseBuilder(context, AppDatabase::class.java, AppDatabase.NAME)
            .addMigrations(*AppDatabase.MIGRATIONS)
            .setJournalMode(androidx.room.RoomDatabase.JournalMode.WRITE_AHEAD_LOGGING)
            .build()

    @Provides
    fun scanDao(db: AppDatabase): ScanDao = db.scanDao()

    @Provides
    fun threatDao(db: AppDatabase): ThreatDao = db.threatDao()

    @Provides
    fun adFilterDao(db: AppDatabase): AdFilterDao = db.adFilterDao()

    @Provides
    fun vpnSessionDao(db: AppDatabase): VpnSessionDao = db.vpnSessionDao()

    @Provides
    fun updateHistoryDao(db: AppDatabase): UpdateHistoryDao = db.updateHistoryDao()

    @Provides
    fun settingsDao(db: AppDatabase): SettingsDao = db.settingsDao()
}
