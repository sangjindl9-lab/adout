package kr.eumsoft.securitypro.data.db

import androidx.room.Database
import androidx.room.RoomDatabase
import kr.eumsoft.securitypro.data.db.dao.AdFilterDao
import kr.eumsoft.securitypro.data.db.dao.ScanDao
import kr.eumsoft.securitypro.data.db.dao.SettingsDao
import kr.eumsoft.securitypro.data.db.dao.ThreatDao
import kr.eumsoft.securitypro.data.db.dao.UpdateHistoryDao
import kr.eumsoft.securitypro.data.db.dao.VpnSessionDao
import kr.eumsoft.securitypro.data.db.entity.AdFilterRuleEntity
import kr.eumsoft.securitypro.data.db.entity.AdFilterSourceEntity
import kr.eumsoft.securitypro.data.db.entity.AllowedDomainEntity
import kr.eumsoft.securitypro.data.db.entity.BlockedDnsEventEntity
import kr.eumsoft.securitypro.data.db.entity.BlockedDomainEntity
import kr.eumsoft.securitypro.data.db.entity.InstalledAppEntity
import kr.eumsoft.securitypro.data.db.entity.ScanFindingEntity
import kr.eumsoft.securitypro.data.db.entity.ScanResultEntity
import kr.eumsoft.securitypro.data.db.entity.ScanSessionEntity
import kr.eumsoft.securitypro.data.db.entity.SecuritySettingEntity
import kr.eumsoft.securitypro.data.db.entity.ThreatDbVersionEntity
import kr.eumsoft.securitypro.data.db.entity.ThreatHashEntity
import kr.eumsoft.securitypro.data.db.entity.ThreatRuleEntity
import kr.eumsoft.securitypro.data.db.entity.ThreatSourceEntity
import kr.eumsoft.securitypro.data.db.entity.UpdateHistoryEntity
import kr.eumsoft.securitypro.data.db.entity.VpnSessionEntity

/**
 * EUM SECURITY PRO 로컬 데이터베이스(16개 테이블).
 */
@Database(
    entities = [
        ScanSessionEntity::class,
        ScanResultEntity::class,
        ScanFindingEntity::class,
        InstalledAppEntity::class,
        ThreatHashEntity::class,
        ThreatRuleEntity::class,
        ThreatSourceEntity::class,
        ThreatDbVersionEntity::class,
        AdFilterRuleEntity::class,
        AdFilterSourceEntity::class,
        BlockedDnsEventEntity::class,
        AllowedDomainEntity::class,
        BlockedDomainEntity::class,
        VpnSessionEntity::class,
        UpdateHistoryEntity::class,
        SecuritySettingEntity::class,
    ],
    version = 2,
    exportSchema = true,
)
abstract class AppDatabase : RoomDatabase() {
    abstract fun scanDao(): ScanDao
    abstract fun threatDao(): ThreatDao
    abstract fun adFilterDao(): AdFilterDao
    abstract fun vpnSessionDao(): VpnSessionDao
    abstract fun updateHistoryDao(): UpdateHistoryDao
    abstract fun settingsDao(): SettingsDao

    companion object {
        const val NAME = "eum_security_pro.db"

        /** 실제 기기/테스트에서 사용할 마이그레이션 목록. */
        val MIGRATIONS = ALL_MIGRATIONS
    }
}
