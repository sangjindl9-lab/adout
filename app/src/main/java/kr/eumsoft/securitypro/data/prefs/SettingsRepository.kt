package kr.eumsoft.securitypro.data.prefs

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.core.stringSetPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import kr.eumsoft.securitypro.core.dns.BlockResponseMode

val Context.eumSettingsDataStore: DataStore<Preferences> by preferencesDataStore(name = "eum_settings")

enum class ThemeMode { SYSTEM, LIGHT, DARK }

enum class DnsMode {
    /** 시스템 DNS(기본). VPN 은 로컬 DNS 로 응답하고 업스트림은 시스템 DNS 를 쓴다. */
    SYSTEM,

    /** DNS-over-HTTPS */
    DOH,

    /** DNS-over-TLS */
    DOT,
}

data class AppSettings(
    val adBlockEnabled: Boolean = true,
    val blockTracking: Boolean = true,
    val blockPhishing: Boolean = true,
    val blockMalware: Boolean = true,
    val autoUpdate: Boolean = true,
    val autoScan: Boolean = false,
    val notificationsEnabled: Boolean = true,
    val themeMode: ThemeMode = ThemeMode.SYSTEM,
    /** system, ko, en, ja, zh-CN, es */
    val language: String = "system",
    val dnsMode: DnsMode = DnsMode.SYSTEM,
    /** cloudflare, google, adguard, custom */
    val dnsProvider: String = "cloudflare",
    val customDnsName: String = "",
    val blockResponseMode: BlockResponseMode = BlockResponseMode.NXDOMAIN,
    val logRetentionDays: Int = 30,
    /** 일시 중지 종료 시각(0 또는 과거면 중지 아님) */
    val pauseUntil: Long = 0L,
    val excludedPackages: Set<String> = emptySet(),
    val lastQuickScanAt: Long = 0L,
    val lastUpdateCheckAt: Long = 0L,
    val seeded: Boolean = false,
) {
    fun isPaused(now: Long): Boolean = pauseUntil > now

    val categories: Set<String>
        get() = buildSet {
            add("ADS")
            if (blockTracking) add("TRACKING")
            if (blockPhishing) add("PHISHING")
            if (blockMalware) add("MALWARE")
            add("USER")
        }
}

@Singleton
class SettingsRepository @Inject constructor(
    @ApplicationContext private val context: Context,
) {

    private object Keys {
        val AD_BLOCK = booleanPreferencesKey("ad_block_enabled")
        val BLOCK_TRACKING = booleanPreferencesKey("block_tracking")
        val BLOCK_PHISHING = booleanPreferencesKey("block_phishing")
        val BLOCK_MALWARE = booleanPreferencesKey("block_malware")
        val AUTO_UPDATE = booleanPreferencesKey("auto_update")
        val AUTO_SCAN = booleanPreferencesKey("auto_scan")
        val NOTIFICATIONS = booleanPreferencesKey("notifications")
        val THEME = stringPreferencesKey("theme_mode")
        val LANGUAGE = stringPreferencesKey("language")
        val DNS_MODE = stringPreferencesKey("dns_mode")
        val DNS_PROVIDER = stringPreferencesKey("dns_provider")
        val CUSTOM_DNS = stringPreferencesKey("custom_dns")
        val BLOCK_MODE = stringPreferencesKey("block_response_mode")
        val RETENTION_DAYS = intPreferencesKey("log_retention_days")
        val PAUSE_UNTIL = longPreferencesKey("pause_until")
        val EXCLUDED = stringSetPreferencesKey("excluded_packages")
        val LAST_SCAN = longPreferencesKey("last_quick_scan_at")
        val LAST_UPDATE = longPreferencesKey("last_update_check_at")
        val SEEDED = booleanPreferencesKey("seeded_builtin_filters")
    }

    val settings: Flow<AppSettings> = context.eumSettingsDataStore.data.map { prefs ->
        AppSettings(
            adBlockEnabled = prefs[Keys.AD_BLOCK] ?: true,
            blockTracking = prefs[Keys.BLOCK_TRACKING] ?: true,
            blockPhishing = prefs[Keys.BLOCK_PHISHING] ?: true,
            blockMalware = prefs[Keys.BLOCK_MALWARE] ?: true,
            autoUpdate = prefs[Keys.AUTO_UPDATE] ?: true,
            autoScan = prefs[Keys.AUTO_SCAN] ?: false,
            notificationsEnabled = prefs[Keys.NOTIFICATIONS] ?: true,
            themeMode = runCatching { ThemeMode.valueOf(prefs[Keys.THEME] ?: "SYSTEM") }
                .getOrDefault(ThemeMode.SYSTEM),
            language = prefs[Keys.LANGUAGE] ?: "system",
            dnsMode = runCatching { DnsMode.valueOf(prefs[Keys.DNS_MODE] ?: "SYSTEM") }
                .getOrDefault(DnsMode.SYSTEM),
            dnsProvider = prefs[Keys.DNS_PROVIDER] ?: "cloudflare",
            customDnsName = prefs[Keys.CUSTOM_DNS] ?: "",
            blockResponseMode = runCatching {
                BlockResponseMode.valueOf(prefs[Keys.BLOCK_MODE] ?: "NXDOMAIN")
            }.getOrDefault(BlockResponseMode.NXDOMAIN),
            logRetentionDays = prefs[Keys.RETENTION_DAYS] ?: 30,
            pauseUntil = prefs[Keys.PAUSE_UNTIL] ?: 0L,
            excludedPackages = prefs[Keys.EXCLUDED] ?: emptySet(),
            lastQuickScanAt = prefs[Keys.LAST_SCAN] ?: 0L,
            lastUpdateCheckAt = prefs[Keys.LAST_UPDATE] ?: 0L,
            seeded = prefs[Keys.SEEDED] ?: false,
        )
    }

    suspend fun setAdBlockEnabled(value: Boolean) = put { it[Keys.AD_BLOCK] = value }

    suspend fun setBlockTracking(value: Boolean) = put { it[Keys.BLOCK_TRACKING] = value }

    suspend fun setBlockPhishing(value: Boolean) = put { it[Keys.BLOCK_PHISHING] = value }

    suspend fun setBlockMalware(value: Boolean) = put { it[Keys.BLOCK_MALWARE] = value }

    suspend fun setAutoUpdate(value: Boolean) = put { it[Keys.AUTO_UPDATE] = value }

    suspend fun setAutoScan(value: Boolean) = put { it[Keys.AUTO_SCAN] = value }

    suspend fun setNotifications(value: Boolean) = put { it[Keys.NOTIFICATIONS] = value }

    suspend fun setThemeMode(value: ThemeMode) = put { it[Keys.THEME] = value.name }

    suspend fun setLanguage(value: String) = put { it[Keys.LANGUAGE] = value }

    suspend fun setDnsMode(value: DnsMode) = put { it[Keys.DNS_MODE] = value.name }

    suspend fun setDnsProvider(value: String) = put { it[Keys.DNS_PROVIDER] = value }

    suspend fun setCustomDnsName(value: String) = put { it[Keys.CUSTOM_DNS] = value }

    suspend fun setBlockResponseMode(value: BlockResponseMode) = put { it[Keys.BLOCK_MODE] = value.name }

    suspend fun setLogRetentionDays(value: Int) = put { it[Keys.RETENTION_DAYS] = value.coerceIn(1, 365) }

    suspend fun pauseFor(now: Long, minutes: Int) =
        put { it[Keys.PAUSE_UNTIL] = now + minutes * 60_000L }

    suspend fun resume() = put { it[Keys.PAUSE_UNTIL] = 0L }

    suspend fun setExcludedPackages(packages: Set<String>) = put { it[Keys.EXCLUDED] = packages }

    suspend fun markQuickScan(now: Long) = put { it[Keys.LAST_SCAN] = now }

    suspend fun markUpdateCheck(now: Long) = put { it[Keys.LAST_UPDATE] = now }

    suspend fun markSeeded() = put { it[Keys.SEEDED] = true }

    private suspend fun put(block: (androidx.datastore.preferences.core.MutablePreferences) -> Unit) {
        context.eumSettingsDataStore.edit { prefs -> block(prefs) }
    }
}
