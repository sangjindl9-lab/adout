package kr.eumsoft.securitypro.data.db

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import java.io.File
import kotlinx.coroutines.flow.first
import org.json.JSONArray
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * 스키마 1 → 2 마이그레이션 검증.
 *
 * v1 데이터베이스는 앱에 체크인된 exported schema(app/schemas/**/1.json)의 DDL 로 실제 생성하고,
 * Room 으로 v2 를 열어 (1) 마이그레이션이 엔티티 정의와 일치하는지(Room 검증),
 * (2) 기존 데이터가 보존되는지, (3) 새 컬럼이 사용 가능한지 확인한다.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class MigrationTest {

    private lateinit var context: Context

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        context.deleteDatabase(DB_NAME)
    }

    @After
    fun tearDown() {
        context.deleteDatabase(DB_NAME)
    }

    @Test
    fun `v1 에서 v2 로 데이터를 보존하며 마이그레이션한다`() = kotlinx.coroutines.runBlocking {
        createVersion1Database()

        val db = Room.databaseBuilder(context, AppDatabase::class.java, DB_NAME)
            .addMigrations(MIGRATION_1_2)
            .allowMainThreadQueries()
            .build()
        try {
            // 최초 접근 시 마이그레이션이 실행되고 Room 이 스키마를 검증한다.
            val sources = db.adFilterDao().sourcesOnce()
            assertEquals(1, sources.size)
            assertEquals("기존 필터", sources.first().name)
            assertEquals(42, sources.first().ruleCount)
            assertEquals(null, sources.first().etag)

            val history = db.updateHistoryDao().recent(5).first()
            assertEquals(1, history.size)
            assertEquals("AD_FILTER", history.first().targetType)
            assertEquals(3L, history.first().toVersion)
            assertEquals(null, history.first().httpStatus)

            // 새 컬럼에 값을 쓸 수 있다.
            db.adFilterDao().upsertSources(
                listOf(sources.first().copy(etag = "W/\"abc\""))
            )
            assertEquals("W/\"abc\"", db.adFilterDao().sourcesOnce().first().etag)
        } finally {
            db.close()
        }
    }

    @Test
    fun `v2 스키마에 16개 테이블이 모두 존재한다`() {
        val db = Room.databaseBuilder(context, AppDatabase::class.java, DB_NAME)
            .addMigrations(MIGRATION_1_2)
            .allowMainThreadQueries()
            .build()
        db.openHelper.writableDatabase
        val expected = listOf(
            "scan_sessions", "scan_results", "scan_findings", "installed_apps",
            "threat_hashes", "threat_rules", "threat_sources", "threat_db_versions",
            "ad_filter_rules", "ad_filter_sources", "blocked_dns_events",
            "allowed_domains", "blocked_domains", "vpn_sessions", "update_history",
            "security_settings",
        )
        val found = mutableSetOf<String>()
        db.openHelper.readableDatabase.query("SELECT name FROM sqlite_master WHERE type='table'")
            .use { cursor ->
                while (cursor.moveToNext()) found += cursor.getString(0)
            }
        db.close()
        expected.forEach { table -> assertTrue("테이블 없음: $table", found.contains(table)) }
        assertEquals(16, expected.count { found.contains(it) })
    }

    /** 체크인된 v1 스키마 JSON 의 DDL 로 실제 v1 DB 를 만든다. */
    private fun createVersion1Database() {
        val schema = schemaFile(1)
        val sql = extractCreateStatements(schema.readText())
        val path = context.getDatabasePath(DB_NAME)
        path.parentFile?.mkdirs()
        val db = SQLiteDatabase.openOrCreateDatabase(path, null)
        try {
            sql.forEach { statement -> db.execSQL(statement) }
            db.execSQL(
                """
                INSERT INTO ad_filter_sources
                  (name, url, license, category, enabled, priority, ruleCount, lastUpdatedAt,
                   lastUpdateStatus, isBuiltin, isTestData, updatedAt)
                VALUES ('기존 필터', 'https://example.invalid/list.txt', 'MIT', 'ADS', 1, 100, 42, 1000,
                        'SUCCESS', 1, 0, 1000)
                """.trimIndent()
            )
            db.execSQL(
                """
                INSERT INTO update_history
                  (targetType, fromVersion, toVersion, status, bytes, sha256, signatureOk,
                   startedAt, finishedAt, message)
                VALUES ('AD_FILTER', 0, 3, 'SUCCESS', 2048, NULL, 1, 1000, 2000, 'ok')
                """.trimIndent()
            )
            db.version = 1
        } finally {
            db.close()
        }
        assertTrue("v1 DB 가 생성되지 않았습니다.", path.exists())
    }

    private fun schemaFile(version: Int): File {
        val candidates = listOf(
            File("schemas/kr.eumsoft.securitypro.data.db.AppDatabase/$version.json"),
            File("app/schemas/kr.eumsoft.securitypro.data.db.AppDatabase/$version.json"),
        )
        return candidates.firstOrNull { it.isFile }
            ?: error("스키마 파일을 찾을 수 없습니다: ${candidates.map { it.absolutePath }}")
    }

    /** exported schema JSON 에서 테이블/인덱스 DDL 을 뽑는다. */
    private fun extractCreateStatements(json: String): List<String> {
        val root = org.json.JSONObject(json)
        val database = root.getJSONObject("database")
        val entities = database.getJSONArray("entities")
        val statements = ArrayList<String>()
        for (i in 0 until entities.length()) {
            val entity = entities.getJSONObject(i)
            val tableName = entity.getString("tableName")
            statements += entity.getString("createSql").replace("\${TABLE_NAME}", tableName)
            val indices = entity.optJSONArray("indices") ?: JSONArray()
            for (j in 0 until indices.length()) {
                statements += indices.getJSONObject(j).getString("createSql")
                    .replace("\${TABLE_NAME}", tableName)
            }
        }
        require(statements.size >= 16) { "DDL 문이 부족합니다: ${statements.size}" }
        return statements
    }

    private companion object {
        const val DB_NAME = "migration-test.db"
    }
}
