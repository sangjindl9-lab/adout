package kr.eumsoft.securitypro.data.updater

import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kr.eumsoft.securitypro.core.crypto.Sha256
import kr.eumsoft.securitypro.data.db.AppDatabase
import kr.eumsoft.securitypro.data.db.entity.ThreatHashEntity
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class UpdateClientTest {

    private lateinit var db: AppDatabase
    private val keys = Ed25519TestKeys.generate()
    private val base = "https://updates.invalid/base"

    private class FakeFetcher : Fetcher {
        val responses = ConcurrentHashMap<String, Fetcher.Response>()
        val requests = mutableListOf<String>()

        override suspend fun get(url: String, maxBytes: Long, etag: String?): Fetcher.Response {
            requests += url
            return responses[url] ?: Fetcher.Response(404, ByteArray(0))
        }
    }

    @Before
    fun setUp() {
        db = Room.inMemoryDatabaseBuilder(
            ApplicationProvider.getApplicationContext(),
            AppDatabase::class.java,
        ).allowMainThreadQueries().build()
    }

    @After
    fun tearDown() {
        db.close()
    }

    private fun signedManifest(
        target: UpdateTarget,
        version: Long,
        payload: ByteArray,
        entryCount: Int,
        isTestData: Boolean = true,
    ): String {
        val payloadUrl = "$base/${target.pathSegment}/data-$version.json"
        val canonical = UpdateManifestCodec.canonicalBytes(
            target = target,
            version = version,
            versionLabel = "2026.11.$version",
            publishedAt = 1_800_000_000_000L,
            payloadUrl = payloadUrl,
            payloadSha256 = Sha256.of(payload),
            payloadSize = payload.size.toLong(),
            entryCount = entryCount,
            isTestData = isTestData,
        )
        val signature = Ed25519TestKeys.sign(keys, canonical)
        return "{\"manifest\":${String(canonical)},\"signature\":\"${Ed25519TestKeys.base64(signature)}\"}"
    }

    private fun client(fetcher: Fetcher, publicKey: String = keys.publicKeyHex): UpdateClient =
        UpdateClient(
            db = db,
            fetcher = fetcher,
            configuration = UpdateConfiguration(base, publicKey),
        )

    private fun hashPayload(vararg hashes: String): ByteArray =
        hashes.mapIndexed { index, sha ->
            """{"sha256":"$sha","threatName":"Test.Malware.$index","family":"TestFam","category":"malware","severity":"HIGH","confidence":90,"source":"unit-test"}"""
        }.joinToString(prefix = "[", postfix = "]").toByteArray()

    private fun sampleHash(seed: String): String = Sha256.of(seed)

    @Test
    fun `서명된 해시 업데이트를 적용하고 버전을 기록한다`() = runBlocking {
        val fetcher = FakeFetcher()
        val payload = hashPayload(sampleHash("a"), sampleHash("b"))
        val json = signedManifest(UpdateTarget.THREAT_HASH, 5, payload, entryCount = 2)
        fetcher.responses["$base/threat-hash/manifest.json"] = Fetcher.Response(200, json.toByteArray())
        fetcher.responses["$base/threat-hash/data-5.json"] = Fetcher.Response(200, payload)

        val outcome = client(fetcher).update(UpdateTarget.THREAT_HASH)
        assertTrue("결과: $outcome", outcome is UpdateOutcome.Success)
        outcome as UpdateOutcome.Success
        assertEquals(2, outcome.records)
        assertTrue(outcome.signatureVerified)

        assertEquals(2, db.threatDao().countHashesOnce())
        assertNotNull(db.threatDao().findHash(sampleHash("a")))
        val version = db.threatDao().dbVersion(UpdateTarget.THREAT_HASH.dbType)
        assertEquals(5L, version!!.version)
        assertEquals("VERIFIED", version.signatureStatus)
        assertTrue(version.isTestData)

        val history = db.updateHistoryDao().recent(10).first()
        assertEquals("SUCCESS", history.first().status)
        assertTrue(history.first().signatureOk)
    }

    @Test
    fun `페이로드가 변조되면 기존 데이터를 유지한다`() = runBlocking {
        val existing = ThreatHashEntity(
            sha256 = sampleHash("keep"),
            threatName = "Existing",
            category = "malware",
            severity = "HIGH",
            confidence = 80,
            source = "seed",
        )
        db.threatDao().replaceAllHashes(listOf(existing))

        val fetcher = FakeFetcher()
        val originalPayload = hashPayload(sampleHash("x"))
        val json = signedManifest(UpdateTarget.THREAT_HASH, 3, originalPayload, entryCount = 1)
        fetcher.responses["$base/threat-hash/manifest.json"] = Fetcher.Response(200, json.toByteArray())
        fetcher.responses["$base/threat-hash/data-3.json"] = Fetcher.Response(200, hashPayload(sampleHash("y")))

        val outcome = client(fetcher).update(UpdateTarget.THREAT_HASH)
        assertTrue("결과: $outcome", outcome is UpdateOutcome.Rejected)
        assertEquals(UpdateErrorCode.SHA256, (outcome as UpdateOutcome.Rejected).code)
        assertEquals(1, db.threatDao().countHashesOnce())
        assertNotNull(db.threatDao().findHash(sampleHash("keep")))
        assertEquals(null, db.threatDao().dbVersion(UpdateTarget.THREAT_HASH.dbType))
    }

    @Test
    fun `서명이 잘못되면 거부한다`() = runBlocking {
        val fetcher = FakeFetcher()
        val payload = hashPayload(sampleHash("z"))
        val json = signedManifest(UpdateTarget.THREAT_HASH, 4, payload, entryCount = 1)
        fetcher.responses["$base/threat-hash/manifest.json"] = Fetcher.Response(200, json.toByteArray())
        fetcher.responses["$base/threat-hash/data-4.json"] = Fetcher.Response(200, payload)

        val otherKeys = Ed25519TestKeys.generate(ByteArray(32) { (it * 5 + 1).toByte() })
        val outcome = client(fetcher, publicKey = otherKeys.publicKeyHex).update(UpdateTarget.THREAT_HASH)
        assertTrue("결과: $outcome", outcome is UpdateOutcome.Rejected)
        assertEquals(UpdateErrorCode.SIGNATURE, (outcome as UpdateOutcome.Rejected).code)
        assertEquals(0, db.threatDao().countHashesOnce())
    }

    @Test
    fun `다운그레이드 매니페스트를 거부한다`() = runBlocking {
        val fetcher = FakeFetcher()
        val payload5 = hashPayload(sampleHash("v5"))
        val json5 = signedManifest(UpdateTarget.THREAT_HASH, 5, payload5, entryCount = 1)
        fetcher.responses["$base/threat-hash/manifest.json"] = Fetcher.Response(200, json5.toByteArray())
        fetcher.responses["$base/threat-hash/data-5.json"] = Fetcher.Response(200, payload5)
        client(fetcher).update(UpdateTarget.THREAT_HASH)

        val payload4 = hashPayload(sampleHash("v4"))
        val json4 = signedManifest(UpdateTarget.THREAT_HASH, 4, payload4, entryCount = 1)
        fetcher.responses["$base/threat-hash/manifest.json"] = Fetcher.Response(200, json4.toByteArray())
        fetcher.responses["$base/threat-hash/data-4.json"] = Fetcher.Response(200, payload4)

        val outcome = client(fetcher).update(UpdateTarget.THREAT_HASH)
        assertTrue("결과: $outcome", outcome is UpdateOutcome.Rejected)
        assertEquals(UpdateErrorCode.ROLLBACK, (outcome as UpdateOutcome.Rejected).code)
        assertEquals(5L, db.threatDao().dbVersion(UpdateTarget.THREAT_HASH.dbType)!!.version)
        assertNotNull(db.threatDao().findHash(sampleHash("v5")))
    }

    @Test
    fun `YARA 규칙 업데이트를 적용한다`() = runBlocking {
        val fetcher = FakeFetcher()
        val payload = """
            {"engine":"YARA_SUBSET","rules":[
              {"name":"EUM_Test_Rule","category":"test","severity":"HIGH",
               "content":"rule EUM_Test_Rule { strings: ${'$'}a = \"malware\" condition: ${'$'}a }",
               "source":"unit-test","version":"1"}
            ]}
        """.trimIndent().toByteArray()
        val json = signedManifest(UpdateTarget.YARA_RULES, 2, payload, entryCount = 1)
        fetcher.responses["$base/yara-rules/manifest.json"] = Fetcher.Response(200, json.toByteArray())
        fetcher.responses["$base/yara-rules/data-2.json"] = Fetcher.Response(200, payload)

        val outcome = client(fetcher).update(UpdateTarget.YARA_RULES)
        assertTrue("결과: $outcome", outcome is UpdateOutcome.Success)
        val rules = db.threatDao().rulesForEngine("YARA_SUBSET")
        assertEquals(1, rules.size)
        assertEquals("EUM_Test_Rule", rules.first().ruleName)
    }

    @Test
    fun `필터 업데이트는 소스를 만들고 규칙을 넣는다`() = runBlocking {
        val fetcher = FakeFetcher()
        val payload = """
            {"source":"Unit Test Filter","category":"ADS","license":"MIT","rules":[
              "||ads.example.com^",
              "@@||safe.example.com^",
              "0.0.0.0 tracker.example.net"
            ]}
        """.trimIndent().toByteArray()
        val json = signedManifest(UpdateTarget.AD_FILTER, 9, payload, entryCount = 3)
        fetcher.responses["$base/ad-filter/manifest.json"] = Fetcher.Response(200, json.toByteArray())
        fetcher.responses["$base/ad-filter/data-9.json"] = Fetcher.Response(200, payload)

        val outcome = client(fetcher).update(UpdateTarget.AD_FILTER)
        assertTrue("결과: $outcome", outcome is UpdateOutcome.Success)
        val sources = db.adFilterDao().sourcesOnce()
        val source = sources.firstOrNull { it.name == "Unit Test Filter" }
        assertNotNull(source)
        assertEquals(3, source!!.ruleCount)
        assertEquals("SUCCESS", source.lastUpdateStatus)
        val rules = db.adFilterDao().activeRules()
        assertEquals(3, rules.size)
    }

    @Test
    fun `설정이 없으면 NOT_CONFIGURED 로 기록한다`() = runBlocking {
        val client = UpdateClient(db, FakeFetcher(), UpdateConfiguration("", ""))
        val outcome = client.update(UpdateTarget.THREAT_HASH)
        assertTrue(outcome is UpdateOutcome.NotConfigured)
        val history = db.updateHistoryDao().recent(5).first()
        assertEquals("NOT_CONFIGURED", history.first().status)
    }

    @Test
    fun `HTTP 오류는 실패로 기록하고 데이터를 건드리지 않는다`() = runBlocking {
        val fetcher = FakeFetcher()
        fetcher.responses["$base/threat-hash/manifest.json"] = Fetcher.Response(503, ByteArray(0))
        val outcome = client(fetcher).update(UpdateTarget.THREAT_HASH)
        assertTrue(outcome is UpdateOutcome.Failed)
        assertEquals(0, db.threatDao().countHashesOnce())
    }
}
