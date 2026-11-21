package kr.eumsoft.securitypro.core.yara

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class YaraEngineTest {

    @Test
    fun `내장 규칙이 모두 컴파일된다`() {
        val result = BuiltInRules.compiledRules()
        assertEquals("컴파일 오류: ${result.errors}", 0, result.errors.size)
        assertEquals(10, result.rules.size)
    }

    @Test
    fun `문자열 규칙이 일치하면 매치된다`() {
        val rule = BuiltInRules.compiledRules().rules.first { it.name == "EUM_Dynamic_Code_Loading" }
        val data = ("Ldalvik/system/DexClassLoader; hello " +
            "Ldalvik/system/InMemoryDexClassLoader;").toByteArray()
        val match = YaraEngine.match(rule, data)
        assertNotNull(match)
        assertEquals(2, match!!.matchedStrings.size)
    }

    @Test
    fun `일치하지 않으면 매치되지 않는다`() {
        val rule = BuiltInRules.compiledRules().rules.first { it.name == "EUM_Dynamic_Code_Loading" }
        val data = "com/example/Normal;".toByteArray()
        assertNull(YaraEngine.match(rule, data))
    }

    @Test
    fun `hex 와일드카드 규칙`() {
        val compiled = YaraEngine.compile(
            """
            rule HexTest {
                strings:
                    ${'$'}mz = { 4D 5A ?? 00 }
                condition:
                    ${'$'}mz
            }
            """.trimIndent(),
        )
        assertEquals(0, compiled.errors.size)
        val rule = compiled.rules.first()
        assertNotNull(YaraEngine.match(rule, byteArrayOf(0x4D, 0x5A, 0x11, 0x00, 0x01)))
        assertNull(YaraEngine.match(rule, byteArrayOf(0x4D, 0x5A, 0x11, 0x01)))
    }

    @Test
    fun `조건식 and or not 과 N of them`() {
        val compiled = YaraEngine.compile(
            """
            rule ConditionTest {
                strings:
                    ${'$'}a = "alpha" ascii
                    ${'$'}b = "beta" ascii
                    ${'$'}c = "gamma" ascii
                condition:
                    2 of them
            }
            """.trimIndent(),
        )
        val rule = compiled.rules.first()
        assertNull(YaraEngine.match(rule, "alpha only".toByteArray()))
        assertNotNull(YaraEngine.match(rule, "alpha and beta".toByteArray()))

        val andRule = YaraEngine.compile(
            """
            rule AndTest {
                strings:
                    ${'$'}a = "alpha"
                    ${'$'}b = "beta"
                condition:
                    ${'$'}a and not ${'$'}b
            }
            """.trimIndent(),
        ).rules.first()
        assertNotNull(YaraEngine.match(andRule, "alpha".toByteArray()))
        assertNull(YaraEngine.match(andRule, "alpha beta".toByteArray()))
    }

    @Test
    fun `wide 문자열 매칭`() {
        val compiled = YaraEngine.compile(
            """
            rule WideTest {
                strings:
                    ${'$'}w = "evil" wide
                condition:
                    ${'$'}w
            }
            """.trimIndent(),
        )
        val rule = compiled.rules.first()
        val wideBytes = byteArrayOf('e'.code.toByte(), 0, 'v'.code.toByte(), 0, 'i'.code.toByte(), 0, 'l'.code.toByte(), 0)
        assertNotNull(YaraEngine.match(rule, wideBytes))
    }

    @Test
    fun `지원하지 않는 문법은 오류로 보고한다`() {
        val compiled = YaraEngine.compile(
            """
            rule RegexRule {
                strings:
                    ${'$'}r = /abc.*/
                condition:
                    ${'$'}r
            }
            """.trimIndent(),
        )
        assertEquals(1, compiled.errors.size)
        assertTrue(compiled.errors[0].reason.contains("정규식"))
        assertTrue(compiled.rules.isEmpty())
    }

    @Test
    fun `대소문자 무시 매칭`() {
        val compiled = YaraEngine.compile(
            """
            rule NoCaseTest {
                strings:
                    ${'$'}a = "payload" nocase
                condition:
                    ${'$'}a
            }
            """.trimIndent(),
        )
        val rule = compiled.rules.first()
        assertNotNull(YaraEngine.match(rule, "PAYLOAD".toByteArray()))
    }

    @Test
    fun `대용량 버퍼에서도 성능 한도 내에서 동작한다`() {
        val rule = BuiltInRules.compiledRules().rules.first { it.name == "EUM_Shell_Execution" }
        val data = ByteArray(2 * 1024 * 1024)
        val needle = "/system/bin/sh".toByteArray()
        needle.copyInto(data, 1_500_000)
        "su -c".toByteArray().copyInto(data, 1_000_000)
        val start = System.nanoTime()
        val match = YaraEngine.match(rule, data)
        val elapsedMs = (System.nanoTime() - start) / 1_000_000
        assertNotNull(match)
        assertTrue("검색 시간이 너무 깁니다: ${elapsedMs}ms", elapsedMs < 5_000)
    }
}
