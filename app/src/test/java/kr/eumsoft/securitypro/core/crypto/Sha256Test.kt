package kr.eumsoft.securitypro.core.crypto

import java.io.ByteArrayInputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class Sha256Test {

    @Test
    fun `표준 테스트 벡터와 일치한다`() {
        assertEquals(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            Sha256.of(ByteArray(0)),
        )
        assertEquals(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            Sha256.of("abc"),
        )
        assertEquals(
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
            Sha256.of("hello"),
        )
        assertEquals(Sha256.EMPTY_SHA256, Sha256.of(""))
        assertEquals("00ff", Sha256.hex(byteArrayOf(0, 0xFF.toByte())))
    }

    @Test
    fun `스트리밍 해시가 일괄 해시와 같다`() {
        val data = ByteArray(300_000) { (it % 251).toByte() }
        val streamed = Sha256.ofStream(ByteArrayInputStream(data))
        assertEquals(Sha256.of(data), streamed)
    }

    @Test
    fun `크기 한도를 넘으면 null`() {
        val data = ByteArray(2048) { 1 }
        assertNull(Sha256.ofStream(ByteArrayInputStream(data), maxBytes = 1024))
        assertEquals(Sha256.of(data), Sha256.ofStream(ByteArrayInputStream(data), maxBytes = 4096))
    }

    @Test
    fun `해시 문자열 형식 검증`() {
        assertTrue(Sha256.isValidHex("a".repeat(64)))
        assertFalse(Sha256.isValidHex("A".repeat(64)))
        assertFalse(Sha256.isValidHex("a".repeat(63)))
        assertFalse(Sha256.isValidHex("z".repeat(64)))
    }

    @Test
    fun `파일 해시와 접근 실패 처리`() {
        val file = java.io.File.createTempFile("sha", ".bin")
        try {
            file.writeBytes("eum-security-pro".toByteArray())
            assertEquals(Sha256.of("eum-security-pro"), Sha256.ofFile(file))
        } finally {
            file.delete()
        }
        assertNull(Sha256.ofFile(java.io.File("/nonexistent/eum-test-file")))
    }
}
