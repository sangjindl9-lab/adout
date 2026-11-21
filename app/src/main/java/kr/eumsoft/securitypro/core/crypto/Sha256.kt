package kr.eumsoft.securitypro.core.crypto

import java.io.File
import java.io.InputStream
import java.security.MessageDigest

/** SHA-256 계산 유틸. 대용량 파일도 스트리밍으로 처리한다. */
object Sha256 {

    const val EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    fun of(bytes: ByteArray): String = hex(MessageDigest.getInstance("SHA-256").digest(bytes))

    fun of(text: String): String = of(text.toByteArray(Charsets.UTF_8))

    fun ofStream(input: InputStream, maxBytes: Long = Long.MAX_VALUE): String? {
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(64 * 1024)
        var total = 0L
        while (true) {
            val read = try {
                input.read(buffer)
            } catch (_: Exception) {
                return null
            }
            if (read <= 0) break
            total += read
            if (total > maxBytes) return null
            digest.update(buffer, 0, read)
        }
        return hex(digest.digest())
    }

    fun ofFile(file: File, maxBytes: Long = 512L * 1024 * 1024): String? {
        if (!file.isFile || !file.canRead()) return null
        if (file.length() > maxBytes) return null
        return try {
            file.inputStream().use { ofStream(it, maxBytes) }
        } catch (_: Exception) {
            null
        }
    }

    fun hex(bytes: ByteArray): String {
        val sb = StringBuilder(bytes.size * 2)
        bytes.forEach { b ->
            val v = b.toInt() and 0xFF
            sb.append(HEX[v ushr 4])
            sb.append(HEX[v and 0x0F])
        }
        return sb.toString()
    }

    private val HEX = "0123456789abcdef".toCharArray()

    /** 해시 문자열 형식 검증(64자 소문자 hex). */
    fun isValidHex(value: String): Boolean =
        value.length == 64 && value.all { it in '0'..'9' || it in 'a'..'f' }
}
