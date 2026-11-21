package kr.eumsoft.securitypro.core.apk

import java.io.File
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * APK 서명 인증서를 읽어 SHA-256 지문을 계산한다.
 *
 * 1) APK Signature Scheme v2/v3 의 APK Signing Block 에서 인증서를 직접 파싱한다.
 * 2) 없으면 v1(JAR) 서명의 PKCS#7 인증서를 읽는다.
 *
 * Android 의 PackageManager 를 쓰지 않으므로 파일 단위 분석과 단위 테스트에서 동일하게 동작한다.
 */
object ApkSignatureReader {

    private const val APK_SIG_BLOCK_MAGIC = "APK Sig Block 42"
    private const val V2_BLOCK_ID = 0x7109871aL
    private const val V3_BLOCK_ID = 0xf05368c0L
    private const val V31_BLOCK_ID = 0x1b93ad61L

    data class Result(
        val certSha256: String?,
        val scheme: String?,
        val signerCount: Int,
        val error: String? = null,
    )

    fun read(file: File): Result {
        val v2 = try {
            readSigningBlock(file)
        } catch (e: Exception) {
            null
        }
        if (v2 != null && v2.certSha256 != null) return v2
        val v1 = try {
            readV1(file)
        } catch (_: Exception) {
            null
        }
        if (v1 != null && v1.certSha256 != null) return v1
        return v2 ?: v1 ?: Result(null, null, 0, "서명 정보를 찾지 못했습니다.")
    }

    /** v2/v3 APK Signing Block 파싱. */
    fun readSigningBlock(file: File): Result? {
        val length = file.length()
        if (length < 32) return null
        val tailSize = minOf(length, 128L * 1024L).toInt()
        val tailStart = length - tailSize
        val tail = ByteArray(tailSize)
        java.io.RandomAccessFile(file, "r").use { raf ->
            raf.seek(tailStart)
            raf.readFully(tail)
        }
        // EOCD 찾기
        var eocd = -1
        for (i in tail.size - 22 downTo 0) {
            if (tail[i].toInt() == 0x50 && tail[i + 1].toInt() == 0x4b &&
                tail[i + 2].toInt() == 0x05 && tail[i + 3].toInt() == 0x06
            ) {
                eocd = i
                break
            }
        }
        if (eocd < 0) return null
        val centralDirOffset = leU32(tail, eocd + 16).toLong()
        if (centralDirOffset < 24 || centralDirOffset > length - 24) return null

        val magicBytes = APK_SIG_BLOCK_MAGIC.toByteArray(Charsets.US_ASCII)
        val headerSize = 24
        val startInFile = (centralDirOffset - headerSize).coerceAtLeast(0)
        val header = ByteArray(headerSize)
        java.io.RandomAccessFile(file, "r").use { raf ->
            raf.seek(startInFile)
            raf.readFully(header)
        }
        for (i in magicBytes.indices) {
            if (header[8 + i] != magicBytes[i]) return null
        }
        val blockSizeInFooter = leU64(header, 0)
        if (blockSizeInFooter < 24 || blockSizeInFooter > centralDirOffset) return null
        val totalBlockSize = blockSizeInFooter + 8
        val blockStart = centralDirOffset - totalBlockSize
        if (blockStart < 0) return null
        val leadingSize = ByteArray(8)
        java.io.RandomAccessFile(file, "r").use { raf ->
            raf.seek(blockStart)
            raf.readFully(leadingSize)
        }
        if (leU64(leadingSize, 0) != blockSizeInFooter) return null
        val block = ByteArray(totalBlockSize.toInt())
        java.io.RandomAccessFile(file, "r").use { raf ->
            raf.seek(blockStart)
            raf.readFully(block)
        }

        var offset = 8L // 첫 사이즈 필드
        val pairsEnd = totalBlockSize - 24
        var v2Value: ByteArray? = null
        var v3Value: ByteArray? = null
        while (offset + 12 <= pairsEnd) {
            val pairLength = leU64(block, offset.toInt())
            if (pairLength < 4 || offset + 8 + pairLength > totalBlockSize) break
            val id = leU32(block, (offset + 8).toInt()).toLong()
            val valueStart = (offset + 12).toInt()
            val valueLength = (pairLength - 4).toInt()
            if (valueLength > 0 && valueStart + valueLength <= block.size) {
                val value = block.copyOfRange(valueStart, valueStart + valueLength)
                when (id) {
                    V2_BLOCK_ID -> v2Value = value
                    V3_BLOCK_ID -> if (v3Value == null) v3Value = value
                    V31_BLOCK_ID -> if (v3Value == null) v3Value = value
                }
            }
            offset += 8 + pairLength
        }

        v3Value?.let { value ->
            parseScheme(value, v3 = true)?.let { return it }
        }
        v2Value?.let { value ->
            parseScheme(value, v3 = false)?.let { return it }
        }
        return null
    }

    /** scheme 값에서 첫 인증서의 SHA-256. */
    private fun parseScheme(value: ByteArray, v3: Boolean): Result? {
        var offset = 0
        // signers: length-prefixed sequence of length-prefixed signers
        val signersLength = readU32(value, offset) ?: return null
        offset += 4
        val signersEnd = minOf(value.size, offset + signersLength)
        var signerCount = 0
        var firstCert: ByteArray? = null
        while (offset + 4 <= signersEnd) {
            val signerLength = readU32(value, offset) ?: break
            offset += 4
            val signerEnd = minOf(signersEnd, offset + signerLength)
            val signerBytes = value.copyOfRange(offset, signerEnd)
            signerCount++
            if (firstCert == null) {
                firstCert = extractFirstCert(signerBytes, v3)
            }
            offset = signerEnd
        }
        val cert = firstCert ?: return null
        return Result(sha256Hex(cert), if (v3) "v3" else "v2", signerCount)
    }

    private fun extractFirstCert(signer: ByteArray, v3: Boolean): ByteArray? {
        var offset = 0
        val signedDataLength = readU32(signer, offset) ?: return null
        offset += 4
        val signedDataEnd = minOf(signer.size, offset + signedDataLength)
        val signedData = signer.copyOfRange(offset, signedDataEnd)
        // signed data: digests(seq), certificates(seq), [v3: minSdk, maxSdk], attributes
        var sdOffset = 0
        val digestsLength = readU32(signedData, sdOffset) ?: return null
        sdOffset += 4 + digestsLength
        if (sdOffset + 4 > signedData.size) return null
        val certsLength = readU32(signedData, sdOffset) ?: return null
        sdOffset += 4
        val certsEnd = minOf(signedData.size, sdOffset + certsLength)
        if (sdOffset + 4 > certsEnd) return null
        val firstCertLength = readU32(signedData, sdOffset) ?: return null
        sdOffset += 4
        if (sdOffset + firstCertLength > certsEnd) return null
        return signedData.copyOfRange(sdOffset, sdOffset + firstCertLength)
    }

    /** v1(JAR) 서명: META-INF 의 RSA/DSA/EC 서명 블록(PKCS#7)에서 인증서를 읽는다. */
    fun readV1(file: File): Result? {
        java.util.zip.ZipFile(file).use { zip ->
            val candidate = zip.entries().asSequence()
                .filter { !it.isDirectory && it.name.startsWith("META-INF/") }
                .firstOrNull {
                    val name = it.name.uppercase()
                    name.endsWith(".RSA") || name.endsWith(".DSA") || name.endsWith(".EC")
                } ?: return null
            val bytes = zip.getInputStream(candidate).use { it.readBytes() }
            val factory = CertificateFactory.getInstance("X.509")
            val certs = factory.generateCertificates(bytes.inputStream())
                .filterIsInstance<X509Certificate>()
            val first = certs.firstOrNull() ?: return null
            return Result(sha256Hex(first.encoded), "v1", certs.size)
        }
    }

    fun sha256Hex(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    private fun readU32(bytes: ByteArray, offset: Int): Int? {
        if (offset + 4 > bytes.size) return null
        return (leU32(bytes, offset))
    }

    private fun leU32(bytes: ByteArray, offset: Int): Int {
        if (offset + 3 >= bytes.size) return 0
        return (bytes[offset].toInt() and 0xFF) or
            ((bytes[offset + 1].toInt() and 0xFF) shl 8) or
            ((bytes[offset + 2].toInt() and 0xFF) shl 16) or
            ((bytes[offset + 3].toInt() and 0xFF) shl 24)
    }

    private fun leU64(bytes: ByteArray, offset: Int): Long {
        if (offset + 7 >= bytes.size) return 0
        var value = 0L
        for (i in 7 downTo 0) {
            value = (value shl 8) or (bytes[offset + i].toLong() and 0xFF)
        }
        return value
    }
}
